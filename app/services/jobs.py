from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.models import IngestionJob, JobAttempt
from app.services.connectors import sync_github, sync_k8s, sync_kong, sync_network, sync_splunk
from app.services.repository import ensure_tenant


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def enqueue_job(db: Session, job_type: str, payload: dict, tenant_code: Optional[str]) -> IngestionJob:
    tenant = ensure_tenant(db, tenant_code)
    job = IngestionJob(
        tenant_id=tenant.id,
        job_type=job_type,
        payload=payload,
        status="queued",
        available_at=_utcnow(),
        max_attempts=3,
    )
    db.add(job)
    db.flush()
    db.commit()
    return job


def _claim_next_job_postgres(db: Session, worker_name: str) -> Optional[IngestionJob]:
    row = db.execute(
        text(
            """
            SELECT id
            FROM ingestion_jobs
            WHERE status = 'queued'
              AND available_at <= NOW()
              AND attempts < max_attempts
            ORDER BY id ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        )
    ).first()
    if not row:
        return None

    job_id = int(row[0])
    job = db.get(IngestionJob, job_id)
    if not job:
        return None

    job.status = "processing"
    job.attempts = int(job.attempts) + 1
    job.locked_by = worker_name
    job.locked_at = _utcnow()
    db.flush()
    return job


def _claim_next_job_sqlite(db: Session, worker_name: str) -> Optional[IngestionJob]:
    job = db.scalar(
        select(IngestionJob)
        .where(
            IngestionJob.status == "queued",
            IngestionJob.available_at <= _utcnow(),
            IngestionJob.attempts < IngestionJob.max_attempts,
        )
        .order_by(IngestionJob.id.asc())
        .limit(1)
    )
    if not job:
        return None

    job.status = "processing"
    job.attempts = int(job.attempts) + 1
    job.locked_by = worker_name
    job.locked_at = _utcnow()
    db.flush()
    return job


def claim_next_job(db: Session, worker_name: str) -> Optional[IngestionJob]:
    if settings.database_url.startswith("postgresql"):
        return _claim_next_job_postgres(db, worker_name)
    return _claim_next_job_sqlite(db, worker_name)


def _run_connector_sync(job: IngestionJob, db: Session) -> dict:
    tenant_code = (job.payload or {}).get("tenant_code")

    if job.job_type == "connector_kong_sync":
        return sync_kong(db, tenant_code)
    if job.job_type == "connector_github_sync":
        return sync_github(db, tenant_code)
    if job.job_type == "connector_splunk_sync":
        return sync_splunk(db, tenant_code)
    if job.job_type == "connector_network_sync":
        return sync_network(db, tenant_code)
    if job.job_type == "connector_k8s_sync":
        return sync_k8s(db, tenant_code)

    raise RuntimeError(f"Unsupported job type: {job.job_type}")


def process_job(db: Session, job: IngestionJob) -> dict:
    attempt = JobAttempt(
        job_id=job.id,
        attempt_no=job.attempts,
        status="started",
        started_at=_utcnow(),
    )
    db.add(attempt)
    db.flush()

    try:
        result = _run_connector_sync(job, db)
        attempt.status = "success"
        attempt.finished_at = _utcnow()

        job.status = "completed"
        job.last_error = None
        job.locked_by = None
        job.locked_at = None
        db.commit()
        return result

    except Exception as exc:  # noqa: BLE001
        attempt.status = "failed"
        attempt.error_message = str(exc)
        attempt.finished_at = _utcnow()

        job.last_error = str(exc)
        job.locked_by = None
        job.locked_at = None

        if job.attempts >= job.max_attempts:
            job.status = "failed"
        else:
            job.status = "queued"
            job.available_at = _utcnow() + timedelta(seconds=10)

        db.commit()
        raise
