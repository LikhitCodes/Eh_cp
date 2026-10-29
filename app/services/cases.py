from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApiEndpoint, Case, CaseArtifact
from app.schemas import CaseCreate
from app.services.repository import ensure_tenant


def create_case(db: Session, tenant_code: str, created_by: str, payload: CaseCreate) -> Case:
    tenant = ensure_tenant(db, tenant_code)

    endpoint = None
    if payload.endpoint_id:
        endpoint = db.get(ApiEndpoint, payload.endpoint_id)

    case = Case(
        tenant_id=tenant.id,
        endpoint_id=payload.endpoint_id,
        title=payload.title,
        status="open",
        severity=payload.severity,
        created_by=created_by,
        assigned_to=payload.assigned_to,
        summary=payload.summary,
    )
    db.add(case)
    db.flush()

    if endpoint:
        artifact = CaseArtifact(
            case_id=case.id,
            artifact_type="endpoint_snapshot",
            source_ref=f"endpoint:{endpoint.id}",
            content={
                "identity": f"{endpoint.method} {endpoint.path} @ {endpoint.host}",
                "lifecycle": endpoint.lifecycle_state.state if endpoint.lifecycle_state else None,
                "risk_score": endpoint.risk_assessment.risk_score if endpoint.risk_assessment else None,
                "risk_severity": endpoint.risk_assessment.severity if endpoint.risk_assessment else None,
            },
        )
        db.add(artifact)

    db.commit()
    db.refresh(case)
    return case


def list_cases(
    db: Session,
    tenant_code: str,
    *,
    status_filter: Optional[str],
    severity_filter: Optional[str],
    limit: int,
    offset: int,
) -> list[Case]:
    tenant = ensure_tenant(db, tenant_code)

    query = select(Case).where(Case.tenant_id == tenant.id)
    if status_filter:
        query = query.where(Case.status == status_filter)
    if severity_filter:
        query = query.where(Case.severity == severity_filter)

    query = query.order_by(Case.id.desc()).offset(offset).limit(limit)
    return list(db.scalars(query))


def get_case_with_artifacts(db: Session, tenant_code: str, case_id: int) -> Optional[Case]:
    tenant = ensure_tenant(db, tenant_code)
    case = db.scalar(select(Case).where(Case.id == case_id, Case.tenant_id == tenant.id))
    return case
