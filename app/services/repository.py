from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ApiEndpoint, EndpointEvidence, Policy, Tenant


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def endpoint_identity(method: str, path: str, host: str, env: str) -> tuple[str, str, str, str]:
    return method.upper(), path, host.lower(), env.lower()


def ensure_tenant(db: Session, tenant_code: Optional[str] = None) -> Tenant:
    code = (tenant_code or settings.default_tenant_code).strip().lower()
    tenant = db.scalar(select(Tenant).where(Tenant.code == code))
    if tenant:
        return tenant

    tenant = Tenant(code=code, name=settings.default_tenant_name)
    db.add(tenant)
    db.flush()
    return tenant


def ensure_default_policy(db: Session, tenant_id: int) -> Policy:
    existing = db.scalar(select(Policy).where(Policy.tenant_id == tenant_id, Policy.name == "high_risk_quarantine"))
    if existing:
        return existing

    policy = Policy(
        tenant_id=tenant_id,
        name="high_risk_quarantine",
        action_type="quarantine",
        min_approvals=1,
        conditions={"risk_score_gte": 85},
        is_active=True,
    )
    db.add(policy)
    db.flush()
    return policy


def get_or_create_endpoint(
    db: Session,
    *,
    method: str,
    path: str,
    host: str,
    env: str,
    tenant_code: Optional[str] = None,
) -> tuple[ApiEndpoint, bool]:
    tenant = ensure_tenant(db, tenant_code)
    ensure_default_policy(db, tenant.id)

    norm_method, norm_path, norm_host, norm_env = endpoint_identity(method, path, host, env)
    endpoint = db.scalar(
        select(ApiEndpoint).where(
            ApiEndpoint.tenant_id == tenant.id,
            ApiEndpoint.method == norm_method,
            ApiEndpoint.path == norm_path,
            ApiEndpoint.host == norm_host,
            ApiEndpoint.env == norm_env,
        )
    )
    if endpoint:
        return endpoint, False

    endpoint = ApiEndpoint(
        tenant_id=tenant.id,
        method=norm_method,
        path=norm_path,
        host=norm_host,
        env=norm_env,
        last_seen_at=utcnow(),
    )
    db.add(endpoint)
    db.flush()
    return endpoint, True


def add_evidence(
    db: Session,
    *,
    endpoint_id: int,
    source_type: str,
    source_ref: str,
    details: dict,
    confidence: float = 0.85,
) -> EndpointEvidence:
    evidence = EndpointEvidence(
        endpoint_id=endpoint_id,
        source_type=source_type,
        source_ref=source_ref,
        details=details,
        confidence=confidence,
    )
    db.add(evidence)
    db.flush()
    return evidence
