from sqlalchemy.orm import Session

from app.models import ApiEndpoint, RiskSnapshot
from app.services.classifier import upsert_lifecycle
from app.services.risk import upsert_risk


def recompute_endpoint(db: Session, endpoint: ApiEndpoint, trigger_event: str = "recompute") -> tuple[str, float, int, str]:
    lifecycle = upsert_lifecycle(db, endpoint)
    risk = upsert_risk(db, endpoint)

    snapshot = RiskSnapshot(
        endpoint_id=endpoint.id,
        risk_score=risk.risk_score,
        severity=risk.severity,
        lifecycle_state=lifecycle.state,
        trigger_event=trigger_event,
    )
    db.add(snapshot)
    db.flush()

    return lifecycle.state, lifecycle.confidence, risk.risk_score, risk.severity


def recompute_all(db: Session, trigger_event: str = "bulk_recompute") -> None:
    endpoints = db.query(ApiEndpoint).all()
    for endpoint in endpoints:
        recompute_endpoint(db, endpoint, trigger_event=trigger_event)
