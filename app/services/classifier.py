from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import ApiEndpoint, LifecycleState


def classify_endpoint(endpoint: ApiEndpoint) -> tuple[str, float, list[str]]:
    reasons: list[str] = []
    state = "active"
    confidence = 0.72

    unknown_owner = not endpoint.owner_team
    weak_auth = endpoint.auth_type in {"none", "weak"}

    if endpoint.deprecated:
        state = "deprecated"
        confidence = 0.82
        reasons.append("Endpoint is marked deprecated in source spec")

    if endpoint.seen_in_gateway and not endpoint.expected_in_code:
        state = "orphaned"
        confidence = 0.85
        reasons.append("Runtime traffic exists but endpoint is missing in code spec")

    if endpoint.seen_in_gateway and (unknown_owner or weak_auth) and (endpoint.deprecated or not endpoint.expected_in_code):
        state = "zombie"
        confidence = 0.9
        reasons.append("Endpoint appears unmanaged with weak controls")

    if endpoint.is_quarantined:
        reasons.append("Endpoint has active quarantine")

    if endpoint.expected_in_code and endpoint.seen_in_gateway and state == "active":
        reasons.append("Endpoint observed in runtime and expected by service spec")

    if not reasons:
        reasons.append("Insufficient evidence; defaulting to active")

    return state, confidence, reasons


def upsert_lifecycle(db: Session, endpoint: ApiEndpoint) -> LifecycleState:
    state, confidence, reasons = classify_endpoint(endpoint)
    lifecycle = endpoint.lifecycle_state

    if lifecycle is None:
        lifecycle = LifecycleState(
            endpoint_id=endpoint.id,
            state=state,
            confidence=confidence,
            reasons=reasons,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(lifecycle)
    else:
        lifecycle.state = state
        lifecycle.confidence = confidence
        lifecycle.reasons = reasons
        lifecycle.updated_at = datetime.now(timezone.utc)

    db.flush()
    return lifecycle
