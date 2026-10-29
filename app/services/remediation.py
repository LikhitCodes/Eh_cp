import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ApiEndpoint, EndpointEvidence, RemediationAction
from app.services.policy import get_approval_count, get_required_approvals


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def action_requires_approval(action_type: str, endpoint: ApiEndpoint) -> bool:
    high_risk = endpoint.risk_assessment is not None and endpoint.risk_assessment.risk_score >= 85
    return action_type in {"quarantine", "decommission"} or high_risk


def _estimate_active_sessions(db: Session, endpoint: ApiEndpoint) -> dict:
    """Estimate active sessions / traffic volume from evidence data."""
    evidence_count = db.scalar(
        select(func.count(EndpointEvidence.id)).where(
            EndpointEvidence.endpoint_id == endpoint.id
        )
    ) or 0

    siem_count = db.scalar(
        select(func.count(EndpointEvidence.id)).where(
            EndpointEvidence.endpoint_id == endpoint.id,
            EndpointEvidence.source_type == "siem",
        )
    ) or 0

    gateway_events = db.scalar(
        select(func.count(EndpointEvidence.id)).where(
            EndpointEvidence.endpoint_id == endpoint.id,
            EndpointEvidence.source_type == "gateway",
        )
    ) or 0

    # Estimate based on observed traffic patterns
    base_sessions = gateway_events * 1200  # Each gateway evidence ≈ 1200 active sessions
    if endpoint.is_external:
        base_sessions = int(base_sessions * 2.5)
    if endpoint.business_critical:
        base_sessions = max(base_sessions, 5000)

    # Sensitivity-adjusted account exposure
    sensitivity_multiplier = {"high": 3.0, "medium": 1.5, "low": 0.5}.get(
        endpoint.data_sensitivity, 1.0
    )
    estimated_accounts = int(base_sessions * sensitivity_multiplier)

    # Transaction volume estimate (banking context)
    daily_txn_estimate = base_sessions * 15  # ~15 txns per session
    if endpoint.data_sensitivity == "high":
        daily_txn_estimate *= 3

    return {
        "evidence_signals": evidence_count,
        "gateway_events_observed": gateway_events,
        "active_threat_signals": siem_count,
        "estimated_active_sessions": max(base_sessions, 100),
        "estimated_affected_accounts": max(estimated_accounts, 50),
        "estimated_daily_transactions": daily_txn_estimate,
        "data_sensitivity": endpoint.data_sensitivity,
    }


def simulate_action(action: RemediationAction, endpoint: ApiEndpoint, db: Session = None) -> dict:
    risk_score = endpoint.risk_assessment.risk_score if endpoint.risk_assessment else 0
    blast_radius = "high" if endpoint.business_critical or risk_score >= 85 else "moderate"

    # Enhanced blast radius with real session estimation
    session_data = {}
    if db:
        session_data = _estimate_active_sessions(db, endpoint)
        estimated_impacted_accounts = session_data.get("estimated_affected_accounts", 750)
    else:
        estimated_impacted_accounts = 5000 if blast_radius == "high" else 750
        if endpoint.is_external:
            estimated_impacted_accounts = int(estimated_impacted_accounts * 1.3)

    # Risk-adjusted recommendation
    recommendation = "Execute during low traffic window with rollback ready."
    if blast_radius == "high":
        recommendation = "CRITICAL: Require dual approval, execute with staged rollout, monitor for 15 minutes."
    if session_data.get("active_threat_signals", 0) > 0:
        recommendation += " Active threats detected — prioritize immediate containment."

    # Downstream dependency analysis
    downstream_services = []
    if endpoint.service_name:
        downstream_services.append(f"{endpoint.service_name} (primary)")
    if endpoint.is_external:
        downstream_services.append("External API consumers")
    if endpoint.business_critical:
        downstream_services.append("Core Banking System")

    return {
        "blast_radius": blast_radius,
        "estimated_impacted_accounts": estimated_impacted_accounts,
        "business_critical": endpoint.business_critical,
        "risk_score": risk_score,
        "recommendation": recommendation,
        "session_analysis": session_data,
        "downstream_services": downstream_services,
        "rollback_available": True,
        "estimated_downtime_minutes": 0 if action.action_type == "rate_limit" else 2,
        "can_staged_rollout": blast_radius == "high",
    }


def execute_action(action: RemediationAction, endpoint: ApiEndpoint) -> None:
    if action.action_type == "rate_limit":
        endpoint.has_rate_limit = True
    elif action.action_type == "quarantine":
        endpoint.is_quarantined = True
    elif action.action_type == "decommission":
        endpoint.is_quarantined = True
        endpoint.deprecated = True
    # alert has no endpoint mutation

    action.status = "executed"
    action.executed_at = _utcnow()
    action.rollback_ref = str(uuid.uuid4())


def rollback_action(action: RemediationAction, endpoint: ApiEndpoint) -> None:
    if action.action_type in {"quarantine", "decommission"}:
        endpoint.is_quarantined = False
    if action.action_type == "rate_limit":
        endpoint.has_rate_limit = False

    action.status = "rolled_back"


def ensure_executable(db: Session, action: RemediationAction, endpoint: ApiEndpoint) -> tuple[bool, str, int, int]:
    if action.status not in {"requested", "approved"}:
        return False, f"Action cannot be executed from status '{action.status}'", 0, 0

    required_approvals = get_required_approvals(db, endpoint, action.action_type)
    approval_count = get_approval_count(db, action.id)

    if action_requires_approval(action.action_type, endpoint) and approval_count < required_approvals:
        return False, "Approval threshold not met", approval_count, required_approvals

    return True, "ok", approval_count, required_approvals
