from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ActionApproval, ApiEndpoint, Policy, RemediationAction


def _policy_matches(policy: Policy, endpoint: ApiEndpoint) -> bool:
    conditions = policy.conditions or {}

    risk_score = endpoint.risk_assessment.risk_score if endpoint.risk_assessment else 0
    lifecycle = endpoint.lifecycle_state.state if endpoint.lifecycle_state else "active"

    risk_floor = int(conditions.get("risk_score_gte", 0))
    lifecycle_in = conditions.get("lifecycle_in", [])

    if risk_score < risk_floor:
        return False

    if lifecycle_in and lifecycle not in lifecycle_in:
        return False

    return True


def get_required_approvals(db: Session, endpoint: ApiEndpoint, action_type: str) -> int:
    required = 1 if action_type in {"quarantine", "decommission"} else 0

    policies = list(
        db.scalars(
            select(Policy).where(
                Policy.tenant_id == endpoint.tenant_id,
                Policy.action_type == action_type,
                Policy.is_active.is_(True),
            )
        )
    )

    for policy in policies:
        if _policy_matches(policy, endpoint):
            required = max(required, policy.min_approvals)

    return required


def get_approval_count(db: Session, action_id: int) -> int:
    return db.scalar(
        select(func.count(ActionApproval.id)).where(
            ActionApproval.action_id == action_id,
            ActionApproval.decision == "approved",
        )
    ) or 0


def attach_approval(
    db: Session,
    action: RemediationAction,
    approver: str,
    approver_role: str,
    comment: str,
) -> ActionApproval:
    approval = ActionApproval(
        action_id=action.id,
        approver=approver,
        approver_role=approver_role,
        decision="approved",
        comment=comment,
    )
    db.add(approval)
    db.flush()
    return approval
