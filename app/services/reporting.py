from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ApiEndpoint, LifecycleState, RemediationAction, RiskAssessment, RiskSnapshot


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_executive_report(db: Session, generated_by: str) -> dict:
    total_endpoints = db.scalar(select(func.count(ApiEndpoint.id))) or 0
    quarantined = db.scalar(select(func.count(ApiEndpoint.id)).where(ApiEndpoint.is_quarantined.is_(True))) or 0

    lifecycle_rows = db.execute(
        select(LifecycleState.state, func.count(LifecycleState.id)).group_by(LifecycleState.state)
    ).all()
    lifecycle_breakdown = {row[0]: row[1] for row in lifecycle_rows}

    severity_rows = db.execute(
        select(RiskAssessment.severity, func.count(RiskAssessment.id)).group_by(RiskAssessment.severity)
    ).all()
    severity_breakdown = {row[0]: row[1] for row in severity_rows}

    top_risks = []
    top_rows = db.execute(
        select(ApiEndpoint.id, ApiEndpoint.method, ApiEndpoint.path, ApiEndpoint.host, RiskAssessment.risk_score, RiskAssessment.severity)
        .join(RiskAssessment, RiskAssessment.endpoint_id == ApiEndpoint.id)
        .order_by(RiskAssessment.risk_score.desc())
        .limit(5)
    ).all()
    for row in top_rows:
        top_risks.append(
            {
                "endpoint_id": row[0],
                "identity": f"{row[1]} {row[2]} @ {row[3]}",
                "risk_score": row[4],
                "severity": row[5],
            }
        )

    action_rows = db.execute(
        select(RemediationAction.status, func.count(RemediationAction.id)).group_by(RemediationAction.status)
    ).all()
    remediation_summary = {row[0]: row[1] for row in action_rows}

    return {
        "generated_at": _utcnow(),
        "generated_by": generated_by,
        "totals": {
            "endpoints": total_endpoints,
            "quarantined": quarantined,
            "high_or_critical": (severity_breakdown.get("high", 0) + severity_breakdown.get("critical", 0)),
        },
        "lifecycle_breakdown": lifecycle_breakdown,
        "severity_breakdown": severity_breakdown,
        "top_risks": top_risks,
        "remediation_summary": remediation_summary,
    }


def build_board_report(db: Session, generated_by: str) -> dict:
    exec_report = build_executive_report(db, generated_by)

    # Baseline: first snapshot per endpoint (initial discovery scores)
    first_snap_ids = select(func.min(RiskSnapshot.id)).group_by(RiskSnapshot.endpoint_id).subquery()
    first_avg = db.scalar(select(func.avg(RiskSnapshot.risk_score)).where(RiskSnapshot.id.in_(select(first_snap_ids))))

    # Current: latest snapshot per endpoint (post-remediation scores)
    latest_snap_ids = select(func.max(RiskSnapshot.id)).group_by(RiskSnapshot.endpoint_id).subquery()
    latest_avg = db.scalar(select(func.avg(RiskSnapshot.risk_score)).where(RiskSnapshot.id.in_(select(latest_snap_ids))))

    if first_avg is None:
        first_avg = latest_avg or 0
    if latest_avg is None:
        latest_avg = 0

    absolute_drop = max(float(first_avg) - float(latest_avg), 0.0)
    pct_drop = 0.0 if float(first_avg) == 0 else (absolute_drop / float(first_avg)) * 100.0

    # Dynamic ROI model: direct loss + RBI regulatory fines + reputation damage
    high_count = exec_report["totals"].get("high_or_critical", 0)
    quarantined = exec_report["totals"].get("quarantined", 0)
    zombie_count = exec_report["lifecycle_breakdown"].get("zombie", 0)

    # Per-endpoint direct loss estimate (data breach, operational disruption)
    estimated_loss_per_high_api = 200000  # INR baseline
    direct_loss_exposure = high_count * estimated_loss_per_high_api

    # RBI regulatory fine risk: RBI can impose up to ₹2Cr per data breach incident
    # Zombie APIs with high-sensitivity data and no auth = highest regulatory risk
    rbi_fine_risk_per_zombie = 500000  # ₹5L average per zombie (conservative of ₹2Cr max)
    regulatory_exposure = zombie_count * rbi_fine_risk_per_zombie

    # Reputation damage: estimated at 3x direct loss for banking sector
    reputation_multiplier = 3
    reputation_exposure = direct_loss_exposure * reputation_multiplier

    total_risk_exposure = direct_loss_exposure + regulatory_exposure + reputation_exposure

    # What we've actually avoided via quarantine actions
    direct_avoided = quarantined * estimated_loss_per_high_api
    regulatory_avoided = min(quarantined, zombie_count) * rbi_fine_risk_per_zombie
    reputation_avoided = direct_avoided * reputation_multiplier
    total_avoided = direct_avoided + regulatory_avoided + reputation_avoided

    # Also factor in risk score improvement
    pct_avoided = int(total_risk_exposure * (pct_drop / 100.0))
    avoided_loss = max(total_avoided, pct_avoided)

    top_actions = []
    rows = db.execute(
        select(
            RemediationAction.id,
            RemediationAction.action_type,
            RemediationAction.status,
            RemediationAction.requested_by,
            RemediationAction.executed_at,
        )
        .order_by(RemediationAction.id.desc())
        .limit(5)
    ).all()
    for row in rows:
        top_actions.append(
            {
                "action_id": row[0],
                "type": row[1],
                "status": row[2],
                "requested_by": row[3],
                "executed_at": row[4],
            }
        )

    summary = (
        "API Sentinel has reduced weighted API risk exposure through policy-governed remediation and improved visibility "
        "across gateway, code, and SIEM evidence streams."
    )

    return {
        "generated_at": _utcnow(),
        "generated_by": generated_by,
        "executive_summary": summary,
        "kpis": {
            "total_endpoints": exec_report["totals"].get("endpoints", 0),
            "high_or_critical": exec_report["totals"].get("high_or_critical", 0),
            "quarantined": exec_report["totals"].get("quarantined", 0),
        },
        "risk_delta": {
            "baseline_avg_score": round(float(first_avg), 2),
            "current_avg_score": round(float(latest_avg), 2),
            "absolute_drop": round(absolute_drop, 2),
            "percentage_drop": round(pct_drop, 2),
        },
        "top_actions": top_actions,
        "roi_estimate": {
            "total_risk_exposure_inr": int(total_risk_exposure),
            "direct_loss_exposure_inr": int(direct_loss_exposure),
            "regulatory_fine_exposure_inr": int(regulatory_exposure),
            "reputation_damage_exposure_inr": int(reputation_exposure),
            "estimated_avoided_loss_inr": int(avoided_loss),
            "direct_loss_avoided_inr": int(direct_avoided),
            "regulatory_fine_avoided_inr": int(regulatory_avoided),
            "reputation_damage_avoided_inr": int(reputation_avoided),
            "zombie_apis_found": zombie_count,
            "endpoints_quarantined": quarantined,
            "assumption": "RBI penalty up to ₹2Cr/breach; reputation at 3× direct loss; calibrate with bank incident data.",
        },
    }
