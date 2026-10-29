from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApiEndpoint, EndpointEvidence, RiskAssessment


SEVERITY_THRESHOLDS = [
    (85, "critical"),
    (70, "high"),
    (40, "medium"),
    (0, "low"),
]


def _severity_from_score(score: int) -> str:
    for floor, label in SEVERITY_THRESHOLDS:
        if score >= floor:
            return label
    return "low"


def compute_risk(endpoint: ApiEndpoint, siem_findings: list[EndpointEvidence]) -> tuple[int, str, list[dict], str]:
    score = 0
    factors: list[dict] = []

    exposure_points = 25 if endpoint.is_external else 5
    score += exposure_points
    factors.append({"factor": "exposure", "points": exposure_points, "detail": "external" if endpoint.is_external else "internal"})

    auth_map = {"none": 30, "weak": 20, "strong": 5}
    auth_points = auth_map.get(endpoint.auth_type, 10)
    score += auth_points
    factors.append({"factor": "auth_posture", "points": auth_points, "detail": endpoint.auth_type})

    sensitivity_map = {"high": 20, "medium": 10, "low": 3, "unknown": 7}
    sens_points = sensitivity_map.get(endpoint.data_sensitivity, 7)
    score += sens_points
    factors.append({"factor": "data_sensitivity", "points": sens_points, "detail": endpoint.data_sensitivity})

    rate_points = 10 if not endpoint.has_rate_limit else 0
    score += rate_points
    factors.append({"factor": "rate_limit", "points": rate_points, "detail": "missing" if rate_points else "present"})

    tls_map = {"none": 15, "tls_1.0": 12, "unknown": 8, "tls_1.2": 3, "tls_1.3": 0, "mtls": 0}
    tls_val = getattr(endpoint, "tls_status", "unknown")
    tls_points = tls_map.get(tls_val, 8)
    score += tls_points
    factors.append({"factor": "encryption", "points": tls_points, "detail": tls_val})

    lifecycle_state = endpoint.lifecycle_state.state if endpoint.lifecycle_state else "active"
    lifecycle_map = {"zombie": 20, "orphaned": 12, "deprecated": 8, "active": 0}
    lifecycle_points = lifecycle_map.get(lifecycle_state, 5)
    score += lifecycle_points
    factors.append({"factor": "lifecycle", "points": lifecycle_points, "detail": lifecycle_state})

    siem_points = 0
    for finding in siem_findings:
        severity = str(finding.details.get("severity", "low"))
        siem_points += {"high": 20, "medium": 10, "low": 5}.get(severity, 5)
    siem_points = min(siem_points, 25)
    score += siem_points
    if siem_points:
        factors.append({"factor": "threat_signals", "points": siem_points, "detail": f"{len(siem_findings)} findings"})

    raw_score = score
    score = min(score, 100)
    severity = _severity_from_score(score)
    cap_note = f" [capped from {raw_score}]" if raw_score > 100 else ""
    explainability = "; ".join(f"{item['factor']}={item['points']}" for item in factors) + cap_note
    return score, severity, factors, explainability


def upsert_risk(db: Session, endpoint: ApiEndpoint) -> RiskAssessment:
    findings = list(
        db.scalars(
            select(EndpointEvidence).where(
                EndpointEvidence.endpoint_id == endpoint.id,
                EndpointEvidence.source_type == "siem",
            )
        )
    )
    score, severity, factors, explainability = compute_risk(endpoint, findings)
    assessment = endpoint.risk_assessment

    if assessment is None:
        assessment = RiskAssessment(
            endpoint_id=endpoint.id,
            risk_score=score,
            severity=severity,
            factors=factors,
            explainability=explainability,
            assessed_at=datetime.now(timezone.utc),
        )
        db.add(assessment)
    else:
        assessment.risk_score = score
        assessment.severity = severity
        assessment.factors = factors
        assessment.explainability = explainability
        assessment.assessed_at = datetime.now(timezone.utc)

    db.flush()
    return assessment
