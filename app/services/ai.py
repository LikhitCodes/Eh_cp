import json

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.models import ApiEndpoint, Case, CaseArtifact, EndpointEvidence, GovernanceRule, LLMGeneration


def _build_prompt(case: Case, artifacts: list[CaseArtifact]) -> str:
    artifact_lines = []
    for artifact in artifacts:
        artifact_lines.append(
            f"- [{artifact.artifact_type}] {artifact.source_ref}: {json.dumps(artifact.content, ensure_ascii=True)[:600]}"
        )

    prompt = (
        "You are a cybersecurity analyst assistant. Summarize this investigation case with explicit evidence citations. "
        "Never suggest autonomous destructive actions.\n\n"
        f"Case ID: {case.id}\n"
        f"Title: {case.title}\n"
        f"Severity: {case.severity}\n"
        f"Status: {case.status}\n"
        "Artifacts:\n"
        + "\n".join(artifact_lines)
        + "\n\nOutput format:\n"
        "1) Situation\n2) Evidence\n3) Recommended next safe actions\n4) Citation IDs"
    )
    return prompt


def _rich_fallback_summary(case: Case, endpoint, artifacts: list[CaseArtifact]) -> str:
    lines = []
    lines.append("## Situation Assessment")
    lines.append(f"Case #{case.id} ({case.severity}) - {case.title}")

    if endpoint:
        lc = endpoint.lifecycle_state.state if endpoint.lifecycle_state else "unknown"
        risk_score = endpoint.risk_assessment.risk_score if endpoint.risk_assessment else "N/A"
        risk_sev = endpoint.risk_assessment.severity if endpoint.risk_assessment else "N/A"
        tls = getattr(endpoint, "tls_status", "unknown")
        auth = endpoint.auth_type

        lines.append(f"Targeting {lc} API: {endpoint.method} {endpoint.path} @ {endpoint.host}")
        lines.append(f"Risk Score: {risk_score}/100 ({risk_sev}) | TLS: {tls} | Auth: {auth}")
        lines.append("")

        lines.append("## Evidence Analysis")
        lines.append(f"- Gateway: {'Active traffic confirmed' if endpoint.seen_in_gateway else 'No gateway traffic observed'}")
        lines.append(f"- Code Repository: {'Found in service specification' if endpoint.expected_in_code else 'NOT found in any service specification - undocumented'}")
        lines.append(f"- SIEM: {'Threat signals detected' if endpoint.seen_in_siem else 'No active threat signals'}")
        lines.append(f"- Owner: {endpoint.owner_team or 'UNASSIGNED - no team responsible'}")
        lines.append("")

        if endpoint.risk_assessment and endpoint.risk_assessment.factors:
            lines.append("## Risk Factor Breakdown")
            factor_parts = []
            for f in endpoint.risk_assessment.factors:
                factor_parts.append(f"{f.get('factor', '?')}={f.get('points', 0)} ({f.get('detail', '')})")
            lines.append(" | ".join(factor_parts))
            lines.append("")

        lines.append("## Recommended Actions")
        if lc == "zombie":
            lines.append("1. IMMEDIATE: Quarantine endpoint via API gateway to block external access")
            lines.append("2. SHORT-TERM: Assign ownership to security operations team")
            lines.append("3. MEDIUM-TERM: Assess data exposure scope and notify compliance")
            lines.append("4. LONG-TERM: Decommission and remove from infrastructure")
        elif lc == "orphaned":
            lines.append("1. IMMEDIATE: Identify owning team through service mesh tracing")
            lines.append("2. SHORT-TERM: Add authentication and rate limiting")
            lines.append("3. MEDIUM-TERM: Document in service registry and add monitoring")
        elif lc == "deprecated":
            lines.append("1. IMMEDIATE: Verify no active consumers depend on this endpoint")
            lines.append("2. SHORT-TERM: Set deprecation headers and notify consumers")
            lines.append("3. MEDIUM-TERM: Plan migration path and sunset date")
        else:
            lines.append("1. Review current security controls and ensure they meet policy")
            lines.append("2. Verify monitoring coverage is adequate")
            lines.append("3. Schedule periodic risk reassessment")

        if endpoint.data_sensitivity == "high" and auth == "none":
            lines.append("")
            lines.append("## Regulatory Note")
            lines.append("Endpoint handles high-sensitivity data with no authentication - potential RBI compliance violation.")
    else:
        lines.append("No linked endpoint available for detailed analysis.")
        lines.append("")
        lines.append("## Recommended Actions")
        lines.append("1. Link this case to a specific API endpoint for deeper analysis")
        lines.append("2. Review case artifacts for actionable threat indicators")

    lines.append("")
    lines.append("## Citations")
    for a in artifacts[:5]:
        lines.append(f"- {a.source_ref}")

    return "\n".join(lines)


def summarize_case(db: Session, case_id: int) -> dict:
    case = db.get(Case, case_id)
    if not case:
        raise ValueError("Case not found")

    artifacts = list(db.scalars(select(CaseArtifact).where(CaseArtifact.case_id == case.id).order_by(CaseArtifact.id.asc())))
    prompt = _build_prompt(case, artifacts)

    sources = [{"artifact_id": artifact.id, "source_ref": artifact.source_ref} for artifact in artifacts]
    model_used = settings.ollama_model
    safe = True

    summary = ""
    try:
        with httpx.Client(timeout=float(settings.ollama_timeout_seconds)) as client:
            resp = client.post(
                f"{settings.ollama_base_url.rstrip('/')}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            body = resp.json()
            summary = str(body.get("response", "")).strip()
    except Exception:
        endpoint = None
        if case.endpoint_id:
            endpoint = db.scalar(
                select(ApiEndpoint)
                .where(ApiEndpoint.id == case.endpoint_id)
                .options(
                    joinedload(ApiEndpoint.lifecycle_state),
                    joinedload(ApiEndpoint.risk_assessment),
                )
            )
        summary = _rich_fallback_summary(case, endpoint, artifacts)
        model_used = "fallback-template"

    generation = LLMGeneration(
        case_id=case.id,
        model=model_used,
        prompt=prompt,
        output_text=summary,
        sources=sources,
        safe=safe,
    )
    db.add(generation)
    db.commit()

    return {
        "case_id": case.id,
        "summary": summary,
        "model": model_used,
        "sources": sources,
        "safe": safe,
    }


def generate_remediation_playbook(db: Session, endpoint: ApiEndpoint) -> dict:
    lc = endpoint.lifecycle_state.state if endpoint.lifecycle_state else "unknown"
    risk_score = endpoint.risk_assessment.risk_score if endpoint.risk_assessment else 0
    risk_sev = endpoint.risk_assessment.severity if endpoint.risk_assessment else "low"
    tls = getattr(endpoint, "tls_status", "unknown")
    auth = endpoint.auth_type
    owner = endpoint.owner_team or "Unassigned"

    evidences = list(db.scalars(
        select(EndpointEvidence).where(EndpointEvidence.endpoint_id == endpoint.id).order_by(EndpointEvidence.id.desc()).limit(10)
    ))
    evidence_sources = [e.source_type for e in evidences]

    governance_violations = []
    rules = list(db.scalars(select(GovernanceRule).where(GovernanceRule.is_active.is_(True))))
    from app.services.governance import evaluate_endpoint_compliance
    compliance = evaluate_endpoint_compliance(endpoint, rules)
    for v in compliance.get("violations", []):
        governance_violations.append(f"{v['rule_name']} ({v['severity']})")

    steps = []
    step_num = 1

    if lc == "zombie":
        steps.append(f"{step_num}. QUARANTINE: Block all traffic via API gateway policy immediately")
        step_num += 1
        steps.append(f"{step_num}. OWNERSHIP: Assign to security operations team for investigation")
        step_num += 1
        if endpoint.seen_in_siem:
            steps.append(f"{step_num}. THREAT RESPONSE: Review SIEM findings and assess data breach potential")
            step_num += 1
        if endpoint.data_sensitivity == "high":
            steps.append(f"{step_num}. COMPLIANCE: Notify compliance team - high-sensitivity data endpoint with inadequate controls")
            step_num += 1
        steps.append(f"{step_num}. DECOMMISSION: Remove from infrastructure after investigation concludes")
        step_num += 1
    elif lc == "orphaned":
        steps.append(f"{step_num}. DISCOVERY: Trace service mesh to identify originating deployment")
        step_num += 1
        steps.append(f"{step_num}. SECURE: Add authentication (OAuth2/mTLS) and rate limiting")
        step_num += 1
        steps.append(f"{step_num}. DOCUMENT: Register in API catalog with owner assignment")
        step_num += 1
        steps.append(f"{step_num}. MONITOR: Add endpoint to continuous monitoring schedule")
        step_num += 1
    elif lc == "deprecated":
        steps.append(f"{step_num}. AUDIT CONSUMERS: Identify all active consumers of this deprecated endpoint")
        step_num += 1
        steps.append(f"{step_num}. MIGRATION: Provide migration path to replacement endpoint")
        step_num += 1
        steps.append(f"{step_num}. SUNSET NOTICE: Set Deprecation and Sunset HTTP headers")
        step_num += 1
        steps.append(f"{step_num}. TIMELINE: Schedule decommissioning within 90 days")
        step_num += 1
    else:
        if governance_violations:
            steps.append(f"{step_num}. REMEDIATE: Fix governance violations: {', '.join(governance_violations)}")
            step_num += 1
        if tls in ("none", "tls_1.0"):
            steps.append(f"{step_num}. ENCRYPT: Upgrade to TLS 1.2+ minimum")
            step_num += 1
        if auth == "none":
            steps.append(f"{step_num}. AUTHENTICATE: Implement authentication controls")
            step_num += 1
        if not steps:
            steps.append(f"{step_num}. MAINTAIN: Continue monitoring - endpoint meets current policy requirements")

    return {
        "endpoint_id": endpoint.id,
        "identity": f"{endpoint.method} {endpoint.path} @ {endpoint.host}",
        "lifecycle_state": lc,
        "risk_score": risk_score,
        "risk_severity": risk_sev,
        "tls_status": tls,
        "auth_type": auth,
        "owner_team": owner,
        "evidence_sources": list(set(evidence_sources)),
        "governance_violations": governance_violations,
        "compliance_score": compliance.get("score", 100),
        "playbook_steps": steps,
        "priority": "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low",
        "estimated_effort": "1-2 hours" if lc in ("zombie", "orphaned") else "1-2 weeks" if lc == "deprecated" else "varies",
    }
