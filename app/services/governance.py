from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApiEndpoint, GovernanceRule


def evaluate_endpoint_compliance(endpoint: ApiEndpoint, rules: list[GovernanceRule]) -> dict:
    checks = []
    violations = []

    for rule in rules:
        if not rule.is_active:
            continue

        passed = True
        detail = ""

        if rule.rule_type == "auth_required":
            passed = endpoint.auth_type != "none"
            detail = f"auth_type={endpoint.auth_type}"
        elif rule.rule_type == "owner_required":
            passed = bool(endpoint.owner_team)
            detail = f"owner_team={endpoint.owner_team or 'unassigned'}"
        elif rule.rule_type == "rate_limit_external":
            if endpoint.is_external:
                passed = endpoint.has_rate_limit
                detail = f"external={endpoint.is_external}, rate_limited={endpoint.has_rate_limit}"
            else:
                detail = "internal endpoint, rule not applicable"
        elif rule.rule_type == "tls_minimum":
            passed = getattr(endpoint, "tls_status", "unknown") in ("tls_1.2", "tls_1.3", "mtls")
            detail = f"tls_status={getattr(endpoint, 'tls_status', 'unknown')}"
        elif rule.rule_type == "code_spec_required":
            passed = endpoint.expected_in_code
            detail = f"expected_in_code={endpoint.expected_in_code}"
        elif rule.rule_type == "siem_clear":
            passed = not endpoint.seen_in_siem
            detail = f"seen_in_siem={endpoint.seen_in_siem}"

        check = {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "rule_type": rule.rule_type,
            "passed": passed,
            "severity": rule.severity,
            "detail": detail,
        }
        checks.append(check)
        if not passed:
            violations.append(check)

    total = len(checks)
    passed_count = sum(1 for c in checks if c["passed"])
    score = round((passed_count / total) * 100, 1) if total > 0 else 100.0

    return {
        "compliant": len(violations) == 0,
        "score": score,
        "compliance_score": score,
        "total_checks": total,
        "passed_checks": passed_count,
        "violations": violations,
        "checks": checks,
    }


def evaluate_all_compliance(db: Session, tenant_id: int) -> dict:
    rules = list(db.scalars(
        select(GovernanceRule).where(GovernanceRule.tenant_id == tenant_id, GovernanceRule.is_active.is_(True))
    ))
    endpoints = list(db.scalars(select(ApiEndpoint).where(ApiEndpoint.tenant_id == tenant_id)))

    results = []
    total_score = 0.0
    total_violations = 0
    compliant_count = 0

    for ep in endpoints:
        result = evaluate_endpoint_compliance(ep, rules)
        results.append({
            "endpoint_id": ep.id,
            "method": ep.method,
            "path": ep.path,
            "host": ep.host,
            "identity": f"{ep.method} {ep.path} @ {ep.host}",
            "lifecycle_state": ep.lifecycle_state.state if ep.lifecycle_state else "unknown",
            "compliance_score": result["score"],
            **result,
        })
        total_score += result["score"]
        total_violations += len(result["violations"])
        if result["compliant"]:
            compliant_count += 1

    avg_score = round(total_score / len(endpoints), 1) if endpoints else 100.0

    return {
        "aggregate_score": avg_score,
        "total_endpoints": len(endpoints),
        "compliant_endpoints": compliant_count,
        "non_compliant_endpoints": len(endpoints) - compliant_count,
        "total_violations": total_violations,
        "endpoints": results,
    }
