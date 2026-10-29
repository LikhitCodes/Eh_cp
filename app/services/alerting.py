"""
Alerting service — webhook & email notifications for critical events.

Sends alerts when:
  - New zombie APIs are discovered
  - Critical risk endpoints detected
  - Governance violations exceed threshold
  - Remediation actions executed/failed
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_alert_payload(
    alert_type: str,
    severity: str,
    title: str,
    details: dict,
    source: str = "api-sentinel",
) -> dict:
    return {
        "alert_type": alert_type,
        "severity": severity,
        "title": title,
        "source": source,
        "timestamp": _utcnow_iso(),
        "details": details,
        "platform": "API Sentinel v0.4.0",
        "environment": "production",
    }


def send_webhook_alert(payload: dict) -> bool:
    """Send alert to configured webhook (Slack, Teams, PagerDuty, OpsGenie)."""
    url = settings.alert_webhook_url.strip()
    if not url:
        logger.debug("No webhook URL configured; skipping alert")
        return False

    try:
        # Format for Slack-compatible webhook
        slack_payload = {
            "text": f"🚨 *{payload['title']}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 {payload['title']}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{payload['severity'].upper()}"},
                        {"type": "mrkdwn", "text": f"*Type:*\n{payload['alert_type']}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{payload['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{payload['source']}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```{json.dumps(payload['details'], indent=2, default=str)[:1500]}```",
                    },
                },
            ],
        }

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=slack_payload)
            resp.raise_for_status()
            logger.info("Webhook alert sent: %s", payload["title"])
            return True
    except Exception as e:
        logger.warning("Failed to send webhook alert: %s", str(e))
        return False


def alert_zombie_discovered(
    endpoint_id: int,
    method: str,
    path: str,
    host: str,
    risk_score: int,
    data_sensitivity: str,
    tenant_code: str,
) -> bool:
    """Alert when a new zombie API is discovered."""
    payload = _build_alert_payload(
        alert_type="zombie_api_discovered",
        severity="critical" if data_sensitivity == "high" else "high",
        title=f"Zombie API Discovered: {method} {path}",
        details={
            "endpoint_id": endpoint_id,
            "method": method,
            "path": path,
            "host": host,
            "risk_score": risk_score,
            "data_sensitivity": data_sensitivity,
            "tenant": tenant_code,
            "action_required": "Review and quarantine immediately",
            "description": (
                f"Undocumented API endpoint {method} {path} detected in live traffic "
                f"at {host}. This endpoint is not registered in any code repository "
                f"and has no assigned owner. Risk score: {risk_score}/100."
            ),
        },
    )
    return send_webhook_alert(payload)


def alert_critical_risk(
    endpoint_id: int,
    identity: str,
    risk_score: int,
    factors: list[dict],
    lifecycle_state: str,
) -> bool:
    """Alert when a critical-risk endpoint is identified."""
    payload = _build_alert_payload(
        alert_type="critical_risk_detected",
        severity="critical",
        title=f"Critical Risk API: {identity} (Score: {risk_score})",
        details={
            "endpoint_id": endpoint_id,
            "identity": identity,
            "risk_score": risk_score,
            "lifecycle_state": lifecycle_state,
            "top_factors": factors[:5],
            "action_required": "Immediate investigation and containment required",
        },
    )
    return send_webhook_alert(payload)


def alert_remediation_executed(
    action_id: int,
    action_type: str,
    endpoint_identity: str,
    executed_by: str,
    blast_radius: str,
) -> bool:
    """Alert when a remediation action is executed."""
    payload = _build_alert_payload(
        alert_type="remediation_executed",
        severity="high" if blast_radius == "high" else "medium",
        title=f"Remediation Executed: {action_type} on {endpoint_identity}",
        details={
            "action_id": action_id,
            "action_type": action_type,
            "endpoint": endpoint_identity,
            "executed_by": executed_by,
            "blast_radius": blast_radius,
            "status": "executed",
        },
    )
    return send_webhook_alert(payload)


def alert_governance_violation(
    total_violations: int,
    critical_violations: int,
    affected_endpoints: int,
    top_violations: list[dict],
) -> bool:
    """Alert when governance violations exceed threshold."""
    if total_violations < 3:
        return False  # Don't alert for minor violations

    payload = _build_alert_payload(
        alert_type="governance_violations",
        severity="critical" if critical_violations > 0 else "high",
        title=f"Governance Alert: {total_violations} violations across {affected_endpoints} endpoints",
        details={
            "total_violations": total_violations,
            "critical_violations": critical_violations,
            "affected_endpoints": affected_endpoints,
            "top_violations": top_violations[:5],
            "action_required": "Review governance compliance dashboard",
        },
    )
    return send_webhook_alert(payload)


# ── Alert history (in-memory for demo, would be DB-backed in production) ─────
_alert_history: list[dict] = []
MAX_HISTORY = 100


def record_alert(alert_type: str, severity: str, title: str, details: Optional[dict] = None) -> dict:
    """Record an alert in history and attempt webhook delivery."""
    payload = _build_alert_payload(alert_type, severity, title, details or {})
    sent = send_webhook_alert(payload)
    entry = {**payload, "delivered": sent}
    _alert_history.insert(0, entry)
    if len(_alert_history) > MAX_HISTORY:
        _alert_history.pop()
    return entry


def get_alert_history(limit: int = 50) -> list[dict]:
    """Return recent alert history."""
    return _alert_history[:limit]
