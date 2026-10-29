from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ApiEndpoint, GovernanceRule, ScanSchedule
from app.services.repository import ensure_default_policy, ensure_tenant


def _ensure_governance_rules(db: Session, tenant_id: int) -> None:
    existing = db.scalar(select(GovernanceRule).where(GovernanceRule.tenant_id == tenant_id).limit(1))
    if existing:
        return

    rules = [
        GovernanceRule(tenant_id=tenant_id, name="Authentication Required", rule_type="auth_required",
                       description="All APIs must have authentication (auth != none)", severity="critical"),
        GovernanceRule(tenant_id=tenant_id, name="Owner Assignment Required", rule_type="owner_required",
                       description="All APIs must have an assigned owner team", severity="high"),
        GovernanceRule(tenant_id=tenant_id, name="Rate Limiting for External APIs", rule_type="rate_limit_external",
                       description="External-facing APIs must have rate limiting enabled", severity="high"),
        GovernanceRule(tenant_id=tenant_id, name="TLS 1.2+ Required", rule_type="tls_minimum",
                       description="All APIs must use TLS 1.2 or higher encryption", severity="critical"),
        GovernanceRule(tenant_id=tenant_id, name="Code Specification Required", rule_type="code_spec_required",
                       description="All APIs must be documented in a code repository", severity="medium"),
        GovernanceRule(tenant_id=tenant_id, name="No Active Threat Signals", rule_type="siem_clear",
                       description="APIs must not have active high-severity SIEM threat signals", severity="high"),
    ]
    db.add_all(rules)


def _ensure_scan_schedules(db: Session, tenant_id: int) -> None:
    existing = db.scalar(select(ScanSchedule).where(ScanSchedule.tenant_id == tenant_id).limit(1))
    if existing:
        return

    now = datetime.now(timezone.utc)
    schedules = [
        ScanSchedule(tenant_id=tenant_id, connector_type="kong", interval_minutes=30,
                     next_run_at=now + timedelta(minutes=30)),
        ScanSchedule(tenant_id=tenant_id, connector_type="github", interval_minutes=60,
                     next_run_at=now + timedelta(minutes=60)),
        ScanSchedule(tenant_id=tenant_id, connector_type="splunk", interval_minutes=15,
                     next_run_at=now + timedelta(minutes=15)),
        ScanSchedule(tenant_id=tenant_id, connector_type="network", interval_minutes=120,
                     next_run_at=now + timedelta(minutes=120)),
        ScanSchedule(tenant_id=tenant_id, connector_type="k8s", interval_minutes=60,
                     next_run_at=now + timedelta(minutes=60)),
    ]
    db.add_all(schedules)


def _auto_connect_juiceshop(db: Session, tenant_id: int) -> None:
    """Auto-connect Juice Shop as the default data source on first boot.
    Only runs when no endpoints exist yet (fresh DB)."""
    has_endpoints = db.scalar(select(ApiEndpoint).limit(1))
    if has_endpoints:
        return  # Data already exists — don't overwrite

    from app.services.connectors import (
        connect_source,
        sync_github,
        sync_kong,
        sync_splunk,
        sync_network,
        sync_k8s,
    )

    # 1. Code Repository: actual GitHub repo link
    connect_source(db, tenant_id, "github", "https://github.com/juice-shop/juice-shop")
    # 2. API Gateway: actual public hosted Juice Shop instance
    connect_source(db, tenant_id, "kong", "https://juice-shop.herokuapp.com")
    # 3. SIEM / Threat Intel: realistic Splunk Cloud telemetry endpoint
    connect_source(db, tenant_id, "splunk", "https://splunk-cloud.com/juice-shop-telemetry")
    # Network Scanner and K8s Scanner are internal infrastructure probes (not external URL connectors)

    # Sync all 5 connectors with Juice Shop data
    tenant_code = settings.default_tenant_code
    sync_github(db, tenant_code)
    sync_kong(db, tenant_code)
    sync_splunk(db, tenant_code)
    sync_network(db, tenant_code)
    sync_k8s(db, tenant_code)


def bootstrap_defaults(db: Session) -> None:
    tenant = ensure_tenant(db, settings.default_tenant_code)
    ensure_default_policy(db, tenant.id)
    _ensure_governance_rules(db, tenant.id)
    _ensure_scan_schedules(db, tenant.id)
    db.commit()
    _auto_connect_juiceshop(db, tenant.id)

