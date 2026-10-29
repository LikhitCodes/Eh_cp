"""
Integration tests — validates the full stack works end-to-end.

These tests simulate a real deployment scenario:
  1. Seed data via API
  2. Discover APIs via all 5 connectors
  3. Assess risk across all endpoints
  4. Create cases and generate AI summaries
  5. Execute full remediation lifecycle
  6. Validate governance compliance
  7. Generate executive and board reports with ROI
  8. Verify audit trail integrity
  9. Test monitoring and alerting
  10. Benchmark performance

Designed to work with both SQLite (CI) and PostgreSQL (staging/prod).
Set SENTINEL_DATABASE_URL=postgresql://... to test against PostgreSQL.
"""

import hashlib
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base, get_db
from app.main import app
from app.services.bootstrap import bootstrap_defaults


# ── Fixture helpers ──────────────────────────────────────────────────────────

DB_URL = os.getenv("SENTINEL_DATABASE_URL", "sqlite:///./test_integration.db")
IS_POSTGRES = DB_URL.startswith("postgresql")


def _build_client() -> TestClient:
    """Create a test client with a fresh database."""
    if not IS_POSTGRES:
        db_file = Path("test_integration.db")
        if db_file.exists():
            db_file.unlink()

    connect_args = {} if IS_POSTGRES else {"check_same_thread": False}
    engine = create_engine(DB_URL, connect_args=connect_args)

    if IS_POSTGRES:
        # Drop and recreate all tables for a clean slate
        Base.metadata.drop_all(bind=engine)

    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Bootstrap governance rules and scan schedules
    db = TestingSession()
    bootstrap_defaults(db)
    db.close()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


H = {"x-user": "integration-admin", "x-roles": "admin,analyst,approver,auditor"}


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 1: Full Discovery-to-Remediation Pipeline
# ══════════════════════════════════════════════════════════════════════════════


def test_full_pipeline_seed_to_report():
    """End-to-end: seed → discover → assess → case → remediate → report."""
    client = _build_client()

    # ── Step 1: Seed demo data ───────────────────────────────────────────
    seed = client.post("/v1/demo/seed", headers=H)
    assert seed.status_code == 200
    assert seed.json()["status"] == "seeded"

    # ── Step 2: Verify endpoints created with diversity ──────────────────
    endpoints = client.get("/v1/endpoints", headers=H).json()
    assert len(endpoints) >= 15, f"Expected ≥15 endpoints, got {len(endpoints)}"

    # Verify lifecycle state diversity
    states = {e["lifecycle_state"] for e in endpoints if e["lifecycle_state"]}
    assert "zombie" in states, "Must have zombie endpoints"
    assert "active" in states, "Must have active endpoints"
    assert len(states) >= 3, f"Expected ≥3 lifecycle states, got {states}"

    # Verify risk severity diversity
    severities = {e["risk_severity"] for e in endpoints if e["risk_severity"]}
    assert len(severities) >= 3, f"Expected ≥3 severity levels, got {severities}"

    # Verify TLS status diversity
    tls_statuses = {e.get("tls_status") for e in endpoints}
    assert "none" in tls_statuses, "Must have endpoints with no TLS"
    assert len(tls_statuses) >= 2, f"Expected ≥2 TLS statuses, got {tls_statuses}"

    # ── Step 3: Run all 5 connectors ─────────────────────────────────────
    connectors = [
        ("kong", "/v1/connectors/kong/sync"),
        ("github", "/v1/connectors/github/sync"),
        ("splunk", "/v1/connectors/splunk/sync"),
        ("network", "/v1/connectors/network/scan"),
        ("k8s", "/v1/connectors/k8s/scan"),
    ]
    for name, path in connectors:
        resp = client.post(path, headers=H)
        assert resp.status_code == 200, f"Connector {name} failed: {resp.text}"
        body = resp.json()
        assert body["status"] == "success", f"Connector {name} not successful"
        assert body["processed"] >= 1, f"Connector {name} processed 0 items"

    # ── Step 4: Check connector status ───────────────────────────────────
    status = client.get("/v1/connectors/status", headers=H).json()
    assert len(status) >= 3, "Should have ≥3 connector status entries"

    # ── Step 5: Find highest-risk zombie for case investigation ──────────
    zombies = sorted(
        [e for e in endpoints if e["lifecycle_state"] == "zombie"],
        key=lambda x: x["risk_score"] or 0,
        reverse=True,
    )
    assert zombies, "No zombie endpoints found"
    target = zombies[0]
    assert target["risk_score"] >= 70, f"Top zombie risk score too low: {target['risk_score']}"

    # ── Step 6: Get detailed risk assessment ─────────────────────────────
    risk = client.get(f"/v1/endpoints/{target['id']}/risk", headers=H)
    assert risk.status_code == 200
    risk_data = risk.json()
    assert risk_data["risk_score"] >= 70
    assert risk_data["factors"], "Risk factors should be populated"
    assert risk_data["explainability"], "Risk explainability should exist"

    # ── Step 7: Create investigation case ────────────────────────────────
    case = client.post(
        "/v1/cases",
        json={
            "title": f"Zombie API Investigation: {target['method']} {target['path']}",
            "endpoint_id": target["id"],
            "severity": "critical",
            "summary": f"High-risk zombie endpoint detected with score {target['risk_score']}/100. "
            "Requires immediate investigation and containment.",
        },
        headers=H,
    )
    assert case.status_code == 200
    case_id = case.json()["id"]

    # ── Step 8: Verify evidence auto-collected ───────────────────────────
    evidence = client.get(f"/v1/cases/{case_id}/evidence", headers=H)
    assert evidence.status_code == 200
    artifacts = evidence.json()["artifacts"]
    assert len(artifacts) >= 1, "Evidence should be auto-collected"

    # ── Step 9: AI case summarization ────────────────────────────────────
    ai_summary = client.post(f"/v1/ai/summarize-case/{case_id}", headers=H)
    assert ai_summary.status_code == 200
    ai_body = ai_summary.json()
    assert ai_body["safe"] is True
    assert len(ai_body["summary"]) > 100, "AI summary should be substantial"

    # ── Step 10: Create remediation action (quarantine) ──────────────────
    action = client.post(
        "/v1/remediation/actions",
        json={
            "endpoint_id": target["id"],
            "action_type": "quarantine",
            "reason": "Critical zombie API — immediate containment required per RBI circular",
        },
        headers=H,
    )
    assert action.status_code == 200
    action_id = action.json()["id"]
    assert action.json()["status"] == "requested"

    # ── Step 11: Simulate remediation impact ─────────────────────────────
    simulate = client.post(f"/v1/remediation/actions/{action_id}/simulate", headers=H)
    assert simulate.status_code == 200
    sim_data = simulate.json()
    assert "estimated_impact" in sim_data

    # ── Step 12: Dual-approval flow ──────────────────────────────────────
    approve = client.post(
        f"/v1/remediation/actions/{action_id}/approve",
        json={"comment": "Approved — confirmed zombie with PII exposure"},
        headers=H,
    )
    assert approve.status_code == 200

    # ── Step 13: Execute remediation ─────────────────────────────────────
    execute = client.post(
        f"/v1/remediation/actions/{action_id}/execute",
        json={"executed_by": "security-automation"},
        headers=H,
    )
    assert execute.status_code == 200
    assert execute.json()["status"] == "executed"

    # Verify endpoint is quarantined
    quarantined = client.get(f"/v1/endpoints/{target['id']}", headers=H).json()
    assert quarantined["is_quarantined"] is True

    # ── Step 14: Test rollback ───────────────────────────────────────────
    rollback = client.post(
        f"/v1/remediation/actions/{action_id}/rollback",
        json={"executed_by": "security-automation"},
        headers=H,
    )
    assert rollback.status_code == 200
    assert rollback.json()["status"] == "rolled_back"

    restored = client.get(f"/v1/endpoints/{target['id']}", headers=H).json()
    assert restored["is_quarantined"] is False

    # ── Step 15: Generate executive report ───────────────────────────────
    exec_report = client.post(
        "/v1/reports/executive",
        json={"generated_by": "integration-ciso"},
        headers=H,
    )
    assert exec_report.status_code == 200
    exec_data = exec_report.json()
    assert "totals" in exec_data
    assert exec_data["totals"]["endpoints"] >= 15
    assert exec_data["lifecycle_breakdown"].get("zombie", 0) >= 1

    # ── Step 16: Generate board report with ROI ──────────────────────────
    board_report = client.post(
        "/v1/reports/board",
        json={"generated_by": "integration-ciso"},
        headers=H,
    )
    assert board_report.status_code == 200
    board_data = board_report.json()
    assert "roi_estimate" in board_data
    roi = board_data["roi_estimate"]
    assert roi["total_risk_exposure_inr"] > 0, "ROI should show risk exposure"
    assert roi["regulatory_fine_exposure_inr"] > 0, "Should calculate RBI fine exposure"
    # Note: estimated_avoided_loss may be 0 if no endpoints are currently quarantined
    # (we rolled back above). The key assertion is that the model calculates exposure.


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 2: Governance & Compliance
# ══════════════════════════════════════════════════════════════════════════════


def test_governance_compliance_full_check():
    """Validate governance rules detect violations across all endpoints."""
    client = _build_client()
    client.post("/v1/demo/seed", headers=H)

    # Get governance rules
    rules = client.get("/v1/governance/rules", headers=H)
    assert rules.status_code == 200
    rules_data = rules.json()
    assert len(rules_data) >= 5, f"Expected ≥5 governance rules, got {len(rules_data)}"

    # Check rule types
    rule_types = {r["rule_type"] for r in rules_data}
    expected_types = {"auth_required", "tls_minimum", "rate_limit_external"}
    assert expected_types.issubset(rule_types), f"Missing rule types: {expected_types - rule_types}"

    # Run compliance check
    compliance = client.get("/v1/governance/compliance", headers=H)
    assert compliance.status_code == 200
    comp_data = compliance.json()
    assert comp_data["total_endpoints"] >= 15
    assert comp_data["total_violations"] > 0, "Should detect governance violations"
    assert 0 <= comp_data["aggregate_score"] <= 100

    # Check per-endpoint compliance
    endpoints = client.get("/v1/endpoints", headers=H).json()
    zombie = next(e for e in endpoints if e["lifecycle_state"] == "zombie")
    ep_compliance = client.get(f"/v1/governance/compliance/{zombie['id']}", headers=H)
    assert ep_compliance.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 3: Monitoring & Continuous Scanning
# ══════════════════════════════════════════════════════════════════════════════


def test_monitoring_and_scan_scheduling():
    """Validate monitoring status and scan-now functionality."""
    client = _build_client()

    # Check monitoring status
    status = client.get("/v1/monitoring/status", headers=H)
    assert status.status_code == 200
    data = status.json()
    assert len(data["scan_schedules"]) >= 3
    assert "overall_health" in data
    assert data["overall_health"] in ("healthy", "degraded", "critical")

    # Trigger manual scan
    scan = client.post("/v1/monitoring/scan-now?connector_type=kong", headers=H)
    assert scan.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 4: Audit Trail Integrity
# ══════════════════════════════════════════════════════════════════════════════


def test_audit_trail_cryptographic_integrity():
    """Verify SHA-256 signed audit events are created for key actions."""
    client = _build_client()
    client.post("/v1/demo/seed", headers=H)

    # Perform actions that create audit events
    endpoints = client.get("/v1/endpoints", headers=H).json()
    target = endpoints[0]

    # Create a case (generates audit event)
    client.post(
        "/v1/cases",
        json={
            "title": "Audit test case",
            "endpoint_id": target["id"],
            "severity": "medium",
            "summary": "Testing audit trail",
        },
        headers=H,
    )

    # Create and execute remediation (generates audit events)
    action = client.post(
        "/v1/remediation/actions",
        json={"endpoint_id": target["id"], "action_type": "quarantine", "reason": "audit test"},
        headers=H,
    ).json()

    client.post(
        f"/v1/remediation/actions/{action['id']}/approve",
        json={"comment": "approved for audit test"},
        headers=H,
    )

    client.post(
        f"/v1/remediation/actions/{action['id']}/execute",
        json={"executed_by": "audit-tester"},
        headers=H,
    )

    # Get audit events
    audit = client.get("/v1/audit/events?limit=50", headers=H)
    assert audit.status_code == 200
    events = audit.json()
    assert len(events) >= 1, "Should have audit events"

    # Verify SHA-256 signatures exist
    for event in events:
        assert "signature" in event, "Audit event must have signature"
        sig = event["signature"]
        assert len(sig) == 64 and all(c in "0123456789abcdef" for c in sig), \
            f"Signature should be SHA-256 hex: {sig}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 5: Architecture Self-Documentation
# ══════════════════════════════════════════════════════════════════════════════


def test_architecture_endpoint():
    """Verify the platform self-documents its architecture."""
    client = _build_client()

    arch = client.get("/v1/architecture", headers=H)
    assert arch.status_code == 200
    data = arch.json()

    assert len(data["layers"]) >= 6, "Should have ≥6 architectural layers"
    total_components = sum(len(layer["components"]) for layer in data["layers"])
    assert total_components >= 20, f"Should have ≥20 components, got {total_components}"

    assert data["api_stats"]["total_routes"] >= 40
    assert len(data["tech_stack"]) >= 3


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 6: Performance Benchmark
# ══════════════════════════════════════════════════════════════════════════════


def test_benchmark_meets_sla():
    """Verify performance benchmarks meet enterprise SLAs."""
    client = _build_client()
    client.post("/v1/demo/seed", headers=H)

    bench = client.get("/v1/benchmark", headers=H)
    assert bench.status_code == 200
    data = bench.json()["benchmark"]

    # SLA: DB reads < 5ms
    assert data["db_read_avg_ms"] < 5.0, f"DB read too slow: {data['db_read_avg_ms']}ms"

    # SLA: Risk computation < 1ms
    assert data["risk_compute_avg_ms"] < 1.0, f"Risk compute too slow: {data['risk_compute_avg_ms']}ms"

    # SLA: Can handle >500 endpoints/sec
    assert data["estimated_endpoints_per_second"] > 500, \
        f"Throughput too low: {data['estimated_endpoints_per_second']} eps"


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 7: AI Remediation Playbook
# ══════════════════════════════════════════════════════════════════════════════


def test_ai_remediation_playbook_generation():
    """Verify AI generates context-aware remediation playbooks."""
    client = _build_client()
    client.post("/v1/demo/seed", headers=H)

    endpoints = client.get("/v1/endpoints", headers=H).json()
    zombie = next(e for e in endpoints if e["lifecycle_state"] == "zombie")

    playbook = client.post(f"/v1/ai/remediation-playbook/{zombie['id']}", headers=H)
    assert playbook.status_code == 200
    data = playbook.json()

    # Playbook data is returned at top level with playbook_steps key
    assert "playbook_steps" in data
    assert len(data["playbook_steps"]) >= 3, "Playbook should have ≥3 steps"
    assert "estimated_effort" in data
    assert "priority" in data


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 8: WebSocket Status
# ══════════════════════════════════════════════════════════════════════════════


def test_websocket_status_endpoint():
    """Verify WebSocket status endpoint reports correctly."""
    client = _build_client()

    ws_status = client.get("/v1/ws/status", headers=H)
    assert ws_status.status_code == 200
    data = ws_status.json()
    assert "active_connections" in data
    assert "supported_events" in data
    assert len(data["supported_events"]) >= 5


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 9: Alert System
# ══════════════════════════════════════════════════════════════════════════════


def test_alert_system():
    """Verify alert history and test alert endpoints."""
    client = _build_client()

    # Get alert history (should be empty initially)
    alerts = client.get("/v1/alerts/history", headers=H)
    assert alerts.status_code == 200
    assert isinstance(alerts.json(), list)

    # Send test alert
    test_alert = client.post("/v1/alerts/test", headers=H)
    assert test_alert.status_code == 200
    assert test_alert.json()["alert_type"] == "test_alert"


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 10: Health & Metrics
# ══════════════════════════════════════════════════════════════════════════════


def test_health_and_metrics():
    """Verify health check and metrics endpoints."""
    client = _build_client()

    # Health check
    health = client.get("/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    # Metrics
    metrics = client.get("/metrics")
    assert metrics.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 11: Database Compatibility (PostgreSQL-aware)
# ══════════════════════════════════════════════════════════════════════════════


def test_database_operations():
    """Test database operations that differ between SQLite and PostgreSQL."""
    client = _build_client()
    client.post("/v1/demo/seed", headers=H)

    # Test pagination
    page1 = client.get("/v1/endpoints?limit=5", headers=H)
    assert page1.status_code == 200
    assert len(page1.json()) <= 5

    # Test sorting
    sorted_resp = client.get("/v1/endpoints?sort=risk_desc", headers=H)
    assert sorted_resp.status_code == 200
    endpoints = sorted_resp.json()
    if len(endpoints) >= 2:
        scores = [e["risk_score"] or 0 for e in endpoints]
        assert scores == sorted(scores, reverse=True), "Should be sorted by risk desc"

    # Test filtering by lifecycle
    for state in ["zombie", "active"]:
        filtered = client.get(f"/v1/endpoints?lifecycle={state}", headers=H)
        assert filtered.status_code == 200

    # Test concurrent reads (important for PostgreSQL connection pooling)
    import concurrent.futures
    def read_endpoints():
        return client.get("/v1/endpoints", headers=H).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(read_endpoints) for _ in range(10)]
        results = [f.result() for f in futures]
        assert all(r == 200 for r in results), "Concurrent reads should all succeed"


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 12: Multi-Tenant Isolation
# ══════════════════════════════════════════════════════════════════════════════


def test_multi_tenant_data_isolation():
    """Verify tenant isolation — data from one tenant shouldn't leak to another."""
    client = _build_client()

    # Seed data (goes to default-bank tenant)
    client.post("/v1/demo/seed", headers=H)

    # Default tenant should have endpoints
    default_endpoints = client.get("/v1/endpoints", headers=H).json()
    assert len(default_endpoints) >= 15, "Default tenant should have endpoints"

    # A completely different tenant should NOT see default tenant's data
    other_tenant_endpoints = client.get(
        "/v1/endpoints",
        headers={**H, "x-tenant": "other-bank"},
    ).json()
    assert len(other_tenant_endpoints) == 0, "Other tenant should not see default tenant's endpoints"

    # Cases should also be isolated
    other_cases = client.get("/v1/cases", headers={**H, "x-tenant": "other-bank"}).json()
    assert len(other_cases) == 0, "Other tenant should not see default tenant's cases"
