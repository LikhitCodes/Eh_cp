from pathlib import Path
import base64
import json

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base, get_db
from app.main import app


TEST_DB = "sqlite:///./test_api_sentinel.db"


def _build_client() -> TestClient:
    db_file = Path("test_api_sentinel.db")
    if db_file.exists():
        db_file.unlink()

    engine = create_engine(TEST_DB, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _seed(client: TestClient):
    seed_resp = client.post("/v1/demo/seed")
    assert seed_resp.status_code == 200


def _make_dev_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}

    def _pack(chunk: dict) -> str:
        raw = json.dumps(chunk, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    return f"{_pack(header)}.{_pack(payload)}.sig"


def _set_auth_settings(**overrides):
    original = {key: getattr(settings, key) for key in overrides}
    for key, value in overrides.items():
        setattr(settings, key, value)
    return original


def _restore_auth_settings(original: dict):
    for key, value in original.items():
        setattr(settings, key, value)


def test_auth_me_returns_principal():
    client = _build_client()
    resp = client.get("/v1/auth/me", headers={"x-user": "alice", "x-roles": "analyst,approver", "x-tenant": "bankx"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "alice"
    assert "analyst" in body["roles"]
    assert body["tenant_code"] == "bankx"


def test_auth_me_rejects_invalid_bearer_when_verified_mode_enabled():
    client = _build_client()
    original = _set_auth_settings(
        auth_required=True,
        auth_require_verified_jwt=True,
        auth_allow_insecure_dev_tokens=False,
        auth_jwks_url="http://keycloak.invalid/jwks",
    )
    try:
        resp = client.get("/v1/auth/me", headers={"authorization": "Bearer not.a.valid"})
        assert resp.status_code == 401
    finally:
        _restore_auth_settings(original)


def test_auth_me_rejects_unmapped_roles_when_enforcement_enabled():
    client = _build_client()
    original = _set_auth_settings(
        auth_required=False,
        auth_require_verified_jwt=False,
        auth_allow_insecure_dev_tokens=True,
        auth_enforce_mapped_roles=True,
        auth_allowed_roles="admin,analyst,approver,auditor",
        auth_role_aliases_json="{}",
    )
    try:
        token = _make_dev_token({"preferred_username": "eve", "roles": ["external-user"]})
        resp = client.get("/v1/auth/me", headers={"authorization": f"Bearer {token}"})
        assert resp.status_code == 403
    finally:
        _restore_auth_settings(original)


def test_seed_creates_high_risk_zombie_endpoint():
    client = _build_client()
    _seed(client)

    endpoints_resp = client.get("/v1/endpoints")
    assert endpoints_resp.status_code == 200
    endpoints = endpoints_resp.json()
    assert len(endpoints) >= 3

    zombies = [e for e in endpoints if e["lifecycle_state"] == "zombie"]
    assert zombies
    assert any(e["risk_score"] >= 85 for e in zombies)


def test_connector_sync_runs_with_simulated_fallback():
    client = _build_client()
    resp = client.post("/v1/connectors/kong/sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connector_type"] == "kong"
    assert body["status"] == "success"
    assert body["processed"] >= 1


def test_rbac_denies_unauthorized_action_creation():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    target = endpoints[0]

    denied = client.post(
        "/v1/remediation/actions",
        json={"endpoint_id": target["id"], "action_type": "quarantine", "reason": "deny-check"},
        headers={"x-roles": "viewer"},
    )
    assert denied.status_code == 403


def test_action_simulate_and_execute_flow():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    candidate = sorted(endpoints, key=lambda item: item["risk_score"] or 0, reverse=True)[0]

    action_resp = client.post(
        "/v1/remediation/actions",
        json={
            "endpoint_id": candidate["id"],
            "action_type": "quarantine",
            "reason": "test containment",
        },
        headers={"x-user": "analyst1", "x-roles": "analyst"},
    )
    assert action_resp.status_code == 200
    action = action_resp.json()

    sim_resp = client.post(
        f"/v1/remediation/actions/{action['id']}/simulate",
        headers={"x-user": "approver1", "x-roles": "approver"},
    )
    assert sim_resp.status_code == 200
    assert "estimated_impact" in sim_resp.json()

    approve = client.post(
        f"/v1/remediation/actions/{action['id']}/approve",
        json={"comment": "approved"},
        headers={"x-user": "approver1", "x-roles": "approver"},
    )
    assert approve.status_code == 200

    execute = client.post(
        f"/v1/remediation/actions/{action['id']}/execute",
        json={"executed_by": "runner"},
        headers={"x-user": "approver1", "x-roles": "approver"},
    )
    assert execute.status_code == 200
    assert execute.json()["status"] == "executed"


def test_case_and_ai_summary_flow():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    candidate = sorted(endpoints, key=lambda item: item["risk_score"] or 0, reverse=True)[0]

    case_resp = client.post(
        "/v1/cases",
        json={
            "title": "Investigate zombie endpoint",
            "endpoint_id": candidate["id"],
            "severity": "high",
            "summary": "Initial triage",
        },
        headers={"x-user": "analyst1", "x-roles": "analyst"},
    )
    assert case_resp.status_code == 200
    case_id = case_resp.json()["id"]

    evidence = client.get(f"/v1/cases/{case_id}/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["artifacts"]

    ai_resp = client.post(f"/v1/ai/summarize-case/{case_id}")
    assert ai_resp.status_code == 200
    ai_body = ai_resp.json()
    assert ai_body["safe"] is True
    assert ai_body["summary"]


def test_board_report_contains_roi_fields():
    client = _build_client()
    _seed(client)

    report = client.post("/v1/reports/board", json={"generated_by": "qa-ciso"})
    assert report.status_code == 200
    body = report.json()

    assert "risk_delta" in body
    assert "roi_estimate" in body
    assert "estimated_avoided_loss_inr" in body["roi_estimate"]


def test_action_rollback_restores_endpoint_state():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    candidate = sorted(endpoints, key=lambda item: item["risk_score"] or 0, reverse=True)[0]

    action = client.post(
        "/v1/remediation/actions",
        json={
            "endpoint_id": candidate["id"],
            "action_type": "quarantine",
            "reason": "rollback test",
        },
        headers={"x-user": "analyst1", "x-roles": "analyst"},
    ).json()

    client.post(
        f"/v1/remediation/actions/{action['id']}/approve",
        json={"comment": "approve"},
        headers={"x-user": "approver1", "x-roles": "approver"},
    )
    client.post(
        f"/v1/remediation/actions/{action['id']}/execute",
        json={"executed_by": "runner"},
        headers={"x-user": "approver1", "x-roles": "approver"},
    )

    rollback_resp = client.post(
        f"/v1/remediation/actions/{action['id']}/rollback",
        json={"executed_by": "runner"},
        headers={"x-user": "approver1", "x-roles": "approver"},
    )
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["status"] == "rolled_back"

    endpoint_resp = client.get(f"/v1/endpoints/{candidate['id']}")
    assert endpoint_resp.status_code == 200
    assert endpoint_resp.json()["is_quarantined"] is False


def test_network_scanner_discovers_shadow_apis():
    client = _build_client()
    resp = client.post("/v1/connectors/network/scan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connector_type"] == "network"
    assert body["status"] == "success"
    assert body["processed"] >= 1


def test_k8s_scanner_discovers_deployment_apis():
    client = _build_client()
    resp = client.post("/v1/connectors/k8s/scan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connector_type"] == "k8s"
    assert body["status"] == "success"
    assert body["processed"] >= 1


def _bootstrap(client: TestClient):
    """Trigger bootstrap_defaults on the test DB so governance rules and scan schedules exist."""
    from app.database import get_db as _real_get_db
    from app.services.bootstrap import bootstrap_defaults
    override = app.dependency_overrides.get(_real_get_db)
    if override:
        gen = override()
        db = next(gen)
        bootstrap_defaults(db)
        try:
            next(gen)
        except StopIteration:
            pass


def test_governance_compliance_returns_violations():
    client = _build_client()
    _bootstrap(client)
    _seed(client)

    resp = client.get("/v1/governance/compliance")
    assert resp.status_code == 200
    body = resp.json()
    assert "aggregate_score" in body
    assert "total_endpoints" in body
    assert body["total_endpoints"] >= 10
    assert body["total_violations"] > 0


def test_monitoring_status_returns_schedule():
    client = _build_client()
    _bootstrap(client)
    resp = client.get("/v1/monitoring/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "scan_schedules" in body
    assert len(body["scan_schedules"]) >= 3
    assert "overall_health" in body


def test_tls_status_affects_risk_score():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    assert len(endpoints) >= 10

    tls_none = [e for e in endpoints if e.get("tls_status") == "none"]
    tls_secure = [e for e in endpoints if e.get("tls_status") in ("tls_1.3", "mtls")]

    assert tls_none, "Should have endpoints with no TLS"
    assert tls_secure, "Should have endpoints with strong TLS"

    avg_none = sum(e["risk_score"] or 0 for e in tls_none) / len(tls_none)
    avg_secure = sum(e["risk_score"] or 0 for e in tls_secure) / len(tls_secure)
    assert avg_none > avg_secure, "Endpoints with no TLS should have higher risk scores"


def test_expanded_seed_creates_diverse_endpoints():
    client = _build_client()
    _seed(client)

    endpoints = client.get("/v1/endpoints").json()
    assert len(endpoints) >= 15

    states = {e["lifecycle_state"] for e in endpoints if e["lifecycle_state"]}
    assert "active" in states
    assert "zombie" in states

    severities = {e["risk_severity"] for e in endpoints if e["risk_severity"]}
    assert len(severities) >= 3
