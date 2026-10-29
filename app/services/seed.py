from sqlalchemy.orm import Session

from app.schemas import GatewayIngestRequest, GatewayEventIn, GitEndpointIn, GitIngestRequest, GitSpecIn, SiemFindingIn, SiemIngestRequest
from app.services.ingestion import ingest_gateway_events, ingest_git_specs, ingest_siem_findings


def seed_demo_data(db: Session) -> dict:
    gateway_req = GatewayIngestRequest(
        source_ref="demo-gateway",
        tenant_code="default-bank",
        events=[
            # --- Active, well-managed APIs ---
            GatewayEventIn(
                method="GET", path="/v1/accounts/{id}", host="api.bank.internal", env="prod",
                service_name="account-service", owner_team="retail-platform",
                auth_type="strong", has_rate_limit=True, data_sensitivity="high",
                tls_status="tls_1.3", is_external=False, business_critical=True,
            ),
            GatewayEventIn(
                method="GET", path="/v1/cards/balance", host="api.bank.internal", env="prod",
                service_name="cards-service", owner_team="cards-platform",
                auth_type="strong", has_rate_limit=True, data_sensitivity="high",
                tls_status="mtls", is_external=False, business_critical=True,
            ),
            GatewayEventIn(
                method="POST", path="/v1/kyc/verify", host="api.bank.internal", env="prod",
                service_name="kyc-service", owner_team="compliance-platform",
                auth_type="strong", has_rate_limit=True, data_sensitivity="high",
                tls_status="mtls", is_external=False, business_critical=True,
            ),
            GatewayEventIn(
                method="GET", path="/v1/notifications/push", host="api.bank.internal", env="prod",
                service_name="notification-svc", owner_team="digital-channels",
                auth_type="strong", has_rate_limit=True, data_sensitivity="low",
                tls_status="tls_1.3", is_external=False,
            ),
            GatewayEventIn(
                method="PUT", path="/v1/beneficiary/update", host="api.bank.internal", env="prod",
                service_name="beneficiary-svc", owner_team="payments-platform",
                auth_type="strong", has_rate_limit=True, data_sensitivity="high",
                tls_status="tls_1.3", is_external=False, business_critical=True,
            ),
            GatewayEventIn(
                method="GET", path="/v2/upi/status", host="api.bank.internal", env="prod",
                service_name="upi-service", owner_team="payments-platform",
                auth_type="strong", has_rate_limit=True, data_sensitivity="medium",
                tls_status="tls_1.3", is_external=False,
            ),
            GatewayEventIn(
                method="GET", path="/v1/loan/status", host="api.bank.internal", env="prod",
                service_name="loan-service", owner_team="lending-platform",
                auth_type="weak", has_rate_limit=False, data_sensitivity="medium",
                tls_status="tls_1.2", is_external=False,
            ),
            GatewayEventIn(
                method="GET", path="/internal/health-check", host="api.bank.internal", env="prod",
                service_name="infra-monitor", owner_team="sre-team",
                auth_type="none", has_rate_limit=False, data_sensitivity="low",
                tls_status="none", is_external=False,
            ),
            # --- Zombie APIs (no owner, no auth, in gateway but not in code) ---
            GatewayEventIn(
                method="POST", path="/legacy/export/customers", host="legacy.bank.com", env="prod",
                service_name="legacy-export", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=True,
            ),
            GatewayEventIn(
                method="POST", path="/legacy/wire-transfer", host="legacy.bank.com", env="prod",
                service_name="legacy-wire", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=True,
            ),
            GatewayEventIn(
                method="DELETE", path="/admin/user/purge", host="legacy.bank.com", env="prod",
                service_name="admin-service", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=True,
            ),
            GatewayEventIn(
                method="POST", path="/partner/data-export", host="partner-gw.bank.com", env="prod",
                service_name="partner-api", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="tls_1.0", is_external=True,
            ),
            # --- Orphaned (in gateway, not in code, has owner + strong auth => orphaned not zombie) ---
            GatewayEventIn(
                method="GET", path="/internal/debug/config", host="api.bank.internal", env="prod",
                service_name="debug-service", owner_team="devops-team",
                auth_type="strong", has_rate_limit=False, data_sensitivity="medium",
                tls_status="none", is_external=False,
            ),
            GatewayEventIn(
                method="GET", path="/internal/cache/stats", host="api.bank.internal", env="prod",
                service_name="cache-service", owner_team="infra-team",
                auth_type="strong", has_rate_limit=False, data_sensitivity="low",
                tls_status="tls_1.2", is_external=False,
            ),
            # --- Deprecated APIs ---
            GatewayEventIn(
                method="GET", path="/legacy/forex/rates", host="api.bank.internal", env="prod",
                service_name="legacy-forex", owner_team="treasury-team",
                auth_type="strong", has_rate_limit=False, data_sensitivity="medium",
                tls_status="tls_1.0", is_external=False,
            ),
            GatewayEventIn(
                method="POST", path="/legacy/batch/reconcile", host="api.bank.internal", env="prod",
                service_name="legacy-batch", owner_team="ops-team",
                auth_type="strong", has_rate_limit=False, data_sensitivity="medium",
                tls_status="tls_1.0", is_external=False,
            ),
        ],
    )

    git_req = GitIngestRequest(
        tenant_code="default-bank",
        specs=[
            GitSpecIn(
                source_ref="git-account-repo", service_name="account-service", owner_team="retail-platform",
                endpoints=[
                    GitEndpointIn(method="GET", path="/v1/accounts/{id}", host="api.bank.internal", env="prod"),
                    GitEndpointIn(method="GET", path="/v1/accounts", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-loan-repo", service_name="loan-service", owner_team="lending-platform",
                endpoints=[
                    GitEndpointIn(method="GET", path="/v1/loan/status", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-cards-repo", service_name="cards-service", owner_team="cards-platform",
                endpoints=[
                    GitEndpointIn(method="GET", path="/v1/cards/balance", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-kyc-repo", service_name="kyc-service", owner_team="compliance-platform",
                endpoints=[
                    GitEndpointIn(method="POST", path="/v1/kyc/verify", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-notification-repo", service_name="notification-svc", owner_team="digital-channels",
                endpoints=[
                    GitEndpointIn(method="GET", path="/v1/notifications/push", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-beneficiary-repo", service_name="beneficiary-svc", owner_team="payments-platform",
                endpoints=[
                    GitEndpointIn(method="PUT", path="/v1/beneficiary/update", host="api.bank.internal", env="prod"),
                    GitEndpointIn(method="GET", path="/v2/upi/status", host="api.bank.internal", env="prod"),
                ],
            ),
            GitSpecIn(
                source_ref="git-infra-repo", service_name="infra-monitor", owner_team="sre-team",
                endpoints=[
                    GitEndpointIn(method="GET", path="/internal/health-check", host="api.bank.internal", env="prod"),
                ],
            ),
            # Deprecated specs
            GitSpecIn(
                source_ref="git-legacy-forex", service_name="legacy-forex", owner_team="treasury-team",
                endpoints=[
                    GitEndpointIn(method="GET", path="/legacy/forex/rates", host="api.bank.internal", env="prod", deprecated=True),
                ],
            ),
            GitSpecIn(
                source_ref="git-legacy-batch", service_name="legacy-batch", owner_team="ops-team",
                endpoints=[
                    GitEndpointIn(method="POST", path="/legacy/batch/reconcile", host="api.bank.internal", env="prod", deprecated=True),
                ],
            ),
        ],
    )

    siem_req = SiemIngestRequest(
        source_ref="demo-siem",
        tenant_code="default-bank",
        findings=[
            SiemFindingIn(
                method="POST", path="/legacy/export/customers", host="legacy.bank.com", env="prod",
                severity="high", indicator="credential_stuffing_pattern",
            ),
            SiemFindingIn(
                method="POST", path="/legacy/export/customers", host="legacy.bank.com", env="prod",
                severity="high", indicator="sensitive_data_exfiltration_signal",
            ),
            SiemFindingIn(
                method="POST", path="/legacy/wire-transfer", host="legacy.bank.com", env="prod",
                severity="high", indicator="unauthorized_fund_transfer_attempt",
            ),
            SiemFindingIn(
                method="DELETE", path="/admin/user/purge", host="legacy.bank.com", env="prod",
                severity="high", indicator="privilege_escalation_attempt",
            ),
            SiemFindingIn(
                method="POST", path="/partner/data-export", host="partner-gw.bank.com", env="prod",
                severity="medium", indicator="unusual_data_volume_exfiltration",
            ),
            SiemFindingIn(
                method="GET", path="/internal/debug/config", host="api.bank.internal", env="prod",
                severity="medium", indicator="config_exposure_attempt",
            ),
        ],
    )

    ingest_gateway_events(db, gateway_req)
    ingest_git_specs(db, git_req)
    ingest_siem_findings(db, siem_req)

    return {
        "status": "seeded",
        "message": "Demo dataset loaded with 16 endpoints across 4 lifecycle states. Multiple zombie APIs detected with threat signals.",
    }
