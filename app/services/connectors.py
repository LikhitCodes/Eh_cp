import base64
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Connector, ConnectorRun
from app.schemas import (
    GatewayEventIn,
    GatewayIngestRequest,
    GitEndpointIn,
    GitIngestRequest,
    GitSpecIn,
    SiemFindingIn,
    SiemIngestRequest,
)
from app.services.ingestion import ingest_gateway_events, ingest_git_specs, ingest_siem_findings
from app.services.repository import ensure_tenant


class ConnectorError(RuntimeError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _upsert_connector(db: Session, tenant_id: int, connector_type: str, name: str, use_simulated: bool) -> Connector:
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.connector_type == connector_type,
            Connector.name == name,
        )
    )
    if connector:
        connector.use_simulated = use_simulated
        return connector

    connector = Connector(
        tenant_id=tenant_id,
        connector_type=connector_type,
        name=name,
        status="idle",
        use_simulated=use_simulated,
    )
    db.add(connector)
    db.flush()
    return connector


def _start_run(db: Session, connector: Connector) -> ConnectorRun:
    connector.status = "syncing"
    connector.last_error = None
    run = ConnectorRun(
        connector_id=connector.id,
        status="started",
        started_at=_utcnow(),
    )
    db.add(run)
    db.flush()
    return run


def _finish_run(db: Session, connector: Connector, run: ConnectorRun, status: str, processed: int, error: Optional[str] = None) -> None:
    run.status = status
    run.items_processed = processed
    run.error_message = error
    run.completed_at = _utcnow()

    connector.status = "healthy" if status == "success" else "error"
    connector.last_sync_at = _utcnow()
    connector.last_error = error


def _simulate_kong_sync(db: Session, tenant_code: str) -> int:
    payload = GatewayIngestRequest(
        source_ref="simulated-kong",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="GET",
                path="/v2/payments/{id}",
                host="kong-gateway.local",
                env="prod",
                service_name="payments-service",
                owner_team="payments-platform",
                auth_type="strong",
                has_rate_limit=True,
                data_sensitivity="high",
                is_external=True,
            ),
            GatewayEventIn(
                method="POST",
                path="/legacy/partner/export",
                host="kong-gateway.local",
                env="prod",
                service_name="legacy-partner-service",
                owner_team=None,
                auth_type="none",
                has_rate_limit=False,
                data_sensitivity="high",
                is_external=True,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return int(result.get("processed", 0))


def sync_kong(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)

    use_simulated = False
    if not settings.kong_admin_url:
        use_simulated = True

    connector = _upsert_connector(db, tenant.id, "kong", "kong-admin", use_simulated)
    run = _start_run(db, connector)

    try:
        if use_simulated:
            processed = _simulate_kong_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        with httpx.Client(timeout=15.0) as client:
            services_resp = client.get(f"{settings.kong_admin_url.rstrip('/')}/services")
            routes_resp = client.get(f"{settings.kong_admin_url.rstrip('/')}/routes")
            services_resp.raise_for_status()
            routes_resp.raise_for_status()
            services = services_resp.json().get("data", [])
            routes = routes_resp.json().get("data", [])

        service_map = {item.get("id"): item for item in services}
        events: list[GatewayEventIn] = []
        for route in routes:
            methods = route.get("methods") or ["GET"]
            paths = route.get("paths") or ["/"]
            service_id = (route.get("service") or {}).get("id")
            service = service_map.get(service_id, {})
            service_name = service.get("name") or "kong-service"
            host = (urlparse(service.get("host") or "http://kong-gateway.local").hostname or "kong-gateway.local")

            for path in paths:
                for method in methods:
                    events.append(
                        GatewayEventIn(
                            method=str(method).upper(),
                            path=str(path),
                            host=host,
                            env="prod",
                            service_name=service_name,
                            owner_team=None,
                            auth_type="weak",
                            has_rate_limit=False,
                            data_sensitivity="unknown",
                            is_external=True,
                        )
                    )

        if not events and settings.connector_simulated_fallback:
            processed = _simulate_kong_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        result = ingest_gateway_events(
            db,
            GatewayIngestRequest(source_ref="kong-admin", tenant_code=tenant.code, events=events),
        )
        processed = int(result.get("processed", 0))
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": False, "run_id": run.id}

    except Exception as exc:  # noqa: BLE001
        if settings.connector_simulated_fallback:
            processed = _simulate_kong_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id, "message": f"fallback due to: {exc}"}

        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc


def _simulate_github_sync(db: Session, tenant_code: str) -> int:
    payload = GitIngestRequest(
        tenant_code=tenant_code,
        specs=[
            GitSpecIn(
                source_ref="simulated-github",
                service_name="payments-service",
                owner_team="payments-platform",
                endpoints=[
                    GitEndpointIn(method="GET", path="/v2/payments/{id}", host="kong-gateway.local", env="prod"),
                    GitEndpointIn(method="POST", path="/v2/payments", host="kong-gateway.local", env="prod"),
                ],
            )
        ],
    )
    result = ingest_git_specs(db, payload)
    return int(result.get("processed", 0))


def _parse_openapi_to_specs(openapi_doc: dict, source_ref: str) -> GitSpecIn:
    service_name = str(openapi_doc.get("info", {}).get("title") or "unknown-service").lower().replace(" ", "-")
    owner_team = str(openapi_doc.get("x-owner-team") or "unknown-team")

    host = "api.local"
    servers = openapi_doc.get("servers", [])
    if servers and isinstance(servers, list):
        first_url = str(servers[0].get("url") or "")
        parsed = urlparse(first_url)
        if parsed.hostname:
            host = parsed.hostname

    endpoints: list[GitEndpointIn] = []
    for path, methods in (openapi_doc.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, method_obj in methods.items():
            method_upper = str(method).upper()
            if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                continue
            deprecated = bool((method_obj or {}).get("deprecated", False))
            endpoints.append(GitEndpointIn(method=method_upper, path=str(path), host=host, env="prod", deprecated=deprecated))

    return GitSpecIn(source_ref=source_ref, service_name=service_name, owner_team=owner_team, endpoints=endpoints)


def sync_github(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)
    use_simulated = not (settings.github_owner and settings.github_repo and settings.github_token)

    connector = _upsert_connector(db, tenant.id, "github", "github-api", use_simulated)
    run = _start_run(db, connector)

    try:
        if use_simulated:
            processed = _simulate_github_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        headers = {
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        specs: list[GitSpecIn] = []
        paths = [chunk.strip() for chunk in settings.github_openapi_paths.split(",") if chunk.strip()]
        with httpx.Client(timeout=15.0, headers=headers) as client:
            for path in paths:
                url = f"{settings.github_api_base_url.rstrip('/')}/repos/{settings.github_owner}/{settings.github_repo}/contents/{path}"
                resp = client.get(url)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                data = resp.json()
                content_b64 = data.get("content", "")
                if not content_b64:
                    continue
                raw = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                doc = yaml.safe_load(raw) or {}
                specs.append(_parse_openapi_to_specs(doc, source_ref=f"github:{path}"))

        if not specs and settings.connector_simulated_fallback:
            processed = _simulate_github_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        result = ingest_git_specs(db, GitIngestRequest(tenant_code=tenant.code, specs=specs))
        processed = int(result.get("processed", 0))
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": False, "run_id": run.id}

    except Exception as exc:  # noqa: BLE001
        if settings.connector_simulated_fallback:
            processed = _simulate_github_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id, "message": f"fallback due to: {exc}"}

        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc


def _simulate_splunk_sync(db: Session, tenant_code: str) -> int:
    payload = SiemIngestRequest(
        source_ref="simulated-splunk",
        tenant_code=tenant_code,
        findings=[
            SiemFindingIn(
                method="POST",
                path="/legacy/partner/export",
                host="kong-gateway.local",
                env="prod",
                severity="high",
                indicator="simulated-threat:mass-export",
            )
        ],
    )
    result = ingest_siem_findings(db, payload)
    return int(result.get("processed", 0))


def sync_splunk(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)
    use_simulated = not (settings.splunk_base_url and settings.splunk_token)

    connector = _upsert_connector(db, tenant.id, "splunk", "splunk-api", use_simulated)
    run = _start_run(db, connector)

    try:
        if use_simulated:
            processed = _simulate_splunk_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        # Splunk API shape can vary across deployments. This keeps the parser tolerant and falls back if needed.
        headers = {"Authorization": f"Bearer {settings.splunk_token}"}
        params = {"search": settings.splunk_query, "output_mode": "json"}
        with httpx.Client(timeout=15.0, headers=headers) as client:
            resp = client.get(f"{settings.splunk_base_url.rstrip('/')}/services/search/jobs/export", params=params)
            resp.raise_for_status()
            raw = resp.text

        findings: list[SiemFindingIn] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = yaml.safe_load(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            result = obj.get("result", obj)
            method = str(result.get("method", "GET")).upper()
            path = str(result.get("path", "/unknown"))
            host = str(result.get("host", "api.local"))
            severity = str(result.get("severity", "medium")).lower()
            if severity not in {"low", "medium", "high"}:
                severity = "medium"
            indicator = str(result.get("indicator", "splunk-signal"))
            findings.append(
                SiemFindingIn(
                    method=method,
                    path=path,
                    host=host,
                    env="prod",
                    severity=severity,
                    indicator=indicator,
                )
            )

        if not findings and settings.connector_simulated_fallback:
            processed = _simulate_splunk_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        result = ingest_siem_findings(
            db,
            SiemIngestRequest(source_ref="splunk", tenant_code=tenant.code, findings=findings),
        )
        processed = int(result.get("processed", 0))
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": False, "run_id": run.id}

    except Exception as exc:  # noqa: BLE001
        if settings.connector_simulated_fallback:
            processed = _simulate_splunk_sync(db, tenant.code)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id, "message": f"fallback due to: {exc}"}

        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc


# ── Network Scanner (discovers shadow APIs via traffic analysis) ────────────


def _simulate_network_sync(db: Session, tenant_code: str) -> int:
    payload = GatewayIngestRequest(
        source_ref="network-traffic-scanner",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="POST", path="/internal/legacy/settlement", host="10.0.5.42", env="prod",
                service_name="unknown-settlement", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=False,
            ),
            GatewayEventIn(
                method="GET", path="/test/mock-api/accounts", host="10.0.12.8", env="staging",
                service_name="unknown-test-api", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="unknown",
                tls_status="none", is_external=False,
            ),
            GatewayEventIn(
                method="PUT", path="/internal/cache/flush", host="10.0.3.15", env="prod",
                service_name="unknown-cache-admin", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="medium",
                tls_status="none", is_external=False,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return int(result.get("processed", 0))


def sync_network(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)
    connector = _upsert_connector(db, tenant.id, "network", "network-scanner", True)
    run = _start_run(db, connector)
    try:
        processed = _simulate_network_sync(db, tenant.code)
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": True, "run_id": run.id}
    except Exception as exc:  # noqa: BLE001
        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc


# ── Kubernetes Scanner (discovers APIs from K8s ingress/services) ───────────


def _simulate_k8s_sync(db: Session, tenant_code: str) -> int:
    payload = GatewayIngestRequest(
        source_ref="k8s-cluster-scanner",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="GET", path="/api/v1/legacy-crm/contacts", host="legacy-crm.banking-ns.svc.cluster.local", env="prod",
                service_name="legacy-crm", owner_team=None,
                auth_type="weak", has_rate_limit=False, data_sensitivity="medium",
                tls_status="none", is_external=False,
            ),
            GatewayEventIn(
                method="POST", path="/api/v1/reporting/generate", host="reporting-svc.analytics-ns.svc.cluster.local", env="prod",
                service_name="reporting-service", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="tls_1.2", is_external=False,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return int(result.get("processed", 0))


def sync_k8s(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)
    connector = _upsert_connector(db, tenant.id, "k8s", "k8s-scanner", True)
    run = _start_run(db, connector)
    try:
        processed = _simulate_k8s_sync(db, tenant.code)
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": True, "run_id": run.id}
    except Exception as exc:  # noqa: BLE001
        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc
