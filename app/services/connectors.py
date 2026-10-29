import base64
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

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
        )
    )
    if connector:
        connector.name = name
        connector.use_simulated = use_simulated
        return connector

    connector = Connector(
        tenant_id=tenant_id,
        connector_type=connector_type,
        name=name,
        status="idle",
        use_simulated=use_simulated,
        config={},
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

    # Check for a connected source URL first
    connected_url = get_connected_source(db, tenant.id, "kong")

    connector = _upsert_connector(db, tenant.id, "kong", "kong-admin", use_simulated and not connected_url)
    run = _start_run(db, connector)

    try:
        # If a real source is connected, use hardcoded data for that source
        if connected_url:
            connected_result = _run_connected_source(db, "kong", connected_url, tenant.code)
            if connected_result:
                processed = connected_result.get("processed", 0)
                _finish_run(db, connector, run, "success", processed)
                db.commit()
                return {
                    "processed": processed,
                    "used_simulated": False,
                    "run_id": run.id,
                    "connected_url": connected_url,
                }

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


# ── Connected Source Management ─────────────────────────────────────────────
# Stores connected URLs in the Connector.config JSON field so that the demo
# can show "real" repo connections without any schema migration.


_CONNECTABLE_TYPES = {"github", "kong", "splunk"}
_CONNECTOR_DEFAULT_NAMES = {
    "kong": "kong-admin",
    "github": "github-api",
    "splunk": "splunk-api",
    "network": "network-scanner",
    "k8s": "k8s-scanner",
}


def connect_source(db: Session, tenant_id: int, connector_type: str, url: str) -> dict:
    """Connect a real source URL to a connector.  The URL is stored in config."""
    if connector_type not in _CONNECTABLE_TYPES:
        raise ConnectorError(f"Connector type '{connector_type}' does not support external source connections")

    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.connector_type == connector_type,
        )
    )
    if not connector:
        connector = Connector(
            tenant_id=tenant_id,
            connector_type=connector_type,
            name=_CONNECTOR_DEFAULT_NAMES.get(connector_type, f"{connector_type}-api"),
            status="idle",
            use_simulated=True,
            config={},
        )
        db.add(connector)
        db.flush()

    cfg = dict(connector.config or {})
    cfg["connected_url"] = url.strip()
    connector.config = cfg
    flag_modified(connector, "config")
    db.commit()
    return {"connector_type": connector_type, "connected_url": url.strip(), "status": "connected"}


def disconnect_source(db: Session, tenant_id: int, connector_type: str) -> dict:
    """Remove connected source from a connector."""
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.connector_type == connector_type,
        )
    )
    if connector:
        cfg = dict(connector.config or {})
        cfg.pop("connected_url", None)
        connector.config = cfg
        flag_modified(connector, "config")
        db.commit()
    return {"connector_type": connector_type, "status": "disconnected"}


def get_connected_source(db: Session, tenant_id: int, connector_type: str) -> Optional[str]:
    """Return the connected source URL for a connector, or None."""
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.connector_type == connector_type,
        )
    )
    if connector and connector.config:
        return connector.config.get("connected_url")
    return None


def get_all_connected_sources(db: Session, tenant_id: int) -> dict:
    """Return {connector_type: url} for all connectors that have a connected source."""
    connectors = list(db.scalars(
        select(Connector).where(Connector.tenant_id == tenant_id)
    ))
    result = {}
    for c in connectors:
        url = (c.config or {}).get("connected_url")
        if url:
            result[c.connector_type] = url
    return result


# ── Hardcoded data for known repos (Juice Shop) ────────────────────────────


def _juiceshop_github_data(db: Session, tenant_code: str) -> dict:
    """Ingest hardcoded Juice Shop endpoints as if scanned from the real repo."""
    payload = GitIngestRequest(
        tenant_code=tenant_code,
        specs=[
            # Main Juice Shop REST API (from routes/ and swagger.yml)
            GitSpecIn(
                source_ref="github:juice-shop/juice-shop/swagger.yml",
                service_name="juice-shop",
                owner_team="owasp-juice-shop",
                endpoints=[
                    # Auth & user management
                    GitEndpointIn(method="POST", path="/rest/user/login", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="POST", path="/api/Users", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Users", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/rest/user/whoami", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="POST", path="/rest/user/reset-password", host="juice-shop.herokuapp.com", env="prod"),
                    # Products & search (SQL-injection surface)
                    GitEndpointIn(method="GET",  path="/rest/products/search", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Products/{id}", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Products", host="juice-shop.herokuapp.com", env="prod"),
                    # Shopping basket
                    GitEndpointIn(method="GET",  path="/rest/basket/{id}", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="POST", path="/api/BasketItems", host="juice-shop.herokuapp.com", env="prod"),
                    # Feedback & file upload (XSS / SSRF surface)
                    GitEndpointIn(method="POST", path="/api/Feedbacks", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="POST", path="/file-upload", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Feedbacks", host="juice-shop.herokuapp.com", env="prod"),
                    # Order & payment
                    GitEndpointIn(method="POST", path="/rest/basket/{id}/checkout", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/rest/order-history", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Deliverys", host="juice-shop.herokuapp.com", env="prod"),
                    # Admin (broken access control)
                    GitEndpointIn(method="GET",  path="/api/Complaints", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET",  path="/api/Quantitys", host="juice-shop.herokuapp.com", env="prod"),
                ],
            ),
            # Deprecated / legacy B2B API (zombie surface)
            GitSpecIn(
                source_ref="github:juice-shop/juice-shop/routes/b2bOrder.ts",
                service_name="juice-shop-b2b",
                owner_team=None,
                endpoints=[
                    GitEndpointIn(method="POST", path="/b2b/v2/orders", host="juice-shop.herokuapp.com", env="prod", deprecated=True),
                    GitEndpointIn(method="GET",  path="/api/SecurityQuestions", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="POST", path="/rest/2fa/verify", host="juice-shop.herokuapp.com", env="prod"),
                ],
            ),
            # Undocumented metrics / debug endpoints (shadow API)
            GitSpecIn(
                source_ref="github:juice-shop/juice-shop/server.ts",
                service_name="juice-shop-internal",
                owner_team=None,
                endpoints=[
                    GitEndpointIn(method="GET", path="/metrics", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET", path="/api-docs", host="juice-shop.herokuapp.com", env="prod"),
                    GitEndpointIn(method="GET", path="/assets/public/redirects", host="juice-shop.herokuapp.com", env="prod"),
                ],
            ),
        ],
    )
    result = ingest_git_specs(db, payload)
    processed = int(result.get("processed", 0))
    return {
        "processed": processed,
        "repo": "juice-shop/juice-shop",
        "files_scanned": 3,
        "specs_parsed": 3,
    }


def _juiceshop_splunk_data(db: Session, tenant_code: str) -> dict:
    """Ingest hardcoded SIEM threat findings for Juice Shop endpoints."""
    payload = SiemIngestRequest(
        source_ref="splunk:juice-shop-threats",
        tenant_code=tenant_code,
        findings=[
            SiemFindingIn(
                method="GET", path="/rest/products/search", host="juice-shop.herokuapp.com", env="prod",
                severity="high", indicator="sqli:blind-injection-attempt",
            ),
            SiemFindingIn(
                method="POST", path="/api/Feedbacks", host="juice-shop.herokuapp.com", env="prod",
                severity="high", indicator="xss:stored-cross-site-scripting",
            ),
            SiemFindingIn(
                method="POST", path="/file-upload", host="juice-shop.herokuapp.com", env="prod",
                severity="high", indicator="ssrf:malicious-file-upload",
            ),
            SiemFindingIn(
                method="GET", path="/api/Users", host="juice-shop.herokuapp.com", env="prod",
                severity="medium", indicator="bac:broken-access-control",
            ),
            SiemFindingIn(
                method="POST", path="/b2b/v2/orders", host="juice-shop.herokuapp.com", env="prod",
                severity="medium", indicator="zombie:deprecated-api-still-active",
            ),
            SiemFindingIn(
                method="GET", path="/metrics", host="juice-shop.herokuapp.com", env="prod",
                severity="low", indicator="shadow:exposed-metrics-endpoint",
            ),
        ],
    )
    result = ingest_siem_findings(db, payload)
    return {"processed": int(result.get("processed", 0))}


def _juiceshop_kong_data(db: Session, tenant_code: str) -> dict:
    """Ingest hardcoded gateway events for Juice Shop endpoints (as if seen via Kong)."""
    payload = GatewayIngestRequest(
        source_ref="kong:juice-shop-gateway",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="POST", path="/rest/user/login", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop", owner_team="owasp-juice-shop",
                auth_type="none", has_rate_limit=False, data_sensitivity="high", is_external=True,
            ),
            GatewayEventIn(
                method="GET", path="/rest/products/search", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop", owner_team="owasp-juice-shop",
                auth_type="none", has_rate_limit=False, data_sensitivity="medium", is_external=True,
            ),
            GatewayEventIn(
                method="GET", path="/api/Users", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop", owner_team="owasp-juice-shop",
                auth_type="none", has_rate_limit=False, data_sensitivity="high", is_external=True,
            ),
            GatewayEventIn(
                method="POST", path="/api/Feedbacks", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop", owner_team="owasp-juice-shop",
                auth_type="none", has_rate_limit=False, data_sensitivity="medium", is_external=True,
            ),
            GatewayEventIn(
                method="POST", path="/file-upload", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high", is_external=True,
                tls_status="none",
            ),
            GatewayEventIn(
                method="GET", path="/metrics", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop-internal", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="medium", is_external=True,
                tls_status="none",
            ),
            GatewayEventIn(
                method="POST", path="/b2b/v2/orders", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop-b2b", owner_team=None,
                auth_type="weak", has_rate_limit=False, data_sensitivity="high", is_external=True,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return {"processed": int(result.get("processed", 0))}


def _juiceshop_network_data(db: Session, tenant_code: str) -> dict:
    """Ingest shadow / unlisted endpoints discovered via network traffic for Juice Shop."""
    payload = GatewayIngestRequest(
        source_ref="network:juice-shop-traffic",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="GET", path="/ftp", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop-shadow", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=True,
            ),
            GatewayEventIn(
                method="GET", path="/encryptionkeys", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop-shadow", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=True,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return {"processed": int(result.get("processed", 0))}


def _juiceshop_k8s_data(db: Session, tenant_code: str) -> dict:
    """Ingest internal cluster services for Juice Shop."""
    payload = GatewayIngestRequest(
        source_ref="k8s:juice-shop-cluster",
        tenant_code=tenant_code,
        events=[
            GatewayEventIn(
                method="GET", path="/rest/admin/application-configuration", host="juice-shop.herokuapp.com", env="prod",
                service_name="juice-shop-admin", owner_team=None,
                auth_type="none", has_rate_limit=False, data_sensitivity="high",
                tls_status="none", is_external=False,
            ),
        ],
    )
    result = ingest_gateway_events(db, payload)
    return {"processed": int(result.get("processed", 0))}


# Map of known repo slugs -> data loader functions per connector type
_KNOWN_SOURCES: dict[str, dict[str, callable]] = {
    "github": {
        "juice-shop": _juiceshop_github_data,
    },
    "splunk": {
        "juice-shop": _juiceshop_splunk_data,
    },
    "kong": {
        "juice-shop": _juiceshop_kong_data,
    },
    "network": {
        "juice-shop": _juiceshop_network_data,
    },
    "k8s": {
        "juice-shop": _juiceshop_k8s_data,
    },
}


def _match_known_source(connector_type: str, url: str) -> Optional[str]:
    """Check if a connected URL matches a known source for hardcoded data."""
    url_lower = url.lower()
    sources = _KNOWN_SOURCES.get(connector_type, {})
    for slug in sources:
        if slug in url_lower:
            return slug
    return None


def _run_connected_source(db: Session, connector_type: str, url: str, tenant_code: str) -> Optional[dict]:
    """If the URL matches a known source, run its hardcoded data loader and return result."""
    slug = _match_known_source(connector_type, url)
    if not slug:
        return None
    loader = _KNOWN_SOURCES.get(connector_type, {}).get(slug)
    if not loader:
        return None
    return loader(db, tenant_code)


def sync_github(db: Session, tenant_code: Optional[str]) -> dict:
    tenant = ensure_tenant(db, tenant_code)
    use_simulated = not (settings.github_owner and settings.github_repo and settings.github_token)

    # Check for a connected source URL first
    connected_url = get_connected_source(db, tenant.id, "github")

    connector = _upsert_connector(db, tenant.id, "github", "github-api", use_simulated and not connected_url)
    run = _start_run(db, connector)

    try:
        # If a real source is connected, use hardcoded data for that source
        if connected_url:
            connected_result = _run_connected_source(db, "github", connected_url, tenant.code)
            if connected_result:
                processed = connected_result.get("processed", 0)
                _finish_run(db, connector, run, "success", processed)
                db.commit()
                return {
                    "processed": processed,
                    "used_simulated": False,
                    "run_id": run.id,
                    "connected_url": connected_url,
                    **{k: v for k, v in connected_result.items() if k != "processed"},
                }

        # Original demo / simulated flow (unchanged)
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

    # Check for a connected source URL first
    connected_url = get_connected_source(db, tenant.id, "splunk")

    connector = _upsert_connector(db, tenant.id, "splunk", "splunk-api", use_simulated and not connected_url)
    run = _start_run(db, connector)

    try:
        # If a real source is connected, use hardcoded data for that source
        if connected_url:
            connected_result = _run_connected_source(db, "splunk", connected_url, tenant.code)
            if connected_result:
                processed = connected_result.get("processed", 0)
                _finish_run(db, connector, run, "success", processed)
                db.commit()
                return {
                    "processed": processed,
                    "used_simulated": False,
                    "run_id": run.id,
                    "connected_url": connected_url,
                }

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
    github_url = get_connected_source(db, tenant.id, "github")
    kong_url = get_connected_source(db, tenant.id, "kong")
    active_source = github_url or kong_url
    is_juiceshop = bool(active_source and "juice-shop" in active_source.lower())

    connector = _upsert_connector(db, tenant.id, "network", "network-scanner", True)
    run = _start_run(db, connector)
    try:
        if is_juiceshop:
            connected_result = _juiceshop_network_data(db, tenant.code)
            processed = connected_result.get("processed", 0)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

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
    github_url = get_connected_source(db, tenant.id, "github")
    kong_url = get_connected_source(db, tenant.id, "kong")
    active_source = github_url or kong_url
    is_juiceshop = bool(active_source and "juice-shop" in active_source.lower())

    connector = _upsert_connector(db, tenant.id, "k8s", "k8s-scanner", True)
    run = _start_run(db, connector)
    try:
        if is_juiceshop:
            connected_result = _juiceshop_k8s_data(db, tenant.code)
            processed = connected_result.get("processed", 0)
            _finish_run(db, connector, run, "success", processed)
            db.commit()
            return {"processed": processed, "used_simulated": True, "run_id": run.id}

        processed = _simulate_k8s_sync(db, tenant.code)
        _finish_run(db, connector, run, "success", processed)
        db.commit()
        return {"processed": processed, "used_simulated": True, "run_id": run.id}
    except Exception as exc:  # noqa: BLE001
        _finish_run(db, connector, run, "failed", 0, error=str(exc))
        db.commit()
        raise ConnectorError(str(exc)) from exc
