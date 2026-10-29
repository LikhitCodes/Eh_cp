from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.schemas import GatewayIngestRequest, GitIngestRequest, SiemIngestRequest
from app.services.audit import create_audit_event
from app.services.recompute import recompute_endpoint
from app.services.repository import add_evidence, get_or_create_endpoint


def _seen_time(dt: Optional[datetime]) -> datetime:
    return dt or datetime.now(timezone.utc)


def ingest_gateway_events(db: Session, payload: GatewayIngestRequest) -> dict:
    processed_ids: list[int] = []

    for event in payload.events:
        endpoint, created = get_or_create_endpoint(
            db,
            method=event.method,
            path=event.path,
            host=event.host,
            env=event.env,
            tenant_code=payload.tenant_code,
        )

        before = {
            "seen_in_gateway": endpoint.seen_in_gateway,
            "owner_team": endpoint.owner_team,
            "auth_type": endpoint.auth_type,
        }

        endpoint.seen_in_gateway = True
        endpoint.last_seen_at = _seen_time(event.observed_at)
        endpoint.service_name = event.service_name or endpoint.service_name
        endpoint.owner_team = event.owner_team or endpoint.owner_team
        endpoint.is_external = event.is_external
        endpoint.auth_type = event.auth_type
        endpoint.has_rate_limit = event.has_rate_limit
        endpoint.data_sensitivity = event.data_sensitivity
        endpoint.business_critical = event.business_critical
        if event.tls_status != "unknown":
            endpoint.tls_status = event.tls_status

        add_evidence(
            db,
            endpoint_id=endpoint.id,
            source_type="gateway",
            source_ref=payload.source_ref,
            details={"created": created},
            confidence=0.95,
        )
        lifecycle_state, lifecycle_confidence, risk_score, risk_severity = recompute_endpoint(
            db,
            endpoint,
            trigger_event="gateway_ingest",
        )

        create_audit_event(
            db,
            entity_type="endpoint",
            entity_id=str(endpoint.id),
            event_type="gateway_ingest",
            actor="gateway-collector",
            before=before,
            after={
                "seen_in_gateway": endpoint.seen_in_gateway,
                "lifecycle": lifecycle_state,
                "risk_score": risk_score,
                "risk_severity": risk_severity,
                "lifecycle_confidence": lifecycle_confidence,
            },
        )

        processed_ids.append(endpoint.id)

    db.commit()
    return {"processed": len(processed_ids), "endpoint_ids": processed_ids}


def ingest_git_specs(db: Session, payload: GitIngestRequest) -> dict:
    processed_ids: list[int] = []

    for spec in payload.specs:
        for endpoint_spec in spec.endpoints:
            endpoint, _created = get_or_create_endpoint(
                db,
                method=endpoint_spec.method,
                path=endpoint_spec.path,
                host=endpoint_spec.host,
                env=endpoint_spec.env,
                tenant_code=payload.tenant_code,
            )

            before = {
                "expected_in_code": endpoint.expected_in_code,
                "deprecated": endpoint.deprecated,
                "owner_team": endpoint.owner_team,
            }

            endpoint.expected_in_code = True
            endpoint.deprecated = endpoint_spec.deprecated
            endpoint.service_name = spec.service_name
            endpoint.owner_team = spec.owner_team or endpoint.owner_team

            add_evidence(
                db,
                endpoint_id=endpoint.id,
                source_type="git",
                source_ref=spec.source_ref,
                details={"service_name": spec.service_name},
                confidence=0.9,
            )

            lifecycle_state, lifecycle_confidence, risk_score, risk_severity = recompute_endpoint(
                db,
                endpoint,
                trigger_event="git_ingest",
            )

            create_audit_event(
                db,
                entity_type="endpoint",
                entity_id=str(endpoint.id),
                event_type="git_ingest",
                actor="repo-scanner",
                before=before,
                after={
                    "expected_in_code": endpoint.expected_in_code,
                    "deprecated": endpoint.deprecated,
                    "lifecycle": lifecycle_state,
                    "risk_score": risk_score,
                    "risk_severity": risk_severity,
                    "lifecycle_confidence": lifecycle_confidence,
                },
            )
            processed_ids.append(endpoint.id)

    db.commit()
    return {"processed": len(processed_ids), "endpoint_ids": processed_ids}


def ingest_siem_findings(db: Session, payload: SiemIngestRequest) -> dict:
    processed_ids: list[int] = []

    for finding in payload.findings:
        endpoint, _created = get_or_create_endpoint(
            db,
            method=finding.method,
            path=finding.path,
            host=finding.host,
            env=finding.env,
            tenant_code=payload.tenant_code,
        )

        before = {"seen_in_siem": endpoint.seen_in_siem}
        endpoint.seen_in_siem = True

        add_evidence(
            db,
            endpoint_id=endpoint.id,
            source_type="siem",
            source_ref=payload.source_ref,
            details={
                "severity": finding.severity,
                "indicator": finding.indicator,
            },
            confidence=0.88,
        )

        lifecycle_state, lifecycle_confidence, risk_score, risk_severity = recompute_endpoint(
            db,
            endpoint,
            trigger_event="siem_ingest",
        )

        create_audit_event(
            db,
            entity_type="endpoint",
            entity_id=str(endpoint.id),
            event_type="siem_ingest",
            actor="siem-connector",
            before=before,
            after={
                "seen_in_siem": endpoint.seen_in_siem,
                "lifecycle": lifecycle_state,
                "risk_score": risk_score,
                "risk_severity": risk_severity,
                "lifecycle_confidence": lifecycle_confidence,
            },
        )
        processed_ids.append(endpoint.id)

    db.commit()
    return {"processed": len(processed_ids), "endpoint_ids": processed_ids}
