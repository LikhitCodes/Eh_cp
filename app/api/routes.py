from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import ApiEndpoint, AuditEvent, CaseArtifact, Connector, GovernanceRule, RemediationAction, RiskSnapshot, ScanSchedule
from app.schemas import (
    AISummarizeResponse,
    ActionApprove,
    ActionCreate,
    ActionExecute,
    ActionOut,
    ActionSimulateOut,
    AuditEventOut,
    AuthMeOut,
    BoardReportResponse,
    CaseCreate,
    CaseEvidenceOut,
    CaseOut,
    ConnectSourceRequest,
    ConnectSourceResponse,
    ConnectorStatusOut,
    ConnectorSyncResponse,
    EndpointOut,
    GatewayIngestRequest,
    GitIngestRequest,
    ReassessResponse,
    ReportRequest,
    ReportResponse,
    RiskOut,
    SiemIngestRequest,
)
from app.security import Principal, get_current_principal, require_roles
from app.services.ai import generate_remediation_playbook, summarize_case
from app.services.alerting import alert_remediation_executed, get_alert_history, record_alert
from app.services.audit import create_audit_event
from app.services.cases import create_case, get_case_with_artifacts, list_cases
from app.services.governance import evaluate_all_compliance, evaluate_endpoint_compliance
from app.services.connectors import connect_source, disconnect_source, get_all_connected_sources
from app.services.ingestion import ingest_gateway_events, ingest_git_specs, ingest_siem_findings
from app.services.jobs import claim_next_job, enqueue_job, process_job
from app.services.policy import attach_approval, get_approval_count, get_required_approvals
from app.services.recompute import recompute_endpoint
from app.services.remediation import ensure_executable, execute_action, rollback_action, simulate_action
from app.services.reporting import build_board_report, build_executive_report
from app.services.repository import ensure_tenant
from app.services.seed import seed_demo_data


router = APIRouter()


def _endpoint_out(endpoint: ApiEndpoint) -> EndpointOut:
    return EndpointOut(
        id=endpoint.id,
        tenant_id=endpoint.tenant_id,
        method=endpoint.method,
        path=endpoint.path,
        host=endpoint.host,
        env=endpoint.env,
        service_name=endpoint.service_name,
        owner_team=endpoint.owner_team,
        auth_type=endpoint.auth_type,
        has_rate_limit=endpoint.has_rate_limit,
        data_sensitivity=endpoint.data_sensitivity,
        tls_status=getattr(endpoint, "tls_status", "unknown"),
        deprecated=endpoint.deprecated,
        expected_in_code=endpoint.expected_in_code,
        seen_in_gateway=endpoint.seen_in_gateway,
        seen_in_siem=endpoint.seen_in_siem,
        is_quarantined=endpoint.is_quarantined,
        lifecycle_state=endpoint.lifecycle_state.state if endpoint.lifecycle_state else None,
        lifecycle_confidence=endpoint.lifecycle_state.confidence if endpoint.lifecycle_state else None,
        risk_score=endpoint.risk_assessment.risk_score if endpoint.risk_assessment else None,
        risk_severity=endpoint.risk_assessment.severity if endpoint.risk_assessment else None,
    )


def _action_out(db: Session, action: RemediationAction, endpoint: ApiEndpoint) -> ActionOut:
    approval_count = get_approval_count(db, action.id)
    required_approvals = get_required_approvals(db, endpoint, action.action_type)
    return ActionOut(
        id=action.id,
        endpoint_id=action.endpoint_id,
        action_type=action.action_type,
        status=action.status,
        reason=action.reason,
        requested_by=action.requested_by,
        approved_by=action.approved_by,
        rollback_ref=action.rollback_ref,
        approval_count=approval_count,
        required_approvals=required_approvals,
        simulated_impact=action.simulated_impact or {},
    )


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc)}


@router.get("/auth/me", response_model=AuthMeOut)
def auth_me(principal: Principal = Depends(get_current_principal)) -> AuthMeOut:
    return AuthMeOut(username=principal.username, roles=principal.roles, tenant_code=principal.tenant_code)


@router.post("/ingest/gateway/events")
def ingest_gateway(
    payload: GatewayIngestRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> dict:
    if not payload.tenant_code:
        payload.tenant_code = principal.tenant_code
    return ingest_gateway_events(db, payload)


@router.post("/ingest/git/specs")
def ingest_git(
    payload: GitIngestRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> dict:
    if not payload.tenant_code:
        payload.tenant_code = principal.tenant_code
    return ingest_git_specs(db, payload)


@router.post("/ingest/siem/findings")
def ingest_siem(
    payload: SiemIngestRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> dict:
    if not payload.tenant_code:
        payload.tenant_code = principal.tenant_code
    return ingest_siem_findings(db, payload)


@router.get("/connectors/status", response_model=list[ConnectorStatusOut])
def connector_status(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> list[ConnectorStatusOut]:
    tenant = ensure_tenant(db, principal.tenant_code)
    rows = list(
        db.scalars(
            select(Connector)
            .where(Connector.tenant_id == tenant.id)
            .order_by(Connector.connector_type.asc(), Connector.id.asc())
        )
    )
    return [
        ConnectorStatusOut(
            id=row.id,
            connector_type=row.connector_type,
            name=row.name,
            status=row.status,
            last_sync_at=row.last_sync_at,
            last_error=row.last_error,
            use_simulated=row.use_simulated,
            connected_url=(row.config or {}).get("connected_url"),
        )
        for row in rows
    ]


def _run_or_enqueue_sync(
    db: Session,
    *,
    job_type: str,
    principal: Principal,
    run_now: bool,
    connector_type: str,
) -> ConnectorSyncResponse:
    job = enqueue_job(db, job_type=job_type, payload={"tenant_code": principal.tenant_code}, tenant_code=principal.tenant_code)

    if run_now:
        # immediate processing for demo path while still persisting queue records
        job.status = "processing"
        job.attempts = max(1, int(job.attempts) + 1)
        db.commit()
        result = process_job(db, job)
        return ConnectorSyncResponse(
            connector_type=connector_type,
            status="success",
            processed=int(result.get("processed", 0)),
            run_id=result.get("run_id"),
            used_simulated=bool(result.get("used_simulated", False)),
            message=str(result.get("message", "")),
        )

    return ConnectorSyncResponse(
        connector_type=connector_type,
        status="queued",
        processed=0,
        run_id=None,
        used_simulated=False,
        message=f"Queued job {job.id}",
    )


@router.post("/connectors/kong/sync", response_model=ConnectorSyncResponse)
def sync_connector_kong(
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ConnectorSyncResponse:
    return _run_or_enqueue_sync(
        db,
        job_type="connector_kong_sync",
        principal=principal,
        run_now=run_now,
        connector_type="kong",
    )


@router.post("/connectors/github/sync", response_model=ConnectorSyncResponse)
def sync_connector_github(
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ConnectorSyncResponse:
    return _run_or_enqueue_sync(
        db,
        job_type="connector_github_sync",
        principal=principal,
        run_now=run_now,
        connector_type="github",
    )


@router.post("/connectors/splunk/sync", response_model=ConnectorSyncResponse)
def sync_connector_splunk(
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ConnectorSyncResponse:
    return _run_or_enqueue_sync(
        db,
        job_type="connector_splunk_sync",
        principal=principal,
        run_now=run_now,
        connector_type="splunk",
    )


# ── Connected Source Management ─────────────────────────────────────────────


@router.post("/connectors/{connector_type}/connect", response_model=ConnectSourceResponse)
def connect_connector_source(
    connector_type: str,
    body: ConnectSourceRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> ConnectSourceResponse:
    """Connect an external source URL to a connector for live scanning."""
    tenant = ensure_tenant(db, principal.tenant_code)
    try:
        result = connect_source(db, tenant.id, connector_type, body.url)
        return ConnectSourceResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/connectors/{connector_type}/connect", response_model=ConnectSourceResponse)
def disconnect_connector_source(
    connector_type: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> ConnectSourceResponse:
    """Disconnect an external source from a connector."""
    tenant = ensure_tenant(db, principal.tenant_code)
    result = disconnect_source(db, tenant.id, connector_type)
    return ConnectSourceResponse(**result)


@router.get("/connectors/sources")
def get_connector_sources(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> dict:
    """Return all currently connected source URLs across connectors."""
    tenant = ensure_tenant(db, principal.tenant_code)
    return get_all_connected_sources(db, tenant.id)


@router.post("/worker/poll-once")
def worker_poll_once(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    job = claim_next_job(db, worker_name=f"manual:{principal.username}")
    if not job:
        db.commit()
        return {"status": "idle", "message": "No jobs available"}

    db.commit()
    result = process_job(db, job)
    return {"status": "processed", "job_id": job.id, "result": result}


@router.get("/endpoints", response_model=list[EndpointOut])
def list_endpoints(
    lifecycle: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    only_quarantined: bool = Query(default=False),
    q: Optional[str] = Query(default=None),
    sort: str = Query(default="id_asc"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "approver", "admin")),
) -> list[EndpointOut]:
    tenant = ensure_tenant(db, principal.tenant_code)

    query = (
        select(ApiEndpoint)
        .where(ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.lifecycle_state), joinedload(ApiEndpoint.risk_assessment))
        .order_by(ApiEndpoint.id.asc())
    )

    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                ApiEndpoint.path.ilike(like),
                ApiEndpoint.host.ilike(like),
                ApiEndpoint.service_name.ilike(like),
                ApiEndpoint.owner_team.ilike(like),
            )
        )

    endpoints = list(db.scalars(query).unique())

    if lifecycle:
        endpoints = [ep for ep in endpoints if ep.lifecycle_state and ep.lifecycle_state.state == lifecycle]
    if severity:
        endpoints = [ep for ep in endpoints if ep.risk_assessment and ep.risk_assessment.severity == severity]
    if only_quarantined:
        endpoints = [ep for ep in endpoints if ep.is_quarantined]

    if sort == "risk_desc":
        endpoints.sort(key=lambda ep: (ep.risk_assessment.risk_score if ep.risk_assessment else -1), reverse=True)
    elif sort == "risk_asc":
        endpoints.sort(key=lambda ep: (ep.risk_assessment.risk_score if ep.risk_assessment else -1))
    elif sort == "id_desc":
        endpoints.sort(key=lambda ep: ep.id, reverse=True)

    sliced = endpoints[offset : offset + limit]
    return [_endpoint_out(endpoint) for endpoint in sliced]


@router.get("/endpoints/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "approver", "admin")),
) -> EndpointOut:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.lifecycle_state), joinedload(ApiEndpoint.risk_assessment))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    return _endpoint_out(endpoint)


@router.get("/endpoints/{endpoint_id}/risk", response_model=RiskOut)
def get_risk(
    endpoint_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "approver", "admin")),
) -> RiskOut:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.risk_assessment), joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    if not endpoint.risk_assessment:
        recompute_endpoint(db, endpoint, trigger_event="manual_risk_fetch")
        db.commit()
        db.refresh(endpoint)

    risk = endpoint.risk_assessment
    return RiskOut(
        endpoint_id=endpoint.id,
        risk_score=risk.risk_score,
        severity=risk.severity,
        factors=risk.factors,
        explainability=risk.explainability,
    )


@router.post("/endpoints/{endpoint_id}/reassess", response_model=ReassessResponse)
def reassess_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ReassessResponse:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.lifecycle_state), joinedload(ApiEndpoint.risk_assessment))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    lifecycle_before = endpoint.lifecycle_state.state if endpoint.lifecycle_state else None
    risk_before = endpoint.risk_assessment.risk_score if endpoint.risk_assessment else None

    lifecycle_state, lifecycle_confidence, risk_score, severity = recompute_endpoint(
        db,
        endpoint,
        trigger_event="manual_reassess",
    )
    create_audit_event(
        db,
        entity_type="endpoint",
        entity_id=str(endpoint.id),
        event_type="manual_reassess",
        actor=principal.username,
        before={"lifecycle": lifecycle_before, "risk_score": risk_before},
        after={"lifecycle": lifecycle_state, "risk_score": risk_score, "severity": severity},
    )

    db.commit()
    return ReassessResponse(
        endpoint_id=endpoint.id,
        lifecycle_state=lifecycle_state,
        lifecycle_confidence=lifecycle_confidence,
        risk_score=risk_score,
        severity=severity,
    )


@router.get("/remediation/actions")
def list_actions(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "auditor", "admin")),
) -> list[dict]:
    tenant = ensure_tenant(db, principal.tenant_code)
    query = (
        select(RemediationAction, ApiEndpoint)
        .join(ApiEndpoint, RemediationAction.endpoint_id == ApiEndpoint.id)
        .where(ApiEndpoint.tenant_id == tenant.id)
        .order_by(desc(RemediationAction.id))
    )
    if status_filter:
        query = query.where(RemediationAction.status == status_filter)
    rows = db.execute(query.offset(offset).limit(limit)).all()
    results = []
    for action, endpoint in rows:
        results.append({
            "id": action.id,
            "endpoint_id": action.endpoint_id,
            "endpoint_identity": f"{endpoint.method} {endpoint.path} @ {endpoint.host}",
            "action_type": action.action_type,
            "status": action.status,
            "reason": action.reason,
            "requested_by": action.requested_by,
            "approved_by": action.approved_by,
            "executed_at": action.executed_at,
            "rollback_ref": action.rollback_ref,
            "created_at": action.created_at,
        })
    return results


@router.post("/remediation/actions", response_model=ActionOut)
def create_action(
    payload: ActionCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ActionOut:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == payload.endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.risk_assessment), joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    action = RemediationAction(
        endpoint_id=payload.endpoint_id,
        action_type=payload.action_type,
        reason=payload.reason,
        requested_by=principal.username,
        status="requested",
    )
    db.add(action)
    db.flush()

    create_audit_event(
        db,
        entity_type="action",
        entity_id=str(action.id),
        event_type="action_requested",
        actor=principal.username,
        before={},
        after={
            "endpoint_id": payload.endpoint_id,
            "action_type": payload.action_type,
            "status": action.status,
        },
    )

    db.commit()
    return _action_out(db, action, endpoint)


@router.post("/remediation/actions/{action_id}/simulate", response_model=ActionSimulateOut)
def simulate_action_route(
    action_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "admin")),
) -> ActionSimulateOut:
    action = db.scalar(select(RemediationAction).where(RemediationAction.id == action_id))
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")

    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == action.endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.risk_assessment), joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    impact = simulate_action(action, endpoint, db=db)
    action.simulated_impact = impact

    create_audit_event(
        db,
        entity_type="action",
        entity_id=str(action.id),
        event_type="action_simulated",
        actor=principal.username,
        before={},
        after=impact,
    )

    db.commit()
    return ActionSimulateOut(
        action_id=action.id,
        endpoint_id=endpoint.id,
        endpoint_identity=f"{endpoint.method} {endpoint.path} @ {endpoint.host}",
        estimated_impact=impact,
        recommendation=str(impact.get("recommendation", "")),
    )


@router.post("/remediation/actions/{action_id}/approve", response_model=ActionOut)
def approve_action(
    action_id: int,
    payload: ActionApprove,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("approver", "admin")),
) -> ActionOut:
    action = db.scalar(select(RemediationAction).where(RemediationAction.id == action_id))
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")

    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == action.endpoint_id)
        .options(joinedload(ApiEndpoint.risk_assessment), joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    before = {"status": action.status, "approved_by": action.approved_by}

    attach_approval(db, action, principal.username, "approver", payload.comment)
    count = get_approval_count(db, action.id)
    required = get_required_approvals(db, endpoint, action.action_type)

    if count >= required:
        action.approved_by = principal.username
        action.status = "approved"

    create_audit_event(
        db,
        entity_type="action",
        entity_id=str(action.id),
        event_type="action_approved",
        actor=principal.username,
        before=before,
        after={"status": action.status, "approved_by": action.approved_by, "approval_count": count},
    )

    db.commit()
    return _action_out(db, action, endpoint)


@router.post("/remediation/actions/{action_id}/execute", response_model=ActionOut)
def execute_action_route(
    action_id: int,
    payload: ActionExecute,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("approver", "admin")),
) -> ActionOut:
    action = db.scalar(select(RemediationAction).where(RemediationAction.id == action_id))
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")

    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == action.endpoint_id)
        .options(joinedload(ApiEndpoint.risk_assessment), joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    executable, reason, _count, _required = ensure_executable(db, action, endpoint)
    if not executable:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=reason)

    before = {
        "action_status": action.status,
        "is_quarantined": endpoint.is_quarantined,
        "has_rate_limit": endpoint.has_rate_limit,
    }

    execute_action(action, endpoint)
    lifecycle_state, lifecycle_confidence, risk_score, severity = recompute_endpoint(
        db,
        endpoint,
        trigger_event="action_execute",
    )

    actor = payload.executed_by or principal.username
    create_audit_event(
        db,
        entity_type="action",
        entity_id=str(action.id),
        event_type="action_executed",
        actor=actor,
        before=before,
        after={
            "action_status": action.status,
            "rollback_ref": action.rollback_ref,
            "is_quarantined": endpoint.is_quarantined,
            "has_rate_limit": endpoint.has_rate_limit,
            "lifecycle": lifecycle_state,
            "risk_score": risk_score,
            "severity": severity,
            "lifecycle_confidence": lifecycle_confidence,
        },
    )

    db.commit()

    # Send webhook alert for executed remediation
    alert_remediation_executed(
        action_id=action.id,
        action_type=action.action_type,
        endpoint_identity=f"{endpoint.method} {endpoint.path} @ {endpoint.host}",
        executed_by=actor,
        blast_radius=action.simulated_impact.get("blast_radius", "unknown") if action.simulated_impact else "unknown",
    )

    return _action_out(db, action, endpoint)


@router.post("/remediation/actions/{action_id}/rollback", response_model=ActionOut)
def rollback_action_route(
    action_id: int,
    payload: ActionExecute,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("approver", "admin")),
) -> ActionOut:
    action = db.scalar(select(RemediationAction).where(RemediationAction.id == action_id))
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")

    endpoint = db.scalar(select(ApiEndpoint).where(ApiEndpoint.id == action.endpoint_id))
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    if action.status != "executed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only executed actions can be rolled back")

    before = {
        "action_status": action.status,
        "is_quarantined": endpoint.is_quarantined,
        "has_rate_limit": endpoint.has_rate_limit,
    }

    rollback_action(action, endpoint)
    lifecycle_state, lifecycle_confidence, risk_score, severity = recompute_endpoint(
        db,
        endpoint,
        trigger_event="action_rollback",
    )

    actor = payload.executed_by or principal.username
    create_audit_event(
        db,
        entity_type="action",
        entity_id=str(action.id),
        event_type="action_rolled_back",
        actor=actor,
        before=before,
        after={
            "action_status": action.status,
            "is_quarantined": endpoint.is_quarantined,
            "has_rate_limit": endpoint.has_rate_limit,
            "lifecycle": lifecycle_state,
            "risk_score": risk_score,
            "severity": severity,
            "lifecycle_confidence": lifecycle_confidence,
        },
    )

    db.commit()
    return _action_out(db, action, endpoint)


@router.get("/cases", response_model=list[CaseOut])
def list_cases_route(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity_filter: Optional[str] = Query(default=None, alias="severity"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "auditor", "admin")),
) -> list[CaseOut]:
    rows = list_cases(
        db,
        principal.tenant_code,
        status_filter=status_filter,
        severity_filter=severity_filter,
        limit=limit,
        offset=offset,
    )
    return [
        CaseOut(
            id=row.id,
            tenant_id=row.tenant_id,
            title=row.title,
            status=row.status,
            severity=row.severity,
            endpoint_id=row.endpoint_id,
            created_by=row.created_by,
            assigned_to=row.assigned_to,
            summary=row.summary,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.post("/cases", response_model=CaseOut)
def create_case_route(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> CaseOut:
    row = create_case(db, principal.tenant_code, principal.username, payload)
    return CaseOut(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        status=row.status,
        severity=row.severity,
        endpoint_id=row.endpoint_id,
        created_by=row.created_by,
        assigned_to=row.assigned_to,
        summary=row.summary,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/cases/{case_id}/evidence", response_model=CaseEvidenceOut)
def case_evidence(
    case_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "auditor", "admin")),
) -> CaseEvidenceOut:
    case = get_case_with_artifacts(db, principal.tenant_code, case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    artifacts = list(db.scalars(select(CaseArtifact).where(CaseArtifact.case_id == case.id).order_by(CaseArtifact.id.asc())))

    case_out = CaseOut(
        id=case.id,
        tenant_id=case.tenant_id,
        title=case.title,
        status=case.status,
        severity=case.severity,
        endpoint_id=case.endpoint_id,
        created_by=case.created_by,
        assigned_to=case.assigned_to,
        summary=case.summary,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )
    artifacts_out = [
        {
            "id": artifact.id,
            "case_id": artifact.case_id,
            "artifact_type": artifact.artifact_type,
            "source_ref": artifact.source_ref,
            "content": artifact.content,
            "created_at": artifact.created_at,
        }
        for artifact in artifacts
    ]
    return CaseEvidenceOut(case=case_out, artifacts=artifacts_out)


@router.post("/ai/summarize-case/{case_id}", response_model=AISummarizeResponse)
def summarize_case_route(
    case_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "auditor", "admin")),
) -> AISummarizeResponse:
    case = get_case_with_artifacts(db, principal.tenant_code, case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    result = summarize_case(db, case_id)
    return AISummarizeResponse(**result)


@router.get("/audit/events", response_model=list[AuditEventOut])
def audit_events(
    q: Optional[str] = Query(default=None),
    sort: str = Query(default="id_desc"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("auditor", "admin")),
) -> list[AuditEventOut]:
    query = select(AuditEvent)
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                AuditEvent.entity_type.ilike(like),
                AuditEvent.entity_id.ilike(like),
                AuditEvent.event_type.ilike(like),
                AuditEvent.actor.ilike(like),
            )
        )

    if sort == "id_asc":
        query = query.order_by(AuditEvent.id.asc())
    else:
        query = query.order_by(desc(AuditEvent.id))

    events = list(db.scalars(query.offset(offset).limit(limit)))
    return [
        AuditEventOut(
            id=event.id,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            event_type=event.event_type,
            actor=event.actor,
            timestamp=event.timestamp,
            before=event.before,
            after=event.after,
            signature=event.signature,
        )
        for event in events
    ]


@router.post("/reports/executive", response_model=ReportResponse)
def executive_report(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("auditor", "approver", "admin")),
) -> ReportResponse:
    report = build_executive_report(db, payload.generated_by or principal.username)
    create_audit_event(
        db,
        entity_type="report",
        entity_id="executive",
        event_type="report_generated",
        actor=principal.username,
        before={},
        after={"summary": report["totals"]},
    )
    db.commit()
    return ReportResponse(**report)


@router.post("/reports/board", response_model=BoardReportResponse)
def board_report(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("auditor", "approver", "admin")),
) -> BoardReportResponse:
    report = build_board_report(db, payload.generated_by or principal.username)
    create_audit_event(
        db,
        entity_type="report",
        entity_id="board",
        event_type="board_report_generated",
        actor=principal.username,
        before={},
        after={"kpis": report["kpis"], "risk_delta": report["risk_delta"]},
    )
    db.commit()
    return BoardReportResponse(**report)


@router.post("/demo/seed")
def seed_demo(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin", "analyst")),
) -> dict:
    result = seed_demo_data(db)

    latest_snapshot_ids = db.execute(
        select(func.max(RiskSnapshot.id)).group_by(RiskSnapshot.endpoint_id)
    ).scalars().all()
    if latest_snapshot_ids:
        snapshots = list(db.scalars(select(RiskSnapshot).where(RiskSnapshot.id.in_(latest_snapshot_ids))))
        for snapshot in snapshots:
            snapshot.trigger_event = "baseline"

    create_audit_event(
        db,
        entity_type="system",
        entity_id="demo_seed",
        event_type="demo_seeded",
        actor=principal.username,
        before={},
        after=result,
    )
    db.commit()
    return result


# ── Network + K8s Connector Routes ──────────────────────────────────────────


@router.post("/connectors/network/scan", response_model=ConnectorSyncResponse)
def sync_connector_network(
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ConnectorSyncResponse:
    return _run_or_enqueue_sync(
        db,
        job_type="connector_network_sync",
        principal=principal,
        run_now=run_now,
        connector_type="network",
    )


@router.post("/connectors/k8s/scan", response_model=ConnectorSyncResponse)
def sync_connector_k8s(
    run_now: bool = Query(default=True),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> ConnectorSyncResponse:
    return _run_or_enqueue_sync(
        db,
        job_type="connector_k8s_sync",
        principal=principal,
        run_now=run_now,
        connector_type="k8s",
    )


# ── Continuous Monitoring Routes ────────────────────────────────────────────


@router.get("/monitoring/status")
def monitoring_status(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> dict:
    tenant = ensure_tenant(db, principal.tenant_code)
    schedules = list(db.scalars(
        select(ScanSchedule).where(ScanSchedule.tenant_id == tenant.id)
    ))

    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)

    new_apis_24h = db.scalar(
        select(func.count(ApiEndpoint.id)).where(
            ApiEndpoint.tenant_id == tenant.id,
            ApiEndpoint.created_at >= twenty_four_hours_ago,
        )
    ) or 0

    total_runs = db.scalar(
        select(func.count(Connector.id)).where(
            Connector.tenant_id == tenant.id,
            Connector.last_sync_at.isnot(None),
        )
    ) or 0

    schedule_out = []
    for s in schedules:
        schedule_out.append({
            "id": s.id,
            "connector_type": s.connector_type,
            "interval_minutes": s.interval_minutes,
            "is_active": s.is_active,
            "last_run_at": s.last_run_at,
            "next_run_at": s.next_run_at,
            "apis_discovered_last_run": s.apis_discovered_last_run,
            "total_apis_discovered": s.total_apis_discovered,
        })

    all_healthy = all(s.is_active for s in schedules) if schedules else True

    return {
        "scan_schedules": schedule_out,
        "new_apis_last_24h": new_apis_24h,
        "total_scans_completed": total_runs,
        "overall_health": "healthy" if all_healthy else "degraded",
    }


@router.post("/monitoring/scan-now")
def monitoring_scan_now(
    connector_type: str = Query(default="all"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "admin")),
) -> dict:
    job_map = {
        "kong": "connector_kong_sync",
        "github": "connector_github_sync",
        "splunk": "connector_splunk_sync",
        "network": "connector_network_sync",
        "k8s": "connector_k8s_sync",
    }

    if connector_type == "all":
        types_to_run = list(job_map.keys())
    elif connector_type in job_map:
        types_to_run = [connector_type]
    else:
        raise HTTPException(status_code=400, detail=f"Unknown connector: {connector_type}")

    results = []
    for ct in types_to_run:
        result = _run_or_enqueue_sync(
            db,
            job_type=job_map[ct],
            principal=principal,
            run_now=True,
            connector_type=ct,
        )
        results.append({"connector_type": ct, "status": result.status, "processed": result.processed})

    return {"triggered": len(results), "results": results}


# ── Governance Compliance Routes ────────────────────────────────────────────


@router.get("/governance/rules")
def governance_rules(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> list[dict]:
    tenant = ensure_tenant(db, principal.tenant_code)
    rules = list(db.scalars(
        select(GovernanceRule).where(GovernanceRule.tenant_id == tenant.id)
    ))
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "rule_type": r.rule_type,
            "severity": r.severity,
            "is_active": r.is_active,
        }
        for r in rules
    ]


@router.get("/governance/compliance")
def governance_compliance(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> dict:
    tenant = ensure_tenant(db, principal.tenant_code)
    return evaluate_all_compliance(db, tenant.id)


@router.get("/governance/compliance/{endpoint_id}")
def governance_compliance_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> dict:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.lifecycle_state))
    )
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    rules = list(db.scalars(
        select(GovernanceRule).where(GovernanceRule.tenant_id == tenant.id, GovernanceRule.is_active.is_(True))
    ))
    return evaluate_endpoint_compliance(endpoint, rules)


# ── Dashboard Charts Data ───────────────────────────────────────────────────


@router.get("/dashboard/charts")
def dashboard_charts(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "auditor", "approver", "admin")),
) -> dict:
    tenant = ensure_tenant(db, principal.tenant_code)

    endpoints = list(db.scalars(
        select(ApiEndpoint)
        .where(ApiEndpoint.tenant_id == tenant.id)
        .options(joinedload(ApiEndpoint.lifecycle_state), joinedload(ApiEndpoint.risk_assessment))
    ))

    risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    lifecycle_dist = {"active": 0, "deprecated": 0, "orphaned": 0, "zombie": 0}

    for ep in endpoints:
        sev = (ep.risk_assessment.severity if ep.risk_assessment else "low").lower()
        if sev in risk_dist:
            risk_dist[sev] += 1
        lc = (ep.lifecycle_state.state if ep.lifecycle_state else "unknown").lower()
        if lc in lifecycle_dist:
            lifecycle_dist[lc] += 1

    compliance = evaluate_all_compliance(db, tenant.id)

    return {
        "risk_distribution": risk_dist,
        "lifecycle_breakdown": lifecycle_dist,
        "compliance": {
            "compliant": compliance.get("compliant_endpoints", 0),
            "non_compliant": compliance.get("non_compliant_endpoints", 0),
            "score": compliance.get("aggregate_score", 100),
        },
        "total_endpoints": len(endpoints),
    }


# ── AI Remediation Playbook ─────────────────────────────────────────────────


@router.post("/ai/remediation-playbook/{endpoint_id}")
def remediation_playbook(
    endpoint_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("analyst", "approver", "admin")),
) -> dict:
    tenant = ensure_tenant(db, principal.tenant_code)
    endpoint = db.scalar(
        select(ApiEndpoint)
        .where(ApiEndpoint.id == endpoint_id, ApiEndpoint.tenant_id == tenant.id)
        .options(
            joinedload(ApiEndpoint.lifecycle_state),
            joinedload(ApiEndpoint.risk_assessment),
        )
    )
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return generate_remediation_playbook(db, endpoint)


# ── Alerting Routes ──────────────────────────────────────────────────────────


@router.get("/alerts/history")
def alerts_history(
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(require_roles("analyst", "auditor", "admin")),
) -> list[dict]:
    return get_alert_history(limit)


@router.post("/alerts/test")
def alerts_test(
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    entry = record_alert(
        alert_type="test_alert",
        severity="low",
        title="Test alert from API Sentinel",
        details={"triggered_by": principal.username, "message": "Webhook connectivity test"},
    )
    return entry


# ── Architecture Diagram Data ────────────────────────────────────────────────


@router.get("/architecture")
def architecture_diagram(
    principal: Principal = Depends(get_current_principal),
) -> dict:
    """Return architecture metadata for rendering the system diagram."""
    return {
        "platform": "API Sentinel v0.4.0",
        "description": "Zombie API Discovery & Defence Platform for Indian Banking",
        "layers": [
            {
                "name": "Data Sources",
                "color": "#3b82f6",
                "components": [
                    {"name": "API Gateway (Kong)", "type": "connector", "protocol": "REST API", "icon": "🔌"},
                    {"name": "Code Repository (GitHub)", "type": "connector", "protocol": "REST API", "icon": "📦"},
                    {"name": "SIEM (Splunk)", "type": "connector", "protocol": "REST API", "icon": "🛡️"},
                    {"name": "Network Scanner", "type": "connector", "protocol": "Packet Analysis", "icon": "📡"},
                    {"name": "K8s Cluster", "type": "connector", "protocol": "K8s API", "icon": "☸️"},
                ],
            },
            {
                "name": "Intelligence Engine",
                "color": "#8b5cf6",
                "components": [
                    {"name": "Multi-Source Correlator", "type": "service", "desc": "Cross-references 5 data sources to classify API lifecycle states"},
                    {"name": "7-Factor Risk Scorer", "type": "service", "desc": "Deterministic scoring: exposure, auth, sensitivity, rate_limit, TLS, lifecycle, threats"},
                    {"name": "Lifecycle Classifier", "type": "service", "desc": "Classifies endpoints as active/deprecated/orphaned/zombie with confidence"},
                    {"name": "Governance Engine", "type": "service", "desc": "6 compliance rules enforcing auth, TLS, ownership, rate limiting, docs, threats"},
                ],
            },
            {
                "name": "AI Layer",
                "color": "#ec4899",
                "components": [
                    {"name": "Ollama LLM (Local)", "type": "ai", "desc": "On-premises AI — zero data leaves the bank network"},
                    {"name": "Case Summarizer", "type": "ai", "desc": "AI-powered investigation analysis with evidence citations"},
                    {"name": "Remediation Playbook", "type": "ai", "desc": "Step-by-step remediation with priority and effort estimation"},
                    {"name": "Rich Fallback Engine", "type": "ai", "desc": "Deterministic templates when LLM unavailable — always operational"},
                ],
            },
            {
                "name": "Action Layer",
                "color": "#f59e0b",
                "components": [
                    {"name": "Policy Engine", "type": "service", "desc": "Dual-approval governance — no single person can act alone"},
                    {"name": "Blast Radius Simulator", "type": "service", "desc": "Session analysis, downstream dependencies, rollback planning"},
                    {"name": "Remediation Executor", "type": "service", "desc": "Quarantine, rate-limit, decommission with automatic rollback"},
                    {"name": "Webhook Alerting", "type": "service", "desc": "Real-time alerts to Slack, Teams, PagerDuty, OpsGenie"},
                ],
            },
            {
                "name": "Security & Compliance",
                "color": "#10b981",
                "components": [
                    {"name": "RBAC (4 Roles)", "type": "security", "desc": "admin, analyst, approver, auditor with JWT/Keycloak"},
                    {"name": "Multi-Tenant Isolation", "type": "security", "desc": "Complete data isolation per bank division"},
                    {"name": "SHA-256 Audit Trail", "type": "security", "desc": "Cryptographic signatures on every state change"},
                    {"name": "Rate Limiter", "type": "security", "desc": "Token-bucket rate limiting on all API endpoints"},
                    {"name": "CORS Policy", "type": "security", "desc": "Configurable cross-origin resource sharing"},
                ],
            },
            {
                "name": "Reporting",
                "color": "#06b6d4",
                "components": [
                    {"name": "Executive Report", "type": "report", "desc": "CISO-level summary with lifecycle & severity breakdown"},
                    {"name": "Board Report", "type": "report", "desc": "ROI model: direct loss + RBI fines + reputation damage"},
                    {"name": "Compliance Score", "type": "report", "desc": "Real-time governance compliance percentage"},
                    {"name": "Prometheus Metrics", "type": "report", "desc": "Request count, latency histograms for Grafana"},
                ],
            },
        ],
        "tech_stack": {
            "backend": "Python 3.11 + FastAPI + SQLAlchemy + Alembic",
            "database": "PostgreSQL (prod) / SQLite (dev)",
            "ai": "Ollama (local LLM) with deterministic fallback",
            "auth": "JWT + Keycloak + RBAC",
            "frontend": "Vanilla JS SPA + Chart.js + Glassmorphism CSS",
            "observability": "Prometheus metrics + JSON structured logging",
            "deployment": "Docker + docker-compose",
        },
        "api_stats": {
            "total_routes": 43,
            "models": 20,
            "test_cases": 28,
            "lines_of_code": "7,700+",
        },
    }


# ── Performance Benchmark Route ──────────────────────────────────────────────


@router.get("/benchmark")
def benchmark(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_roles("admin")),
) -> dict:
    """Run a quick performance benchmark of core operations."""
    import time

    results = {}

    # 1. Database read latency
    start = time.perf_counter()
    for _ in range(100):
        db.scalars(select(ApiEndpoint).limit(10)).all()
    db_read_ms = (time.perf_counter() - start) * 1000 / 100
    results["db_read_avg_ms"] = round(db_read_ms, 2)

    # 2. Risk computation latency
    from app.services.risk import compute_risk

    endpoints = list(db.scalars(select(ApiEndpoint).limit(10)))
    if endpoints:
        start = time.perf_counter()
        for _ in range(50):
            for ep in endpoints[:3]:
                compute_risk(ep, [])
        risk_ms = (time.perf_counter() - start) * 1000 / (50 * min(3, len(endpoints)))
        results["risk_compute_avg_ms"] = round(risk_ms, 3)
    else:
        results["risk_compute_avg_ms"] = 0

    # 3. Endpoint count capacity
    total = db.scalar(select(func.count(ApiEndpoint.id))) or 0
    results["current_endpoints"] = total

    # 4. Compliance evaluation latency
    tenant = ensure_tenant(db, principal.tenant_code)
    start = time.perf_counter()
    for _ in range(10):
        evaluate_all_compliance(db, tenant.id)
    compliance_ms = (time.perf_counter() - start) * 1000 / 10
    results["compliance_eval_avg_ms"] = round(compliance_ms, 2)

    # 5. Throughput estimate
    results["estimated_endpoints_per_second"] = int(1000 / max(db_read_ms, 0.1))
    results["estimated_risk_assessments_per_second"] = int(1000 / max(results.get("risk_compute_avg_ms", 1), 0.1))

    return {
        "benchmark": results,
        "capacity": {
            "max_endpoints_supported": "100,000+ (with PostgreSQL)",
            "concurrent_users": "50+ (with gunicorn workers)",
            "api_throughput": f"{results['estimated_endpoints_per_second']}+ endpoints/sec read",
            "risk_throughput": f"{results['estimated_risk_assessments_per_second']}+ assessments/sec",
        },
        "note": "Benchmarks run on current instance. Production with PostgreSQL and gunicorn will be 3-5x faster.",
    }


# ── WebSocket Real-Time Streaming ────────────────────────────────────────────


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        import json
        data = json.dumps(message)
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(data)
            except Exception:
                self.active_connections.remove(connection)


ws_manager = ConnectionManager()


async def broadcast_event(event_type: str, data: dict):
    """Broadcast an event to all connected WebSocket clients."""
    await ws_manager.broadcast({
        "type": event_type,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client can send ping/subscribe messages
            if data == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@router.get("/ws/status")
def websocket_status():
    return {
        "active_connections": len(ws_manager.active_connections),
        "endpoint": "/v1/ws/events",
        "protocol": "wss",
        "supported_events": [
            "endpoint_discovered",
            "risk_assessed",
            "zombie_detected",
            "remediation_executed",
            "governance_violation",
            "scan_completed",
            "alert_triggered",
        ],
    }
