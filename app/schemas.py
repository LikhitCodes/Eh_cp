from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class GatewayEventIn(BaseModel):
    method: str
    path: str
    host: str
    env: str = "prod"
    service_name: Optional[str] = None
    owner_team: Optional[str] = None
    observed_at: Optional[datetime] = None
    is_external: bool = True
    auth_type: Literal["none", "weak", "strong"] = "none"
    has_rate_limit: bool = False
    data_sensitivity: Literal["unknown", "low", "medium", "high"] = "unknown"
    tls_status: Literal["none", "tls_1.0", "tls_1.2", "tls_1.3", "mtls", "unknown"] = "unknown"
    business_critical: bool = False


class GatewayIngestRequest(BaseModel):
    source_ref: str = "gateway-log"
    tenant_code: Optional[str] = None
    events: list[GatewayEventIn] = Field(default_factory=list)


class GitEndpointIn(BaseModel):
    method: str
    path: str
    host: str
    env: str = "prod"
    deprecated: bool = False


class GitSpecIn(BaseModel):
    source_ref: str = "repo-spec"
    service_name: str
    owner_team: Optional[str] = None
    endpoints: list[GitEndpointIn] = Field(default_factory=list)


class GitIngestRequest(BaseModel):
    tenant_code: Optional[str] = None
    specs: list[GitSpecIn] = Field(default_factory=list)


class SiemFindingIn(BaseModel):
    method: str
    path: str
    host: str
    env: str = "prod"
    severity: Literal["low", "medium", "high"] = "medium"
    indicator: str


class SiemIngestRequest(BaseModel):
    source_ref: str = "siem"
    tenant_code: Optional[str] = None
    findings: list[SiemFindingIn] = Field(default_factory=list)


class EndpointOut(BaseModel):
    id: int
    tenant_id: int
    method: str
    path: str
    host: str
    env: str
    service_name: Optional[str]
    owner_team: Optional[str]
    auth_type: str
    has_rate_limit: bool
    data_sensitivity: str
    tls_status: str = "unknown"
    deprecated: bool
    expected_in_code: bool
    seen_in_gateway: bool
    seen_in_siem: bool
    is_quarantined: bool
    lifecycle_state: Optional[str]
    lifecycle_confidence: Optional[float]
    risk_score: Optional[int]
    risk_severity: Optional[str]


class RiskOut(BaseModel):
    endpoint_id: int
    risk_score: int
    severity: str
    factors: list[dict]
    explainability: str


class ReassessResponse(BaseModel):
    endpoint_id: int
    lifecycle_state: str
    lifecycle_confidence: float
    risk_score: int
    severity: str


class ActionCreate(BaseModel):
    endpoint_id: int
    action_type: Literal["alert", "rate_limit", "quarantine", "decommission"]
    reason: str = ""


class ActionOut(BaseModel):
    id: int
    endpoint_id: int
    action_type: str
    status: str
    reason: str
    requested_by: str
    approved_by: Optional[str]
    rollback_ref: Optional[str]
    approval_count: int = 0
    required_approvals: int = 1
    simulated_impact: dict = Field(default_factory=dict)


class ActionApprove(BaseModel):
    comment: str = ""


class ActionExecute(BaseModel):
    executed_by: Optional[str] = None


class ActionSimulateOut(BaseModel):
    action_id: int
    endpoint_id: int
    endpoint_identity: str
    estimated_impact: dict
    recommendation: str


class ReportRequest(BaseModel):
    generated_by: str = "ciso"


class ReportResponse(BaseModel):
    generated_at: datetime
    generated_by: str
    totals: dict
    lifecycle_breakdown: dict
    severity_breakdown: dict
    top_risks: list[dict]
    remediation_summary: dict


class BoardReportResponse(BaseModel):
    generated_at: datetime
    generated_by: str
    executive_summary: str
    kpis: dict
    risk_delta: dict
    top_actions: list[dict]
    roi_estimate: dict


class AuditEventOut(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    event_type: str
    actor: str
    timestamp: datetime
    before: dict
    after: dict
    signature: str


class AuthMeOut(BaseModel):
    username: str
    roles: list[str]
    tenant_code: str


class ConnectorSyncResponse(BaseModel):
    connector_type: str
    status: str
    processed: int
    run_id: Optional[int] = None
    used_simulated: bool = False
    message: str = ""


class ConnectorStatusOut(BaseModel):
    id: int
    connector_type: str
    name: str
    status: str
    last_sync_at: Optional[datetime]
    last_error: Optional[str]
    use_simulated: bool


class CaseCreate(BaseModel):
    title: str
    endpoint_id: Optional[int] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    summary: str = ""
    assigned_to: Optional[str] = None


class CaseOut(BaseModel):
    id: int
    tenant_id: int
    title: str
    status: str
    severity: str
    endpoint_id: Optional[int]
    created_by: str
    assigned_to: Optional[str]
    summary: str
    created_at: datetime
    updated_at: datetime


class CaseArtifactOut(BaseModel):
    id: int
    case_id: int
    artifact_type: str
    source_ref: str
    content: dict
    created_at: datetime


class CaseEvidenceOut(BaseModel):
    case: CaseOut
    artifacts: list[CaseArtifactOut]


class AISummarizeResponse(BaseModel):
    case_id: int
    summary: str
    model: str
    sources: list[dict]
    safe: bool
