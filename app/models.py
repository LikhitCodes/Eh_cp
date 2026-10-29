from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[list["TenantUser"]] = relationship(back_populates="tenant")
    endpoints: Mapped[list["ApiEndpoint"]] = relationship(back_populates="tenant")
    connectors: Mapped[list["Connector"]] = relationship(back_populates="tenant")
    policies: Mapped[list["Policy"]] = relationship(back_populates="tenant")
    cases: Mapped[list["Case"]] = relationship(back_populates="tenant")


class TenantUser(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (UniqueConstraint("tenant_id", "username", name="uq_tenant_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"
    __table_args__ = (UniqueConstraint("tenant_id", "method", "path", "host", "env", name="uq_endpoint_identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)

    method: Mapped[str] = mapped_column(String(16), index=True)
    path: Mapped[str] = mapped_column(String(512), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    env: Mapped[str] = mapped_column(String(64), index=True)

    service_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owner_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_critical: Mapped[bool] = mapped_column(Boolean, default=False)

    is_external: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_type: Mapped[str] = mapped_column(String(32), default="none")
    has_rate_limit: Mapped[bool] = mapped_column(Boolean, default=False)
    data_sensitivity: Mapped[str] = mapped_column(String(32), default="unknown")
    tls_status: Mapped[str] = mapped_column(String(32), default="unknown")

    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    expected_in_code: Mapped[bool] = mapped_column(Boolean, default=False)
    seen_in_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    seen_in_siem: Mapped[bool] = mapped_column(Boolean, default=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False)

    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="endpoints")
    lifecycle_state: Mapped["LifecycleState"] = relationship(back_populates="endpoint", uselist=False)
    risk_assessment: Mapped["RiskAssessment"] = relationship(back_populates="endpoint", uselist=False)
    evidences: Mapped[list["EndpointEvidence"]] = relationship(back_populates="endpoint")
    actions: Mapped[list["RemediationAction"]] = relationship(back_populates="endpoint")
    cases: Mapped[list["Case"]] = relationship(back_populates="endpoint")


class EndpointEvidence(Base):
    __tablename__ = "endpoint_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_ref: Mapped[str] = mapped_column(String(255), default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="evidences")


class LifecycleState(Base):
    __tablename__ = "lifecycle_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), unique=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="lifecycle_state")


class RiskAssessment(Base):
    __tablename__ = "risk_assessment"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), unique=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    factors: Mapped[list[dict]] = mapped_column(JSON, default=list)
    explainability: Mapped[str] = mapped_column(Text, default="")
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="risk_assessment")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="requested")
    reason: Mapped[str] = mapped_column(String(512), default="")

    requested_by: Mapped[str] = mapped_column(String(128), default="system")
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    simulated_impact: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="actions")
    approvals: Mapped[list["ActionApproval"]] = relationship(back_populates="action")


class ActionApproval(Base):
    __tablename__ = "action_approvals"
    __table_args__ = (UniqueConstraint("action_id", "approver", name="uq_action_approver"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("remediation_actions.id", ondelete="CASCADE"), index=True)
    approver: Mapped[str] = mapped_column(String(128), index=True)
    approver_role: Mapped[str] = mapped_column(String(64), default="approver")
    decision: Mapped[str] = mapped_column(String(32), default="approved")
    comment: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    action: Mapped[RemediationAction] = relationship(back_populates="approvals")


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_tenant_policy_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(32), default="quarantine")
    min_approvals: Mapped[int] = mapped_column(Integer, default=1)
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="policies")


class Connector(Base):
    __tablename__ = "connectors"
    __table_args__ = (UniqueConstraint("tenant_id", "connector_type", "name", name="uq_tenant_connector"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    connector_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="idle")
    use_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="connectors")
    runs: Mapped[list["ConnectorRun"]] = relationship(back_populates="connector")


class ConnectorRun(Base):
    __tablename__ = "connector_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    connector_id: Mapped[int] = mapped_column(ForeignKey("connectors.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="started")
    items_processed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    connector: Mapped[Connector] = relationship(back_populates="runs")


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[Optional[int]] = mapped_column(ForeignKey("api_endpoints.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(64), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    created_by: Mapped[str] = mapped_column(String(128), default="analyst")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="cases")
    endpoint: Mapped[Optional[ApiEndpoint]] = relationship(back_populates="cases")
    artifacts: Mapped[list["CaseArtifact"]] = relationship(back_populates="case")
    generations: Mapped[list["LLMGeneration"]] = relationship(back_populates="case")


class CaseArtifact(Base):
    __tablename__ = "case_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    source_ref: Mapped[str] = mapped_column(String(255), default="")
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="artifacts")


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    job_type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    locked_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    locked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    attempts_log: Mapped[list["JobAttempt"]] = relationship(back_populates="job")


class JobAttempt(Base):
    __tablename__ = "job_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), index=True)
    attempt_no: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="started")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    job: Mapped[IngestionJob] = relationship(back_populates="attempts_log")


class LLMGeneration(Base):
    __tablename__ = "llm_generations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[Optional[int]] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    model: Mapped[str] = mapped_column(String(128), default="llama3.1:8b-instruct")
    prompt: Mapped[str] = mapped_column(Text, default="")
    output_text: Mapped[str] = mapped_column(Text, default="")
    sources: Mapped[list[dict]] = mapped_column(JSON, default=list)
    safe: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Optional[Case]] = relationship(back_populates="generations")


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    lifecycle_state: Mapped[str] = mapped_column(String(32), index=True)
    trigger_event: Mapped[str] = mapped_column(String(64), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)
    signature: Mapped[str] = mapped_column(String(128), index=True)


class GovernanceRule(Base):
    __tablename__ = "governance_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    rule_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    connector_type: Mapped[str] = mapped_column(String(32), index=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    apis_discovered_last_run: Mapped[int] = mapped_column(Integer, default=0)
    total_apis_discovered: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
