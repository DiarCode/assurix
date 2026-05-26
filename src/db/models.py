"""SQLAlchemy ORM models for Assurix."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TargetType(StrEnum):
    WEBAPP = "webapp"
    API = "api"
    CODEBASE = "codebase"


class EngagementStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


class ArtifactType(StrEnum):
    SCREENSHOT = "screenshot"
    HAR = "har"
    REQUEST_RESPONSE = "request_response"
    TRACE = "trace"
    DOM_SNAPSHOT = "dom_snapshot"
    SEMGREP_OUTPUT = "semgrep_output"


# ---------------------------------------------------------------------------
# Relational tables
# ---------------------------------------------------------------------------


class ScopePolicy(Base):
    __tablename__ = "scope_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    rate_rps: Mapped[float] = mapped_column(Float, default=10.0)
    max_iterations: Mapped[int] = mapped_column(Integer, default=50)
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    targets: Mapped[list["Target"]] = relationship("Target", back_populates="policy")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_type: Mapped[TargetType] = mapped_column(String(20), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_method: Mapped[str | None] = mapped_column(String(50), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(ForeignKey("scope_policies.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    policy: Mapped[ScopePolicy | None] = relationship("ScopePolicy", back_populates="targets")
    engagements: Mapped[list["Engagement"]] = relationship("Engagement", back_populates="target")


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    status: Mapped[EngagementStatus] = mapped_column(String(20), default=EngagementStatus.PENDING)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    iteration_count: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    target: Mapped[Target] = relationship("Target", back_populates="engagements")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="engagement")
    jobs: Mapped[list["Job"]] = relationship("Job", back_populates="engagement")
    artifacts: Mapped[list["EvidenceArtifact"]] = relationship(
        "EvidenceArtifact", back_populates="engagement"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="engagement")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(String(20), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_agent: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    engagement: Mapped[Engagement] = relationship("Engagement", back_populates="findings")
    artifacts: Mapped[list["EvidenceArtifact"]] = relationship(
        "EvidenceArtifact", back_populates="finding"
    )


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    artifact_type: Mapped[ArtifactType] = mapped_column(String(50), nullable=False)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    engagement: Mapped[Engagement] = relationship("Engagement", back_populates="artifacts")
    finding: Mapped[Finding | None] = relationship("Finding", back_populates="artifacts")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    engagement: Mapped[Engagement | None] = relationship("Engagement", back_populates="audit_logs")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[JobStatus] = mapped_column(String(20), default=JobStatus.QUEUED)
    priority: Mapped[int] = mapped_column(Integer, default=5)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    engagement: Mapped[Engagement] = relationship("Engagement", back_populates="jobs")


# ---------------------------------------------------------------------------
# Graph tables
# ---------------------------------------------------------------------------


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(500), nullable=False)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    edge_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)

# Benchmark models (imported separately to keep main models clean)
