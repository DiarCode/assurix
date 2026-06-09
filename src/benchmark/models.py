"""SQLAlchemy models for benchmark tracking: BenchmarkRun, BenchmarkResult, CompetitorScore."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.models import Base


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    suite_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_version: Mapped[str] = mapped_column(String(50), default="0.1.0")
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    f1: Mapped[float | None] = mapped_column(Float, nullable=True)
    fpr: Mapped[float | None] = mapped_column(Float, nullable=True)
    accuracy: Mapped[float | None] = mapped_column(Float, nullable=True)
    weighted_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    pass_at_k_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    k_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # BountyBench phase scores — populated by phase_scorer when the
    # suite is "bountybench".  See src/benchmark/phase_scorer.py.
    bountybench_detect_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    bountybench_exploit_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    bountybench_patch_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    bountybench_all_phases_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    bountybench_phase_detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # CyberGym PoC scoring — populated by phase_scorer when the suite is
    # "cybergym".
    cybergym_poc_pass_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    cybergym_poc_detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    results: Mapped[list["BenchmarkResult"]] = relationship(
        "BenchmarkResult", back_populates="run", cascade="all, delete-orphan",
    )


class BenchmarkResult(Base):
    __tablename__ = "benchmark_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("benchmark_runs.id"), nullable=False, index=True)
    test_case_id: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    expected: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    actual: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tp: Mapped[bool] = mapped_column(default=False)
    fp: Mapped[bool] = mapped_column(default=False)
    tn: Mapped[bool] = mapped_column(default=False)
    fn: Mapped[bool] = mapped_column(default=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity_expected: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity_actual: Mapped[str | None] = mapped_column(String(20), nullable=True)
    response_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    run: Mapped[BenchmarkRun] = relationship("BenchmarkRun", back_populates="results")


class CompetitorScore(Base):
    __tablename__ = "competitor_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    suite_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    competitor_name: Mapped[str] = mapped_column(String(100), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    f1: Mapped[float | None] = mapped_column(Float, nullable=True)
    fpr: Mapped[float | None] = mapped_column(Float, nullable=True)
    pass_at_k: Mapped[float | None] = mapped_column(Float, nullable=True)
    date_recorded: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC),
    )
    source: Mapped[str | None] = mapped_column(Text, nullable=True)