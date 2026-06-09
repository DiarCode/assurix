"""Assurix benchmark tracking and comparison module."""

from src.benchmark.scoring import (
    classify_result, confusion_matrix, f1_score, false_positive_rate,
    overall_scores, pass_at_k, precision, recall, category_scores,
)
from src.benchmark.registry import BenchmarkSuite, get_suite, list_suites, load_ground_truth
from src.benchmark.runner import BenchmarkRunner
from src.benchmark.report import ReportGenerator
from src.benchmark.docker_target import (
    BENCHMARK_TARGETS,
    DockerTarget,
    DockerTargetManager,
    DockerUnavailableError,
    ContainerStartError,
    HealthCheckTimeoutError,
    JUICE_SHOP,
    DVWA,
    WEBGOAT,
)
from src.benchmark.capability_scorer import (
    CapabilityScore,
    CapabilityReport,
    MythosMetrics,
    TIER_NAMES,
    score_finding,
    compute_overall_score,
    compute_multi_target_report,
    compute_mythos_metrics,
)

__all__ = [
    "BenchmarkRunner", "BenchmarkSuite", "ReportGenerator",
    "classify_result", "confusion_matrix", "f1_score", "false_positive_rate",
    "get_suite", "list_suites", "load_ground_truth",
    "overall_scores", "pass_at_k", "precision", "recall", "category_scores",
    # Docker targets
    "BENCHMARK_TARGETS", "DockerTarget", "DockerTargetManager",
    "DockerUnavailableError", "ContainerStartError", "HealthCheckTimeoutError",
    "JUICE_SHOP", "DVWA", "WEBGOAT",
    # Capability scorer
    "CapabilityScore", "CapabilityReport", "TIER_NAMES",
    "score_finding", "compute_overall_score", "compute_multi_target_report",
    "MythosMetrics", "compute_mythos_metrics",
]
