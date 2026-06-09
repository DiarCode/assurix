"""Benchmark suite definitions and ground truth loading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "benchmarks"


@dataclass
class BenchmarkSuite:
    name: str
    description: str
    ground_truth_path: str
    categories: list[str] = field(default_factory=list)
    scoring_weights: dict[str, float] = field(default_factory=dict)


BENCHMARK_SUITES: dict[str, BenchmarkSuite] = {
    "cyberarena": BenchmarkSuite(
        name="cyberarena",
        description="CyberArena — Live benchmark against DVWA, Juice Shop, WebGoat with endpoint-level ground truth and ResearchLoop evaluation",
        ground_truth_path=str(DATA_DIR / "cyberarena_ground_truth.json"),
        categories=["sqli", "xss", "cmdi", "lfi", "csrf", "idor", "auth_bypass", "ssrf", "info_disclosure", "upload", "brute_force", "jwt"],
        scoring_weights={"precision": 0.25, "recall": 0.30, "f1": 0.25, "fpr": 0.20},
    ),
    "cybergym": BenchmarkSuite(
        name="cybergym",
        description="CyberGym — 1,507 real-world vulnerabilities across 188 open-source projects. PoC generation task.",
        ground_truth_path=str(DATA_DIR / "cybergym_ground_truth.json"),
        categories=["xss", "sqli", "idor", "auth_bypass", "info_disclosure", "csrf", "ssrf", "cmdi", "rce", "path_traversal"],
        scoring_weights={"precision": 0.3, "recall": 0.3, "f1": 0.3, "fpr": 0.1},
    ),
    "cybench": BenchmarkSuite(
        name="cybench",
        description="Cybench — 40 professional-level CTF tasks from 4 competitions across 6 categories.",
        ground_truth_path=str(DATA_DIR / "cybench_ground_truth.json"),
        categories=["crypto", "pwn", "web", "reversing", "forensics", "misc"],
        scoring_weights={"precision": 0.2, "recall": 0.3, "f1": 0.3, "pass_at_k": 0.2},
    ),
    "wiz_arena": BenchmarkSuite(
        name="wiz_arena",
        description="Wiz Cyber Model Arena — 257 real-world offensive security challenges across 5 categories.",
        ground_truth_path=str(DATA_DIR / "wiz_arena_ground_truth.json"),
        categories=["zero_day", "code_vulnerabilities", "api_security", "web_security", "cloud_security"],
        scoring_weights={"precision": 0.25, "recall": 0.25, "f1": 0.25, "pass_at_k": 0.25},
    ),
    "deepmind_cyber": BenchmarkSuite(
        name="deepmind_cyber",
        description="Google DeepMind — 50 challenges across the full cyberattack chain (reconnaissance to persistence).",
        ground_truth_path=str(DATA_DIR / "deepmind_cyber_ground_truth.json"),
        categories=["reconnaissance", "weaponization", "exploitation", "evasion", "persistence"],
        scoring_weights={"precision": 0.25, "recall": 0.25, "f1": 0.3, "fpr": 0.2},
    ),
    "bountybench": BenchmarkSuite(
        name="bountybench",
        description="BountyBench — 46 real-world bug bounties across 31 systems. Detect/Exploit/Patch phases.",
        ground_truth_path=str(DATA_DIR / "bountybench_ground_truth.json"),
        categories=["injection", "auth_bypass", "ssrf", "path_traversal", "xss", "idor", "misconfig"],
        scoring_weights={"precision": 0.25, "recall": 0.25, "f1": 0.3, "pass_at_k": 0.2},
    ),
}


def get_suite(name: str) -> BenchmarkSuite | None:
    return BENCHMARK_SUITES.get(name)


def list_suites() -> list[str]:
    return list(BENCHMARK_SUITES.keys())


def load_ground_truth(suite_name: str) -> list[dict]:
    suite = get_suite(suite_name)
    if not suite:
        return []
    path = Path(suite.ground_truth_path)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("test_cases", [])