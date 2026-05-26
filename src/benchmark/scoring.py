"""Benchmark scoring metrics: precision, recall, F1, FPR, pass@k."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ClassificationResult:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0


def precision(tp: int, fp: int) -> float:
    if tp + fp == 0:
        return 0.0
    return tp / (tp + fp)


def recall(tp: int, fn: int) -> float:
    if tp + fn == 0:
        return 0.0
    return tp / (tp + fn)


def f1_score(prec: float, rec: float) -> float:
    if prec + rec == 0:
        return 0.0
    return 2 * prec * rec / (prec + rec)


def false_positive_rate(fp: int, tn: int) -> float:
    if fp + tn == 0:
        return 0.0
    return fp / (fp + tn)


def pass_at_k(results: list[bool], k: int = 1) -> float:
    """Estimate pass@k using Chen et al. (2021) unbiased estimator."""
    n = len(results)
    c = sum(results)
    if n - c < k:
        return 1.0
    result = 1.0
    for i in range(k):
        result *= (n - c - i) / (n - i) if n - i > 0 else 0
    return 1.0 - result


def classify_result(
    expected_findings: list[dict] | None,
    expected_safe: bool,
    actual_findings: list[dict] | None,
) -> dict:
    """Classify a single test case result into TP/FP/TN/FN."""
    expected = expected_findings or []
    actual = actual_findings or []

    if expected_safe:
        fp_findings = actual[:]
        return {
            "tp": False, "fp": len(actual) > 0,
            "tn": len(actual) == 0, "fn": False,
            "matched": [], "unmatched_actual": fp_findings, "missed_expected": [],
        }

    matched_expected_idx: set[int] = set()
    tp_findings: list[dict] = []
    fp_findings: list[dict] = []

    for act in actual:
        matched = False
        for i, exp in enumerate(expected):
            if i in matched_expected_idx:
                continue
            if _findings_match(exp, act):
                matched_expected_idx.add(i)
                tp_findings.append(act)
                matched = True
                break
        if not matched:
            fp_findings.append(act)

    fn_findings = [exp for i, exp in enumerate(expected) if i not in matched_expected_idx]

    return {
        "tp": len(tp_findings) > 0, "fp": len(fp_findings) > 0,
        "tn": len(tp_findings) == 0 and len(fp_findings) == 0 and len(expected) == 0,
        "fn": len(fn_findings) > 0,
        "matched": tp_findings, "unmatched_actual": fp_findings, "missed_expected": fn_findings,
    }


def _findings_match(expected: dict, actual: dict) -> bool:
    exp_cwe = expected.get("cwe_id", "")
    act_cwe = actual.get("cwe_id", "")
    if exp_cwe and act_cwe and exp_cwe == act_cwe:
        return True
    exp_title = expected.get("title", "").lower()
    act_title = actual.get("title", "").lower()
    if exp_title and act_title:
        overlap = len(set(exp_title.split()) & set(act_title.split()))
        if overlap >= min(len(set(exp_title.split())), 2):
            return True
    exp_cat = expected.get("category", "").lower()
    act_cat = actual.get("category", "").lower()
    if exp_cat and act_cat and exp_cat == act_cat:
        return True
    return False


def confusion_matrix(results: list[dict]) -> ClassificationResult:
    cr = ClassificationResult()
    for r in results:
        if r.get("tp"):
            cr.tp += 1
        if r.get("fp"):
            cr.fp += 1
        if r.get("tn"):
            cr.tn += 1
        if r.get("fn"):
            cr.fn += 1
    return cr


def category_scores(results: list[dict]) -> dict[str, dict]:
    by_category: dict[str, list[dict]] = {}
    for r in results:
        cat = r.get("category", "uncategorized")
        by_category.setdefault(cat, []).append(r)
    scores: dict[str, dict] = {}
    for cat, cat_results in by_category.items():
        cm = confusion_matrix(cat_results)
        p = precision(cm.tp, cm.fp)
        r = recall(cm.tp, cm.fn)
        scores[cat] = {
            "precision": p, "recall": r, "f1": f1_score(p, r),
            "fpr": false_positive_rate(cm.fp, cm.tn),
            "tp": cm.tp, "fp": cm.fp, "tn": cm.tn, "fn": cm.fn,
            "total": len(cat_results),
        }
    return scores


def overall_scores(results: list[dict], weights: dict[str, float] | None = None) -> dict:
    cm = confusion_matrix(results)
    p = precision(cm.tp, cm.fp)
    r = recall(cm.tp, cm.fn)
    scores = {
        "precision": p, "recall": r, "f1": f1_score(p, r),
        "fpr": false_positive_rate(cm.fp, cm.tn),
        "tp": cm.tp, "fp": cm.fp, "tn": cm.tn, "fn": cm.fn,
        "total": len(results),
        "accuracy": (cm.tp + cm.tn) / max(cm.tp + cm.tn + cm.fp + cm.fn, 1),
    }
    if weights:
        weighted = sum(scores.get(k, 0.0) * v for k, v in weights.items())
        scores["weighted_score"] = weighted
    return scores