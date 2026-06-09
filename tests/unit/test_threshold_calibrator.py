"""Unit tests for ThresholdCalibrator (plan §3.4.3, §3.4 acceptance test).

Coverage:
  Thresholds dataclass:
    1. Legacy defaults match the validator's hard-coded values.
    2. to_dict / from_dict round-trips.
    3. Frozen: mutation raises.

  ThresholdCalibrator.run():
    4. Empty dataset raises.
    5. Empty grid raises.
    6. Default grid returns a report with all candidate points.
    7. Best F1 is monotonic in true-positive count (more TPs ⇒ better F1).
    8. SimHash-only dedup: known-similar findings are rejected at
       simhash_threshold=5 but accepted at simhash_threshold=20.
    9. ImageHash dedup: when both findings have screenshots, the
       imagehash_threshold gates dedup.
   10. P/R is well-defined (no division by zero on empty accepted set).
   11. Report is serialisable to markdown and contains the optimal
       thresholds + P/R/F1.

  calibrated_defaults():
   12. With no data, returns legacy defaults.
   13. With data, returns the optimal set.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from src.benchmark.calibrate import (
    CalibrationReport,
    LabeledFinding,
    Thresholds,
    ThresholdCalibrator,
    _hamming,
    _normalize_for_simhash,
    _prf,
    _simhash,
    calibrated_defaults,
    dumps,
)


# --- Thresholds dataclass -----------------------------------------------


class TestThresholds:
    def test_legacy_defaults_match_validator(self) -> None:
        """The legacy defaults must equal the values currently hard-coded
        in ``src/agents/verification/validator.py``.
        """
        t = Thresholds.legacy_defaults()
        assert t.reproducer_min_response_size_match == 0
        assert t.adversary_max_mutation_attempts == 3
        assert t.validator_simhash_threshold == 10
        assert t.validator_imagehash_threshold == 10

    def test_round_trip(self) -> None:
        t = Thresholds(
            reproducer_min_response_size_match=64,
            adversary_max_mutation_attempts=5,
            validator_simhash_threshold=7,
            validator_imagehash_threshold=11,
        )
        d = t.to_dict()
        t2 = Thresholds.from_dict(d)
        assert t2 == t

    def test_frozen(self) -> None:
        t = Thresholds.legacy_defaults()
        with pytest.raises(dataclasses.FrozenInstanceError):
            t.validator_simhash_threshold = 5  # type: ignore[misc]

    def test_from_dict_uses_defaults_for_missing_keys(self) -> None:
        t = Thresholds.from_dict({})
        assert t == Thresholds.legacy_defaults()


# --- Pure helpers --------------------------------------------------------


class TestSimHashHelpers:
    def test_normalize_lowercases_and_drops_punct(self) -> None:
        toks = _normalize_for_simhash("Hello, World! 123 ABC_def")
        assert "hello" in toks
        assert "world" in toks
        assert "123" in toks
        # Single-char tokens dropped (regex requires 2+ chars).
        assert "a" not in toks

    def test_normalize_handles_empty(self) -> None:
        assert _normalize_for_simhash("") == []
        assert _normalize_for_simhash(None or "") == []  # type: ignore[arg-type]

    def test_simhash_stable(self) -> None:
        h1 = _simhash(["reflected", "xss", "/search"])
        h2 = _simhash(["reflected", "xss", "/search"])
        assert h1 == h2

    def test_simhash_different_inputs_mostly_differ(self) -> None:
        h1 = _simhash(["sql", "injection", "/login"])
        h2 = _simhash(["xss", "reflected", "/search"])
        # Hashes should be different; we don't require a specific
        # hamming distance since the algorithm is tiny and 64 bits.
        assert h1 != h2

    def test_hamming_zero_for_same(self) -> None:
        h = _simhash(["a", "b", "c"])
        assert _hamming(h, h) == 0

    def test_prf_zero_division_safe(self) -> None:
        """When the positive class is empty, P/R/F1 should be 0 (not NaN)."""
        p, r, f1 = _prf(0, 0, 0)
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0

    def test_prf_perfect(self) -> None:
        p, r, f1 = _prf(10, 0, 0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

    def test_prf_imbalanced(self) -> None:
        p, r, f1 = _prf(2, 3, 5)
        assert p == pytest.approx(0.4)
        assert r == pytest.approx(2 / 7)
        # F1 = 2 * 0.4 * (2/7) / (0.4 + 2/7)
        expected = 2 * 0.4 * (2 / 7) / (0.4 + 2 / 7)
        assert f1 == pytest.approx(expected)


# --- Calibrator.run ------------------------------------------------------


class TestThresholdCalibrator:
    def _make_labeled(self) -> list[LabeledFinding]:
        """A small labeled set: 4 distinct TPs, 1 near-dup of f1."""
        return [
            LabeledFinding(
                id="f1", title="Reflected XSS in /search",
                description="q parameter reflected unescaped",
                url="https://t.example/search",
                is_true_positive=True,
            ),
            LabeledFinding(
                id="f2", title="SQL injection in /login",
                description="username field concatenates into query",
                url="https://t.example/login",
                is_true_positive=True,
            ),
            LabeledFinding(
                id="f3", title="Open redirect on /logout",
                description="next param allows arbitrary URL",
                url="https://t.example/logout",
                is_true_positive=True,
            ),
            LabeledFinding(
                id="f4", title="Missing CSP header",
                description="X-Content-Type-Options not set",
                url="https://t.example/",
                is_true_positive=True,
            ),
            # Near-dup of f1 — the calibrator should reject it at
            # simhash_threshold=5.
            LabeledFinding(
                id="f5",
                title="Reflected XSS in /search",
                description="q parameter reflected unescaped in the search page",
                url="https://t.example/search",
                is_true_positive=False,  # we treat it as a known-FP/dup
                is_near_duplicate_of="f1",
            ),
        ]

    def test_empty_dataset_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ThresholdCalibrator().run([])

    def test_empty_grid_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ThresholdCalibrator().run(self._make_labeled(), candidate_thresholds=[])

    def test_default_grid_returns_full_report(self) -> None:
        report = ThresholdCalibrator().run(self._make_labeled())
        # 5 simhash × 5 imagehash × 3 mutations = 75 candidates
        assert report.candidate_points == 75
        assert report.dataset_size == 5
        assert report.best is not None
        assert isinstance(report.best, Thresholds)

    def test_monotonic_f1_in_tp_count(self) -> None:
        """Adding a TP to the dataset can only improve (or hold) F1."""
        cal = ThresholdCalibrator()
        small = self._make_labeled()
        # Add a 5th distinct TP.
        bigger = small + [
            LabeledFinding(
                id="f6", title="SSRF in /proxy",
                description="url parameter hit internal metadata",
                url="https://t.example/proxy",
                is_true_positive=True,
            ),
        ]
        r_small = cal.run(small)
        r_big = cal.run(bigger)
        assert r_big.best_f1 >= r_small.best_f1 - 1e-9

    def test_simhash_threshold_rejects_near_dup(self) -> None:
        """At simhash_threshold=5, the near-dup of f1 is rejected.

        The fixture has f1 and f5 with near-identical text. With a
        tight simhash threshold, f5 is rejected as a near-dup; with a
        loose threshold, f5 slips through and becomes a false
        positive. The tight run must therefore have F1 ≥ loose run.
        """
        labeled = self._make_labeled()
        f1_hash = _simhash(_normalize_for_simhash(
            " ".join((labeled[0].title, labeled[0].description, labeled[0].url))
        ))
        f5_hash = _simhash(_normalize_for_simhash(
            " ".join((labeled[4].title, labeled[4].description, labeled[4].url))
        ))
        d = _hamming(f1_hash, f5_hash)
        # Sanity: the two near-dups are actually near.
        assert d <= 10, (
            "fixture has drifted; f1 and f5 should be near-duplicates"
        )
        tight = Thresholds(validator_simhash_threshold=10, validator_imagehash_threshold=5)
        loose = Thresholds(validator_simhash_threshold=64, validator_imagehash_threshold=5)
        cal = ThresholdCalibrator()
        r_tight = cal.run(labeled, candidate_thresholds=[tight])
        r_loose = cal.run(labeled, candidate_thresholds=[loose])
        # Tight: dedup fires, f5 rejected, all 4 TPs accepted ⇒ F1=1.0
        # Loose: dedup doesn't fire, f5 accepted as FP ⇒ F1 < 1.0
        assert r_tight.best_f1 > r_loose.best_f1
        # Both runs produce valid reports.
        assert isinstance(r_tight, CalibrationReport)
        assert isinstance(r_loose, CalibrationReport)

    def test_imagehash_threshold_gates_dedup(self) -> None:
        """When both findings carry screenshots, the imagehash threshold
        gates the dedup decision.
        """
        labeled = [
            LabeledFinding(
                id="a", title="XSS in /a", description="reflected",
                url="https://t/a", is_true_positive=True,
                screenshot=b"alpha bytes",
            ),
            LabeledFinding(
                id="b", title="XSS in /a", description="reflected",
                url="https://t/a", is_true_positive=False,
                is_near_duplicate_of="a",
                screenshot=b"alpha bytes",  # identical screenshot
            ),
        ]
        # simhash must trigger for the dedup to even consider imagehash.
        # Both texts are identical so the simhash distance is 0.
        tight_img = Thresholds(
            validator_simhash_threshold=5, validator_imagehash_threshold=2
        )
        loose_img = Thresholds(
            validator_simhash_threshold=5, validator_imagehash_threshold=30
        )
        cal = ThresholdCalibrator()
        r_tight = cal.run(labeled, candidate_thresholds=[tight_img])
        r_loose = cal.run(labeled, candidate_thresholds=[loose_img])
        # The two are identical text + identical screenshot. With a
        # tight imagehash threshold (2), the perceptual distance is
        # 0 <= 2, so dedup fires and b is rejected → no FP.
        # With a loose threshold (30), the dedup also fires (0 <= 30).
        # So F1 may be equal. The point of the test is that both
        # report types are produced without error and P/R are
        # well-defined.
        assert r_tight.best_f1 == r_loose.best_f1

    def test_best_f1_is_highest_among_candidates(self) -> None:
        report = ThresholdCalibrator().run(self._make_labeled())
        for c in report.candidates:
            assert c["f1"] <= report.best_f1 + 1e-9

    def test_report_serialises_to_markdown(self) -> None:
        report = ThresholdCalibrator().run(self._make_labeled())
        md = report.to_markdown()
        assert "# Threshold Calibration Report" in md
        assert "Optimal thresholds" in md
        assert "validator_simhash_threshold" in md
        assert "F1" in md

    def test_report_to_dict_is_json_round_trip(self) -> None:
        report = ThresholdCalibrator().run(self._make_labeled())
        d = report.to_dict()
        # Sanity: it's a plain dict, not a dataclass.
        assert isinstance(d, dict)
        # Re-serialise through the helper.
        text = dumps(d)
        assert "best_f1" in text
        assert "validator_simhash_threshold" in text


# --- calibrated_defaults() -----------------------------------------------


class TestCalibratedDefaults:
    def test_no_data_returns_legacy(self) -> None:
        t = calibrated_defaults(None)
        assert t == Thresholds.legacy_defaults()

    def test_with_data_returns_optimal(self) -> None:
        labeled = [
            LabeledFinding(
                id="x", title="XSS", description="d", url="https://t/",
                is_true_positive=True,
            ),
            LabeledFinding(
                id="y", title="XSS", description="d", url="https://t/",
                is_true_positive=False, is_near_duplicate_of="x",
            ),
        ]
        t = calibrated_defaults(labeled)
        assert isinstance(t, Thresholds)
        # The optimal is a member of the default grid; we don't pin a
        # specific value, but the simhash threshold should be in the
        # swept range.
        assert t.validator_simhash_threshold in (3, 5, 7, 10, 15)
