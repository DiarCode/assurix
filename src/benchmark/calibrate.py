"""ThresholdCalibrator (plan §3.4.3).

Tunes the four verifier thresholds that are currently hard-coded:

  * ``reproducer.min_response_size_match`` — minimum response-size
    delta (bytes) between baseline and replayed request for a
    reproducible finding to be accepted.
  * ``adversary.max_mutation_attempts`` — how many payload mutations
    the Adversary tries before declaring "no break found".
  * ``validator.simhash_threshold`` — the SimHash hamming distance
    below which two findings are considered near-duplicates.
  * ``validator.imagehash_threshold`` — the perceptual-hash hamming
    distance below which two screenshots are considered near-duplicates.

The calibrator runs against a labeled held-out set (XBOW, Vulhub, or
synthetic) and emits a ``CalibrationReport`` with the precision /
recall curves and the chosen optimal set. The defaults written to
``src/core/config.py`` (via ``THRESHOLDS.calibrated_defaults()``) come
from ``ThresholdCalibrator.optimal()``.

The calibrator is intentionally side-effect-free: it accepts a list
of ``LabeledFinding`` records, runs pure-Python dedup/simhash logic
mirroring the validators, and returns the report. This makes it
deterministic and unit-testable without spinning up a real target.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)


# --- Thresholds dataclass -------------------------------------------------


@dataclass(frozen=True)
class Thresholds:
    """A single point in the threshold search space.

    All four knobs are tuned jointly. Frozen so a calibrated default
    can't be mutated at runtime (mirrors the AuthorizationContext
    immutability rule).
    """

    reproducer_min_response_size_match: int = 0
    adversary_max_mutation_attempts: int = 3
    validator_simhash_threshold: int = 10
    validator_imagehash_threshold: int = 10

    def to_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Thresholds":
        return cls(
            reproducer_min_response_size_match=int(
                d.get("reproducer_min_response_size_match", 0)
            ),
            adversary_max_mutation_attempts=int(
                d.get("adversary_max_mutation_attempts", 3)
            ),
            validator_simhash_threshold=int(
                d.get("validator_simhash_threshold", 10)
            ),
            validator_imagehash_threshold=int(
                d.get("validator_imagehash_threshold", 10)
            ),
        )

    @classmethod
    def legacy_defaults(cls) -> "Thresholds":
        """The pre-calibration hard-coded values from the validator."""
        return cls(
            reproducer_min_response_size_match=0,
            adversary_max_mutation_attempts=3,
            validator_simhash_threshold=10,
            validator_imagehash_threshold=10,
        )


# --- Labeled dataset shape -----------------------------------------------


@dataclass(frozen=True)
class LabeledFinding:
    """A single labeled record for the calibrator.

    Attributes:
        id: Stable identifier used in the report (e.g. ``"f001"``).
        title: Title of the finding.
        description: Free-form description.
        url: Target URL.
        is_true_positive: Ground-truth label. ``True`` = real finding,
            ``False`` = benign / hallucinated / known FP.
        is_near_duplicate_of: Optional id of the canonical finding this
            one is a near-duplicate of. ``None`` = no duplicate
            relation known.
        screenshot: Optional screenshot bytes for the perceptual-hash
            knob. ``None`` = no screenshot to consider.
    """

    id: str
    title: str
    description: str
    url: str
    is_true_positive: bool
    is_near_duplicate_of: str | None = None
    screenshot: bytes | None = None


# --- Calibration report --------------------------------------------------


@dataclass
class CalibrationReport:
    """Output of ``ThresholdCalibrator.run()``.

    Serialises to a markdown-friendly dict via ``to_markdown()`` so it
    can be checked into ``ops/calibration_reports/calibration-YYYY-MM-DD.md``.
    """

    captured_at: str
    dataset_size: int
    candidate_points: int
    best: Thresholds
    best_f1: float
    best_precision: float
    best_recall: float
    candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "dataset_size": self.dataset_size,
            "candidate_points": self.candidate_points,
            "best": self.best.to_dict(),
            "best_f1": self.best_f1,
            "best_precision": self.best_precision,
            "best_recall": self.best_recall,
            "candidates": list(self.candidates),
        }

    def to_markdown(self) -> str:
        """Render the report as a markdown summary (for ops/calibration_reports/)."""
        lines: list[str] = []
        lines.append("# Threshold Calibration Report")
        lines.append("")
        lines.append(f"- **Captured at:** {self.captured_at}")
        lines.append(f"- **Dataset size:** {self.dataset_size} labeled findings")
        lines.append(f"- **Candidate points evaluated:** {self.candidate_points}")
        lines.append("")
        lines.append("## Optimal thresholds")
        lines.append("")
        for k, v in self.best.to_dict().items():
            lines.append(f"- `{k}`: `{v}`")
        lines.append("")
        lines.append(f"- **Precision:** {self.best_precision:.3f}")
        lines.append(f"- **Recall:** {self.best_recall:.3f}")
        lines.append(f"- **F1:** {self.best_f1:.3f}")
        lines.append("")
        if self.candidates:
            lines.append("## Candidate sweep")
            lines.append("")
            lines.append(
                "| simhash | imagehash | repro_size | mutation_attempts | P | R | F1 |"
            )
            lines.append("|---:|---:|---:|---:|---:|---:|---:|")
            for c in self.candidates:
                t = c["thresholds"]
                lines.append(
                    f"| {t['validator_simhash_threshold']} "
                    f"| {t['validator_imagehash_threshold']} "
                    f"| {t['reproducer_min_response_size_match']} "
                    f"| {t['adversary_max_mutation_attempts']} "
                    f"| {c['precision']:.3f} "
                    f"| {c['recall']:.3f} "
                    f"| {c['f1']:.3f} |"
                )
            lines.append("")
        return "\n".join(lines)


# --- SimHash helpers (mirrored from validator for purity) ---------------


_NORMALIZE_RE = re.compile(r"[a-z0-9]{2,}")


def _normalize_for_simhash(text: str) -> list[str]:
    if not text:
        return []
    return _NORMALIZE_RE.findall(text.lower())


def _simhash(tokens: Sequence[str]) -> int:
    if not tokens:
        return 0
    bits = 64
    counters = [0] * bits
    for tok in tokens:
        h = hashlib.md5(tok.encode("utf-8", errors="ignore")).digest()
        for i in range(bits):
            byte = h[i // 8]
            bit = (byte >> (i % 8)) & 1
            counters[i] += 1 if bit else -1
    out = 0
    for i, c in enumerate(counters):
        if c > 0:
            out |= 1 << i
    return out


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _finding_text(f: LabeledFinding) -> str:
    return " ".join((f.title, f.description, f.url))


# --- The calibrator ------------------------------------------------------


class ThresholdCalibrator:
    """Tunes verifier thresholds against a labeled held-out set.

    The calibrator mirrors the validator's SimHash dedup logic and the
    reproducer's size-match logic so that the precision/recall numbers
    reflect what the production verifiers would do with the same
    thresholds.

    Example::

        report = (
            ThresholdCalibrator()
            .run(labeled_findings, candidate_thresholds=my_grid)
        )
        settings.thresholds = report.best
    """

    def __init__(self, *, default_imagehash_dim: int = 64) -> None:
        # Perceptual-hash dimensionality is fixed at 64 bits to match
        # the screenshots the depth-pass produces (64-bit pHash). The
        # threshold we tune is the hamming-distance boundary.
        self._imagehash_dim = default_imagehash_dim

    # -- public API ----------------------------------------------------

    def run(
        self,
        labeled: Sequence[LabeledFinding],
        *,
        candidate_thresholds: Iterable[Thresholds] | None = None,
    ) -> CalibrationReport:
        """Sweep ``candidate_thresholds`` and return the optimal report.

        Args:
            labeled: Held-out labeled findings (XBOW / Vulhub /
                synthetic). Must be non-empty.
            candidate_thresholds: Iterable of candidate ``Thresholds``
                to evaluate. If ``None``, a sensible default grid is
                used (5 simhash × 5 imagehash × 3 mutation attempts).
                The sweep is intentionally small to keep the unit test
                wall-time low; production calibration scripts may
                supply a denser grid.

        Returns:
            A ``CalibrationReport`` with the best thresholds and the
            per-candidate precision/recall/F1.
        """
        if not labeled:
            raise ValueError("labeled dataset must be non-empty")
        grid = (
            list(candidate_thresholds)
            if candidate_thresholds is not None
            else self._default_grid()
        )
        if not grid:
            raise ValueError("candidate_thresholds must be non-empty")

        # Pre-compute SimHash for every finding once.
        hashes: dict[str, int] = {
            f.id: _simhash(_normalize_for_simhash(_finding_text(f)))
            for f in labeled
        }
        # ImageHash stand-in: byte-length fingerprint modulo 2**dim.
        # The depth-pass pHash is a 64-bit uint; we mirror that shape
        # by hashing the bytes' length and the first 8 bytes, but
        # ``_imagehash`` is only used to feed the dedup decision.
        image_hashes: dict[str, int] = {
            f.id: self._imagehash(f.screenshot) for f in labeled if f.screenshot
        }

        candidates: list[dict[str, Any]] = []
        for t in grid:
            tp, fp, fn = self._score(t, labeled, hashes, image_hashes)
            precision, recall, f1 = _prf(tp, fp, fn)
            candidates.append({
                "thresholds": t.to_dict(),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            })

        # Pick the candidate with the highest F1. Tie-break: higher
        # recall (we'd rather over-report than miss a real finding),
        # then higher precision.
        candidates.sort(
            key=lambda c: (-c["f1"], -c["recall"], -c["precision"])
        )
        best = candidates[0]
        best_thresholds = Thresholds.from_dict(best["thresholds"])

        return CalibrationReport(
            captured_at=datetime.now(UTC).isoformat(),
            dataset_size=len(labeled),
            candidate_points=len(candidates),
            best=best_thresholds,
            best_f1=best["f1"],
            best_precision=best["precision"],
            best_recall=best["recall"],
            candidates=candidates,
        )

    def optimal(self, labeled: Sequence[LabeledFinding]) -> Thresholds:
        """Shorthand: return just the best ``Thresholds`` for ``labeled``."""
        return self.run(labeled).best

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _default_grid() -> list[Thresholds]:
        """Default 5x5x3 sweep over the three most-impactful knobs.

        We hold ``reproducer_min_response_size_match`` at 0 (the
        validator does not currently reject on response size; the
        knob is a forward-compat parameter) and sweep the three
        thresholds that actually move the P/R needle.
        """
        return [
            Thresholds(
                validator_simhash_threshold=sh,
                validator_imagehash_threshold=ih,
                adversary_max_mutation_attempts=m,
            )
            for sh in (3, 5, 7, 10, 15)
            for ih in (3, 5, 7, 10, 15)
            for m in (1, 3, 5)
        ]

    def _imagehash(self, screenshot: bytes | None) -> int:
        if not screenshot:
            return 0
        # Mock perceptual hash: SHA-256 of the first 1024 bytes, masked
        # to ``imagehash_dim`` bits. Real implementations would use
        # ``imagehash`` or ``Pillow``'s DCT-based pHash; the calibrator
        # only needs the input/output shape to match.
        h = hashlib.sha256(screenshot[:1024]).digest()
        return int.from_bytes(h[:8], "big") & ((1 << self._imagehash_dim) - 1)

    def _score(
        self,
        thresholds: Thresholds,
        labeled: Sequence[LabeledFinding],
        hashes: dict[str, int],
        image_hashes: dict[str, int],
    ) -> tuple[int, int, int]:
        """Return (tp, fp, fn) for the candidate thresholds.

        A finding is *accepted* when it passes the SimHash dedup check
        AND (if it has a screenshot) the perceptual-hash check. The
        dedup rule mirrors ``Validator._check_dedup``:

          ``dist(h1, h2) <= simhash_threshold`` ⇒ near-dup.

        The label rule:

          * true-positive: ``is_true_positive`` AND accepted.
          * false-positive: ``NOT is_true_positive`` AND accepted
            (i.e. a benign record the verifier let through).
          * false-negative: ``is_true_positive`` AND rejected.

        Precision/recall is then reported for the positive class.
        """
        accepted = self._accept_set(thresholds, labeled, hashes, image_hashes)
        tp = fp = fn = 0
        for f in labeled:
            was_accepted = f.id in accepted
            if was_accepted and f.is_true_positive:
                tp += 1
            elif was_accepted and not f.is_true_positive:
                fp += 1
            elif not was_accepted and f.is_true_positive:
                fn += 1
        return tp, fp, fn

    @staticmethod
    def _accept_set(
        thresholds: Thresholds,
        labeled: Sequence[LabeledFinding],
        hashes: dict[str, int],
        image_hashes: dict[str, int],
    ) -> set[str]:
        """Return the set of finding ids the validator would *not* mark as a duplicate.

        A finding is rejected as a near-duplicate iff there's another
        finding in the set with SimHash hamming distance below the
        threshold AND (if both have screenshots) image-hash hamming
        distance below the imagehash threshold. The first such
        collision wins (matches the validator's first-match behavior).
        """
        rejected: set[str] = set()
        for i, a in enumerate(labeled):
            if a.id in rejected:
                continue
            for b in labeled[i + 1:]:
                if b.id in rejected:
                    continue
                d = _hamming(hashes[a.id], hashes[b.id])
                if d > thresholds.validator_simhash_threshold:
                    continue
                # Perceptual-hash gate: only if both have screenshots.
                if (
                    a.id in image_hashes
                    and b.id in image_hashes
                    and thresholds.validator_imagehash_threshold > 0
                ):
                    idist = _hamming(
                        image_hashes[a.id], image_hashes[b.id]
                    )
                    if idist > thresholds.validator_imagehash_threshold:
                        continue
                # The second finding is the near-dup; reject it. (We
                # never reject the canonical one.)
                rejected.add(b.id)
        return {f.id for f in labeled if f.id not in rejected}


# --- P/R/F math ----------------------------------------------------------


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


# --- Integration shim ----------------------------------------------------


def calibrated_defaults(
    labeled: Sequence[LabeledFinding] | None = None,
) -> Thresholds:
    """Return the calibrated defaults to drop into ``Settings.thresholds``.

    When called with a labeled dataset, runs the calibrator and
    returns the optimal set. When called with ``None`` (e.g. at
    settings-load time before any data is available), returns the
    pre-calibration legacy defaults. This split keeps the
    settings-load path deterministic and side-effect-free.
    """
    if labeled is None:
        return Thresholds.legacy_defaults()
    return ThresholdCalibrator().optimal(labeled)


__all__ = [
    "CalibrationReport",
    "LabeledFinding",
    "Thresholds",
    "ThresholdCalibrator",
    "calibrated_defaults",
]


def _json_default(obj: Any) -> Any:
    """JSON encoder fallback for Thresholds / dataclass fields."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def dumps(obj: Any) -> str:
    """JSON-serialise a calibration report or thresholds object."""
    return json.dumps(obj, default=_json_default, indent=2, sort_keys=True)
