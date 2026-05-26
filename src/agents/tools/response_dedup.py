"""Response deduplication using exact hash + SimHash similarity detection.

Eliminates false positives from soft-404 pages, SPA catch-all responses,
and other near-identical responses that differ only in dynamic content.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# SimHash parameters
_SIMHASH_BITS = 64
_SIMHASH_FEATURE_LEN = 4  # 4-character shingles


def _simhash(text: str, bits: int = _SIMHASH_BITS) -> int:
    """Compute SimHash of text using character shingles as features."""
    v = [0] * bits
    features = set()
    for i in range(len(text) - _SIMHASH_FEATURE_LEN + 1):
        features.add(text[i:i + _SIMHASH_FEATURE_LEN])
    for feature in features:
        h = int(hashlib.md5(feature.encode()).hexdigest(), 16)
        for j in range(bits):
            if h & (1 << j):
                v[j] += 1
            else:
                v[j] -= 1
    return sum(1 << i for i in range(bits) if v[i] >= 0)


def _hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two hashes."""
    return bin(a ^ b).count("1")


def _similarity(a: int, b: int, bits: int = _SIMHASH_BITS) -> float:
    """Compute similarity ratio (0.0-1.0) between two SimHash values."""
    return 1.0 - (_hamming_distance(a, b) / bits)


@dataclass
class DedupResult:
    is_duplicate: bool
    original_url: str = ""
    similarity: float = 0.0
    response_hash: str = ""


class ResponseDeduplicator:
    """Two-tier response deduplication: exact SHA256 hash + SimHash similarity."""

    EXACT_HASH_PREFIX_LEN = 16
    SIMHASH_THRESHOLD = 0.85

    def __init__(self, simhash_threshold: float = 0.85) -> None:
        self.simhash_threshold = simhash_threshold
        self._seen_exact: dict[str, str] = {}   # hash[:16] -> url
        self._seen_simhash: list[tuple[int, str]] = []  # (simhash, url)

    def check_response(self, url: str, body: str) -> DedupResult:
        """Check if a response body is a duplicate of a previously seen one.

        Tier 1: Exact SHA256 hash matching.
        Tier 2: SimHash similarity for near-identical responses (SPA catch-alls).
        """
        # Tier 1: Exact hash
        body_hash = hashlib.sha256(body.encode()).hexdigest()[:self.EXACT_HASH_PREFIX_LEN]
        if body_hash in self._seen_exact:
            return DedupResult(
                is_duplicate=True,
                original_url=self._seen_exact[body_hash],
                similarity=1.0,
                response_hash=body_hash,
            )

        # Tier 2: SimHash similarity
        sim = _simhash(body)
        for prev_sim, prev_url in self._seen_simhash:
            sim_score = _similarity(sim, prev_sim)
            if sim_score >= self.simhash_threshold:
                return DedupResult(
                    is_duplicate=True,
                    original_url=prev_url,
                    similarity=sim_score,
                    response_hash=body_hash,
                )

        # Not a duplicate — register it
        self._seen_exact[body_hash] = url
        self._seen_simhash.append((sim, url))
        return DedupResult(is_duplicate=False, response_hash=body_hash)

    def dedup_findings(self, findings: list[dict]) -> list[dict]:
        """Remove findings whose HTTP response bodies are duplicates.

        Hashes the response_body field (actual HTTP response) when available,
        falling back to evidence+description only if no response body is stored.
        """
        dedup = ResponseDeduplicator(simhash_threshold=self.simhash_threshold)
        unique: list[dict] = []
        for f in findings:
            # Use actual HTTP response body for dedup, not evidence text
            body = f.get("response_body", "") or f.get("evidence", "") + f.get("description", "")
            result = dedup.check_response(f.get("url", ""), body)
            if not result.is_duplicate:
                unique.append(f)
            else:
                logger.debug("Dedup: %s is duplicate of %s (%.2f)", f.get("url", ""), result.original_url, result.similarity)
        return unique

    def is_soft_404(self, url: str, body: str, baseline_url: str, baseline_body: str) -> bool:
        """Check if a response is a soft-404 by comparing to baseline using SimHash."""
        if not baseline_body:
            return False
        sim = _simhash(body)
        baseline_sim = _simhash(baseline_body)
        return _similarity(sim, baseline_sim) >= self.simhash_threshold

    def reset(self) -> None:
        """Clear all stored hashes for a new scan."""
        self._seen_exact.clear()
        self._seen_simhash.clear()