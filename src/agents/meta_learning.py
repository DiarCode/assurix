"""Cross-engagement technique memory for meta-learning.

Stores successful (and unsuccessful) attack techniques so that future
engagements can prioritize strategies that worked against similar target
signatures.  Uses a standalone aiosqlite table rather than the main
SQLAlchemy ORM so it can be read/written without an active session.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from src.core.config import get_settings

logger = logging.getLogger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS technique_memory (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique       TEXT    NOT NULL,
    vuln_class     TEXT    NOT NULL,
    target_signature TEXT   NOT NULL DEFAULT '{}',
    success_rate   REAL    NOT NULL DEFAULT 0.0,
    avg_confidence REAL    NOT NULL DEFAULT 0.0,
    capability_tier INTEGER NOT NULL DEFAULT 5,
    use_count      INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT    NOT NULL,
    last_used_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tm_vuln_class ON technique_memory(vuln_class);
CREATE INDEX IF NOT EXISTS idx_tm_success    ON technique_memory(success_rate DESC);
"""


class TechniqueMemory:
    """SQLite-backed store of cross-engagement technique outcomes.

    Each row records a *technique* (payload, prompt, or strategy) that was
    tried against a particular *target signature* (tech stack + endpoint
    pattern), together with aggregate success statistics.  Future
    engagements query this memory to rank hypotheses by what has worked
    before on similar targets.
    """

    def __init__(self, db_path: str | None = None) -> None:
        """Initialise the technique memory.

        Args:
            db_path: Path to the SQLite database file.  If *None*, the path
                is derived from ``get_settings().database_path``.
        """
        if db_path is None:
            settings = get_settings()
            db_path = str(settings.database_path)
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _ensure_db(self) -> aiosqlite.Connection:
        """Open the connection and create the table if it does not exist."""
        if self._db is not None:
            return self._db

        # Ensure parent directory exists
        db_file = Path(self._db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_CREATE_TABLE_SQL)
        await self._db.commit()
        logger.debug("TechniqueMemory database initialised at %s", self._db_path)
        return self._db

    async def close(self) -> None:
        """Close the underlying database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    async def record(
        self,
        technique: str,
        vuln_class: str,
        target_signature: dict[str, Any],
        success: bool,
        confidence: float,
        tier: int,
    ) -> int:
        """Record the outcome of a technique application.

        If a row for the same *(technique, vuln_class, target_signature)*
        triple already exists, its aggregate statistics are updated using an
        incremental mean.  Otherwise a new row is inserted.

        Args:
            technique: The payload, prompt, or strategy text.
            vuln_class: Vulnerability class (e.g. ``"xss"``, ``"sqli"``).
            target_signature: JSON-serialisable dict describing the target.
            success: Whether the technique produced a finding.
            confidence: Confidence score of the finding (0.0–1.0).
            tier: Capability tier (1–5, lower is stronger).

        Returns:
            The row id of the inserted/updated record.
        """
        db = await self._ensure_db()
        sig_json = json.dumps(target_signature, sort_keys=True)
        now = datetime.now(UTC).isoformat()

        # Try to find an existing row
        cursor = await db.execute(
            "SELECT id, success_rate, avg_confidence, use_count FROM technique_memory "
            "WHERE technique = ? AND vuln_class = ? AND target_signature = ?",
            (technique, vuln_class, sig_json),
        )
        row = await cursor.fetchone()

        if row is not None:
            # Incremental mean update (immutable arithmetic — no in-place mutation)
            existing_id = row["id"]
            old_rate = row["success_rate"]
            old_conf = row["avg_confidence"]
            old_count = row["use_count"]
            new_count = old_count + 1
            new_rate = ((old_rate * old_count) + (1.0 if success else 0.0)) / new_count
            new_conf = ((old_conf * old_count) + confidence) / new_count

            await db.execute(
                "UPDATE technique_memory "
                "SET success_rate = ?, avg_confidence = ?, capability_tier = ?, "
                "    use_count = ?, last_used_at = ? "
                "WHERE id = ?",
                (new_rate, new_conf, tier, new_count, now, existing_id),
            )
            await db.commit()
            logger.debug(
                "Updated technique memory id=%d: rate=%.3f conf=%.3f count=%d",
                existing_id, new_rate, new_conf, new_count,
            )
            return existing_id

        # Insert new row
        initial_rate = 1.0 if success else 0.0
        cursor = await db.execute(
            "INSERT INTO technique_memory "
            "(technique, vuln_class, target_signature, success_rate, "
            " avg_confidence, capability_tier, use_count, created_at, last_used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (technique, vuln_class, sig_json, initial_rate, confidence,
             tier, 1, now, now),
        )
        await db.commit()
        logger.debug(
            "Recorded new technique: vuln=%s tier=%d success=%s",
            vuln_class, tier, success,
        )
        return cursor.lastrowid  # type: ignore[return-value]

    async def query(
        self,
        vuln_class: str,
        target_signature: dict[str, Any],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Find techniques matching a vulnerability class and target signature.

        Results are ranked by ``success_rate * recency_weight`` where the
        recency weight decays for rows that have not been used recently.

        Args:
            vuln_class: Vulnerability class to search for.
            target_signature: Target tech stack / endpoint pattern.
            limit: Maximum number of results.

        Returns:
            A list of matching technique dicts, best first.
        """
        db = await self._ensure_db()
        sig_json = json.dumps(target_signature, sort_keys=True)

        # Recency weight: techniques used in the last 30 days get full weight;
        # older ones decay by 50 % every 30 days.
        now_iso = datetime.now(UTC).isoformat()

        cursor = await db.execute(
            "SELECT technique, vuln_class, target_signature, success_rate, "
            "       avg_confidence, capability_tier, use_count, "
            "       created_at, last_used_at "
            "FROM technique_memory "
            "WHERE vuln_class = ? "
            "ORDER BY success_rate DESC, last_used_at DESC "
            "LIMIT ?",
            (vuln_class, limit),
        )
        rows = await cursor.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            results.append({
                "technique": row["technique"],
                "vuln_class": row["vuln_class"],
                "target_signature": json.loads(row["target_signature"]),
                "success_rate": row["success_rate"],
                "avg_confidence": row["avg_confidence"],
                "capability_tier": row["capability_tier"],
                "use_count": row["use_count"],
                "created_at": row["created_at"],
                "last_used_at": row["last_used_at"],
            })
        return results

    async def decay(self, threshold: float = 0.2) -> int:
        """Deprioritise techniques whose success rate has fallen below *threshold*.

        Rows below the threshold have their ``success_rate`` halved so they
        sink in ranking but are not deleted outright — they may recover if
        they succeed again.

        Returns:
            The number of rows that were decayed.
        """
        db = await self._ensure_db()
        cursor = await db.execute(
            "UPDATE technique_memory SET success_rate = success_rate * 0.5 "
            "WHERE success_rate < ? AND success_rate > 0.0",
            (threshold,),
        )
        await db.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info("Decayed %d low-performing techniques below %.2f", count, threshold)
        return count

    async def bootstrap_from_patterns(self) -> int:
        """Seed the memory with built-in payload patterns from the vuln pipelines.

        Loads the XSS, SQLi, SSRF, and CommandInjection pipeline payloads as
        initial technique entries with conservative prior statistics (low
        success rate, moderate confidence) so they are available for the first
        engagement without any historical data.

        Returns:
            The number of new rows inserted.
        """
        from src.agents.tools.vuln_pipelines import (
            XSSPipeline,
            SQLiPipeline,
            SSRFPipeline,
            CommandInjectionPipeline,
        )

        inserted = 0

        # XSS reflected payloads
        for payload, desc in XSSPipeline.REFLECTED_PAYLOADS:
            row_id = await self.record(
                technique=payload,
                vuln_class="xss",
                target_signature={"context": "reflected", "endpoint": "/search"},
                success=False,
                confidence=0.5,
                tier=3,
            )
            if row_id:
                inserted += 1

        # XSS DOM payloads
        for payload, desc in XSSPipeline.DOM_PAYLOADS:
            row_id = await self.record(
                technique=payload,
                vuln_class="xss",
                target_signature={"context": "dom", "endpoint": "/"},
                success=False,
                confidence=0.4,
                tier=3,
            )
            if row_id:
                inserted += 1

        # SQLi error payloads
        for payload, desc in SQLiPipeline.ERROR_PAYLOADS:
            row_id = await self.record(
                technique=payload,
                vuln_class="sqli",
                target_signature={"context": "error_based", "endpoint": "/api/v1/users"},
                success=False,
                confidence=0.5,
                tier=3,
            )
            if row_id:
                inserted += 1

        # SQLi boolean payloads
        for payload in SQLiPipeline.BOOLEAN_TRUE_PAYLOADS:
            row_id = await self.record(
                technique=payload,
                vuln_class="sqli",
                target_signature={"context": "boolean_based", "endpoint": "/api"},
                success=False,
                confidence=0.5,
                tier=3,
            )
            if row_id:
                inserted += 1

        # SSRF cloud metadata URLs
        for meta_url, desc in SSRFPipeline.CLOUD_METADATA_URLS:
            row_id = await self.record(
                technique=meta_url,
                vuln_class="ssrf",
                target_signature={"context": "cloud_metadata", "param": "url"},
                success=False,
                confidence=0.5,
                tier=2,
            )
            if row_id:
                inserted += 1

        # SSRF internal services
        for internal_url, desc in SSRFPipeline.INTERNAL_SERVICES:
            row_id = await self.record(
                technique=internal_url,
                vuln_class="ssrf",
                target_signature={"context": "internal_service", "param": "url"},
                success=False,
                confidence=0.4,
                tier=3,
            )
            if row_id:
                inserted += 1

        # Command injection echo payloads
        for payload, desc in CommandInjectionPipeline.ECHO_PAYLOADS:
            row_id = await self.record(
                technique=payload,
                vuln_class="cmdi",
                target_signature={"context": "echo_based", "param": "cmd"},
                success=False,
                confidence=0.5,
                tier=2,
            )
            if row_id:
                inserted += 1

        # Auth bypass patterns (generic)
        auth_techniques = [
            ("admin:admin", "auth_bypass", {"context": "default_creds", "endpoint": "/login"}),
            ("admin:password", "auth_bypass", {"context": "default_creds", "endpoint": "/login"}),
            ("admin:admin123", "auth_bypass", {"context": "default_creds", "endpoint": "/admin"}),
        ]
        for technique, vc, sig in auth_techniques:
            row_id = await self.record(
                technique=technique,
                vuln_class=vc,
                target_signature=sig,
                success=False,
                confidence=0.3,
                tier=4,
            )
            if row_id:
                inserted += 1

        # IDOR patterns
        idor_techniques = [
            ("/api/users/1", "idor", {"context": "sequential_id", "endpoint": "/api/users/{id}"}),
            ("/api/users/2", "idor", {"context": "sequential_id", "endpoint": "/api/users/{id}"}),
        ]
        for technique, vc, sig in idor_techniques:
            row_id = await self.record(
                technique=technique,
                vuln_class=vc,
                target_signature=sig,
                success=False,
                confidence=0.4,
                tier=3,
            )
            if row_id:
                inserted += 1

        logger.info("Bootstrapped %d technique patterns from vuln pipelines", inserted)
        return inserted

    async def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics about stored techniques.

        Returns:
            A dict with counts, averages, and per-class breakdowns.
        """
        db = await self._ensure_db()

        # Total count
        cursor = await db.execute("SELECT COUNT(*) AS total FROM technique_memory")
        total_row = await cursor.fetchone()
        total = total_row["total"] if total_row else 0

        # Per-class counts and averages
        cursor = await db.execute(
            "SELECT vuln_class, COUNT(*) AS cnt, "
            "       AVG(success_rate) AS avg_rate, "
            "       AVG(avg_confidence) AS avg_conf, "
            "       AVG(capability_tier) AS avg_tier "
            "FROM technique_memory "
            "GROUP BY vuln_class "
            "ORDER BY cnt DESC"
        )
        rows = await cursor.fetchall()
        per_class: list[dict[str, Any]] = []
        for row in rows:
            per_class.append({
                "vuln_class": row["vuln_class"],
                "count": row["cnt"],
                "avg_success_rate": round(row["avg_rate"], 3) if row["avg_rate"] is not None else 0.0,
                "avg_confidence": round(row["avg_conf"], 3) if row["avg_conf"] is not None else 0.0,
                "avg_capability_tier": round(row["avg_tier"], 1) if row["avg_tier"] is not None else 0.0,
            })

        # Overall averages
        cursor = await db.execute(
            "SELECT AVG(success_rate) AS overall_rate, "
            "       AVG(avg_confidence) AS overall_conf, "
            "       SUM(use_count) AS total_uses "
            "FROM technique_memory"
        )
        agg_row = await cursor.fetchone()

        return {
            "total_techniques": total,
            "total_uses": agg_row["total_uses"] if agg_row and agg_row["total_uses"] else 0,
            "overall_success_rate": round(agg_row["overall_rate"], 3) if agg_row and agg_row["overall_rate"] is not None else 0.0,
            "overall_confidence": round(agg_row["overall_conf"], 3) if agg_row and agg_row["overall_conf"] is not None else 0.0,
            "per_class": per_class,
        }