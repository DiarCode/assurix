"""Unit tests for the adversarial verifier triad (plan §3.2.3, §5.2).

Coverage:
  1. VerifierVote.is_positive / meets_threshold semantics per role.
  2. TriadOrchestrator._tally consensus rule (all-yes, any-no, threshold miss).
  3. Reproducer: generic replay with payload echo, no-payload, 5xx.
  4. Reproducer: timeout -> not_reproduce, low confidence.
  5. Reproducer: hook-based class-specific verification.
  6. Adversary: validated=True -> not_break, validated=False -> break.
  7. Adversary: LLM error -> not_break with low confidence (safe fallback).
  8. Validator: scope reject when host not allowed.
  9. Validator: dedup catch on near-duplicate title.
  10. Validator: chainable when capability token present.
  11. Validator: not chainable when no hub token matched.
  12. TriadOrchestrator.run: integrates all three via asyncio.gather.
  13. TriadOrchestrator.run: final_validated=False when ANY verifier fails.
  14. TriadOrchestrator.run: final_validated=True only when ALL three pass.
  15. ScopePolicy.is_in_scope default allow-all.
  16. ScopePolicy.is_in_scope respects patterns.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agents.verification import (
    Adversary,
    Reproducer,
    TriadOrchestrator,
    TriadResult,
    Validator,
    VerifierRole,
    VerifierVote,
)
from src.agents.verification.triad import (
    ADVERSARY_MIN_CONFIDENCE,
    REPRODUCER_MIN_CONFIDENCE,
    ScopePolicy,
    VALIDATOR_MIN_CONFIDENCE,
)


# --- VerifierVote mechanics --------------------------------------------

class TestVerifierVote:
    def test_reproducer_positive_only_when_reproduce(self) -> None:
        v = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        assert v.is_positive is True
        assert v.meets_threshold() is True

        v2 = VerifierVote(role=VerifierRole.REPRODUCER, verdict="not_reproduce", confidence=0.9)
        assert v2.is_positive is False
        # meets_threshold ignores verdict — the consensus rule requires BOTH.
        assert v2.meets_threshold() is True

    def test_adversary_positive_only_when_not_break(self) -> None:
        ok = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.7)
        assert ok.is_positive is True
        bad = VerifierVote(role=VerifierRole.ADVERSARY, verdict="break", confidence=0.7)
        assert bad.is_positive is False

    def test_validator_positive_for_accept_or_chainable(self) -> None:
        for verdict in ("accept", "chainable"):
            v = VerifierVote(role=VerifierRole.VALIDATOR, verdict=verdict, confidence=0.7)
            assert v.is_positive is True
        rej = VerifierVote(role=VerifierRole.VALIDATOR, verdict="reject", confidence=0.7)
        assert rej.is_positive is False

    def test_threshold_floors_are_per_role(self) -> None:
        # Reproducer threshold is 0.5
        v = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.4)
        assert v.is_positive is True
        assert v.meets_threshold() is False

        v = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.5)
        assert v.meets_threshold() is True

        # Validator threshold is 0.5
        v = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.4)
        assert v.meets_threshold() is False


# --- TriadOrchestrator._tally ------------------------------------------

class TestTriadTally:
    def test_all_positive_above_threshold_validates(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.8)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.7)
        ok, reason = TriadOrchestrator._tally(repro, adv, val)
        assert ok is True
        assert "All three" in reason

    def test_reproducer_failure_blocks(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="not_reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.8)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.7)
        ok, reason = TriadOrchestrator._tally(repro, adv, val)
        assert ok is False
        assert "Reproducer" in reason

    def test_adversary_break_blocks(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.7)
        ok, _ = TriadOrchestrator._tally(repro, adv, val)
        assert ok is False

    def test_threshold_miss_blocks(self) -> None:
        # Reproducer below its threshold (0.5)
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.3)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.9)
        ok, reason = TriadOrchestrator._tally(repro, adv, val)
        assert ok is False
        assert "Reproducer confidence" in reason

    def test_chainable_counts_as_validator_positive(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="chainable", confidence=0.7)
        ok, _ = TriadOrchestrator._tally(repro, adv, val)
        assert ok is True


# --- ScopePolicy -------------------------------------------------------

class TestScopePolicy:
    def test_default_allow_all(self) -> None:
        s = ScopePolicy()
        assert s.is_in_scope("https://anything.example/path")
        assert s.is_in_scope("https://other.example/")

    def test_pattern_match(self) -> None:
        s = ScopePolicy(allowed_host_patterns=("acme.example",))
        assert s.is_in_scope("https://acme.example/admin")
        assert not s.is_in_scope("https://other.example/admin")

    def test_excluded_paths(self) -> None:
        s = ScopePolicy(excluded_paths=("/logout",))
        # is_in_scope just checks host; exclusion is in the validator.
        assert s.is_in_scope("https://acme.example/logout")


# --- Reproducer -------------------------------------------------------

class TestReproducer:
    def test_no_payload_yields_not_reproduce(self) -> None:
        r = Reproducer()
        vote = asyncio.run(r.vote({"title": "x"}, target="https://t.example/"))
        assert vote.role is VerifierRole.REPRODUCER
        assert vote.verdict == "not_reproduce"
        assert vote.confidence == 0.0

    def test_no_url_yields_not_reproduce(self) -> None:
        r = Reproducer()
        vote = asyncio.run(r.vote({"payload": "x"}, target=""))
        assert vote.verdict == "not_reproduce"

    def test_generic_replay_echoes_payload(self) -> None:
        """When the response echoes the payload in a 200, reproduce."""
        from unittest.mock import patch

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "echoed: <test>"

        r = Reproducer()
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            vote = asyncio.run(r.vote(
                {"payload": "<test>", "url": "https://t.example/"},
                target="https://t.example/",
            ))
        assert vote.verdict == "reproduce"
        assert vote.confidence == 0.6
        assert vote.evidence_hash is not None

    def test_5xx_response_blocks_reproduce(self) -> None:
        from unittest.mock import patch

        mock_response = MagicMock()
        mock_response.status_code = 503

        r = Reproducer()
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            vote = asyncio.run(r.vote(
                {"payload": "x", "url": "https://t.example/"},
                target="https://t.example/",
            ))
        assert vote.verdict == "not_reproduce"
        assert "server error" in vote.reasoning

    def test_http_error_blocks_with_low_confidence(self) -> None:
        from unittest.mock import patch
        import httpx

        r = Reproducer()
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(side_effect=httpx.ConnectError("nope"))
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            vote = asyncio.run(r.vote(
                {"payload": "x", "url": "https://t.example/"},
                target="https://t.example/",
            ))
        assert vote.verdict == "not_reproduce"
        assert vote.confidence <= 0.2

    def test_class_specific_hook_runs(self) -> None:
        """When a hook is registered for the finding class, it runs."""
        async def my_hook(finding, target, client) -> dict[str, Any]:
            return {"reproduced": True, "evidence": "hook ok", "confidence": 0.95}

        r = Reproducer(hooks={"ssrf": my_hook})
        vote = asyncio.run(r.vote(
            {"class": "ssrf", "url": "https://t.example/"},
            target="https://t.example/",
        ))
        assert vote.verdict == "reproduce"
        assert vote.confidence == 0.95
        assert "hook ok" in vote.reasoning


# --- Adversary ---------------------------------------------------------

class TestAdversary:
    def test_validated_translates_to_not_break(self) -> None:
        mock_validator = MagicMock()
        mock_validator.validate_finding = AsyncMock(return_value={
            "validated": True,
            "confidence_score": 0.85,
            "validation_reasoning": "premise holds",
        })
        a = Adversary(llm_validator=mock_validator)
        vote = asyncio.run(a.vote({"title": "x"}, target="https://t.example/"))
        assert vote.role is VerifierRole.ADVERSARY
        assert vote.verdict == "not_break"
        assert vote.confidence == 0.85
        assert "premise holds" in vote.reasoning

    def test_falsified_translates_to_break(self) -> None:
        mock_validator = MagicMock()
        mock_validator.validate_finding = AsyncMock(return_value={
            "validated": False,
            "confidence_score": 0.7,
            "validation_reasoning": "WAF blocks",
        })
        a = Adversary(llm_validator=mock_validator)
        vote = asyncio.run(a.vote({"title": "x"}, target="https://t.example/"))
        assert vote.verdict == "break"
        assert "WAF blocks" in vote.reasoning

    def test_validator_error_falls_back_to_not_break(self) -> None:
        """When the LLM is unavailable, don't block the finding (per plan §5.2)."""
        mock_validator = MagicMock()
        mock_validator.validate_finding = AsyncMock(side_effect=RuntimeError("LLM down"))
        a = Adversary(llm_validator=mock_validator)
        vote = asyncio.run(a.vote({"title": "x"}, target="https://t.example/"))
        assert vote.verdict == "not_break"
        assert vote.confidence == 0.3
        assert "fallback" in vote.reasoning


# --- Validator ---------------------------------------------------------

class TestValidator:
    def test_scope_reject(self) -> None:
        s = ScopePolicy(allowed_host_patterns=("acme.example",))
        v = Validator(scope=s)
        vote = asyncio.run(v.vote(
            {"title": "x", "url": "https://other.example/"},
            scope=s,
        ))
        assert vote.verdict == "reject"
        assert "not in scope" in vote.reasoning

    def test_excluded_path_rejects(self) -> None:
        s = ScopePolicy(allowed_host_patterns=("acme.example",), excluded_paths=("/logout",))
        v = Validator(scope=s)
        vote = asyncio.run(v.vote(
            {"title": "x", "url": "https://acme.example/logout"},
            scope=s,
        ))
        assert vote.verdict == "reject"

    def test_dedup_catches_near_duplicate(self) -> None:
        finding = {
            "title": "SQL injection in /search?q=",
            "description": "User input is concatenated into the query",
            "url": "https://acme.example/search",
        }
        existing = [
            {
                "title": "SQL injection in /search?q=",
                "description": "User input is concatenated into the query",
                "url": "https://acme.example/search",
            }
        ]
        v = Validator()
        vote = asyncio.run(v.vote(finding, existing=existing))
        assert vote.verdict == "reject"
        assert "near-dup" in vote.reasoning

    def test_chainable_when_capability_grant_present(self) -> None:
        finding = {
            "title": "SSRF in image proxy",
            "description": "img_url is fetched without validation",
            "url": "https://acme.example/proxy",
            "capabilities": ["cloud_meta_access"],
        }
        v = Validator()
        vote = asyncio.run(v.vote(finding, existing=[]))
        assert vote.verdict == "chainable"
        assert "grants capability" in vote.reasoning

    def test_chainable_when_hub_word_in_title(self) -> None:
        finding = {
            "title": "Reflected XSS in search",
            "description": "user input echoed",
            "url": "https://acme.example/search",
        }
        v = Validator()
        vote = asyncio.run(v.vote(finding, existing=[]))
        assert vote.verdict == "chainable"
        assert "xss" in vote.reasoning.lower()

    def test_accepts_when_no_chain_signal(self) -> None:
        finding = {
            "title": "Missing security header X-Frame-Options",
            "description": "The X-Frame-Options header is absent",
            "url": "https://acme.example/",
        }
        v = Validator()
        vote = asyncio.run(v.vote(finding, existing=[]))
        assert vote.verdict == "accept"
        assert vote.confidence == 0.6


# --- TriadOrchestrator.run integration ---------------------------------

class TestTriadOrchestratorRun:
    def _make_orchestrator_with_mock_votes(
        self,
        repro: VerifierVote,
        adv: VerifierVote,
        val: VerifierVote,
    ) -> TriadOrchestrator:
        triad = TriadOrchestrator()
        # Patch the lazily-constructed verifier instances.
        triad._reproducer = MagicMock()
        triad._reproducer.vote = AsyncMock(return_value=repro)
        triad._adversary = MagicMock()
        triad._adversary.vote = AsyncMock(return_value=adv)
        triad._validator = MagicMock()
        triad._validator.vote = AsyncMock(return_value=val)
        return triad

    def test_all_pass_validates(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.9)
        triad = self._make_orchestrator_with_mock_votes(repro, adv, val)
        result = asyncio.run(triad.run({"title": "x"}, target="https://t.example/"))
        assert result.final_validated is True
        assert "All three" in result.reason
        assert isinstance(result, TriadResult)

    def test_reproducer_failure_blocks(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="not_reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.9)
        triad = self._make_orchestrator_with_mock_votes(repro, adv, val)
        result = asyncio.run(triad.run({"title": "x"}, target="https://t.example/"))
        assert result.final_validated is False
        assert "Reproducer" in result.reason

    def test_adversary_break_blocks(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="accept", confidence=0.9)
        triad = self._make_orchestrator_with_mock_votes(repro, adv, val)
        result = asyncio.run(triad.run({"title": "x"}, target="https://t.example/"))
        assert result.final_validated is False
        assert "Adversary" in result.reason

    def test_validator_reject_blocks(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="reject", confidence=0.9)
        triad = self._make_orchestrator_with_mock_votes(repro, adv, val)
        result = asyncio.run(triad.run({"title": "x"}, target="https://t.example/"))
        assert result.final_validated is False
        assert "Validator" in result.reason

    def test_result_to_dict_round_trip(self) -> None:
        repro = VerifierVote(role=VerifierRole.REPRODUCER, verdict="reproduce", confidence=0.9)
        adv = VerifierVote(role=VerifierRole.ADVERSARY, verdict="not_break", confidence=0.9)
        val = VerifierVote(role=VerifierRole.VALIDATOR, verdict="chainable", confidence=0.9)
        triad = self._make_orchestrator_with_mock_votes(repro, adv, val)
        result = asyncio.run(triad.run({"title": "x"}, target="https://t.example/"))
        d = result.to_dict()
        assert d["final_validated"] is True
        assert d["reproducer"]["verdict"] == "reproduce"
        assert d["adversary"]["verdict"] == "not_break"
        assert d["validator"]["verdict"] == "chainable"
        # run_ids are unique
        ids = {d["reproducer"]["run_id"], d["adversary"]["run_id"], d["validator"]["run_id"]}
        assert len(ids) == 3
