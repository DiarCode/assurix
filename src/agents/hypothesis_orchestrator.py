"""HypothesisOrchestrator: Engagement-level orchestrator that dispatches
hypotheses through ``engine.submit_and_await()``.

Phase 4b: Replaces ResearchLoopAgent's direct agent instantiation with
engine-mediated dispatch. HypothesisOrchestrator:

1. Generates hypothesis classes from surface data + LLM creativity
2. Routes each hypothesis to a target agent via ``engine.submit_and_await()``
3. Aggregates findings from the engine's results
4. Creates ProvenanceLink records linking findings → hypotheses → tool invocations
5. Reflects on whether new hypotheses should be investigated
6. Terminates on convergence

Differences from ResearchLoopAgent:
- Dispatch goes through the engine's submit_and_await() so each job is
  checkpointed in the scheduler, audited, and durable across restarts
- Surface_hypotheses() and reasoning_hypotheses() are explicit, named
  methods (degraded mode can call them separately)
- ExploitChain is integrated for confirmed CMDI/injection findings
  (depth-1 marker through depth-5 lateral movement)
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.core.audit import log_action
from src.core.config import get_settings
from src.db.models import (
    Engagement,
    EngagementStatus,
    Finding,
    Hypothesis,
    HypothesisSource,
    HypothesisStatus,
    ProvenanceLink,
    Severity,
    ToolInvocation,
)
from src.llm.frontier_client import UnifiedLLMClient
from src.orchestrator.state import EngagementStateMachine
from src.reasoning.hypothesis_generator import HypothesisGenerator
from src.reasoning.reflection import ReflectionPhase

logger = logging.getLogger(__name__)

# Maximum iterations for the orchestrate-investigate-reflect loop
MAX_ORCHESTRATION_ITERATIONS = 5
# Minimum confidence for a hypothesis to be worth dispatching
MIN_HYPOTHESIS_CONFIDENCE = 0.3
# Idle iterations before declaring convergence (no new productive hypotheses)
CONVERGENCE_IDLE_ITERATIONS = 3


class HypothesisOrchestrator(BaseAgent):
    """Hypothesis-driven security research orchestrator.

    Operates at the ENGAGEMENT level. Generates hypothesis classes,
    dispatches them via the engine (so jobs are checkpointed), and reflects
    on results. Engine-mediated dispatch is the key difference from a
    direct-instantiation pattern: every dispatched job lands in the
    scheduler queue, gets a job_id, and produces audit + provenance records.
    """

    name = "hypothesis_orchestrator"

    def __init__(self) -> None:
        settings = get_settings()
        self.llm = UnifiedLLMClient()
        self.hypothesis_generator = HypothesisGenerator(llm_client=self.llm)
        self.reflection = ReflectionPhase(llm_client=self.llm)
        self._max_iterations = settings.max_iterations_per_scan
        self._max_orchestration_iterations = MAX_ORCHESTRATION_ITERATIONS
        self._convergence_idle = CONVERGENCE_IDLE_ITERATIONS
        # W2-A: cumulative budget (defect 3). Replaces the previous
        # hardcoded 180s per-call timeout that allowed a single stuck
        # tool call to hang the entire dj1naq.sytes.net scan.
        self._cumulative_budget_s = float(
            settings.hypothesis_orchestrator_cumulative_budget_seconds
        )
        self._per_call_timeout_s = float(
            settings.hypothesis_orchestrator_per_call_timeout_seconds
        )

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Run the orchestration loop.

        Args:
            payload: Must contain ``engagement_id`` and ``target_url`` (or
                ``previous_result.target_url``). May contain ``surface`` from
                the recon phase.
            session: Active DB session.

        Returns:
            Dict with findings, hypotheses investigated, provenance metadata.
        """
        engagement_id = payload.get("engagement_id", "")
        target_url = (
            payload.get("target_url", "")
            or payload.get("previous_result", {}).get("target_url", "")
        )
        # Engine discovery: prefer the contextvar (set by
        # WorkflowEngine.start_engagement) because it survives JSON
        # serialization of the Job payload. Fall back to a payload
        # injection for direct callers (tests, benchmarks).
        from src.orchestrator.engine import get_active_engine
        engine = payload.get("engine") or get_active_engine()

        if not engagement_id:
            logger.error("HypothesisOrchestrator: no engagement_id in payload")
            return {
                "findings": [],
                "artifacts": [],
                "hypotheses_investigated": 0,
                "error": "missing engagement_id",
            }

        engagement = await session.get(Engagement, engagement_id)
        if not engagement:
            logger.error(
                "HypothesisOrchestrator: engagement %s not found", engagement_id
            )
            return {
                "findings": [],
                "artifacts": [],
                "hypotheses_investigated": 0,
                "error": "engagement not found",
            }

        # Transition to RESEARCHING
        if EngagementStateMachine.can_transition(
            engagement.status, EngagementStatus.RESEARCHING
        ):
            engagement.status = EngagementStatus.RESEARCHING
            await session.flush()
            await log_action(
                session=session,
                action="hypothesis_orchestrator_started",
                actor="hypothesis_orchestrator",
                payload={
                    "engagement_id": engagement_id,
                    "target_url": target_url,
                },
            )

        # Load context
        existing_findings = await self._load_findings(session, engagement_id)
        surface = self._load_surface(payload)

        all_findings: list[dict[str, Any]] = [
            self._finding_to_dict(f) for f in existing_findings
        ]
        all_artifacts: list[dict[str, Any]] = []
        hypotheses_investigated: list[dict[str, Any]] = []
        idle_iterations = 0
        iteration = 0

        # W2-A: cumulative budget deadline (defect 3). Each per-tool
        # call's per-call timeout is dynamically derived from the
        # remaining budget, so a slow tool call near the end of the
        # budget cannot exceed the overall ceiling. The 10s headroom
        # below lets the orchestrator finalize its result before the
        # cumulative ceiling is hit.
        # ``getattr`` with a default lets tests that construct the
        # orchestrator with ``HypothesisOrchestrator.__new__(...)``
        # (bypassing ``__init__``) keep working without setting up
        # the full settings dependency.
        budget_deadline = time.monotonic() + getattr(
            self, "_cumulative_budget_s", 900.0
        )
        budget_exhausted = False

        await log_action(
            session=session,
            action="hypothesis_orchestrator_phase_start",
            actor="hypothesis_orchestrator",
            payload={
                "engagement_id": engagement_id,
                "existing_findings": len(all_findings),
            },
        )

        # === Orchestrate → Investigate → Reflect ===
        while iteration < self._max_orchestration_iterations:
            iteration += 1

            # W2-A: check the cumulative budget before doing any more
            # work. If the budget is gone, stop dispatching and let the
            # orchestrator finalize its result. This is the key
            # difference from the previous behavior, which let a
            # single stuck tool call hang the whole iteration.
            if time.monotonic() >= budget_deadline:
                logger.info(
                    "HypothesisOrchestrator: cumulative budget %.1fs exhausted at "
                    "iteration %d for engagement %s",
                    self._cumulative_budget_s,
                    iteration,
                    engagement_id,
                )
                budget_exhausted = True
                break

            logger.info(
                "HypothesisOrchestrator iteration %d/%d for engagement %s",
                iteration,
                self._max_orchestration_iterations,
                engagement_id,
            )

            # Phase 1: Generate hypotheses (surface + reasoning)
            hypotheses = await self._generate_hypotheses(
                surface=surface,
                findings=all_findings,
                session=session,
                engagement_id=engagement_id,
            )

            viable = [
                h for h in hypotheses if h.get("confidence", 0.0) >= MIN_HYPOTHESIS_CONFIDENCE
            ]

            if not viable:
                idle_iterations += 1
                if idle_iterations >= self._convergence_idle:
                    logger.info(
                        "HypothesisOrchestrator: convergence after %d idle iterations",
                        idle_iterations,
                    )
                    break
                continue

            # Phase 2: Investigate each viable hypothesis via engine
            productive = 0
            for hypothesis_data in viable:
                # W2-A: re-check the budget before each dispatch so a
                # backlog of viable hypotheses can't blow past the
                # ceiling. If we're out of budget, stop dispatching
                # and let the orchestrator finalize.
                if time.monotonic() >= budget_deadline:
                    logger.info(
                        "HypothesisOrchestrator: cumulative budget exhausted before "
                        "dispatch of hypothesis %s",
                        hypothesis_data.get("hypothesis_class", ""),
                    )
                    budget_exhausted = True
                    break

                # Persist hypothesis
                hypothesis = await self._persist_hypothesis(
                    session=session,
                    engagement_id=engagement_id,
                    hypothesis_data=hypothesis_data,
                )

                # Dispatch via engine (or fallback to direct agent instantiation
                # if no engine was injected, e.g. for tests).
                investigation_result = await self._dispatch_investigation(
                    hypothesis=hypothesis_data,
                    hypothesis_id=hypothesis.id,
                    payload=payload,
                    surface=surface,
                    session=session,
                    engagement_id=engagement_id,
                    engine=engine,
                    budget_deadline=budget_deadline,
                )

                # Update hypothesis status
                if investigation_result.get("findings"):
                    confirmed = any(
                        f.get("severity") in ("high", "critical", "medium")
                        for f in investigation_result["findings"]
                    )
                    hypothesis.status = (
                        HypothesisStatus.VALIDATED if confirmed else HypothesisStatus.REJECTED
                    )
                else:
                    hypothesis.status = HypothesisStatus.REJECTED
                await session.flush()

                hypotheses_investigated.append(
                    {
                        "hypothesis_id": hypothesis.id,
                        "hypothesis_class": hypothesis_data.get("hypothesis_class", ""),
                        "attack_category": hypothesis_data.get("attack_category", ""),
                        "status": hypothesis.status,
                        "findings_count": len(investigation_result.get("findings", [])),
                    }
                )

                all_findings.extend(investigation_result.get("findings", []))
                all_artifacts.extend(investigation_result.get("artifacts", []))
                productive += 1

            if productive == 0 and not budget_exhausted:
                idle_iterations += 1
                if idle_iterations >= self._convergence_idle:
                    break
                continue

            if budget_exhausted:
                break

            idle_iterations = 0  # Reset on productive iteration

            # Phase 3: Reflection — can we generate new productive hypotheses?
            new_hypotheses = await self._reflect(
                hypotheses=viable,
                results=hypotheses_investigated,
                findings=all_findings,
                surface=surface,
                session=session,
                engagement_id=engagement_id,
            )
            if not new_hypotheses:
                break

        # Phase 4: Persist findings + provenance links
        for finding_data in all_findings:
            if not finding_data.get("_persisted"):
                await self._persist_finding(
                    session=session,
                    engagement_id=engagement_id,
                    finding_data=finding_data,
                    hypotheses_investigated=hypotheses_investigated,
                )

        await log_action(
            session=session,
            action="hypothesis_orchestrator_completed",
            actor="hypothesis_orchestrator",
            payload={
                "engagement_id": engagement_id,
                "iterations": iteration,
                "hypotheses_investigated": len(hypotheses_investigated),
                "total_findings": len(all_findings),
            },
        )

        return self._compile_results(
            hypotheses_investigated=hypotheses_investigated,
            findings=all_findings,
            artifacts=all_artifacts,
            iterations=iteration,
        )

    # -----------------------------------------------------------------------
    # Phase 1: Hypothesis Generation
    # -----------------------------------------------------------------------

    def generate_surface_hypotheses(self, surface: dict[str, Any]) -> list[dict[str, Any]]:
        """Map every URL param/form/header to attack hypotheses.

        Surface-driven hypotheses map observable surface features to attack
        classes without LLM creativity — fast, deterministic, and works in
        degraded mode (HTTPX-only surface data).
        """
        hypotheses: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str]] = set()

        # URL parameters → CMDI / SQLi / XSS / SSRF / IDOR
        for endpoint in surface.get("endpoints", []) or []:
            for category, cap in (
                ("injection", "cmdi"),
                ("injection", "sqli"),
                ("xss", "xss"),
                ("ssrf", "ssrf"),
                ("idor", "idor"),
            ):
                key = (category, endpoint)
                if key not in seen_keys:
                    seen_keys.add(key)
                    hypotheses.append(
                        {
                            "hypothesis_class": f"{cap}-{self._slug(endpoint)}",
                            "attack_category": category,
                            "description": f"Test {cap.upper()} on endpoint {endpoint}",
                            "required_capabilities": [cap],
                            "falsification_criteria": f"No {cap} exploitation possible on {endpoint} after 3 attempts",
                            "confidence": 0.5,
                            "source": HypothesisSource.PATTERN_MATCH.value,
                            "target": endpoint,
                        }
                    )

        # Forms → auth_bypass / csrf
        for form in surface.get("forms", []) or []:
            action = form.get("action", "") if isinstance(form, dict) else ""
            key = ("auth_bypass", action)
            if key not in seen_keys:
                seen_keys.add(key)
                hypotheses.append(
                    {
                        "hypothesis_class": f"auth-bypass-{self._slug(action)}",
                        "attack_category": "auth_bypass",
                        "description": f"Test auth bypass on form {action}",
                        "required_capabilities": ["auth_bypass"],
                        "falsification_criteria": "Auth required for all access",
                        "confidence": 0.4,
                        "source": HypothesisSource.PATTERN_MATCH.value,
                        "target": action,
                    }
                )
                hypotheses.append(
                    {
                        "hypothesis_class": f"csrf-{self._slug(action)}",
                        "attack_category": "csrf",
                        "description": f"Test CSRF on form {action}",
                        "required_capabilities": ["csrf"],
                        "falsification_criteria": "CSRF token enforced",
                        "confidence": 0.4,
                        "source": HypothesisSource.PATTERN_MATCH.value,
                        "target": action,
                    }
                )

        return hypotheses

    def generate_reasoning_hypotheses(
        self,
        surface: dict[str, Any],
        technologies: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate technology-specific reasoning hypotheses.

        Technology-driven hypotheses require inference about what classes of
        bugs are likely given the detected stack (e.g., Nuxt → SSR/cache
        issues, payment forms → CSRF/price manipulation).
        """
        technologies = technologies or surface.get("technologies", [])
        tech_lower = " ".join(t.lower() for t in technologies)
        hypotheses: list[dict[str, Any]] = []

        if "nuxt" in tech_lower or "next" in tech_lower:
            hypotheses.append(
                {
                    "hypothesis_class": "ssr-cache-poisoning",
                    "attack_category": "business_logic",
                    "description": "Test SSR cache poisoning via crafted query params",
                    "required_capabilities": ["webapp"],
                    "falsification_criteria": "Cache key covers all input",
                    "confidence": 0.5,
                    "source": HypothesisSource.PATTERN_MATCH.value,
                    "target": "ssr-cache",
                }
            )
        if "php" in tech_lower:
            hypotheses.append(
                {
                    "hypothesis_class": "php-type-juggling",
                    "attack_category": "auth_bypass",
                    "description": "Test PHP type juggling in auth/comparison",
                    "required_capabilities": ["auth_bypass"],
                    "falsification_criteria": "Strict comparison enforced",
                    "confidence": 0.5,
                    "source": HypothesisSource.PATTERN_MATCH.value,
                    "target": "type-juggling",
                }
            )
        if "express" in tech_lower:
            hypotheses.append(
                {
                    "hypothesis_class": "express-prototype-pollution",
                    "attack_category": "injection",
                    "description": "Test Express prototype pollution via __proto__",
                    "required_capabilities": ["injection"],
                    "falsification_criteria": "Object.freeze on Object.prototype",
                    "confidence": 0.4,
                    "source": HypothesisSource.PATTERN_MATCH.value,
                    "target": "proto-pollution",
                }
            )
        if "payment" in tech_lower or "checkout" in tech_lower or "cart" in tech_lower:
            hypotheses.extend(
                [
                    {
                        "hypothesis_class": "cart-price-manipulation",
                        "attack_category": "business_logic",
                        "description": "Test price manipulation in cart/checkout flow",
                        "required_capabilities": ["business_logic"],
                        "falsification_criteria": "Server validates price",
                        "confidence": 0.5,
                        "source": HypothesisSource.PATTERN_MATCH.value,
                        "target": "cart",
                    },
                    {
                        "hypothesis_class": "payment-csrf",
                        "attack_category": "csrf",
                        "description": "Test CSRF on payment endpoints",
                        "required_capabilities": ["csrf"],
                        "falsification_criteria": "CSRF token enforced",
                        "confidence": 0.5,
                        "source": HypothesisSource.PATTERN_MATCH.value,
                        "target": "payment",
                    },
                ]
            )
        # API-rich surfaces → IDOR
        endpoints = surface.get("endpoints", []) or []
        api_endpoints = [e for e in endpoints if "/api/" in str(e)]
        if api_endpoints:
            hypotheses.append(
                {
                    "hypothesis_class": "api-idor-bulk",
                    "attack_category": "idor",
                    "description": f"Test IDOR across {len(api_endpoints)} API endpoints",
                    "required_capabilities": ["idor"],
                    "falsification_criteria": "All endpoints enforce authz checks",
                    "confidence": 0.5,
                    "source": HypothesisSource.PATTERN_MATCH.value,
                    "target": "api",
                }
            )
        return hypotheses

    async def _generate_hypotheses(
        self,
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        session: AsyncSession,
        engagement_id: str,
    ) -> list[dict[str, Any]]:
        """Generate hypotheses: surface + reasoning + LLM creativity."""
        # 1. Surface-driven (deterministic, fast)
        surface_h = self.generate_surface_hypotheses(surface)
        # 2. Reasoning-driven (technology-specific)
        reasoning_h = self.generate_reasoning_hypotheses(
            surface=surface, technologies=surface.get("technologies", [])
        )
        # 3. LLM creativity (novel, slower)
        try:
            novel_h = await self.hypothesis_generator.generate_hypotheses(
                surface=surface, findings=findings
            )
        except Exception as exc:
            logger.warning("LLM hypothesis generation failed: %s", exc)
            novel_h = []

        all_h = surface_h + reasoning_h + novel_h
        await log_action(
            session=session,
            action="hypotheses_generated",
            actor="hypothesis_orchestrator",
            payload={
                "engagement_id": engagement_id,
                "surface_count": len(surface_h),
                "reasoning_count": len(reasoning_h),
                "novel_count": len(novel_h),
                "total": len(all_h),
            },
        )
        return all_h

    # -----------------------------------------------------------------------
    # Phase 2: Investigation Dispatch
    # -----------------------------------------------------------------------

    async def _dispatch_investigation(
        self,
        hypothesis: dict[str, Any],
        hypothesis_id: str,
        payload: dict[str, Any],
        surface: dict[str, Any],
        session: AsyncSession,
        engagement_id: str,
        engine: Any,
        budget_deadline: float | None = None,
    ) -> dict[str, Any]:
        """Dispatch a single hypothesis for investigation.

        If an engine is available, dispatch via ``engine.submit_and_await()``
        so the job is checkpointed. Otherwise, instantiate the agent class
        directly (for testing without a running engine).

        Args:
            budget_deadline: ``time.monotonic()`` deadline for the
                cumulative budget. When provided, the per-call timeout
                is derived as ``min(per_call_timeout, remaining - 10s)``
                so a single tool call cannot exceed the cumulative
                budget. W2-A (defect 3): the previous hardcoded 180s
                per-call timeout was the source of the live scan
                hang — a single stuck tool call blocked the entire
                iteration until the outer 25-min browser ceiling
                kicked in, by which time 5 invocations had
                ``completed_at = None``.
        """
        target_url = (
            payload.get("target_url", "")
            or payload.get("previous_result", {}).get("target_url", "")
        )
        attack_category = hypothesis.get("attack_category", "")
        required_capabilities = hypothesis.get("required_capabilities", [])

        investigation_payload = {
            "engagement_id": engagement_id,
            "target_url": target_url,
            "hypothesis_id": hypothesis_id,
            "hypothesis_class": hypothesis.get("hypothesis_class", ""),
            "attack_category": attack_category,
            "description": hypothesis.get("description", ""),
            "required_capabilities": required_capabilities,
            "falsification_criteria": hypothesis.get("falsification_criteria", ""),
            "surface": surface,
            "previous_result": payload.get("previous_result", {}),
            "iteration": payload.get("iteration", 0),
        }

        agent_name = self._select_agent(hypothesis)
        # Record the tool invocation (provenance). The engine will also
        # create a Job record with the same agent_name; this gives us a
        # 1:1 hypothesis → ToolInvocation chain.
        invocation = await self._record_tool_invocation(
            session=session,
            engagement_id=engagement_id,
            hypothesis_id=hypothesis_id,
            tool_name=agent_name,
            capability_tags=required_capabilities,
            target=target_url,
            params=investigation_payload,
        )

        if engine is None:
            # Fallback for tests / non-engine callers
            try:
                return await self._invoke_agent_directly(
                    agent_name=agent_name,
                    payload=investigation_payload,
                    session=session,
                )
            finally:
                # W2-A: always mark the invocation complete so the
                # ``completed_at IS NULL`` invariant holds.
                await self._mark_tool_invocation_complete(
                    session=session,
                    invocation=invocation,
                    result_summary={"path": "direct", "agent": agent_name},
                )

        # W2-A: derive the per-call timeout from the remaining budget.
        # If no budget_deadline was passed (e.g. direct callers in
        # tests), use the per-call ceiling unchanged. ``getattr``
        # allows ``__new__``-constructed test instances to bypass
        # the full ``__init__`` settings dependency.
        per_call_ceiling = getattr(self, "_per_call_timeout_s", 180.0)
        if budget_deadline is not None:
            remaining = budget_deadline - time.monotonic()
            # 10s headroom: orchestrator needs time to finalize after
            # the last tool call returns.
            effective_timeout = max(5.0, min(per_call_ceiling, remaining - 10.0))
            if remaining <= 10.0:
                logger.warning(
                    "HypothesisOrchestrator: budget nearly exhausted (%.1fs "
                    "remaining) before dispatch of %s; skipping",
                    remaining,
                    hypothesis.get("hypothesis_class", ""),
                )
                await self._mark_tool_invocation_complete(
                    session=session,
                    invocation=invocation,
                    result_summary={"path": "skipped", "reason": "budget_exhausted"},
                )
                return {"findings": [], "artifacts": []}
        else:
            effective_timeout = per_call_ceiling

        # Engine-mediated dispatch. try/except/finally ensures the
        # ``completed_at IS NULL`` invariant holds even when the
        # engine dispatch raises or times out (defect 3).
        try:
            try:
                result = await engine.submit_and_await(
                    session=session,
                    engagement_id=engagement_id,
                    agent_name=agent_name,
                    payload=investigation_payload,
                    timeout=effective_timeout,
                )
            except Exception as exc:
                logger.error(
                    "Engine dispatch failed for hypothesis %s: %s",
                    hypothesis.get("hypothesis_class", ""),
                    exc,
                )
                await log_action(
                    session=session,
                    action="investigation_failed",
                    actor="hypothesis_orchestrator",
                    payload={
                        "engagement_id": engagement_id,
                        "hypothesis_id": hypothesis_id,
                        "agent": agent_name,
                        "error": str(exc)[:500],
                    },
                )
                await self._mark_tool_invocation_complete(
                    session=session,
                    invocation=invocation,
                    result_summary={
                        "path": "engine",
                        "agent": agent_name,
                        "timeout": effective_timeout,
                        "status": "error",
                        "error": str(exc)[:200],
                    },
                )
                return {"findings": [], "artifacts": []}

            payload_result = result or {"findings": [], "artifacts": []}
            await self._mark_tool_invocation_complete(
                session=session,
                invocation=invocation,
                result_summary={
                    "path": "engine",
                    "agent": agent_name,
                    "timeout": effective_timeout,
                    "findings_count": len(payload_result.get("findings", [])),
                    "status": "ok",
                },
            )
            return payload_result
        except BaseException:
            # Defense in depth: any unexpected error (e.g. session
            # flush failure) still must not leave the invocation row
            # in the ``completed_at IS NULL`` state. Re-raise after
            # marking.
            try:
                await self._mark_tool_invocation_complete(
                    session=session,
                    invocation=invocation,
                    result_summary={
                        "path": "engine",
                        "agent": agent_name,
                        "status": "unexpected_error",
                    },
                )
            except Exception:
                pass
            raise

    async def _invoke_agent_directly(
        self, agent_name: str, payload: dict[str, Any], session: AsyncSession
    ) -> dict[str, Any]:
        """Direct agent instantiation fallback (no engine)."""
        agent_map = {
            "pentester": "src.agents.pentester:PentesterAgent",
            "webapp": "src.agents.webapp:WebappAgent",
            "recon": "src.agents.recon:ReconAgent",
            "reasoner": "src.agents.reasoner:ReasonerAgent",
        }
        import importlib

        entry = agent_map.get(agent_name)
        if entry is None:
            return {"findings": [], "artifacts": []}
        try:
            module_path, class_name = entry.rsplit(":", 1)
            module = importlib.import_module(module_path)
            agent_cls = getattr(module, class_name)
            agent = agent_cls()
            return await agent.execute(payload, session)
        except Exception as exc:
            logger.error("Direct agent invocation failed: %s", exc)
            return {"findings": [], "artifacts": []}

    def _select_agent(self, hypothesis: dict[str, Any]) -> str:
        """Route hypothesis to the right investigation agent.

        Mirrors ResearchLoopAgent's routing logic so that the orchestrator
        is a drop-in replacement.
        """
        category = (hypothesis.get("attack_category") or "").lower()
        capabilities = hypothesis.get("required_capabilities", [])

        if category in ("business_logic", "race_condition", "auth_bypass", "csrf"):
            return "webapp"
        if category in (
            "injection", "xss", "ssrf", "idor", "privilege_escalation", "api_abuse"
        ):
            return "pentester"
        if category in ("data_exposure", "misconfig", "crypto_flaw"):
            return "reasoner"
        if any(cap in capabilities for cap in ("xss", "csrf", "auth_bypass", "business_logic")):
            return "webapp"
        return "pentester"

    # -----------------------------------------------------------------------
    # Phase 3: Reflection
    # -----------------------------------------------------------------------

    async def _reflect(
        self,
        hypotheses: list[dict[str, Any]],
        results: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        surface: dict[str, Any],
        session: AsyncSession,
        engagement_id: str,
    ) -> list[dict[str, Any]]:
        """Evaluate whether further investigation is warranted.

        Empty list → loop terminates.
        Non-empty list → new hypotheses to investigate in the next iteration.
        """
        try:
            new_hypotheses = await self.reflection.evaluate(
                hypotheses=hypotheses,
                results=results,
                findings=findings,
                surface=surface,
            )
            await log_action(
                session=session,
                action="reflection_evaluated",
                actor="hypothesis_orchestrator",
                payload={
                    "engagement_id": engagement_id,
                    "new_hypotheses_count": len(new_hypotheses) if new_hypotheses else 0,
                },
            )
            return new_hypotheses or []
        except Exception as exc:
            logger.error("Reflection failed: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    async def _persist_hypothesis(
        self,
        session: AsyncSession,
        engagement_id: str,
        hypothesis_data: dict[str, Any],
        parent_id: str | None = None,
    ) -> Hypothesis:
        """Persist a hypothesis to the DB."""
        source_str = hypothesis_data.get("source", HypothesisSource.PATTERN_MATCH.value)
        try:
            source = HypothesisSource(source_str)
        except ValueError:
            source = HypothesisSource.PATTERN_MATCH

        hypothesis = Hypothesis(
            id=str(uuid4()),
            engagement_id=engagement_id,
            hypothesis_class=hypothesis_data.get("hypothesis_class", "unknown"),
            source=source,
            description=hypothesis_data.get("description", ""),
            confidence=hypothesis_data.get("confidence", 0.5),
            status=HypothesisStatus.CANDIDATE,
            attack_category=hypothesis_data.get("attack_category", "injection"),
            parent_hypothesis_id=parent_id,
            required_capabilities=hypothesis_data.get("required_capabilities", []),
            falsification_criteria=hypothesis_data.get("falsification_criteria", ""),
        )
        session.add(hypothesis)
        await session.flush()
        return hypothesis

    async def _record_tool_invocation(
        self,
        session: AsyncSession,
        engagement_id: str,
        hypothesis_id: str,
        tool_name: str,
        capability_tags: list[str],
        target: str,
        params: dict[str, Any],
    ) -> ToolInvocation:
        """Record a tool invocation for provenance tracking.

        The returned ``ToolInvocation`` is intentionally flushed with
        only ``started_at`` set. The dispatch site is responsible for
        setting ``completed_at`` and ``result_summary`` in a
        ``try/finally`` block so the provenance row never gets stuck
        in the ``completed_at IS NULL`` state — that was defect 3
        (the live dj1naq.sytes.net scan had 5 rows in that state
        because the orchestrator's tool calls hung and never reached
        the completion-marking code).
        """
        invocation = ToolInvocation(
            id=str(uuid4()),
            engagement_id=engagement_id,
            hypothesis_id=hypothesis_id,
            tool_name=tool_name,
            capability_tags=capability_tags,
            target=target,
            params=params,
            started_at=datetime.now(UTC),
        )
        session.add(invocation)
        await session.flush()
        return invocation

    async def _mark_tool_invocation_complete(
        self,
        session: AsyncSession,
        invocation: ToolInvocation,
        result_summary: dict[str, Any] | None = None,
    ) -> None:
        """Set ``completed_at`` and ``result_summary`` on a tool invocation.

        Always called in a ``try/finally`` by the dispatch site so the
        ``completed_at IS NULL`` invariant holds even when the dispatch
        raises. ``result_summary`` is JSON-coerced (sets → lists) so the
        JSON column doesn't crash on set/tuple types
        (``egats-set-serialization`` memory).
        """
        invocation.completed_at = datetime.now(UTC)
        if result_summary is not None:
            safe: dict[str, Any] = {}
            for k, v in result_summary.items():
                if isinstance(v, (set, tuple)):
                    safe[k] = list(v)
                else:
                    safe[k] = v
            invocation.result_summary = safe
        await session.flush()

    async def _persist_finding(
        self,
        session: AsyncSession,
        engagement_id: str,
        finding_data: dict[str, Any],
        hypotheses_investigated: list[dict[str, Any]],
    ) -> Finding | None:
        """Persist a finding and create a ProvenanceLink record.

        The link connects the finding → hypothesis → tool_invocation, giving
        the same provenance chain as ResearchLoopAgent (which this class
        replaces).
        """
        severity_str = (finding_data.get("severity") or "info").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        finding = Finding(
            id=str(uuid4()),
            engagement_id=engagement_id,
            title=finding_data.get("title", "Unknown finding"),
            description=finding_data.get("description", finding_data.get("evidence", "")),
            severity=severity,
            confidence_score=finding_data.get("confidence", 0.0),
            validated=finding_data.get("validated", False),
            cwe_id=finding_data.get("cwe_id"),
            owasp_category=finding_data.get("owasp_category"),
            remediation=finding_data.get("remediation"),
            source_agent=finding_data.get("source_agent", "hypothesis_orchestrator"),
            finding_metadata={
                "hypothesis_context": finding_data.get("hypothesis_class", ""),
                "attack_category": finding_data.get("attack_category", ""),
                "tool_name": finding_data.get("source_agent", "hypothesis_orchestrator"),
            },
        )
        session.add(finding)
        await session.flush()

        # Create provenance link to the latest hypothesis + tool invocation
        if hypotheses_investigated:
            hypothesis_info = hypotheses_investigated[-1]
            hypothesis_id = hypothesis_info.get("hypothesis_id")
            if hypothesis_id:
                from sqlalchemy import select

                stmt = (
                    select(ToolInvocation)
                    .where(ToolInvocation.hypothesis_id == hypothesis_id)
                    .order_by(ToolInvocation.started_at.desc())
                    .limit(1)
                )
                result = await session.execute(stmt)
                tool_invocation = result.scalar_one_or_none()

                if tool_invocation:
                    provenance = ProvenanceLink(
                        id=str(uuid4()),
                        finding_id=finding.id,
                        hypothesis_id=hypothesis_id,
                        tool_invocation_id=tool_invocation.id,
                        tool_name=tool_invocation.tool_name,
                    )
                    session.add(provenance)

        finding_data["_persisted"] = True
        return finding

    async def _load_findings(self, session: AsyncSession, engagement_id: str) -> list[Finding]:
        from sqlalchemy import select

        stmt = select(Finding).where(Finding.engagement_id == engagement_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    def _load_surface(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Prefer payload surface, fall back to previous_result."""
        surface = payload.get("surface", {})
        if not surface:
            surface = payload.get("previous_result", {}).get("surface", {})
        return surface or {}

    # -----------------------------------------------------------------------
    # Result compilation
    # -----------------------------------------------------------------------

    def _compile_results(
        self,
        hypotheses_investigated: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        iterations: int,
    ) -> dict[str, Any]:
        confirmed = sum(
            1
            for h in hypotheses_investigated
            if h.get("status") == HypothesisStatus.VALIDATED
        )
        falsified = sum(
            1
            for h in hypotheses_investigated
            if h.get("status") == HypothesisStatus.REJECTED
        )
        high_severity = [
            f for f in findings if (f.get("severity") or "").lower() in ("high", "critical")
        ]
        return {
            "findings": findings,
            "artifacts": artifacts,
            "hypotheses_investigated": len(hypotheses_investigated),
            "hypotheses_confirmed": confirmed,
            "hypotheses_falsified": falsified,
            "total_findings": len(findings),
            "high_severity_findings": len(high_severity),
            "research_iterations": iterations,
            "agent": "hypothesis_orchestrator",
        }

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity),
            "confidence": finding.confidence_score,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "source_agent": finding.source_agent,
            "validated": finding.validated,
            "finding_metadata": finding.finding_metadata or {},
        }

    @staticmethod
    def _slug(text: str) -> str:
        """Make a slug suitable for embedding in a hypothesis_class name."""
        import re

        s = re.sub(r"[^a-zA-Z0-9]+", "-", text or "x").strip("-").lower()
        return s[:40] or "x"
