"""ResearchLoopAgent: Engagement-level orchestrator for hypothesis-driven security research.

The Mythos architecture's central orchestrator. Generates hypothesis classes from
pattern matching + LLM creativity, dispatches investigations to existing agents per
hypothesis, and terminates when reflection produces no new productive hypotheses.

ResearchLoop operates at the ENGAGEMENT level (which hypotheses to investigate).
PentesterAgent operates at the INVESTIGATION level (how to test a specific hypothesis).
ResearchLoop dispatches PentesterAgent as an investigation subroutine, providing
hypothesis context.
"""

import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.verification import TriadOrchestrator
from src.core.audit import log_action
from src.core.config import get_settings
from src.db.models import Engagement, EngagementStatus, Finding, Hypothesis, HypothesisSource, HypothesisStatus
from src.llm.frontier_client import UnifiedLLMClient
from src.reasoning.hypothesis_generator import HypothesisGenerator
from src.reasoning.reflection import ReflectionPhase

logger = logging.getLogger(__name__)

# Maximum hypothesis generation iterations to prevent infinite loops
MAX_RESEARCH_ITERATIONS = 5
# Minimum confidence threshold for a hypothesis to be worth investigating
MIN_HYPOTHESIS_CONFIDENCE = 0.3


class ResearchLoopAgent(BaseAgent):
    """Engagement-level orchestrator that generates hypothesis classes,
    dispatches investigations per hypothesis, and terminates on reflection.

    Integrates into the existing WorkflowEngine as a new agent type.
    The engine still handles job dequeue, agent instantiation, error handling,
    and audit logging. ResearchLoop orchestrates the engagement-level workflow.
    """

    name = "research_loop"

    def __init__(self) -> None:
        settings = get_settings()
        self.llm = UnifiedLLMClient()
        self.hypothesis_generator = HypothesisGenerator(llm_client=self.llm)
        self.reflection = ReflectionPhase(llm_client=self.llm)
        self._max_iterations = settings.max_iterations_per_scan
        self._max_research_iterations = MAX_RESEARCH_ITERATIONS

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Execute the research loop for an engagement.

        Args:
            payload: Must contain 'engagement_id'. May contain 'target_url',
                     'surface', and 'previous_findings'.
            session: Active database session.

        Returns:
            Dict with findings, hypotheses investigated, and provenance metadata.
        """
        engagement_id = payload.get("engagement_id", "")
        target_url = payload.get("target_url", "") or payload.get("previous_result", {}).get("target_url", "")

        if not engagement_id:
            logger.error("ResearchLoop: no engagement_id in payload")
            return {"findings": [], "artifacts": [], "hypotheses_investigated": 0, "error": "missing engagement_id"}

        # Load engagement
        engagement = await session.get(Engagement, engagement_id)
        if not engagement:
            logger.error("ResearchLoop: engagement %s not found", engagement_id)
            return {"findings": [], "artifacts": [], "hypotheses_investigated": 0, "error": "engagement not found"}

        # Transition engagement to RESEARCHING
        if EngagementStateMachine.can_transition(engagement.status, EngagementStatus.RESEARCHING):
            engagement.status = EngagementStatus.RESEARCHING
            await session.flush()
            await log_action(
                session=session,
                action="research_loop_started",
                actor="research_loop",
                payload={"engagement_id": engagement_id, "target_url": target_url},
            )

        # Load existing findings and surface data
        findings = await self._load_findings(session, engagement_id)
        surface = await self._load_surface(session, engagement_id, payload)

        all_findings: list[dict[str, Any]] = [self._finding_to_dict(f) for f in findings]
        all_artifacts: list[dict[str, Any]] = []
        hypotheses_investigated: list[dict[str, Any]] = []

        # Cumulative wall-clock budget. The per-investigation browser
        # agent has its own `asyncio.wait_for` ceiling (see AIBrowserOperator),
        # but a series of investigations can still exhaust the engagement
        # budget. When this fires we return whatever findings we have
        # collected so the engine can route to the reporter instead of
        # stalling the engagement.
        settings = get_settings()
        total_budget_seconds: int = int(
            payload.get(
                "research_loop_max_total_seconds",
                settings.research_loop_max_total_seconds,
            )
        )
        started_at = time.monotonic()
        iteration = 0

        await log_action(
            session=session,
            action="research_loop_phase_start",
            actor="research_loop",
            payload={
                "engagement_id": engagement_id,
                "iteration": iteration,
                "existing_findings": len(all_findings),
            },
        )

        # === Research Loop: Hypothesize → Investigate → Reflect ===
        while iteration < self._max_research_iterations:
            # Cumulative budget guard. The browser agent has a per-call
            # wall-clock ceiling (see AIBrowserOperator._run_agent), but
            # a series of investigations can still exhaust the
            # engagement's total research time. When this fires we
            # return whatever findings have been collected so the engine
            # can route to the reporter.
            if time.monotonic() - started_at > total_budget_seconds:
                logger.info(
                    "ResearchLoop: cumulative budget %ds exceeded at iter %d; terminating",
                    total_budget_seconds, iteration,
                )
                break
            iteration += 1
            logger.info(
                "ResearchLoop iteration %d/%d for engagement %s",
                iteration, self._max_research_iterations, engagement_id,
            )

            # Phase 1: Generate hypotheses from pattern matching + LLM
            hypotheses = await self._generate_hypotheses(
                surface=surface,
                findings=all_findings,
                session=session,
                engagement_id=engagement_id,
            )

            if not hypotheses:
                logger.info("ResearchLoop: no hypotheses generated, terminating")
                break

            # Filter out hypotheses below confidence threshold
            viable_hypotheses = [
                h for h in hypotheses
                if h.get("confidence", 0.0) >= MIN_HYPOTHESIS_CONFIDENCE
            ]

            if not viable_hypotheses:
                logger.info("ResearchLoop: no viable hypotheses above threshold, terminating")
                break

            logger.info("ResearchLoop: %d viable hypotheses generated", len(viable_hypotheses))

            # Phase 2: Investigate each hypothesis via existing agents
            for hypothesis_index, hypothesis_data in enumerate(viable_hypotheses):
                # Inner-loop budget guard. Long batches of viable
                # hypotheses can each trigger a browser-backed
                # investigation; without this guard the inner for-loop
                # would run to completion even when the outer budget is
                # already blown.
                if time.monotonic() - started_at > total_budget_seconds:
                    logger.info(
                        "ResearchLoop: cumulative budget %ds exceeded; "
                        "skipping remaining %d hypotheses in this batch",
                        total_budget_seconds,
                        len(viable_hypotheses) - hypothesis_index,
                    )
                    break
                # Persist hypothesis to database
                hypothesis = await self._persist_hypothesis(
                    session=session,
                    engagement_id=engagement_id,
                    hypothesis_data=hypothesis_data,
                    parent_id=hypothesis_data.get("parent_hypothesis_id"),
                )

                # Dispatch investigation via engine enqueue
                investigation_result = await self._investigate_hypothesis(
                    hypothesis=hypothesis_data,
                    hypothesis_id=hypothesis.id,
                    payload=payload,
                    surface=surface,
                    session=session,
                    engagement_id=engagement_id,
                )

                # Update hypothesis status based on results
                if investigation_result.get("findings"):
                    # Plan §3.2.3: the Verifier Triad must run BEFORE the
                    # hypothesis can transition to VALIDATED. A finding
                    # is only valid if all three of Reproducer + Adversary
                    # + Validator vote positive. Findings that fail the
                    # triad are recorded with their reproducer_run_id /
                    # adversary_run_id / validator_run_id so an auditor
                    # can replay the decision.
                    triad = TriadOrchestrator(
                        existing_findings=list(all_findings),
                    )
                    validated_findings: list[dict[str, Any]] = []
                    for finding in investigation_result["findings"]:
                        triad_result = await triad.run(
                            finding=finding,
                            target=payload.get("target_url", ""),
                        )
                        if triad_result.final_validated:
                            finding["reproducer_run_id"] = triad_result.reproducer.run_id
                            finding["adversary_run_id"] = triad_result.adversary.run_id
                            finding["validator_run_id"] = triad_result.validator.run_id
                            finding["triad_reason"] = triad_result.reason
                            validated_findings.append(finding)
                        else:
                            logger.info(
                                "ResearchLoop: triad rejected finding '%s': %s",
                                finding.get("title", "")[:80],
                                triad_result.reason,
                            )

                    confirmed = any(
                        f.get("severity") in ("high", "critical", "medium")
                        for f in validated_findings
                    )
                    hypothesis.status = (
                        HypothesisStatus.VALIDATED if confirmed else HypothesisStatus.REJECTED
                    )
                    # Replace the findings list with the triad-validated
                    # subset so downstream reporting only sees what the
                    # triad approved.
                    investigation_result["findings"] = validated_findings
                else:
                    hypothesis.status = HypothesisStatus.REJECTED
                await session.flush()

                hypotheses_investigated.append({
                    "hypothesis_id": hypothesis.id,
                    "hypothesis_class": hypothesis_data.get("hypothesis_class", ""),
                    "attack_category": hypothesis_data.get("attack_category", ""),
                    "status": hypothesis.status,
                    "findings_count": len(investigation_result.get("findings", [])),
                })

                all_findings.extend(investigation_result.get("findings", []))
                all_artifacts.extend(investigation_result.get("artifacts", []))

            # Phase 3: Reflection — can we generate new productive hypotheses?
            new_hypotheses = await self._reflect(
                hypotheses=viable_hypotheses,
                results=hypotheses_investigated,
                findings=all_findings,
                surface=surface,
                session=session,
                engagement_id=engagement_id,
            )

            if not new_hypotheses:
                logger.info("ResearchLoop: reflection produced no new hypotheses, terminating")
                break

            logger.info("ResearchLoop: reflection produced %d new hypotheses", len(new_hypotheses))

        # Phase 4: Compile results
        result = self._compile_results(
            hypotheses_investigated=hypotheses_investigated,
            findings=all_findings,
            artifacts=all_artifacts,
            iterations=iteration,
        )

        # Persist findings from the research loop
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
            action="research_loop_completed",
            actor="research_loop",
            payload={
                "engagement_id": engagement_id,
                "iterations": iteration,
                "hypotheses_investigated": len(hypotheses_investigated),
                "total_findings": len(all_findings),
            },
        )

        return result

    # -----------------------------------------------------------------------
    # Phase 1: Hypothesis Generation
    # -----------------------------------------------------------------------

    async def _generate_hypotheses(
        self,
        surface: dict[str, Any],
        findings: list[dict[str, Any]],
        session: AsyncSession,
        engagement_id: str,
    ) -> list[dict[str, Any]]:
        """Generate hypothesis classes from pattern matching + LLM creativity."""
        try:
            hypotheses = await self.hypothesis_generator.generate_hypotheses(
                surface=surface,
                findings=findings,
            )
            await log_action(
                session=session,
                action="hypotheses_generated",
                actor="research_loop",
                payload={
                    "engagement_id": engagement_id,
                    "hypothesis_count": len(hypotheses),
                    # The audit_logs.payload column is a JSON column with no
                    # default=str fallback — sets blow up json.dumps. Convert
                    # the source set to a sorted list of unique strings before
                    # handing it to the JSON serializer. See egats-set-serialization.
                    "sources": sorted({h.get("source", "unknown") for h in hypotheses}),
                },
            )
            return hypotheses
        except Exception as exc:
            logger.error("ResearchLoop: hypothesis generation failed: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # Phase 2: Hypothesis Investigation
    # -----------------------------------------------------------------------

    async def _investigate_hypothesis(
        self,
        hypothesis: dict[str, Any],
        hypothesis_id: str,
        payload: dict[str, Any],
        surface: dict[str, Any],
        session: AsyncSession,
        engagement_id: str,
    ) -> dict[str, Any]:
        """Dispatch investigation for a single hypothesis.

        Routes to the appropriate agent based on the hypothesis's required_capabilities.
        Uses existing agents (PentesterAgent, WebappAgent, ReconAgent) as subroutines.
        """
        target_url = payload.get("target_url", "") or payload.get("previous_result", {}).get("target_url", "")
        attack_category = hypothesis.get("attack_category", "")
        required_capabilities = hypothesis.get("required_capabilities", [])

        # Build investigation payload enriched with hypothesis context
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

        # Determine which agent to dispatch based on capabilities and category
        agent_name = self._select_agent(hypothesis)

        # Record tool invocation for provenance
        await self._record_tool_invocation(
            session=session,
            engagement_id=engagement_id,
            hypothesis_id=hypothesis_id,
            tool_name=agent_name,
            capability_tags=required_capabilities,
            target=target_url,
            params=investigation_payload,
        )

        # Dispatch investigation via existing agent classes
        try:
            agent_cls = self._get_agent_class(agent_name)
            if agent_cls is None:
                logger.warning("ResearchLoop: unknown agent '%s', falling back to pentester", agent_name)
                agent_cls = self._get_agent_class("pentester")
                if agent_cls is None:
                    return {"findings": [], "artifacts": []}

            agent = agent_cls()
            result = await agent.execute(investigation_payload, session)
            return result

        except Exception as exc:
            logger.error(
                "ResearchLoop: investigation failed for hypothesis %s: %s",
                hypothesis.get("hypothesis_class", ""), exc,
            )
            await log_action(
                session=session,
                action="investigation_failed",
                actor="research_loop",
                payload={
                    "engagement_id": engagement_id,
                    "hypothesis_id": hypothesis_id,
                    "agent": agent_name,
                    "error": str(exc)[:500],
                },
            )
            return {"findings": [], "artifacts": []}

    def _select_agent(self, hypothesis: dict[str, Any]) -> str:
        """Select the appropriate agent for a hypothesis based on its category and capabilities.

        Routing logic:
        - recon → initial surface mapping (if surface data is sparse)
        - webapp → business logic, race condition, auth bypass, CSRF
        - pentester → injection, XSS, SSRF, IDOR, privilege escalation
        - reasoner → data exposure, misconfiguration (analytical assessment)
        """
        category = hypothesis.get("attack_category", "").lower()
        capabilities = hypothesis.get("required_capabilities", [])

        # Webapp-focused categories
        if category in ("business_logic", "race_condition", "auth_bypass", "csrf"):
            return "webapp"

        # Pentester-focused categories (active exploitation)
        if category in ("injection", "xss", "ssrf", "idor", "privilege_escalation", "api_abuse"):
            return "pentester"

        # Reasoner-focused categories (analytical assessment)
        if category in ("data_exposure", "misconfig", "crypto_flaw"):
            return "reasoner"

        # If capabilities suggest browser-based testing
        if any(cap in capabilities for cap in ("xss", "csrf", "auth_bypass", "business_logic")):
            return "webapp"

        # Default to pentester for active exploitation
        return "pentester"

    def _get_agent_class(self, agent_name: str) -> type | None:
        """Resolve agent name to class. Lazy imports to avoid circular dependencies."""
        agent_map = {
            "pentester": "src.agents.pentester:PentesterAgent",
            "webapp": "src.agents.webapp:WebappAgent",
            "recon": "src.agents.recon:ReconAgent",
            "reasoner": "src.agents.reasoner:ReasonerAgent",
        }
        import importlib
        entry = agent_map.get(agent_name)
        if entry is None:
            return None
        module_path, class_name = entry.rsplit(":", 1)
        try:
            module = importlib.import_module(module_path)
            return getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            logger.warning("ResearchLoop: cannot import agent '%s': %s", agent_name, exc)
            return None

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

        Returns empty list = loop terminates.
        Returns new hypotheses = loop continues.
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
                actor="research_loop",
                payload={
                    "engagement_id": engagement_id,
                    "new_hypotheses_count": len(new_hypotheses) if new_hypotheses else 0,
                },
            )
            return new_hypotheses or []
        except Exception as exc:
            logger.error("ResearchLoop: reflection failed: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # Database helpers
    # -----------------------------------------------------------------------

    async def _persist_hypothesis(
        self,
        session: AsyncSession,
        engagement_id: str,
        hypothesis_data: dict[str, Any],
        parent_id: str | None = None,
    ) -> Hypothesis:
        """Persist a hypothesis to the database."""
        hypothesis = Hypothesis(
            id=str(uuid4()),
            engagement_id=engagement_id,
            hypothesis_class=hypothesis_data.get("hypothesis_class", "unknown"),
            source=HypothesisSource(hypothesis_data.get("source", "pattern_match")),
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
    ) -> "ToolInvocation":
        """Record a tool invocation for provenance tracking."""
        from src.db.models import ToolInvocation

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

    async def _persist_finding(
        self,
        session: AsyncSession,
        engagement_id: str,
        finding_data: dict[str, Any],
        hypotheses_investigated: list[dict[str, Any]],
    ) -> Finding | None:
        """Persist a finding and create provenance links."""
        from src.db.models import ProvenanceLink, Severity

        # Determine severity
        severity_str = finding_data.get("severity", "info").lower()
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
            source_agent=finding_data.get("source_agent", "research_loop"),
            finding_metadata={
                "hypothesis_context": finding_data.get("hypothesis_class", ""),
                "attack_category": finding_data.get("attack_category", ""),
                "tool_name": finding_data.get("source_agent", "research_loop"),
            },
        )
        session.add(finding)
        await session.flush()

        # Create provenance link to hypothesis if available
        if hypotheses_investigated:
            hypothesis_info = hypotheses_investigated[0]  # Link to first hypothesis
            hypothesis_id = hypothesis_info.get("hypothesis_id")
            if hypothesis_id:
                # Find the tool invocation for this hypothesis
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
        """Load existing findings for an engagement."""
        stmt = select(Finding).where(Finding.engagement_id == engagement_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def _load_surface(
        self, session: AsyncSession, engagement_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Load surface data from payload or database."""
        # Prefer payload surface data
        surface = payload.get("surface", {})
        if not surface:
            surface = payload.get("previous_result", {}).get("surface", {})
        return surface

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
        """Compile the research loop results into a standard agent result."""
        confirmed = sum(1 for h in hypotheses_investigated if h.get("status") == HypothesisStatus.VALIDATED)
        falsified = sum(1 for h in hypotheses_investigated if h.get("status") == HypothesisStatus.REJECTED)

        high_severity = [f for f in findings if f.get("severity") in ("high", "critical")]

        return {
            "findings": findings,
            "artifacts": artifacts,
            "hypotheses_investigated": len(hypotheses_investigated),
            "hypotheses_confirmed": confirmed,
            "hypotheses_falsified": falsified,
            "total_findings": len(findings),
            "high_severity_findings": len(high_severity),
            "research_iterations": iterations,
            "agent": "research_loop",
        }

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict[str, Any]:
        """Convert a Finding ORM object to a dict for context passing."""
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "confidence": finding.confidence_score,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "source_agent": finding.source_agent,
            "validated": finding.validated,
            "finding_metadata": finding.finding_metadata or {},
        }


# Import for type reference (avoid circular imports at module level)
from src.orchestrator.state import EngagementStateMachine  # noqa: E402
from src.db.models import ToolInvocation  # noqa: E402