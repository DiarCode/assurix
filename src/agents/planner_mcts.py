"""LATS — Language Agent Tree Search for pentesting action selection.

Implements Monte Carlo Tree Search with LLM-guided expansion:
- Selection: UCB1 formula picks most promising node
- Expansion: LLM generates 3-5 possible next actions per node
- Simulation: Quick rollout evaluating action quality
- Backpropagation: Update node values from simulation results

Used by the ReAct loop in PentesterAgent to select the best next action.
"""

from __future__ import annotations

import json
import logging
import math
import random
from dataclasses import dataclass, field
from typing import Any

from src.agents.base import BaseAgent
from src.core.config import get_settings
from src.llm.client import OllamaClient
from src.patterns.library import VulnerabilityPatternLibrary

logger = logging.getLogger(__name__)

LATS_EXPANSION_SYSTEM = """You are a security testing strategist. Given the current state of a pentest,
generate 3-5 specific next actions to test. Each action should target a different vulnerability class
or attack vector.

For each action, provide:
- action_type: one of fuzz_params, fuzz_dirs, fuzz_post_body, fuzz_cookies, fuzz_headers_injection,
  xss_pipeline, sqli_pipeline, ssrf_pipeline, cmdi_pipeline, auth_bypass, idor_test,
  timing_test, credential_test, graphql_test, websocket_test
- target: specific URL or endpoint to test
- reason: why this action might discover a vulnerability
- priority: critical|high|medium|low
- expected_evidence: what evidence would confirm a finding

Respond in JSON:
{"actions": [{"action_type": "...", "target": "...", "reason": "...", "priority": "...", "expected_evidence": "..."}]}"""

MCTS_PLANNER_SYSTEM = """You are a security investigation planner. Given suspicious points and surface data from a target, produce a prioritized investigation plan.

For each investigation, specify:
- task_type: one of xss_hunt, auth_test, api_discover, error_probe, missing_code_check
- target: specific URL or component to investigate
- context: what evidence suggests this is worth investigating
- priority: critical|high|medium|low
- reason: why this investigation might find a real vulnerability

Respond in JSON only:
{
  "investigations": [
    {
      "task_type": "...",
      "target": "...",
      "context": "...",
      "priority": "...",
      "reason": "..."
    }
  ],
  "attack_hypotheses": [
    {
      "hypothesis": "...",
      "confidence": 0.0-1.0,
      "evidence": "..."
    }
  ]
}

Focus on investigations most likely to produce high-confidence findings."""


@dataclass
class MCTSNode:
    """A node in the MCTS investigation tree."""

    task_type: str
    target: str
    context: str = ""
    priority: str = "medium"
    reason: str = ""
    visits: int = 0
    total_reward: float = 0.0
    children: list[MCTSNode] = field(default_factory=list)
    parent: MCTSNode | None = None
    expanded: bool = False

    @property
    def ucb1(self) -> float:
        """Upper Confidence Bound for Trees score."""
        if self.visits == 0:
            return float("inf")
        exploit = self.total_reward / self.visits
        explore = math.sqrt(2 * math.log(self.parent.visits) / self.visits) if self.parent and self.parent.visits > 0 else 0
        return exploit + 1.41 * explore

    @property
    def avg_reward(self) -> float:
        return self.total_reward / self.visits if self.visits > 0 else 0.0


class MCTSPlannerAgent(BaseAgent):
    """Plans investigations using MCTS over suspicious points and patterns.

    P4 enhancement: LLM-guided expansion generates child actions.
    Used by ReAct loop for _select_action.
    """

    name = "planner_mcts"

    def __init__(self, max_expansions: int = 3, simulation_depth: int = 2) -> None:
        super().__init__()
        self._pattern_lib = VulnerabilityPatternLibrary()
        self.max_expansions = max_expansions
        self.simulation_depth = simulation_depth
        self._tree: MCTSNode | None = None

    async def execute(self, payload: dict[str, Any], session: Any) -> dict[str, Any]:
        target_url = payload.get("target_url", "")
        previous = payload.get("previous_result", {})
        iteration = payload.get("iteration", 0)

        if not target_url:
            target_url = previous.get("target_url", "")

        surface = previous.get("surface", {})
        findings = previous.get("findings", [])
        suspicious_points = previous.get("suspicious_points", [])

        settings = get_settings()

        candidates = self._build_candidates(suspicious_points, surface, findings, target_url)
        root = self._build_tree(candidates, target_url)
        self._tree = root
        self._simulate(root, iterations=min(len(candidates) * 3, 30))

        ranked = sorted(root.children, key=lambda n: n.ucb1, reverse=True)
        top_investigations = ranked[: settings.parallel_agents * 2]

        llm_plan = {}
        if top_investigations and surface:
            llm_plan = await self._llm_plan(top_investigations, surface, target_url, iteration)

        investigations = self._merge_plans(top_investigations, llm_plan)

        from src.core.audit import log_action
        await log_action(
            session=session,
            action="mcts_plan_generated",
            actor="planner_mcts",
            payload={
                "target_url": target_url,
                "candidates": len(candidates),
                "selected": len(investigations),
                "iteration": iteration,
            },
        )

        return {
            "findings": findings,
            "artifacts": [],
            "directives": [],
            "investigations": investigations,
            "suspicious_points": suspicious_points,
            "target_url": target_url,
            "surface": surface,
            "attack_hypotheses": llm_plan.get("attack_hypotheses", []),
        }

    async def select_next_action(
        self,
        target_url: str,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        top_hypotheses: list[dict[str, Any]] | None = None,
        failed_actions: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Select the best next action for the ReAct loop using LATS.

        This is the main entry point for P4 integration with the ReAct loop.
        """
        failed_set = set()
        if failed_actions:
            failed_set = {(a.get("action", ""), a.get("url", "")) for a in failed_actions}

        surface = observations.get("surface", {})
        suspicious = observations.get("suspicious_points", [])

        # Build or update the tree
        if self._tree is None:
            candidates = self._build_candidates(suspicious, surface, confirmed_findings, target_url)
            self._tree = self._build_tree(candidates, target_url)

        # Add hypothesis-driven candidates if available
        if top_hypotheses:
            self._add_hypothesis_nodes(self._tree, top_hypotheses, target_url)

        # Run LLM-guided expansion on most promising node
        best_leaf = self._select_leaf(self._tree)
        if best_leaf and not best_leaf.expanded:
            await self._expand_node(best_leaf, observations, target_url)

        # Run simulations
        self._simulate(self._tree, iterations=15)

        # Select best action not already failed
        ranked = sorted(self._tree.children, key=lambda n: n.ucb1, reverse=True)
        for node in ranked:
            action_key = (node.task_type, node.target)
            if action_key not in failed_set:
                return {
                    "action_type": node.task_type,
                    "target": node.target,
                    "reason": node.reason,
                    "priority": node.priority,
                    "mcts_visits": node.visits,
                    "mcts_avg_reward": round(node.avg_reward, 3),
                }

        # All actions failed — try LLM expansion for new ideas
        new_actions = await self._llm_expand_actions(observations, confirmed_findings, target_url, failed_actions or [])
        if new_actions:
            return new_actions[0]

        return None

    def _select_leaf(self, node: MCTSNode) -> MCTSNode | None:
        """Select the most promising leaf node for expansion."""
        while node.children:
            unvisited = [c for c in node.children if c.visits == 0]
            if unvisited:
                return random.choice(unvisited)
            node = max(node.children, key=lambda c: c.ucb1)
        return node if node.task_type != "root" else (node.children[0] if node.children else None)

    async def _expand_node(self, node: MCTSNode, observations: dict, target_url: str) -> None:
        """Expand a node using LLM-guided action generation."""
        node.expanded = True
        try:
            new_actions = await self._llm_expand_actions(observations, [], target_url, [])
            for action in new_actions[:self.max_expansions]:
                child = MCTSNode(
                    task_type=action.get("action_type", "error_probe"),
                    target=action.get("target", target_url),
                    context=action.get("reason", ""),
                    priority=action.get("priority", "medium"),
                    reason=action.get("reason", ""),
                    parent=node,
                )
                child._expected_evidence = action.get("expected_evidence", "")
                node.children.append(child)
        except Exception as exc:
            logger.warning("LATS expansion failed for node %s: %s", node.task_type, exc)

    async def _llm_expand_actions(
        self,
        observations: dict[str, Any],
        confirmed_findings: list[dict[str, Any]],
        target_url: str,
        failed_actions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Use LLM to generate candidate next actions."""
        llm = OllamaClient()
        try:
            obs_summary = {
                "endpoints": observations.get("endpoints", [])[:8],
                "technologies": observations.get("technologies", [])[:5],
                "open_ports": [p.get("port") for p in observations.get("open_ports", [])[:5]],
                "auth_pages": observations.get("auth_pages", [])[:3],
            }
            findings_summary = [
                {"title": f.get("title"), "severity": f.get("severity")}
                for f in confirmed_findings[:5]
            ]
            failed_summary = [
                f"{a.get('action', '')} on {a.get('url', '')}"
                for a in failed_actions[:5]
            ]

            prompt = (
                f"Target: {target_url}\n"
                f"Observations: {json.dumps(obs_summary)}\n"
                f"Confirmed findings: {json.dumps(findings_summary)}\n"
                f"Failed actions (do not repeat): {json.dumps(failed_summary)}\n\n"
                "Generate 3-5 specific next actions to test for vulnerabilities."
            )

            response = await llm.chat(
                messages=[
                    {"role": "system", "content": LATS_EXPANSION_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                task_type="classification",
                max_tokens=1024,
            )
            parsed = OllamaClient.extract_json(response)
            if isinstance(parsed, dict) and "actions" in parsed:
                return parsed["actions"]
            return []
        except Exception as exc:
            logger.warning("LATS LLM expansion failed: %s", exc)
            return []
        finally:
            await llm.close()

    def _add_hypothesis_nodes(
        self, root: MCTSNode, hypotheses: list[dict[str, Any]], target_url: str
    ) -> None:
        """Add hypothesis-driven action nodes to the tree."""
        hypothesis_action_map = {
            "xss": "xss_pipeline",
            "sqli": "sqli_pipeline",
            "ssrf": "ssrf_pipeline",
            "cmdi": "cmdi_pipeline",
            "auth": "auth_bypass",
            "idor": "idor_test",
            "timing": "timing_test",
        }
        existing_types = {c.task_type for c in root.children}

        for h in hypotheses:
            vuln_type = h.get("vuln_type", "").lower()
            action_type = hypothesis_action_map.get(vuln_type, "error_probe")
            if action_type in existing_types:
                continue
            posterior = h.get("posterior", 0.5)
            if posterior < 0.3:
                continue
            child = MCTSNode(
                task_type=action_type,
                target=h.get("target_url", target_url) or target_url,
                context=h.get("description", ""),
                priority="high" if posterior > 0.7 else "medium",
                reason=f"Hypothesis-driven ({vuln_type}, posterior={posterior:.2f})",
                parent=root,
            )
            child._confidence = posterior
            root.children.append(child)
            existing_types.add(action_type)

    def reset_tree(self) -> None:
        """Reset the tree for a new scan."""
        self._tree = None

    def _build_candidates(
        self,
        suspicious_points: list[dict],
        surface: dict,
        findings: list[dict],
        target_url: str,
    ) -> list[dict]:
        candidates: list[dict] = []

        for sp in suspicious_points:
            sp_type = sp.get("sp_type", "unknown")
            confidence = sp.get("confidence", 0.5)
            location = sp.get("location", target_url)
            reason = sp.get("reason", "")
            vuln_types = sp.get("vuln_types", [])

            task_map = {
                "missing_csrf": "auth_test",
                "missing_rate_limit": "auth_test",
                "missing_cors_policy": "error_probe",
                "missing_csp": "xss_hunt",
                "xss_sink": "xss_hunt",
                "auth_form": "auth_test",
                "missing_auth": "auth_test",
                "missing_validation": "api_discover",
                "api_endpoint": "api_discover",
                "form_with_inputs": "xss_hunt",
                "js_dangerous_pattern": "xss_hunt",
            }

            task_type = task_map.get(sp_type, "error_probe")
            priority = "critical" if confidence > 0.8 else "high" if confidence > 0.6 else "medium"

            candidates.append({
                "task_type": task_type,
                "target": location,
                "context": reason,
                "priority": priority,
                "reason": f"Suspicious point ({sp_type}, conf={confidence:.2f}): {reason}",
                "confidence": confidence,
                "vuln_types": vuln_types,
            })

        for finding in findings[:10]:
            matches = self._pattern_lib.match(finding)
            for pattern, score in matches[:2]:
                candidates.append({
                    "task_type": self._category_to_task(pattern.category),
                    "target": target_url,
                    "context": finding.get("title", ""),
                    "priority": pattern.severity if score > 0.7 else "medium",
                    "reason": f"Pattern match ({pattern.name}, score={score:.2f}) from finding: {finding.get('title', '')}",
                    "confidence": score,
                    "vuln_types": [pattern.name],
                })

        applicable = self._pattern_lib.get_applicable_patterns(surface)
        for pattern in applicable[:5]:
            if not any(c.get("vuln_types", []) and pattern.name in c.get("vuln_types", []) for c in candidates):
                candidates.append({
                    "task_type": self._category_to_task(pattern.category),
                    "target": target_url,
                    "context": f"Tech stack suggests {pattern.name} risk",
                    "priority": pattern.severity,
                    "reason": f"Applicable pattern ({pattern.name}): {pattern.description}",
                    "confidence": 0.4,
                    "vuln_types": [pattern.name],
                })

        return candidates

    def _build_tree(self, candidates: list[dict], target_url: str) -> MCTSNode:
        root = MCTSNode(task_type="root", target=target_url)
        for c in candidates:
            child = MCTSNode(
                task_type=c["task_type"],
                target=c["target"],
                context=c.get("context", ""),
                priority=c.get("priority", "medium"),
                reason=c.get("reason", ""),
                parent=root,
            )
            child._confidence = c.get("confidence", 0.5)
            child._vuln_types = c.get("vuln_types", [])
            root.children.append(child)
        return root

    def _simulate(self, root: MCTSNode, iterations: int) -> None:
        for _ in range(iterations):
            node = self._select(root)
            reward = self._evaluate(node)
            self._backpropagate(node, reward)

    def _select(self, node: MCTSNode) -> MCTSNode:
        while node.children:
            unvisited = [c for c in node.children if c.visits == 0]
            if unvisited:
                return random.choice(unvisited)
            node = max(node.children, key=lambda c: c.ucb1)
        return node

    def _evaluate(self, node: MCTSNode) -> float:
        confidence = getattr(node, "_confidence", 0.5)
        priority_mult = {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.7}
        mult = priority_mult.get(node.priority, 1.0)
        vuln_types = getattr(node, "_vuln_types", [])
        diversity_bonus = min(0.2, len(vuln_types) * 0.1)
        noise = random.gauss(0, 0.05)
        return max(0.0, min(1.0, confidence * mult + diversity_bonus + noise))

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        while node is not None:
            node.visits += 1
            node.total_reward += reward
            node = node.parent

    async def _llm_plan(
        self, investigations: list[MCTSNode], surface: dict, target_url: str, iteration: int
    ) -> dict:
        inv_summaries = [
            f"- [{inv.priority}] {inv.task_type}: {inv.target} — {inv.reason}"
            for inv in investigations[:10]
        ]

        surface_summary = {
            "technologies": surface.get("technologies", []),
            "pages": len(surface.get("pages", [])),
            "forms": len(surface.get("forms", [])),
            "auth_pages": surface.get("auth_pages", []),
            "endpoints": surface.get("endpoints", [])[:5],
        }

        llm = OllamaClient()
        try:
            response = await llm.chat(
                messages=[
                    {"role": "system", "content": MCTS_PLANNER_SYSTEM},
                    {"role": "user", "content": (
                        f"Target: {target_url} (iteration {iteration})\n"
                        f"Surface: {json.dumps(surface_summary)}\n"
                        f"Candidate investigations:\n" + "\n".join(inv_summaries) + "\n\n"
                        "Prioritize and refine these investigations. Add any missing critical ones."
                    )},
                ],
                task_type="classification",
                max_tokens=2048,
            )
            return self._parse_response(response)
        except Exception as exc:
            logger.warning("MCTS planner LLM call failed: %s", exc)
            return {}
        finally:
            await llm.close()

    def _merge_plans(self, mcts_investigations: list[MCTSNode], llm_plan: dict) -> list[dict]:
        results: list[dict] = []

        for node in mcts_investigations:
            results.append({
                "type": "investigation",
                "task_type": node.task_type,
                "target": node.target,
                "context": node.context,
                "priority": node.priority,
                "reason": node.reason,
                "mcts_visits": node.visits,
                "mcts_avg_reward": round(node.avg_reward, 3),
            })

        for inv in llm_plan.get("investigations", [])[:5]:
            if not any(r.get("task_type") == inv.get("task_type") and r.get("target") == inv.get("target") for r in results):
                results.append({
                    "type": "investigation",
                    "task_type": inv.get("task_type", "error_probe"),
                    "target": inv.get("target", ""),
                    "context": inv.get("context", ""),
                    "priority": inv.get("priority", "medium"),
                    "reason": inv.get("reason", ""),
                    "mcts_visits": 0,
                    "mcts_avg_reward": 0.0,
                })

        return results

    @staticmethod
    def _category_to_task(category: str) -> str:
        mapping = {
            "A01:2021": "auth_test",
            "A02:2021": "error_probe",
            "A03:2021": "xss_hunt",
            "A04:2021": "api_discover",
            "A05:2021": "error_probe",
            "A06:2021": "error_probe",
            "A07:2021": "auth_test",
            "A08:2021": "error_probe",
            "A09:2021": "error_probe",
            "A10:2021": "api_discover",
        }
        return mapping.get(category, "error_probe")

    @staticmethod
    def _parse_response(response: str) -> dict:
        result = OllamaClient.extract_json(response)
        if isinstance(result, dict):
            return result
        return {"investigations": [], "attack_hypotheses": []}