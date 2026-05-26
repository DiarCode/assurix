"""Causal Attack Graph — chains findings into exploit paths.

Instead of isolated findings, produces:
- Node: a finding or security condition
- Edge: causal relationship (enables, requires, exacerbates)
- Path: chain of nodes from entry point to impact

Example chain:
  Missing CORS -> enables -> XSS -> enables -> Cookie theft -> leads to -> Account takeover
"""

import json
import logging
from typing import Any

from src.llm.client import OllamaClient

logger = logging.getLogger(__name__)

ATTACK_GRAPH_SYSTEM = """You are a security expert building causal attack graphs. Given a list of
findings and surface data, identify how findings CHAIN TOGETHER into realistic exploit paths.

For each chain:
- Start from an entry point (what the attacker first exploits)
- Show each step with the finding that enables it
- End with impact (what the attacker achieves)
- Mark edges as: "enables" (finding A makes finding B exploitable),
  "requires" (finding B needs finding A to be exploitable),
  "exacerbates" (finding A makes finding B more severe)

Respond in JSON:
{
  "attack_paths": [
    {
      "name": "Descriptive name for this attack path",
      "severity": "critical|high|medium|low",
      "steps": [
        {"finding": "finding title", "role": "entry_point|enabler|escalation|impact", "edge_to_next": "enables|requires|exacerbates"},
        ...
      ],
      "description": "How this chain of vulnerabilities creates real risk"
    }
  ],
  "isolated_findings": ["finding titles that don't chain with others"]
}"""


class AttackGraphBuilder:
    """Builds causal attack graphs that chain findings into exploit paths."""

    def __init__(self) -> None:
        self.paths: list[dict[str, Any]] = []
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []

    async def build_graph(self, findings: list[dict], surface: dict) -> dict[str, Any]:
        """Build attack graph from findings using LLM causal reasoning."""
        if not findings:
            return {"attack_paths": [], "nodes": [], "edges": []}

        llm = OllamaClient()
        try:
            findings_json = json.dumps(findings[:20], default=str)[:4000]
            surface_json = json.dumps(
                {k: v for k, v in surface.items() if k in ("technologies", "auth_pages", "endpoints", "headers")},
                default=str,
            )[:1000]

            response = await llm.chat(
                messages=[
                    {"role": "system", "content": ATTACK_GRAPH_SYSTEM},
                    {"role": "user", "content": (
                        f"Findings: {findings_json}\n\n"
                        f"Surface: {surface_json}\n\n"
                        "Build the attack graph showing how findings chain together."
                    )},
                ],
                task_type="reasoning",
                max_tokens=2048,
            )

            result = self._parse_graph_response(response)
            self.paths = result.get("attack_paths", [])
            self.nodes = self._extract_nodes(findings)
            self.edges = self._extract_edges(result)

            return {
                "attack_paths": self.paths,
                "nodes": self.nodes,
                "edges": self.edges,
                "isolated_findings": result.get("isolated_findings", []),
            }

        except Exception as exc:
            logger.error("Attack graph building failed: %s", exc)
            return self._heuristic_chain(findings)
        finally:
            await llm.close()

    @staticmethod
    def _extract_nodes(findings: list[dict]) -> list[dict[str, Any]]:
        nodes = []
        for f in findings[:30]:
            nodes.append({
                "id": f.get("title", "unknown")[:50],
                "severity": f.get("severity", "info"),
                "type": f.get("source_agent", "unknown"),
                "confidence": f.get("confidence_score", 0.5),
            })
        return nodes

    @staticmethod
    def _extract_edges(result: dict) -> list[dict[str, Any]]:
        edges = []
        for path in result.get("attack_paths", []):
            steps = path.get("steps", [])
            for i in range(len(steps) - 1):
                edges.append({
                    "from": steps[i].get("finding", "")[:50],
                    "to": steps[i + 1].get("finding", "")[:50],
                    "relationship": steps[i].get("edge_to_next", "enables"),
                })
        return edges

    @staticmethod
    def _heuristic_chain(findings: list[dict]) -> dict[str, Any]:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "info"), 0), reverse=True
        )

        paths = []
        high_findings = [f for f in sorted_findings if severity_order.get(f.get("severity", "info"), 0) >= 2]
        if len(high_findings) >= 2:
            steps = []
            for i, f in enumerate(high_findings[:5]):
                role = "entry_point" if i == 0 else ("impact" if i == len(high_findings[:5]) - 1 else "enabler")
                steps.append({
                    "finding": f.get("title", "unknown")[:50],
                    "role": role,
                    "edge_to_next": "enables" if i < len(high_findings[:5]) - 1 else "n/a",
                })
            paths.append({
                "name": "High-severity finding chain",
                "severity": "high",
                "steps": steps,
                "description": "Chain of high-severity findings that could enable escalation",
            })

        return {
            "attack_paths": paths,
            "nodes": AttackGraphBuilder._extract_nodes(findings),
            "edges": [],
            "isolated_findings": [f.get("title", "")[:50] for f in findings if severity_order.get(f.get("severity", "info"), 0) < 2],
        }

    @staticmethod
    def _parse_graph_response(response: str) -> dict[str, Any]:
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

        logger.warning("Failed to parse attack graph response")
        return {"attack_paths": [], "isolated_findings": []}