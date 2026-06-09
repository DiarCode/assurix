"""CodebaseIntelligenceAgent: Extends ReconAgent with AST-based codebase analysis.

Called by ResearchLoop before hypothesis generation. Parses the target codebase,
builds a knowledge graph, and produces a ranked attack surface. The ResearchLoop
uses this output to seed HypothesisGenerator with more accurate hypotheses.
"""

import logging
from typing import Any
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.codebase_intelligence.parser import TreeSitterParser
from src.agents.codebase_intelligence.graph_builder import KnowledgeGraphBuilder
from src.agents.codebase_intelligence.surface_ranker import AttackSurfaceRanker
from src.core.audit import log_action
from src.schemas.surface import AttackSurface, EndpointNode

logger = logging.getLogger(__name__)


class CodebaseIntelligenceAgent(BaseAgent):
    """Analyzes codebase structure to produce knowledge graphs and ranked attack surfaces.

    Extends ReconAgent by providing deeper code-level analysis:
    - AST parsing via tree-sitter (with LLM fallback)
    - Knowledge graph construction (call graphs, data flows, auth boundaries)
    - Attack surface ranking by risk factors

    Called by ResearchLoop before hypothesis generation.
    """

    name = "codebase_intelligence"

    def __init__(self) -> None:
        from src.llm.frontier_client import UnifiedLLMClient
        self.parser = TreeSitterParser(llm_client=UnifiedLLMClient())
        self.graph_builder = KnowledgeGraphBuilder()
        self.ranker = AttackSurfaceRanker()

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        """Analyze a codebase and produce knowledge graph + ranked attack surface.

        Args:
            payload: Must contain 'repo_path' or 'target_url'. May contain
                     'surface' data from ReconAgent.
            session: Active database session.

        Returns:
            Dict with keys: knowledge_graph_stats, ranked_surface, parsed_data.
        """
        repo_path = payload.get("repo_path", "")
        engagement_id = payload.get("engagement_id", "")
        surface_data = payload.get("surface", payload.get("previous_result", {}).get("surface", {}))

        # Phase 1: Parse codebase (if repo path provided)
        parsed_data: dict[str, list] = {}
        if repo_path and Path(repo_path).is_dir():
            parsed_data = await self.parser.parse_codebase(repo_path)
            await log_action(
                session=session,
                action="codebase_parsed",
                actor="codebase_intelligence",
                payload={
                    "engagement_id": engagement_id,
                    "repo_path": repo_path,
                    "functions_found": len(parsed_data.get("functions", [])),
                    "http_handlers_found": len(parsed_data.get("http_handlers", [])),
                    "auth_decorators_found": len(parsed_data.get("auth_decorators", [])),
                    "dangerous_functions_found": len(parsed_data.get("dangerous_functions", [])),
                },
            )

        # Phase 2: Build knowledge graph from parsed data
        graph = self.graph_builder.build_from_parsed(parsed_data)
        graph_stats = self.graph_builder.get_graph_stats()

        # Persist graph to database if engagement_id provided
        if engagement_id:
            try:
                await self.graph_builder.persist_to_db(engagement_id, session)
            except Exception as exc:
                logger.warning("Failed to persist knowledge graph: %s", exc)

        # Phase 3: Build and rank attack surface
        # Merge surface data from ReconAgent with codebase analysis
        merged_surface = self._merge_surface_data(surface_data, parsed_data)
        ranked_surface = self.ranker.rank_surface(merged_surface, graph_data=graph_stats)

        # Convert ranked surface to AttackSurface model for ResearchLoop
        attack_surface = self._build_attack_surface(merged_surface, ranked_surface)

        await log_action(
            session=session,
            action="attack_surface_ranked",
            actor="codebase_intelligence",
            payload={
                "engagement_id": engagement_id,
                "total_endpoints": len(ranked_surface),
                "high_risk_endpoints": sum(1 for e in ranked_surface if e.get("risk_score", 0) > 0.7),
                "graph_stats": graph_stats,
            },
        )

        return {
            "findings": [],
            "artifacts": [],
            "knowledge_graph_stats": graph_stats,
            "ranked_surface": ranked_surface,
            "attack_surface": attack_surface.model_dump() if isinstance(attack_surface, AttackSurface) else attack_surface,
            "parsed_data_summary": {
                "functions": len(parsed_data.get("functions", [])),
                "http_handlers": len(parsed_data.get("http_handlers", [])),
                "auth_decorators": len(parsed_data.get("auth_decorators", [])),
                "dangerous_functions": len(parsed_data.get("dangerous_functions", [])),
                "env_vars": len(parsed_data.get("env_vars", [])),
                "data_models": len(parsed_data.get("data_models", [])),
            },
            "agent": "codebase_intelligence",
        }

    def _merge_surface_data(
        self, surface_data: dict[str, Any], parsed_data: dict[str, list]
    ) -> dict[str, Any]:
        """Merge ReconAgent surface data with codebase analysis data."""
        merged = dict(surface_data) if surface_data else {}

        # Add parsed endpoints to surface
        if "endpoints" not in merged:
            merged["endpoints"] = []

        for handler in parsed_data.get("http_handlers", []):
            merged["endpoints"].append({
                "url": handler.get("file", ""),
                "method": "GET",
                "auth_required": False,
                "source": "codebase_intelligence",
            })

        # Add parsed technologies
        existing_techs = set(merged.get("technologies", []))
        # Infer technologies from imports
        for imp in parsed_data.get("imports", []):
            text = imp.get("text", "").lower()
            if "django" in text or "from django" in text:
                existing_techs.add("Django")
            if "flask" in text or "from flask" in text:
                existing_techs.add("Flask")
            if "fastapi" in text or "from fastapi" in text:
                existing_techs.add("FastAPI")
            if "sqlalchemy" in text:
                existing_techs.add("SQLAlchemy")
        merged["technologies"] = list(existing_techs)

        return merged

    def _build_attack_surface(
        self, surface_data: dict[str, Any], ranked_surface: list[dict[str, Any]]
    ) -> AttackSurface:
        """Build an AttackSurface model from merged surface data and ranking."""
        # Convert ranked endpoints to EndpointNode models
        endpoint_nodes = []
        for entry in ranked_surface:
            endpoint_nodes.append(EndpointNode(
                url=entry.get("url", ""),
                method=entry.get("method", "GET"),
                auth_required=entry.get("auth_required", False),
                data_sensitivity=entry.get("data_sensitivity", "low"),
            ))

        return AttackSurface(
            target_url=surface_data.get("target_url", surface_data.get("pages", [""])[0] if surface_data.get("pages") else ""),
            endpoints=endpoint_nodes,
            technologies=surface_data.get("technologies", []),
            auth_pages=surface_data.get("auth_pages", []),
            forms=surface_data.get("forms", []),
            headers=surface_data.get("headers", {}),
            raw_surface=surface_data,
        )