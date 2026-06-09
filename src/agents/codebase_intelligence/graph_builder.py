"""KnowledgeGraphBuilder: Produces NetworkX directed graph from parsed code.

Builds a knowledge graph with nodes (services, endpoints, data flows, trust boundaries)
and edges (calls, data_flows, auth_boundaries). Stored in GraphNode/GraphEdge
database models for persistence and querying by ResearchLoop.
"""

import logging
from typing import Any
from uuid import uuid4

import networkx as nx

from src.db.models import GraphEdge, GraphNode
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class KnowledgeGraphBuilder:
    """Builds a knowledge graph from parsed codebase data.

    Takes the output of TreeSitterParser and constructs a directed graph
    where:
    - Nodes represent services, endpoints, data models, functions, trust boundaries
    - Edges represent calls, data flows, authentication boundaries

    The graph is stored both in-memory (NetworkX) for algorithmic analysis
    and in the database (GraphNode/GraphEdge) for persistence.
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def build_from_parsed(self, parsed_data: dict[str, list[dict[str, Any]]]) -> nx.DiGraph:
        """Build a knowledge graph from TreeSitterParser output.

        Args:
            parsed_data: Output from TreeSitterParser.parse_codebase()

        Returns:
            NetworkX DiGraph with security-relevant nodes and edges.
        """
        # Add HTTP handler nodes
        for handler in parsed_data.get("http_handlers", []):
            self._add_endpoint_node(handler)

        # Add authentication boundary nodes
        for auth in parsed_data.get("auth_decorators", []):
            self._add_auth_node(auth)

        # Add data model nodes
        for model in parsed_data.get("data_models", []):
            self._add_model_node(model)

        # Add function nodes with security context
        for func in parsed_data.get("functions", []):
            self._add_function_node(func)

        # Add dangerous function nodes
        for dangerous in parsed_data.get("dangerous_functions", []):
            self._add_dangerous_node(dangerous)

        # Add environment variable nodes
        for env_var in parsed_data.get("env_vars", []):
            self._add_env_node(env_var)

        # Build edges from call relationships
        self._infer_edges(parsed_data)

        return self.graph

    def _add_endpoint_node(self, handler: dict[str, Any]) -> str:
        """Add an HTTP endpoint node to the graph."""
        node_id = f"endpoint:{handler.get('file', '')}:{handler.get('line', 0)}"
        self.graph.add_node(
            node_id,
            node_type="endpoint",
            label=handler.get("pattern", handler.get("name", "unknown")),
            properties={
                "file": handler.get("file", ""),
                "line": handler.get("line", 0),
                "description": handler.get("line_text", ""),
            },
        )
        return node_id

    def _add_auth_node(self, auth: dict[str, Any]) -> str:
        """Add an authentication boundary node."""
        node_id = f"auth:{auth.get('file', '')}:{auth.get('line', 0)}"
        self.graph.add_node(
            node_id,
            node_type="auth_boundary",
            label=auth.get("pattern", "auth_check"),
            properties={
                "file": auth.get("file", ""),
                "line": auth.get("line", 0),
                "description": auth.get("line_text", ""),
            },
        )
        return node_id

    def _add_model_node(self, model: dict[str, Any]) -> str:
        """Add a data model node."""
        node_id = f"model:{model.get('name', 'unknown')}:{model.get('file', '')}"
        self.graph.add_node(
            node_id,
            node_type="data_model",
            label=model.get("name", "unknown"),
            properties={
                "file": model.get("file", ""),
                "line": model.get("line", 0),
            },
        )
        return node_id

    def _add_function_node(self, func: dict[str, Any]) -> str:
        """Add a function node with security context."""
        node_id = f"func:{func.get('name', 'unknown')}:{func.get('file', '')}:{func.get('line', 0)}"
        self.graph.add_node(
            node_id,
            node_type="function",
            label=func.get("name", "unknown"),
            properties={
                "file": func.get("file", ""),
                "line": func.get("line", 0),
                "end_line": func.get("end_line", func.get("line", 0)),
            },
        )
        return node_id

    def _add_dangerous_node(self, dangerous: dict[str, Any]) -> str:
        """Add a dangerous function call node."""
        node_id = f"dangerous:{dangerous.get('pattern', 'unknown')}:{dangerous.get('file', '')}:{dangerous.get('line', 0)}"
        self.graph.add_node(
            node_id,
            node_type="dangerous_function",
            label=dangerous.get("pattern", "unknown"),
            properties={
                "file": dangerous.get("file", ""),
                "line": dangerous.get("line", 0),
                "description": dangerous.get("line_text", ""),
            },
        )
        return node_id

    def _add_env_node(self, env_var: dict[str, Any]) -> str:
        """Add an environment variable reference node."""
        node_id = f"env:{env_var.get('file', '')}:{env_var.get('line', 0)}"
        self.graph.add_node(
            node_id,
            node_type="env_var",
            label=env_var.get("pattern", "env_var"),
            properties={
                "file": env_var.get("file", ""),
                "line": env_var.get("line", 0),
                "description": env_var.get("line_text", ""),
            },
        )
        return node_id

    def _infer_edges(self, parsed_data: dict[str, list[dict[str, Any]]]) -> None:
        """Infer edges between nodes based on co-location and naming patterns.

        This is a heuristic approach — LLM fallback can provide more accurate edges.
        """
        # Connect auth decorators to nearby endpoints
        for auth in parsed_data.get("auth_decorators", []):
            auth_id = f"auth:{auth.get('file', '')}:{auth.get('line', 0)}"
            for handler in parsed_data.get("http_handlers", []):
                if handler.get("file") == auth.get("file"):
                    endpoint_id = f"endpoint:{handler.get('file', '')}:{handler.get('line', 0)}"
                    self.graph.add_edge(
                        endpoint_id, auth_id,
                        edge_type="auth_check",
                        properties={"confidence": "heuristic"},
                    )

        # Connect dangerous functions to their containing function
        for dangerous in parsed_data.get("dangerous_functions", []):
            dangerous_id = f"dangerous:{dangerous.get('pattern', 'unknown')}:{dangerous.get('file', '')}:{dangerous.get('line', 0)}"
            for func in parsed_data.get("functions", []):
                if func.get("file") == dangerous.get("file"):
                    func_start = func.get("line", 0)
                    func_end = func.get("end_line", func_start)
                    if func_start <= dangerous.get("line", 0) <= func_end:
                        func_id = f"func:{func.get('name', 'unknown')}:{func.get('file', '')}:{func.get('line', 0)}"
                        self.graph.add_edge(
                            func_id, dangerous_id,
                            edge_type="contains_dangerous",
                            properties={"confidence": "heuristic"},
                        )

    async def persist_to_db(self, engagement_id: str, session: AsyncSession) -> None:
        """Persist the knowledge graph to the database.

        Stores nodes and edges as GraphNode and GraphEdge records.
        """
        # Persist nodes
        for node_id, node_data in self.graph.nodes(data=True):
            graph_node = GraphNode(
                id=str(uuid4()),
                engagement_id=engagement_id,
                node_type=node_data.get("node_type", "unknown"),
                label=node_data.get("label", node_id),
                properties=node_data.get("properties", {}),
            )
            session.add(graph_node)

        # Persist edges
        for source_id, target_id, edge_data in self.graph.edges(data=True):
            graph_edge = GraphEdge(
                id=str(uuid4()),
                engagement_id=engagement_id,
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_data.get("edge_type", "unknown"),
                properties=edge_data.get("properties", {}),
            )
            session.add(graph_edge)

        await session.flush()
        logger.info(
            "KnowledgeGraphBuilder: persisted %d nodes and %d edges for engagement %s",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
            engagement_id,
        )

    def get_graph_stats(self) -> dict[str, int]:
        """Get statistics about the built graph."""
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "endpoints": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == "endpoint"
            ),
            "auth_boundaries": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == "auth_boundary"
            ),
            "data_models": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == "data_model"
            ),
            "dangerous_functions": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == "dangerous_function"
            ),
        }