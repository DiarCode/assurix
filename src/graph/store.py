"""GraphStore — NetworkX in-memory graph with SQLite persistence."""

import asyncio
from typing import TYPE_CHECKING

import networkx as nx
from sqlalchemy import select

from src.db.models import GraphEdge, GraphNode
from src.graph.models import AttackPath, GraphEdgeModel, GraphNodeModel, GraphStats

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class GraphStore:
    """Bridge between NetworkX DiGraph and SQLite adjacency tables."""

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        self._graph: nx.DiGraph = nx.DiGraph()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Hydration / Persistence
    # ------------------------------------------------------------------

    async def hydrate(self, session: "AsyncSession") -> None:
        """Load graph from SQLite into NetworkX."""
        async with self._lock:
            self._graph.clear()

            stmt_nodes = select(GraphNode).where(GraphNode.engagement_id == self.engagement_id)
            result_nodes = await session.execute(stmt_nodes)
            for node in result_nodes.scalars().all():
                self._graph.add_node(
                    node.id,
                    engagement_id=node.engagement_id,
                    node_type=node.node_type,
                    label=node.label,
                    **node.properties,
                )

            stmt_edges = select(GraphEdge).where(GraphEdge.engagement_id == self.engagement_id)
            result_edges = await session.execute(stmt_edges)
            for edge in result_edges.scalars().all():
                if edge.source_id in self._graph and edge.target_id in self._graph:
                    self._graph.add_edge(
                        edge.source_id,
                        edge.target_id,
                        id=edge.id,
                        engagement_id=edge.engagement_id,
                        edge_type=edge.edge_type,
                        **edge.properties,
                    )

    async def persist_all(self, session: "AsyncSession") -> None:
        """Replace all graph rows in SQLite with current NetworkX state."""
        async with self._lock:
            await session.execute(
                select(GraphNode).where(GraphNode.engagement_id == self.engagement_id)
            )
            await session.execute(
                select(GraphEdge).where(GraphEdge.engagement_id == self.engagement_id)
            )
            # SQLAlchemy delete-where pattern
            from sqlalchemy import delete

            await session.execute(
                delete(GraphNode).where(GraphNode.engagement_id == self.engagement_id)
            )
            await session.execute(
                delete(GraphEdge).where(GraphEdge.engagement_id == self.engagement_id)
            )

            for node_id, attrs in self._graph.nodes(data=True):
                node = GraphNode(
                    id=node_id,
                    engagement_id=self.engagement_id,
                    node_type=attrs.get("node_type", "unknown"),
                    label=attrs.get("label", ""),
                    properties={k: v for k, v in attrs.items() if k not in {"node_type", "label"}},
                )
                session.add(node)

            for source, target, attrs in self._graph.edges(data=True):
                edge = GraphEdge(
                    id=attrs.get("id", f"{source}_{target}"),
                    engagement_id=self.engagement_id,
                    source_id=source,
                    target_id=target,
                    edge_type=attrs.get("edge_type", "RELATED_TO"),
                    properties={k: v for k, v in attrs.items() if k not in {"id", "edge_type"}},
                )
                session.add(edge)

    async def persist_incremental(
        self,
        session: "AsyncSession",
        nodes: list[GraphNodeModel] | None = None,
        edges: list[GraphEdgeModel] | None = None,
    ) -> None:
        """Insert new nodes/edges without deleting existing rows."""
        async with self._lock:
            for n in nodes or []:
                if n.id not in self._graph:
                    self._graph.add_node(
                        n.id,
                        engagement_id=n.engagement_id,
                        node_type=n.node_type,
                        label=n.label,
                        **n.properties,
                    )
                    session.add(
                        GraphNode(
                            id=n.id,
                            engagement_id=n.engagement_id,
                            node_type=n.node_type,
                            label=n.label,
                            properties=n.properties,
                        )
                    )

            for e in edges or []:
                if not self._graph.has_edge(e.source_id, e.target_id):
                    self._graph.add_edge(
                        e.source_id,
                        e.target_id,
                        id=e.id,
                        engagement_id=e.engagement_id,
                        edge_type=e.edge_type,
                        **e.properties,
                    )
                    session.add(
                        GraphEdge(
                            id=e.id,
                            engagement_id=e.engagement_id,
                            source_id=e.source_id,
                            target_id=e.target_id,
                            edge_type=e.edge_type,
                            properties=e.properties,
                        )
                    )

    # ------------------------------------------------------------------
    # Local mutations
    # ------------------------------------------------------------------

    async def add_node(self, node: GraphNodeModel) -> None:
        async with self._lock:
            self._graph.add_node(
                node.id,
                engagement_id=node.engagement_id,
                node_type=node.node_type,
                label=node.label,
                **node.properties,
            )

    async def add_edge(self, edge: GraphEdgeModel) -> None:
        async with self._lock:
            self._graph.add_edge(
                edge.source_id,
                edge.target_id,
                id=edge.id,
                engagement_id=edge.engagement_id,
                edge_type=edge.edge_type,
                **edge.properties,
            )

    # ------------------------------------------------------------------
    # Algorithms
    # ------------------------------------------------------------------

    async def find_attack_paths(
        self,
        source_type: str = "asset",
        target_type: str = "verified_finding",
        max_length: int = 10,
        top_n: int = 5,
    ) -> list[AttackPath]:
        """Return shortest paths from source-type nodes to target-type nodes."""
        async with self._lock:
            sources = [
                n
                for n, attrs in self._graph.nodes(data=True)
                if attrs.get("node_type") == source_type
            ]
            targets = [
                n
                for n, attrs in self._graph.nodes(data=True)
                if attrs.get("node_type") == target_type
            ]

            paths: list[AttackPath] = []
            for src in sources:
                for tgt in targets:
                    try:
                        sp = nx.shortest_path(self._graph, source=src, target=tgt)
                    except nx.NetworkXNoPath:
                        continue
                    if len(sp) > max_length:
                        continue
                    nodes = []
                    edges = []
                    for i, node_id in enumerate(sp):
                        attrs = self._graph.nodes[node_id]
                        nodes.append(
                            GraphNodeModel(
                                id=node_id,
                                engagement_id=self.engagement_id,
                                node_type=attrs.get("node_type", "unknown"),
                                label=attrs.get("label", ""),
                                properties={
                                    k: v
                                    for k, v in attrs.items()
                                    if k not in {"node_type", "label"}
                                },
                            )
                        )
                        if i < len(sp) - 1:
                            edge_attrs = self._graph.edges[node_id, sp[i + 1]]
                            edges.append(
                                GraphEdgeModel(
                                    id=edge_attrs.get("id", f"{node_id}_{sp[i + 1]}"),
                                    engagement_id=self.engagement_id,
                                    source_id=node_id,
                                    target_id=sp[i + 1],
                                    edge_type=edge_attrs.get("edge_type", "RELATED_TO"),
                                    properties={
                                        k: v
                                        for k, v in edge_attrs.items()
                                        if k not in {"id", "edge_type"}
                                    },
                                )
                            )
                    score = 1.0 / len(sp)
                    paths.append(
                        AttackPath(nodes=nodes, edges=edges, length=len(sp) - 1, score=score)
                    )

            paths.sort(key=lambda p: (-p.score, p.length))
            return paths[:top_n]

    async def page_rank(self, alpha: float = 0.85) -> dict[str, float]:
        """Return PageRank scores for all nodes."""
        async with self._lock:
            if self._graph.number_of_nodes() == 0:
                return {}
            return nx.pagerank(self._graph, alpha=alpha)

    async def get_critical_nodes(self, top_n: int = 10) -> list[dict]:
        """Return highest PageRank nodes with metadata."""
        pr = await self.page_rank()
        sorted_nodes = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {
                "node_id": nid,
                "score": score,
                "label": self._graph.nodes[nid].get("label", ""),
                "node_type": self._graph.nodes[nid].get("node_type", "unknown"),
            }
            for nid, score in sorted_nodes
        ]

    async def stats(self) -> GraphStats:
        """Compute summary statistics."""
        async with self._lock:
            g = self._graph
            node_count = g.number_of_nodes()
            edge_count = g.number_of_edges()
            node_type_counts: dict[str, int] = {}
            edge_type_counts: dict[str, int] = {}
            for _, attrs in g.nodes(data=True):
                nt = attrs.get("node_type", "unknown")
                node_type_counts[nt] = node_type_counts.get(nt, 0) + 1
            for _, _, attrs in g.edges(data=True):
                et = attrs.get("edge_type", "RELATED_TO")
                edge_type_counts[et] = edge_type_counts.get(et, 0) + 1
            density = nx.density(g) if node_count > 1 else 0.0
            avg_degree = sum(dict(g.degree()).values()) / node_count if node_count else 0.0
            return GraphStats(
                engagement_id=self.engagement_id,
                node_count=node_count,
                edge_count=edge_count,
                node_type_counts=node_type_counts,
                edge_type_counts=edge_type_counts,
                density=density,
                avg_degree=avg_degree,
            )
