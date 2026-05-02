"""
Graph analysis helpers - extracted common patterns.
"""

from __future__ import annotations

from collections import deque

from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow
from tessera.core.detection.rules.base import Category, Finding, Remediation, Severity


def get_node(graph: Graph, node_id: str) -> Node | None:
    """Get node by ID safely."""
    return graph.nodes.get(node_id)


def has_node_type(graph: Graph, node_type: str) -> bool:
    """Check if graph contains a node of given type."""
    return any(n.type == node_type for n in graph.nodes.values())


def get_nodes_by_type(graph: Graph, node_type: str) -> list[Node]:
    """Get all nodes of a specific type."""
    return [n for n in graph.nodes.values() if n.type == node_type]


def has_trust_boundary(graph: Graph, boundary: TrustBoundary) -> bool:
    """Check if graph has nodes with given trust boundary."""
    return any(n.trust_boundary == boundary for n in graph.nodes.values())


def get_edges_by_flow(graph: Graph, flow: DataFlow) -> list[Edge]:
    """Get all edges with specific data flow type."""
    return [e for e in graph.edges if e.data_flow == flow]


def get_untrusted_edges(graph: Graph) -> list[Edge]:
    """Get edges crossing from untrusted to trusted boundaries."""
    untrusted = {TrustBoundary.EXTERNAL, TrustBoundary.USER_CONTROLLED}
    return [e for e in graph.edges if e.trust_boundary in untrusted]


def is_untrusted_source(node: Node | None) -> bool:
    """Check if node is from untrusted boundary."""
    if node is None:
        return False
    return node.trust_boundary in {
        TrustBoundary.EXTERNAL,
        TrustBoundary.USER_CONTROLLED,
    }


def is_dangerous_target(node: Node | None) -> bool:
    """Check if node is a dangerous target (database, external, etc)."""
    if node is None:
        return False
    return node.type in {
        "database",
        "external_service",
        "memory_store",
        "tool",
    }


def build_adjacency(graph: Graph) -> dict[str, list[str]]:
    """Build adjacency list from graph edges.

    Useful for path finding algorithms.
    """
    adj: dict[str, list[str]] = {node_id: [] for node_id in graph.nodes}
    for edge in graph.edges:
        adj[edge.from_node].append(edge.to_node)
    return adj



def find_paths_bfs(
    graph: Graph,
    start: str,
    max_depth: int = 3,
    allow_cycles: bool = False,
) -> list[list[str]]:
    """Find all paths from start node up to max_depth using BFS."""
    paths: list[list[str]] = []
    queue: deque[tuple[str, list[str], int]] = deque([(start, [start], 0)])
    
    # Optimize edge lookup: map from_node -> list of to_nodes
    adj = {node_id: [] for node_id in graph.nodes}
    for edge in graph.edges:
        adj[edge.from_node].append(edge.to_node)

    while queue:
        node, path, depth = queue.popleft()

        if depth >= max_depth:
            paths.append(path)
            continue

        for neighbor in adj.get(node, []):
            if allow_cycles or neighbor not in path:
                queue.append((neighbor, path + [neighbor], depth + 1))

    return paths


def find_all_paths(
    graph: Graph,
    start: str,
    end: str,
    max_length: int = 4,
) -> list[list[str]]:
    """Find all paths from start to end node."""
    paths: list[list[str]] = []
    
    # Optimize edge lookup
    adj = {node_id: [] for node_id in graph.nodes}
    for edge in graph.edges:
        adj[edge.from_node].append(edge.to_node)

    def dfs(current: str, path: list[str]) -> None:
        if len(path) > max_length:
            return
        if current == end:
            paths.append(path)
            return

        for neighbor in adj.get(current, []):
            if neighbor not in path:
                dfs(neighbor, path + [neighbor])

    dfs(start, [start])
    return paths


def create_finding(
    rule_id: str,
    severity: Severity,
    category: Category,
    description: str,
    edges: list[str],
    indicators: list[str],
    summary: str,
    how_to_fix: str,
    references: list[str] | None = None,
) -> Finding:
    """Factory function to create findings with consistent structure."""
    return Finding(
        id=rule_id,
        severity=severity,
        category=category,
        description=description,
        edges=edges,
        indicators=indicators,
        remediation=Remediation(
            summary=summary,
            how_to_fix=how_to_fix,
            references=references or [],
        ),
    )
