"""
CFPE-0005: Multi-hop Attack Chain detection rule.

Research: Cognitive complexity increases with nesting depth.
This rule uses simple linear algorithms for clarity.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    get_node,
    is_untrusted_source,
    is_dangerous_target,
    build_adjacency,
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Break long attack chains with validation points",
    "how_to_fix": (
        "1. Break long chains with validation points\n"
        "2. Implement multiple security layers\n"
        "3. Monitor chain interactions\n"
        "4. Add circuit breakers between hops\n"
        "5. Log and alert on multi-hop flows"
    ),
    "references": ["OWASP LLM02", "MITRE ATT&CK"],
}


DANGEROUS_TYPES = frozenset({"tool", "database", "external_service", "memory_store"})


class CFPE0005Rule(DetectionRule):
    """Multi-hop Attack Chain detection.

    Detects complex attack chains spanning 3+ edges.
    Uses simple BFS for cognitive simplicity.
    """

    id = "CFPE-0005"
    name = "Multi-hop Attack Chain"
    applies_to = {"llm", "tool", "rag_corpus", "memory_store", "database"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        adj = build_adjacency(graph)

        for start_id in graph.nodes:
            for path in _find_long_paths(adj, graph, start_id):
                findings.append(
                    create_finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        category=Category.COMPOUND_CHAIN,
                        description=f"Multi-hop attack chain ({len(path)} hops): {' -> '.join(path)}",
                        edges=[f"{path[i]}->{path[i + 1]}" for i in range(len(path) - 1)],
                        indicators=["multi_hop_chain"],
                        **REMEDIATION,
                    )
                )

        return findings


def _find_long_paths(
    adj: dict[str, list[str]],
    graph: Graph,
    start: str,
    max_depth: int = 3,
) -> list[list[str]]:
    """Find paths of max_depth+ from start to dangerous target."""
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str], int]] = [(start, [start], 0)]

    while stack:
        node, path, depth = stack.pop()

        if depth >= max_depth:
            end_node = get_node(graph, path[-1])
            if is_dangerous_target(end_node):
                start_node = get_node(graph, path[0])
                if is_untrusted_source(start_node):
                    paths.append(path)
            continue

        for neighbor in adj.get(node, []):
            if neighbor not in path:
                stack.append((neighbor, path + [neighbor], depth + 1))

    return paths
