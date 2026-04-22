"""
CFPE-0002: Memory Poisoning detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    has_node_type,
    get_edges_by_flow,
    create_finding,
)
from tessera.core.topology.models import Graph, DataFlow


REMEDIATION = {
    "summary": "Use read-only memory for RAG context",
    "how_to_fix": (
        "1. Use read-only memory stores for RAG context\n"
        "2. Implement memory integrity verification\n"
        "3. Separate user context from system memory\n"
        "4. Add memory signing/verification"
    ),
    "references": ["OWASP LLM03", "CWE-20"],
}


class CFPE0002Rule(DetectionRule):
    """Memory Poisoning detection.

    Detects when an LLM can write to persistent memory stores,
    enabling prompt injection through memory manipulation.

    Research: Working memory limitations (Miller's 7±2) mean developers
    can't track all memory modifications. (Cognitive Load Theory)
    """

    id = "CFPE-0002"
    name = "Memory Poisoning"
    applies_to = {"llm", "model", "memory_store"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        if not has_node_type(graph, "memory_store"):
            return findings

        # Check for write operations to memory
        write_edges = get_edges_by_flow(graph, DataFlow.READ_WRITE)

        for edge in write_edges:
            target = graph.nodes.get(edge.to_node)
            if not target or target.type not in {"memory_store", "memory"}:
                continue
            findings.append(
                create_finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    category=Category.COMPOUND_CHAIN,
                    description="Memory poisoning risk - write to persistent memory",
                    edges=[f"{edge.from_node}->{edge.to_node}"],
                    indicators=["memory_persist"],
                    **REMEDIATION,
                )
            )

        return findings
