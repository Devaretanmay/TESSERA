"""
Detection patterns for AI/Agent security vulnerabilities.

CFPE patterns - deterministic rules, no randomness.
"""

from dataclasses import dataclass
from enum import Enum
from tessera.core.topology.models import Graph, Edge, TrustBoundary, DataFlow


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    COMPOUND_CHAIN = "compound_chain"
    ATOMIC_INJECTION = "atomic_injection"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


@dataclass
class Finding:
    """Immutable finding."""

    id: str
    severity: Severity
    category: Category
    description: str
    edges: list[str]
    indicators: list[str]


class DetectionRule:
    """Base rule."""

    id: str
    name: str
    applies_to: set[str]

    def detect(self, graph: Graph) -> list[Finding]:
        raise NotImplementedError


class CFPE0001Rule(DetectionRule):
    """RAG → Tool execution chain."""

    id = "CFPE-0001"
    name = "RAG to Tool"
    applies_to = {"llm", "model", "rag_corpus", "tool"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        node_types = {n.type for n in graph.nodes.values()}

        if self.applies_to & node_types == self.applies_to:
            has_rag = any(n.type in ("rag_corpus", "model") for n in graph.nodes.values())
            has_tool = any(n.type == "tool" for n in graph.nodes.values())

            if has_rag and has_tool:
                edge_ids = []
                for edge in graph.edges:
                    if edge.data_flow == DataFlow.TOOL_CALL:
                        edge_ids.append(f"{edge.from_node}->{edge.to_node}")

                if edge_ids:
                    findings.append(
                        Finding(
                            id=self.id,
                            severity=Severity.HIGH,
                            category=Category.COMPOUND_CHAIN,
                            description="RAG to Tool execution chain detected",
                            edges=edge_ids,
                            indicators=["rag_tool_chain"],
                        )
                    )

        return findings


class CFPE0002Rule(DetectionRule):
    """Memory poisoning."""

    id = "CFPE-0002"
    name = "Memory Poisoning"
    applies_to = {"llm", "model", "memory_store"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        node_types = {n.type for n in graph.nodes.values()}

        if "memory_store" in node_types or "memory" in node_types:
            for edge in graph.edges:
                if edge.data_flow == DataFlow.READ_WRITE:
                    findings.append(
                        Finding(
                            id=self.id,
                            severity=Severity.CRITICAL,
                            category=Category.COMPOUND_CHAIN,
                            description="Memory poisoning risk - write to persistent memory",
                            edges=[f"{edge.from_node}->{edge.to_node}"],
                            indicators=["memory_persist"],
                        )
                    )

        return findings


class CFPE0004Rule(DetectionRule):
    """Agent context propagation."""

    id = "CFPE-0004"
    name = "Agent Context Propagation"
    applies_to = {"llm", "model", "tool"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = graph.nodes.get(edge.from_node)
            to_node = graph.nodes.get(edge.to_node)

            if (
                from_node
                and to_node
                and from_node.trust_boundary != to_node.trust_boundary
                and edge.trust_boundary == TrustBoundary.EXTERNAL
            ):
                findings.append(
                    Finding(
                        id=self.id,
                        severity=Severity.HIGH,
                        category=Category.TRUST_BOUNDARY_BYPASS,
                        description=f"Untrusted data flows to {edge.to_node}",
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["trust_crossing"],
                    )
                )

        return findings


RULES = [
    CFPE0001Rule(),
    CFPE0002Rule(),
    CFPE0004Rule(),
]


def detect(graph: Graph) -> list[Finding]:
    """Run all detection rules."""
    results = []
    for rule in RULES:
        results.extend(rule.detect(graph))
    return results
