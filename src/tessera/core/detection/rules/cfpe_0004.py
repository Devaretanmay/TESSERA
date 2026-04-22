"""
CFPE-0004: Agent Context Propagation detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    get_node,
    create_finding,
)
from tessera.core.topology.models import Graph, TrustBoundary


REMEDIATION = {
    "summary": "Implement trust boundary validation and data sanitization",
    "how_to_fix": (
        "1. Define clear trust boundaries\n"
        "2. Validate data at each boundary\n"
        "3. Implement sanitization functions\n"
        "4. Add firewall rules for cross-boundary flows"
    ),
    "references": ["OWASP LLM04", "CWE-20"],
}


class CFPE0004Rule(DetectionRule):
    """Trust Boundary Bypass detection.

    Detects data flows crossing trust boundaries without validation.
    """

    id = "CFPE-0004"
    name = "Agent Context Propagation"
    applies_to = {"llm", "model", "tool"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = get_node(graph, edge.from_node)
            to_node = get_node(graph, edge.to_node)

            if from_node and to_node:
                if from_node.trust_boundary != to_node.trust_boundary:
                    if edge.trust_boundary == TrustBoundary.EXTERNAL:
                        findings.append(
                            create_finding(
                                rule_id=self.id,
                                severity=Severity.HIGH,
                                category=Category.TRUST_BOUNDARY_BYPASS,
                                description=f"Untrusted data flows to {edge.to_node}",
                                edges=[f"{edge.from_node}->{edge.to_node}"],
                                indicators=["trust_crossing"],
                                **REMEDIATION,
                            )
                        )

        return findings
