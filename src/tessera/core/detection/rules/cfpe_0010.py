"""
CFPE-0010: Agent Skill Injection detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Protect agent skill definitions from injection",
    "how_to_fix": (
        "1. Protect agent skill definitions from injection\n"
        "2. Use read-only skill stores\n"
        "3. Implement skill signing/verification\n"
        "4. Restrict dynamic skill loading"
    ),
    "references": ["OWASP LLM03", "CWE-346"],
}


class CFPE0010Rule(DetectionRule):
    """Agent Skill Injection detection."""

    id = "CFPE-0010"
    name = "Agent Skill Injection"
    applies_to = {"llm", "skill"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        skill_nodes = {node_id for node_id, node in graph.nodes.items() if node.type == "skill"}
        external_nodes = {
            node_id
            for node_id, node in graph.nodes.items()
            if node.trust_boundary.value == "external"
        }
        if not skill_nodes or not external_nodes:
            return findings

        for edge in graph.edges:
            if edge.from_node in external_nodes and edge.to_node in skill_nodes:
                findings.append(
                    create_finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        category=Category.ATOMIC_INJECTION,
                        description=(
                            f"External source '{edge.from_node}' can modify skill '{edge.to_node}'"
                        ),
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["skill_injection"],
                        **REMEDIATION,
                    )
                )

        return findings
