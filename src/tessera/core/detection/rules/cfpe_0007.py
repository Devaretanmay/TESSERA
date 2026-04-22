"""
CFPE-0007: Sensitive Data Exfiltration detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Prevent sensitive data from being sent to external services",
    "how_to_fix": (
        "1. Implement output filtering for sensitive data\n"
        "2. Add data loss prevention (DLP) checks\n"
        "3. Use internal tools for sensitive operations\n"
        "4. Add audit logging for external calls\n"
        "5. Implement rate limiting on external APIs"
    ),
    "references": ["OWASP LLM06", "CWE-306"],
}


class CFPE0007Rule(DetectionRule):
    """Sensitive Data Exfiltration detection."""

    id = "CFPE-0007"
    name = "Sensitive Data Exfiltration"
    applies_to = {"llm", "model", "external_service"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = graph.nodes.get(edge.from_node)
            to_node = graph.nodes.get(edge.to_node)
            if not from_node or not to_node:
                continue
            from_is_llm = from_node.type in {"llm", "model"}
            to_is_external = to_node.type == "external_service"
            if from_is_llm and to_is_external:
                findings.append(
                    create_finding(
                        rule_id=self.id,
                        severity=Severity.CRITICAL,
                        category=Category.COMPOUND_CHAIN,
                        description=f"LLM can send data to external service '{edge.to_node}'",
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["data_exfiltration"],
                        **REMEDIATION,
                    )
                )

        return findings
