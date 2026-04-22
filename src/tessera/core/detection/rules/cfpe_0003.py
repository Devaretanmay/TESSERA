"""
CFPE-0003: External to Database detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    get_node,
    is_untrusted_source,
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Add validation layer between external inputs and database",
    "how_to_fix": (
        "1. Add input validation layer before database access\n"
        "2. Use parameterized queries\n"
        "3. Implement database firewall rules\n"
        "4. Add rate limiting on database endpoints\n"
        "5. Use connection pooling with access controls"
    ),
    "references": ["OWASP LLM04", "CWE-20", "CWE-89"],
}


class CFPE0003Rule(DetectionRule):
    """External to Database attack detection.

    Detects when untrusted/external data can directly access databases
    without proper validation.

    Nielsen's Error Prevention: Prevent errors before they occur.
    """

    id = "CFPE-0003"
    name = "External to Database"
    applies_to = {"external", "user", "database", "user_controlled"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = get_node(graph, edge.from_node)
            to_node = get_node(graph, edge.to_node)

            is_database = to_node is not None and to_node.type == "database"
            if is_untrusted_source(from_node) and is_database:
                findings.append(
                    create_finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        category=Category.TRUST_BOUNDARY_BYPASS,
                        description=(
                            f"Untrusted source '{edge.from_node}' directly accesses "
                            f"database '{edge.to_node}'"
                        ),
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["untrusted_database_access"],
                        **REMEDIATION,
                    )
                )

        return findings
