"""
CFPE-0009: MCP Config Attack detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Secure MCP server configurations",
    "how_to_fix": (
        "1. Validate MCP server configurations\n"
        "2. Use signed configuration files\n"
        "3. Implement configuration audit logging\n"
        "4. Restrict dynamic configuration updates"
    ),
    "references": ["OWASP LLM04", "CWE-16"],
}


class CFPE0009Rule(DetectionRule):
    """MCP Config Attack detection."""

    id = "CFPE-0009"
    name = "MCP Config Attack"
    applies_to = {"mcp_server"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        mcp_servers = {
            node_id for node_id, node in graph.nodes.items() if node.type == "mcp_server"
        }
        if not mcp_servers:
            return findings

        for edge in graph.edges:
            to_node = graph.nodes.get(edge.to_node)
            if edge.from_node in mcp_servers and to_node and to_node.type == "tool":
                findings.append(
                    create_finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        category=Category.COMPOUND_CHAIN,
                        description=f"MCP server '{edge.from_node}' can access tool '{edge.to_node}'",
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["mcp_tool_access"],
                        **REMEDIATION,
                    )
                )

        return findings
