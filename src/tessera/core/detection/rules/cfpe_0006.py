"""
CFPE-0006: Tool to Tool Chaining detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Limit tool-to-tool communication",
    "how_to_fix": (
        "1. Limit tool-to-tool communication\n"
        "2. Implement isolation between tools\n"
        "3. Add validation at each tool boundary\n"
        "4. Use least-privilege for tool access"
    ),
    "references": ["OWASP LLM02", "CWE-862"],
}


class CFPE0006Rule(DetectionRule):
    """Tool to Tool Chaining detection."""

    id = "CFPE-0006"
    name = "Tool to Tool Chaining"
    applies_to = {"tool"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        tools = {node_id for node_id, node in graph.nodes.items() if node.type == "tool"}
        if len(tools) < 2:
            return findings

        tool_to_tool_edges = [
            f"{edge.from_node}->{edge.to_node}"
            for edge in graph.edges
            if edge.from_node in tools and edge.to_node in tools
        ]

        if tool_to_tool_edges:
            findings.append(
                create_finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM,
                    category=Category.COMPOUND_CHAIN,
                    description="Tool-to-tool chaining detected",
                    edges=tool_to_tool_edges,
                    indicators=["tool_chain"],
                    **REMEDIATION,
                )
            )

        return findings
