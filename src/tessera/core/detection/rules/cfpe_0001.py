"""
CFPE-0001: RAG to Tool detection rule.

Research: Cognitive Load Theory suggests breaking complex patterns into smaller,
understandable chunks. This file contains ONLY this one rule.
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
    "summary": "Validate RAG outputs before tool execution",
    "how_to_fix": (
        "1. Validate RAG outputs before tool execution\n"
        "2. Implement least-privilege for tool access\n"
        "3. Add output sanitization between RAG and tools\n"
        "4. Use separate privilege boundaries"
    ),
    "references": ["OWASP LLM02", "CWE-20"],
}


class CFPE0001Rule(DetectionRule):
    """RAG to Tool execution chain detection.

    Detects when an LLM can chain through RAG knowledge retrieval to execute tools,
    enabling potential prompt injection attacks.

    Example vulnerable topology:
        rag_corpus -> knowledge_base -> search_tool
                       |
                       v
        llm ---------> tool_executor

    Research basis: Compound attack chains amplify risk by combining
    multiple vulnerabilities. (MITRE ATT&CK)
    """

    id = "CFPE-0001"
    name = "RAG to Tool"
    applies_to = {"llm", "model", "rag_corpus", "tool"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        # Quick exit if RAG components not present (cognitive optimization)
        has_rag = has_node_type(graph, "rag_corpus") or has_node_type(graph, "model")
        has_tool = has_node_type(graph, "tool")

        if not (has_rag and has_tool):
            return findings

        # Find tool call edges from RAG components
        tool_edges = get_edges_by_flow(graph, DataFlow.TOOL_CALL)

        if tool_edges:
            edge_ids = [f"{e.from_node}->{e.to_node}" for e in tool_edges]
            findings.append(
                create_finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    category=Category.COMPOUND_CHAIN,
                    description="RAG to Tool execution chain detected",
                    edges=edge_ids,
                    indicators=["rag_tool_chain"],
                    **REMEDIATION,
                )
            )

        return findings
