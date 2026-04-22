"""
CFPE-0008: RAG Context Injection detection rule.
"""

from __future__ import annotations
from tessera.core.detection.rules.base import DetectionRule, Finding, Severity, Category
from tessera.core.detection.rules.helpers import (
    create_finding,
)
from tessera.core.topology.models import Graph


REMEDIATION = {
    "summary": "Sanitize user input before adding to RAG context",
    "how_to_fix": (
        "1. Sanitize user input before adding to RAG context\n"
        "2. Use input validation at RAG boundary\n"
        "3. Implement context isolation\n"
        "4. Add audit logging for context modifications"
    ),
    "references": ["OWASP LLM01", "CWE-20"],
}


class CFPE0008Rule(DetectionRule):
    """RAG Context Injection detection."""

    id = "CFPE-0008"
    name = "RAG Context Injection"
    applies_to = {"llm", "rag_corpus"}

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        user_nodes = {node_id for node_id, node in graph.nodes.items() if node.type == "user"}
        rag_nodes = {node_id for node_id, node in graph.nodes.items() if node.type == "rag_corpus"}
        if not user_nodes or not rag_nodes:
            return findings

        for edge in graph.edges:
            if edge.from_node not in user_nodes or edge.to_node not in rag_nodes:
                continue
            findings.append(
                create_finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    category=Category.ATOMIC_INJECTION,
                    description=f"User input directly writes to RAG corpus '{edge.to_node}'",
                    edges=[f"{edge.from_node}->{edge.to_node}"],
                    indicators=["rag_injection"],
                    **REMEDIATION,
                )
            )

        return findings
