from __future__ import annotations

from tessera.core.topology.models import DataFlow, Edge, Graph, Node, TrustBoundary
from tessera.engine.scanner import OutputFormat, Tesseract


def _rag_tool_graph() -> Graph:
    return Graph(
        system="rag-tool",
        nodes={
            "user": Node(id="user", type="user", trust_boundary=TrustBoundary.EXTERNAL),
            "llm": Node(id="llm", type="llm", trust_boundary=TrustBoundary.INTERNAL),
            "rag": Node(id="rag", type="rag_corpus", trust_boundary=TrustBoundary.INTERNAL),
            "tool": Node(id="tool", type="tool", trust_boundary=TrustBoundary.INTERNAL),
        },
        edges=[
            Edge("user", "llm", TrustBoundary.EXTERNAL, DataFlow.API),
            Edge("llm", "rag", TrustBoundary.INTERNAL, DataFlow.RETRIEVAL),
            Edge("llm", "tool", TrustBoundary.INTERNAL, DataFlow.TOOL_CALL),
        ],
    )


def test_text_output_keeps_multiline_remediation_indented():
    scanner = Tesseract()
    output = scanner.scan(_rag_tool_graph(), OutputFormat.TEXT)

    assert "   1. Validate RAG outputs before tool execution" in output
    assert "   2. Implement least-privilege for tool access" in output


def test_sarif_output_is_dict_with_runs():
    scanner = Tesseract()
    output = scanner.scan(_rag_tool_graph(), OutputFormat.SARIF)

    assert isinstance(output, dict)
    assert output["version"] == "2.1.0"
    assert output["runs"]


def test_json_output_contract_contains_summary_and_findings():
    scanner = Tesseract()
    output = scanner.scan(_rag_tool_graph(), OutputFormat.JSON)

    assert output["tessera_version"] == "2.0.0"
    assert "findings" in output
    assert "summary" in output
