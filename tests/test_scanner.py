from __future__ import annotations

import pytest

from tessera.core.topology.models import DataFlow, Edge, Graph, Node, TrustBoundary
from tessera.engine.scanner import OutputFormat, Tesseract


def _sample_graph() -> Graph:
    return Graph(
        system="sample",
        nodes={
            "user": Node(id="user", type="user", trust_boundary=TrustBoundary.EXTERNAL),
            "llm": Node(id="llm", type="llm", trust_boundary=TrustBoundary.INTERNAL),
        },
        edges=[
            Edge(
                from_node="user",
                to_node="llm",
                trust_boundary=TrustBoundary.EXTERNAL,
                data_flow=DataFlow.API,
            )
        ],
    )


def test_scan_without_remediation_strips_remediation_content():
    scanner = Tesseract()
    output = scanner.scan(_sample_graph(), OutputFormat.JSON, include_remediation=False)

    assert isinstance(output, dict)
    assert output["findings"]
    assert all(finding.get("remediation") == {} for finding in output["findings"])


def test_scan_to_dict_rejects_non_dict_formats():
    scanner = Tesseract()

    with pytest.raises(ValueError, match="dict-producing output format"):
        scanner.scan_to_dict(_sample_graph(), output_format=OutputFormat.TEXT)


def test_cfpe_0002_only_flags_memory_write_targets():
    scanner = Tesseract()
    graph = Graph(
        system="memory-and-db",
        nodes={
            "llm": Node(id="llm", type="llm", trust_boundary=TrustBoundary.INTERNAL),
            "memory": Node(
                id="memory",
                type="memory_store",
                trust_boundary=TrustBoundary.INTERNAL,
            ),
            "db": Node(id="db", type="database", trust_boundary=TrustBoundary.INTERNAL),
        },
        edges=[
            Edge(
                from_node="llm",
                to_node="memory",
                trust_boundary=TrustBoundary.INTERNAL,
                data_flow=DataFlow.READ_WRITE,
            ),
            Edge(
                from_node="llm",
                to_node="db",
                trust_boundary=TrustBoundary.INTERNAL,
                data_flow=DataFlow.READ_WRITE,
            ),
        ],
    )

    output = scanner.scan(graph, OutputFormat.JSON)
    cfpe_0002_findings = [f for f in output["findings"] if f["id"] == "CFPE-0002"]

    assert len(cfpe_0002_findings) == 1
    assert cfpe_0002_findings[0]["edges"] == ["llm->memory"]
