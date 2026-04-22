from __future__ import annotations

from tessera.infra.output.base import ScanResult
from tessera.infra.output.html_formatter import HtmlFormatter


def test_html_formatter_escapes_untrusted_finding_content():
    formatter = HtmlFormatter()
    result = ScanResult(
        system="demo<script>",
        version="1.0",
        scan_time_ns=1_000_000,
        graph_nodes=2,
        graph_edges=1,
        findings=[
            {
                "id": "CFPE-0001",
                "severity": "high",
                "category": "compound_chain",
                "description": "<script>alert('x')</script>",
                "edges": ["a-><img src=x onerror=alert(1)>"],
                "indicators": ["test"],
                "remediation": {"how_to_fix": "<b>do not execute</b>"},
            }
        ],
    )

    output = formatter.format(result)
    assert "<script>alert('x')</script>" not in output
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in output
    assert "&lt;b&gt;do not execute&lt;/b&gt;" in output
