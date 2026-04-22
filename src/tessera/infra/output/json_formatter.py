"""
JSON output formatter for TESSERA.
"""

from typing import Any

from tessera.infra.output.base import OutputFormatter, ScanResult


class JsonFormatter(OutputFormatter):
    """Formats TESSERA scan results to JSON."""

    def format_name(self) -> str:
        return "json"

    def format(self, result: ScanResult) -> dict:
        """Format scan results to JSON.

        Args:
            result: ScanResult containing scan findings

        Returns:
            JSON-compatible dictionary
        """
        findings = self._sort_by_severity(result.findings)

        return {
            "tessera_version": "2.0.0",
            "scan": {
                "system": result.system,
                "version": result.version,
                "scan_time_ms": result.scan_time_ns / 1_000_000,
                "graph": {"nodes": result.graph_nodes, "edges": result.graph_edges},
            },
            "findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": self._count_by_severity(findings),
                "by_category": self._count_by_category(findings),
            },
        }

    def _count_by_severity(self, findings: list[dict]) -> dict:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _count_by_category(self, findings: list[dict]) -> dict:
        """Count findings by category."""
        counts = {}
        for finding in findings:
            cat = finding.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1
        return counts


def format_to_json(
    findings: list[dict],
    system: str = "unknown",
    version: str = "1.0",
    scan_time_ns: int = 0,
    nodes: int = 0,
    edges: int = 0,
) -> dict:
    """Convenience function to format findings to JSON.

    Args:
        findings: List of finding dictionaries
        system: System name
        version: System version
        scan_time_ns: Scan duration in nanoseconds
        nodes: Number of nodes in graph
        edges: Number of edges in graph

    Returns:
        JSON-compatible dictionary
    """
    result = ScanResult(
        system=system,
        version=version,
        findings=findings,
        scan_time_ns=scan_time_ns,
        graph_nodes=nodes,
        graph_edges=edges,
    )
    formatter = JsonFormatter()
    return formatter.format(result)
