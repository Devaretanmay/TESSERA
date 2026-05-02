"""
Base output formatter interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Container for scan results."""

    system: str
    version: str
    findings: list[dict]
    scan_time_ns: int
    graph_nodes: int
    graph_edges: int


class OutputFormatter(ABC):
    """Base class for output formatters."""

    @abstractmethod
    def format(self, result: ScanResult) -> str | dict:
        """Format scan results to output string or dict.

        Args:
            result: ScanResult containing scan findings

        Returns:
            Formatted output as string or dict
        """
        pass

    @abstractmethod
    def format_name(self) -> str:
        """Return the format name."""
        pass

    def _calculate_severity_order(self, severity: str) -> int:
        """Map severity to numeric order for sorting."""
        order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }
        return order.get(severity.lower(), 0)

    def _count_by_severity(self, findings: list[dict]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _count_by_category(self, findings: list[dict]) -> dict[str, int]:
        """Count findings by category."""
        counts: dict[str, int] = {}
        for finding in findings:
            cat = finding.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _sort_by_severity(self, findings: list[dict]) -> list[dict]:
        """Sort findings by severity (critical first)."""
        return sorted(
            findings,
            key=lambda f: self._calculate_severity_order(f.get("severity", "info")),
            reverse=True,
        )
