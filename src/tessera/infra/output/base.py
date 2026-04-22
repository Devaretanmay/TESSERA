"""
Base output formatter interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


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

    def _sort_by_severity(self, findings: list[dict]) -> list[dict]:
        """Sort findings by severity (critical first)."""
        return sorted(
            findings,
            key=lambda f: self._calculate_severity_order(f.get("severity", "info")),
            reverse=True,
        )
