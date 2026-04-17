"""
Detection engine - orchestrates rule evaluation.
No business logic here - only orchestration.
"""

from tessera.core.topology.models import Graph
from tessera.core.detection.patterns import detect, Finding


class DetectionEngine:
    """
    Orchestrates detection:
    1. Load rules
    2. Run each rule
    3. Collect findings
    """

    def __init__(self):
        self.findings: list[Finding] = []

    def scan(self, graph: Graph) -> list[Finding]:
        """Scan graph for vulnerabilities."""
        self.findings = detect(graph)
        return self.findings

    def severity_counts(self) -> dict[str, int]:
        """Count by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
