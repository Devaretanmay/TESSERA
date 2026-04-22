"""
Detection engine - orchestrates rule evaluation.
"""

from tessera.core.topology.models import Graph
from tessera.core.detection.rules import detect, Finding


class DetectionEngine:
    def __init__(self):
        self.findings: list[Finding] = []

    def scan(self, graph: Graph) -> list[Finding]:
        self.findings = detect(graph)
        return self.findings

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
