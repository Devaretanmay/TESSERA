"""
Scanner engine - orchestration only.

Pipeline:
1. Load topology
2. Validate
3. Build graph
4. Run detection
5. Build findings
6. Persist results

Each step isolated and testable.
"""

import uuid
from tessera.core.topology.loader import Loader, ValidationError
from tessera.core.topology.models import Graph, Edge, TrustBoundary, DataFlow
from tessera.core.detection.rule_engine import DetectionEngine
from tessera.core.findings.models import Finding, FindingSeverity, FailureType
from tessera.infra.db.repository import Repository, ScanRecord


class PipelineError(Exception):
    """Pipeline failure."""

    pass


class Scanner:
    """
    Main orchestration:
    - NO business logic
    - NO detections rules (in core/detection)
    - NO DB logic (in infra)
    """

    def __init__(self, repo: Repository | None = None):
        self.loader = Loader()
        self.engine = DetectionEngine()
        self.repo = repo or Repository()

    def run(
        self,
        topology_path: str,
        tier: str = "2",
        system: str = "unknown",
    ) -> tuple[str, list[Finding]]:
        """Execute full pipeline."""
        scan_id = str(uuid.uuid4())

        try:
            graph = self._load(topology_path)
            self._validate(graph)
            findings = self._detect(graph)
            results = self._build_findings(scan_id, findings)
            self._persist(scan_id, system, tier, results)

            return scan_id, results

        except ValidationError as e:
            raise PipelineError(f"Validation failed: {e}") from e

    def _load(self, path: str) -> Graph:
        """Step 1: Load topology."""
        return self.loader.load(path)

    def _validate(self, graph: Graph) -> None:
        """Step 2: Validate graph."""
        if not graph.nodes:
            raise ValidationError("Graph has no nodes")

        if not graph.edges:
            raise ValidationError("Graph has no edges")

        for edge in graph.edges:
            if edge.from_node not in graph.nodes:
                raise ValidationError(f"Edge references missing node: {edge.from_node}")
            if edge.to_node not in graph.nodes:
                raise ValidationError(f"Edge references missing node: {edge.to_node}")

    def _detect(self, graph: Graph) -> list:
        """Step 3: Run detection engine."""
        return self.engine.scan(graph)

    def _build_findings(self, scan_id: str, detections: list) -> list[Finding]:
        """Step 4: Build findings from detections."""
        findings = []

        for det in detections:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                scan_id=scan_id,
                severity=FindingSeverity(det.severity),
                failure_type=FailureType(det.category),
                topology_path=det.edges,
                evidence={"indicators": det.indicators},
                remediation={"description": det.description},
            )
            findings.append(finding)

        return findings

    def _persist(self, scan_id: str, system: str, tier: str, findings: list[Finding]) -> None:
        """Step 5: Persist results."""
        scan = ScanRecord(scan_id=scan_id, system=system, tier=tier, status="completed")
        self.repo.save_scan(scan)

        for finding in findings:
            self.repo.save_finding(finding)
