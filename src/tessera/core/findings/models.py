"""
Canonical finding model - single schema for all findings.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FailureType(str, Enum):
    COMPOUND_CHAIN = "compound_chain"
    ATOMIC_INJECTION = "atomic_injection"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


@dataclass
class AttackTraceEntry:
    """Single trace entry."""

    node: str
    action: str
    prompt: str = ""
    response: str = ""
    suspicion_score: float = 0.0
    indicators: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Immutable finding - canonical output."""

    finding_id: str
    scan_id: str
    severity: FindingSeverity
    failure_type: FailureType
    topology_path: list[str] = field(default_factory=list)
    attack_trace: list[AttackTraceEntry] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    remediation: dict = field(default_factory=dict)
    confidence: float = 0.5
    cve_refs: list[str] = field(default_factory=list)
    owasp_mapping: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "severity": self.severity.value,
            "failure_type": self.failure_type.value,
            "topology_path": self.topology_path,
            "attack_trace": [
                {"node": t.node, "action": t.action, "suspicion_score": t.suspicion_score}
                for t in self.attack_trace
            ],
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "cve_refs": self.cve_refs,
            "owasp_mapping": self.owasp_mapping,
            "created_at": self.created_at,
        }
