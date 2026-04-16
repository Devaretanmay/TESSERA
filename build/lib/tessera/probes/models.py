from pydantic import BaseModel, Field
from typing import Literal
from enum import Enum


class FailureCategory(str, Enum):
    COMPOUND_CHAIN = "compound_chain"
    ATOMIC_INJECTION = "atomic_injection"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackPrimitive(str, Enum):
    INJECTION = "injection"
    ESCALATION = "escalation"
    EXFILTRATION = "exfiltration"
    HALLUCINATION = "hallucination"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


class TopologyRequirement(BaseModel):
    min_nodes: int = 1
    required_types: list[str] = Field(default_factory=list)
    edge_flows: list[str] = Field(default_factory=list)


class Probe(BaseModel):
    id: str
    name: str
    version: str = "1.0"
    failure_category: FailureCategory
    severity: Severity
    taxonomy_tags: dict[str, str] = Field(default_factory=dict)
    topology_requirements: TopologyRequirement = Field(
        default_factory=TopologyRequirement
    )
    attack_primitive: AttackPrimitive
    escalation_path: list[str] = Field(default_factory=list)
    detection_indicators: list[str] = Field(default_factory=list)
    chain_patterns: list[str] = Field(default_factory=list)
    prompt_template: str = ""
    is_active: bool = True


class ProbeRegistry:
    def __init__(self):
        self.probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        self.probes[probe.id] = probe

    def get(self, probe_id: str) -> Probe | None:
        return self.probes.get(probe_id)

    def list_by_category(self, category: FailureCategory) -> list[Probe]:
        return [p for p in self.probes.values() if p.failure_category == category]

    def list_by_severity(self, severity: Severity) -> list[Probe]:
        return [p for p in self.probes.values() if p.severity == severity]

    def list_top_n_critical(self, n: int = 20) -> list[Probe]:
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        sorted_probes = sorted(
            self.probes.values(), key=lambda p: severity_order.index(p.severity)
        )
        return sorted_probes[:n]
