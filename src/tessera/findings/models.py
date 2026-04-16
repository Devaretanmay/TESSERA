from pydantic import BaseModel, Field
from typing import Any
from enum import Enum
import uuid
from datetime import datetime


class TokenUsage(BaseModel):
    """Token usage tracking for scans."""

    total: int = 0
    input: int = 0
    output: int = 0

    @property
    def cost_estimate(self) -> float:
        """Estimate cost at $0.01/1K tokens (approx gpt-4 rate)."""
        return (self.total / 1000) * 0.01

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "input": self.input,
            "output": self.output,
            "cost_estimate": f"${self.cost_estimate:.4f}",
        }


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


class AttackTraceEntry(BaseModel):
    node: str
    action: str
    prompt: str = ""
    response: str = ""
    suspicion_score: float = Field(ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    severity: FindingSeverity
    failure_type: FailureType
    topology_path: list[str] = Field(default_factory=list)
    attack_trace: list[AttackTraceEntry] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    cve_refs: list[str] = Field(default_factory=list)
    cfpe_id: str | None = None
    owasp_mapping: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return self.model_dump()

    def to_sarif(self) -> dict:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TESSERA"}},
                    "results": [
                        {
                            "ruleId": self.failure_type.value,
                            "level": self.severity.value,
                            "message": {
                                "text": f"{self.failure_type.value}: {' -> '.join(self.topology_path)}"
                            },
                            "locations": [{"physicalLocation": {}}],
                        }
                    ],
                }
            ],
        }
