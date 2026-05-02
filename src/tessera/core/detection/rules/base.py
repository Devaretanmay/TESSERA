"""
Base classes for CFPE detection rules.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tessera.core.topology.models import Graph


class Severity(str, Enum):
    """Finding severity levels following CVSS-style categorization."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Vulnerability categories."""

    COMPOUND_CHAIN = "compound_chain"
    ATOMIC_INJECTION = "atomic_injection"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


@dataclass
class Remediation:
    """Structured remediation guidance."""

    summary: str
    how_to_fix: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "how_to_fix": self.how_to_fix,
            "references": self.references,
        }


@dataclass
class Finding:
    """A detected vulnerability with structured data."""

    id: str
    severity: Severity
    category: Category
    description: str
    edges: list[str]
    indicators: list[str]
    remediation: Remediation | None = None

    def __post_init__(self) -> None:
        if self.remediation is None:
            self.remediation = Remediation(
                summary="No remediation available",
                how_to_fix="Consult security team",
                references=[],
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "edges": self.edges,
            "indicators": self.indicators,
            "remediation": self.remediation.to_dict() if self.remediation else {},
        }


class DetectionRule(ABC):
    """Abstract base for all CFPE detection rules."""

    id: str
    name: str
    applies_to: set[str]

    @abstractmethod
    def detect(self, graph: Graph) -> list[Finding]:
        """Detect pattern in given graph."""
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.id})"
