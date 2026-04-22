"""
Base LLM provider interface and models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    """Risk assessment levels."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProviderType(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass
class LLMConfig:
    """Configuration for LLM provider."""

    provider: ProviderType = ProviderType.OPENAI
    model: str = "gpt-4"
    api_key: str | None = None
    base_url: str | None = None
    temperature: float = 0.1
    max_tokens: int = 1024
    timeout: int = 30
    max_cost: float = 1.0  # Maximum cost in USD per request


@dataclass
class RiskAssessment:
    """LLM-powered risk assessment result."""

    risk_level: RiskLevel
    confidence: float  # 0.0 to 1.0
    explanation: str
    findings: list[dict] = field(default_factory=list)
    is_false_positive: bool = False
    recommendations: list[str] = field(default_factory=list)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: LLMConfig):
        """Initialize LLM provider.

        Args:
            config: LLM configuration
        """
        self.config = config

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the LLM provider is available.

        Returns:
            True if provider can be used
        """
        pass

    @abstractmethod
    def assess_risk(self, topology: dict, context: str = "") -> RiskAssessment:
        """Assess security risk of a topology using LLM.

        Args:
            topology: Topology graph as dict
            context: Additional context for assessment

        Returns:
            RiskAssessment with findings
        """
        pass

    @abstractmethod
    def filter_false_positives(self, findings: list[dict], topology: dict) -> list[dict]:
        """Filter false positives from findings.

        Args:
            findings: List of findings to filter
            topology: Topology graph

        Returns:
            Filtered findings
        """
        pass

    @abstractmethod
    def close(self):
        """Clean up provider resources."""
        pass


class LLMUnavailableError(Exception):
    """Raised when LLM provider is not available."""

    pass


class LLMError(Exception):
    """General LLM error."""

    pass
