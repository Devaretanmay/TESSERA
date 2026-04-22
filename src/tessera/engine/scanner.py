"""
TESSERA Scanner Engine v2.0

Provides the main scanning interface with multiple output format support.
"""

import time
from enum import Enum
from typing import Any

from tessera.core.topology.models import Graph
from tessera.core.topology.loader import Loader
from tessera.core.detection.patterns import detect, detect_as_dicts
from tessera.infra.output.base import ScanResult
from tessera.infra.output.sarif_formatter import SarifFormatter
from tessera.infra.output.json_formatter import JsonFormatter
from tessera.infra.output.text_formatter import TextFormatter


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    SARIF = "sarif"
    TEXT = "text"


class Tesseract:
    """Main TESSERA scanner class."""

    def __init__(self, config: dict | None = None):
        """Initialize scanner.

        Args:
            config: Optional configuration dict
        """
        self.config = config or {}
        self.formatters = {
            OutputFormat.JSON: JsonFormatter(),
            OutputFormat.SARIF: SarifFormatter(),
            OutputFormat.TEXT: TextFormatter(),
        }
        self._llm_provider = None
        self._llm_enabled = False
        self._llm_config = None

    @property
    def llm_available(self) -> bool:
        """Check if LLM is available."""
        return self._llm_provider is not None

    def enable_llm(self, llm_config: dict | None = None) -> bool:
        """Enable LLM-powered analysis.

        Args:
            llm_config: Optional LLM configuration

        Returns:
            True if LLM was enabled successfully
        """
        from tessera.infra.llm.base import LLMConfig, ProviderType
        from tessera.infra.llm.factory import create_provider, LLMUnavailableError

        if llm_config is None:
            llm_config = {}

        # Build config
        provider = llm_config.get("provider", "openai")
        if isinstance(provider, str):
            provider = ProviderType(provider)

        config = LLMConfig(
            provider=provider,
            model=llm_config.get("model", "gpt-4"),
            api_key=llm_config.get("api_key"),
            base_url=llm_config.get("base_url"),
            temperature=llm_config.get("temperature", 0.1),
            max_tokens=llm_config.get("max_tokens", 1024),
            timeout=llm_config.get("timeout", 30),
        )

        try:
            self._llm_provider = create_provider(config)
            self._llm_enabled = True
            self._llm_config = llm_config
            return True
        except LLMUnavailableError:
            self._llm_provider = None
            self._llm_enabled = False
            return False

    def disable_llm(self):
        """Disable LLM-powered analysis."""
        if self._llm_provider:
            self._llm_provider.close()
        self._llm_provider = None
        self._llm_enabled = False
        self._llm_config = None

    def scan(
        self,
        topology: Graph | str,
        output_format: OutputFormat = OutputFormat.TEXT,
        include_remediation: bool = True,
        llm_enabled: bool = False,
    ) -> str | dict:
        """Scan a topology.

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format (json, sarif, text)
            include_remediation: Include remediation guidance
            llm_enabled: Enable LLM analysis

        Returns:
            Formatted scan results
        """
        # Load topology if path string
        if isinstance(topology, str):
            loader = Loader()
            topology = loader.load(topology)

        # Run detection
        start_time = time.time_ns()
        findings = detect(topology)
        scan_time_ns = time.time_ns() - start_time

        # Convert to dicts for formatters
        findings_dicts = [f.to_dict() for f in findings]

        # LLM-powered false positive filtering
        if llm_enabled and self._llm_enabled and self._llm_provider:
            findings_dicts = self._llm_filter_findings(findings_dicts, topology)

        # Create result
        result = ScanResult(
            system=topology.system,
            version=topology.version,
            findings=findings_dicts,
            scan_time_ns=scan_time_ns,
            graph_nodes=len(topology.nodes),
            graph_edges=len(topology.edges),
        )

        # Format output
        formatter = self.formatters.get(output_format, self.formatters[OutputFormat.TEXT])
        output = formatter.format(result)

        return output

    def _llm_filter_findings(self, findings: list[dict], topology: Graph) -> list[dict]:
        """Filter false positives using LLM."""
        if not findings or not self._llm_provider:
            return findings

        try:
            # Convert topology to dict
            topology_dict = {
                "system": topology.system,
                "version": topology.version,
                "nodes": [
                    {"id": n.id, "type": n.type, "trust_boundary": n.trust_boundary.value}
                    for n in topology.nodes.values()
                ],
                "edges": [
                    {"from": e.from_node, "to": e.to_node, "data_flow": e.data_flow.value}
                    for e in topology.edges
                ],
            }

            return self._llm_provider.filter_false_positives(findings, topology_dict)
        except Exception:
            # Return original findings on error
            return findings

    def scan_with_llm(
        self,
        topology: Graph | str,
        output_format: OutputFormat = OutputFormat.TEXT,
        include_remediation: bool = True,
    ) -> dict:
        """Scan with LLM analysis enabled.

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format
            include_remediation: Include remediation guidance

        Returns:
            Dict with scan results and LLM analysis
        """
        # Load topology if path string
        if isinstance(topology, str):
            loader = Loader()
            topology = loader.load(topology)

        # Run detection
        start_time = time.time_ns()
        findings = detect(topology)
        scan_time_ns = time.time_ns() - start_time

        # Convert to dicts
        findings_dicts = [f.to_dict() for f in findings]

        # LLM analysis
        llm_assessment = None
        if self._llm_enabled and self._llm_provider:
            # Filter false positives
            findings_dicts = self._llm_filter_findings(findings_dicts, topology)

            # Get semantic risk assessment
            try:
                topology_dict = {
                    "system": topology.system,
                    "version": topology.version,
                    "nodes": [
                        {
                            "id": n.id,
                            "type": n.type,
                            "trust_boundary": n.trust_boundary.value,
                        }
                        for n in topology.nodes.values()
                    ],
                    "edges": [
                        {
                            "from": e.from_node,
                            "to": e.to_node,
                            "data_flow": e.data_flow.value,
                        }
                        for e in topology.edges
                    ],
                }
                llm_assessment = self._llm_provider.assess_risk(topology_dict)
            except Exception:
                pass

        # Create result
        result = ScanResult(
            system=topology.system,
            version=topology.version,
            findings=findings_dicts,
            scan_time_ns=scan_time_ns,
            graph_nodes=len(topology.nodes),
            graph_edges=len(topology.edges),
        )

        formatter = self.formatters.get(output_format, self.formatters[OutputFormat.JSON])
        formatted = formatter.format(result)

        # Add LLM assessment to result
        if isinstance(formatted, dict):
            if llm_assessment:
                formatted["llm_assessment"] = {
                    "risk_level": llm_assessment.risk_level.value,
                    "confidence": llm_assessment.confidence,
                    "explanation": llm_assessment.explanation,
                    "recommendations": llm_assessment.recommendations,
                }
            formatted["llm_enabled"] = self._llm_enabled

        return formatted

    def scan_to_dict(
        self,
        topology: Graph | str,
        output_format: OutputFormat = OutputFormat.JSON,
        llm_enabled: bool = False,
    ) -> dict:
        """Scan and return as dict (for programmatic use).

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format
            llm_enabled: Enable LLM analysis

        Returns:
            Dict for further processing
        """
        return self.scan(topology, output_format, llm_enabled=llm_enabled)


def scan(
    topology: Graph | str,
    output_format: str = "text",
    include_remediation: bool = True,
) -> str | dict:
    """Convenience function for quick scanning.

    Args:
        topology: Graph object or path to YAML file
        output_format: Output format (json, sarif, text)
        include_remediation: Include remediation guidance

    Returns:
        Formatted scan results
    """
    format_enum = OutputFormat(output_format.lower())
    scanner = Tesseract()
    return scanner.scan(topology, format_enum, include_remediation)
