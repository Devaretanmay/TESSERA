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

    def scan(
        self,
        topology: Graph | str,
        output_format: OutputFormat = OutputFormat.TEXT,
        include_remediation: bool = True,
    ) -> str | dict:
        """Scan a topology.

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format (json, sarif, text)
            include_remediation: Include remediation guidance

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

    def scan_to_dict(
        self, topology: Graph | str, output_format: OutputFormat = OutputFormat.JSON
    ) -> dict:
        """Scan and return as dict (for programmatic use).

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format

        Returns:
            Dict for further processing
        """
        if isinstance(topology, str):
            loader = Loader()
            topology = loader.load(topology)

        start_time = time.time_ns()
        findings = detect(topology)
        scan_time_ns = time.time_ns() - start_time
        findings_dicts = [f.to_dict() for f in findings]

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

        # Always return dict for this method
        if isinstance(formatted, dict):
            return formatted
        return {"text": formatted, "formatted": formatted}


def scan(
    topology: Graph | str, output_format: str = "text", include_remediation: bool = True
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
