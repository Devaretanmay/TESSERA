"""
TESSERA Scanner Engine v2.0

Provides the main scanning interface with multiple output format support.
"""

import json
import logging
import time
from enum import Enum

from tessera.core.topology.models import Graph
from tessera.core.topology.loader import Loader
from tessera.core.detection.patterns import detect
from tessera.infra.output.base import ScanResult
from tessera.infra.output.sarif_formatter import SarifFormatter
from tessera.infra.output.json_formatter import JsonFormatter
from tessera.infra.output.text_formatter import TextFormatter
from tessera.infra.output.html_formatter import HtmlFormatter


logger = logging.getLogger("tessera.scanner")


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    SARIF = "sarif"
    TEXT = "text"
    HTML = "html"


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
            OutputFormat.HTML: HtmlFormatter(),
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
        output_path: str | None = None,
    ) -> str | dict:
        """Scan a topology.

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format (json, sarif, text)
            include_remediation: Include remediation guidance
            llm_enabled: Enable LLM analysis
            output_path: Optional path to write output file

        Returns:
            Formatted scan results
        """
        if isinstance(output_format, str):
            output_format = OutputFormat(output_format.lower())
        result = self.build_scan_result(
            topology,
            include_remediation=include_remediation,
            llm_enabled=llm_enabled,
        )

        # Format output
        formatter = self.formatters.get(output_format, self.formatters[OutputFormat.TEXT])
        output = formatter.format(result)

        # Write to file if path provided
        if output_path:
            import pathlib

            pathlib.Path(output_path).write_text(
                output if isinstance(output, str) else json.dumps(output, indent=2),
                encoding="utf-8",
            )

        return output

    def _llm_filter_findings(self, findings: list[dict], topology: Graph) -> list[dict]:
        """Filter false positives using LLM."""
        if not findings or not self._llm_provider:
            return findings

        try:
            topology_dict = self._topology_to_dict(topology)
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
        if isinstance(output_format, str):
            output_format = OutputFormat(output_format.lower())
        topology_obj = self._load_topology(topology)
        result = self.build_scan_result(
            topology_obj,
            include_remediation=include_remediation,
            llm_enabled=self._llm_enabled,
        )

        # LLM analysis
        llm_assessment = None
        if self._llm_enabled and self._llm_provider:
            # Get semantic risk assessment
            try:
                topology_dict = self._topology_to_dict(topology_obj)
                llm_assessment = self._llm_provider.assess_risk(topology_dict)
            except Exception as exc:
                logger.warning(
                    "LLM assessment failed",
                    extra={"fields": {"error_code": "llm_assessment_failed", "error": str(exc)}},
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
        include_remediation: bool = True,
    ) -> dict:
        """Scan and return as dict (for programmatic use).

        Args:
            topology: Graph object or path to YAML file
            output_format: Output format
            llm_enabled: Enable LLM analysis
            include_remediation: Include remediation guidance

        Returns:
            Dict for further processing
        """
        result = self.scan(
            topology,
            output_format,
            include_remediation=include_remediation,
            llm_enabled=llm_enabled,
        )
        if not isinstance(result, dict):
            raise ValueError("scan_to_dict requires a dict-producing output format")
        return result

    def build_scan_result(
        self,
        topology: Graph | str,
        *,
        include_remediation: bool = True,
        llm_enabled: bool = False,
    ) -> ScanResult:
        """Build a canonical structured scan result before formatting."""
        topology_obj = self._load_topology(topology)
        start_time = time.time_ns()
        findings = detect(topology_obj)
        scan_time_ns = time.time_ns() - start_time
        findings_dicts = self._prepare_findings(findings, include_remediation)
        if llm_enabled and self._llm_enabled and self._llm_provider:
            findings_dicts = self._llm_filter_findings(findings_dicts, topology_obj)
        findings_dicts = self._deduplicate_findings(findings_dicts)
        result = ScanResult(
            system=topology_obj.system,
            version=topology_obj.version,
            findings=findings_dicts,
            scan_time_ns=scan_time_ns,
            graph_nodes=len(topology_obj.nodes),
            graph_edges=len(topology_obj.edges),
        )
        logger.info(
            "Scan completed",
            extra={
                "fields": {
                    "system": result.system,
                    "finding_count": len(result.findings),
                    "duration_ms": round(result.scan_time_ns / 1_000_000, 3),
                }
            },
        )
        return result

    def _load_topology(self, topology: Graph | str) -> Graph:
        if isinstance(topology, str):
            return Loader().load(topology)
        return topology

    def _topology_to_dict(self, topology: Graph) -> dict:
        return {
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

    def _prepare_findings(self, findings: list, include_remediation: bool) -> list[dict]:
        findings_dicts = [f.to_dict() for f in findings]
        if include_remediation:
            return findings_dicts
        for finding in findings_dicts:
            finding["remediation"] = {}
        return findings_dicts

    def _deduplicate_findings(self, findings: list[dict]) -> list[dict]:
        deduplicated = []
        seen_keys = set()
        for finding in findings:
            key = (
                finding.get("id", ""),
                finding.get("severity", ""),
                finding.get("description", ""),
                tuple(sorted(finding.get("edges", []))),
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduplicated.append(finding)
        return deduplicated


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
