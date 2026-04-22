# TESSERA Core Package
__version__ = "2.0.0"

from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow
from tessera.core.findings.models import Finding, FindingSeverity, FailureType
from tessera.core.detection.patterns import detect, detect_as_dicts
from tessera.infra.output import SarifFormatter, JsonFormatter, TextFormatter, HtmlFormatter
from tessera.infra.output.sarif_formatter import format_to_sarif
from tessera.infra.output.json_formatter import format_to_json
from tessera.infra.output.text_formatter import format_to_text
from tessera.infra.output.html_formatter import format_to_html
from tessera.engine.scanner import Tesseract, scan, OutputFormat
from tessera.infra.llm import (
    LLMProvider,
    LLMConfig,
    RiskAssessment,
    create_provider,
    get_available_providers,
)

__all__ = [
    # Version
    "__version__",
    # Topology models
    "Graph",
    "Node",
    "Edge",
    "TrustBoundary",
    "DataFlow",
    # Findings
    "Finding",
    "FindingSeverity",
    "FailureType",
    # Detection
    "detect",
    "detect_as_dicts",
    # Output formatters
    "SarifFormatter",
    "JsonFormatter",
    "TextFormatter",
    "HtmlFormatter",
    "format_to_sarif",
    "format_to_json",
    "format_to_text",
    "format_to_html",
    # Scanner
    "Tesseract",
    "scan",
    "OutputFormat",
    # LLM (optional)
    "LLMProvider",
    "LLMConfig",
    "RiskAssessment",
    "create_provider",
    "get_available_providers",
]
