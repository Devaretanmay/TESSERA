"""
SARIF v2.1.0 output formatter for TESSERA.

SARIF (Static Analysis Results Interchange Format) is the standard
format for security scanning tools to integrate with GitHub Code Scanning.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from tessera.infra.output.base import OutputFormatter, ScanResult


class SarifFormatter(OutputFormatter):
    """Formats TESSERA scan results to SARIF v2.1.0."""

    def format_name(self) -> str:
        return "sarif"

    def format(self, result: ScanResult) -> dict:
        """Format scan results to SARIF v2.1.0.

        Args:
            result: ScanResult containing scan findings

        Returns:
            SARIF v2.1.0 compliant dictionary
        """
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": self._build_tool(),
                    "results": self._build_results(result),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                            "workingDirectory": {"uri": "file:///"},
                        }
                    ],
                }
            ],
        }

    def _build_tool(self) -> dict:
        """Build tool descriptor."""
        return {
            "driver": {
                "name": "TESSERA",
                "version": "2.0.0",
                "informationUri": "https://github.com/Devaretanmay/TESSERA",
                "rules": self._build_rules(),
            }
        }

    def _build_rules(self) -> list[dict]:
        """Build SARIF rule definitions for all CFPE patterns."""
        rules = [
            {
                "id": "CFPE-0001",
                "name": "RAG to Tool",
                "shortDescription": {"text": "RAG to Tool execution chain detected"},
                "fullDescription": {
                    "text": "Detects when an LLM can chain through RAG knowledge retrieval to execute tools, enabling potential prompt injection attacks."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Implement input validation between RAG and tool execution. Use separate privilege boundaries.",
                    "markdown": "## Remediation\n\n1. Validate RAG outputs before tool execution\n2. Implement least-privilege for tool access\n3. Add output sanitization between RAG and tools",
                },
                "properties": {"security-severity": "8.0"},
            },
            {
                "id": "CFPE-0002",
                "name": "Memory Poisoning",
                "shortDescription": {"text": "Memory poisoning risk detected"},
                "fullDescription": {
                    "text": "Detects when an LLM can write to persistent memory stores, enabling injection of malicious context."
                },
                "defaultConfiguration": {"level": "error"},
                "help": {
                    "text": "Use read-only memory for RAG context. Implement memory signing.",
                    "markdown": "## Remediation\n\n1. Use read-only memory stores for RAG context\n2. Implement memory integrity verification\n3. Separate user context from system memory",
                },
                "properties": {"security-severity": "9.1"},
            },
            {
                "id": "CFPE-0003",
                "name": "External to Database",
                "shortDescription": {"text": "Untrusted external data direct database access"},
                "fullDescription": {
                    "text": "Detects when external/untrusted data can directly access databases without validation."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Add validation layer between external inputs and database.",
                    "markdown": "## Remediation\n\n1. Add input validation layer\n2. Use parameterized queries\n3. Implement database firewall rules",
                },
                "properties": {"security-severity": "8.5"},
            },
            {
                "id": "CFPE-0004",
                "name": "Trust Boundary Bypass",
                "shortDescription": {"text": "Untrusted data crosses trust boundary"},
                "fullDescription": {
                    "text": "Detects when data flows across trust boundaries without proper sanitization."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Implement trust boundary validation and data sanitization.",
                    "markdown": "## Remediation\n\n1. Define clear trust boundaries\n2. Validate data at each boundary\n3. Implement sanitization functions",
                },
                "properties": {"security-severity": "7.5"},
            },
            {
                "id": "CFPE-0005",
                "name": "Multi-hop Attack Chain",
                "shortDescription": {"text": "Multi-hop attack chain detected (3+ edges)"},
                "fullDescription": {
                    "text": "Detects complex attack chains that span 3 or more edges in the topology."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Analyze and break long attack chains. Implement defense in depth.",
                    "markdown": "## Remediation\n\n1. Break long chains with validation points\n2. Implement multiple security layers\n3. Monitor chain interactions",
                },
                "properties": {"security-severity": "8.0"},
            },
            {
                "id": "CFPE-0006",
                "name": "Tool to Tool Chaining",
                "shortDescription": {"text": "Tool chaining detected"},
                "fullDescription": {
                    "text": "Detects when one tool can call another, potentially escalating privileges."
                },
                "defaultConfiguration": {"level": "note"},
                "help": {
                    "text": "Review tool permissions and implement tool isolation.",
                    "markdown": "## Remediation\n\n1. Limit tool-to-tool communication\n2. Implement tool permission model\n3. Audit tool interaction logs",
                },
                "properties": {"security-severity": "5.0"},
            },
            {
                "id": "CFPE-0007",
                "name": "Sensitive Data Exfiltration",
                "shortDescription": {"text": "LLM can send data to external service"},
                "fullDescription": {
                    "text": "Detects when LLM or agent can send sensitive data to external services."
                },
                "defaultConfiguration": {"level": "error"},
                "help": {
                    "text": "Implement output filtering for sensitive data.",
                    "markdown": "## Remediation\n\n1. Implement DLP checks\n2. Add audit logging",
                },
                "properties": {"security-severity": "9.5"},
            },
            {
                "id": "CFPE-0008",
                "name": "RAG Context Injection",
                "shortDescription": {"text": "User input can inject into RAG context"},
                "fullDescription": {
                    "text": "Detects when user input can directly inject into RAG context without sanitization."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Sanitize user input before RAG embedding.",
                    "markdown": "## Remediation\n\n1. Sanitize input\n2. Implement context isolation",
                },
                "properties": {"security-severity": "8.0"},
            },
            {
                "id": "CFPE-0009",
                "name": "MCP Config Attack",
                "shortDescription": {"text": "MCP server vulnerability"},
                "fullDescription": {"text": "Detects potential MCP configuration vulnerabilities."},
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Validate MCP server authenticity.",
                    "markdown": "## Remediation\n\n1. Use signed configs\n2. Implement allowlisting",
                },
                "properties": {"security-severity": "7.5"},
            },
            {
                "id": "CFPE-0010",
                "name": "Agent Skill Injection",
                "shortDescription": {"text": "External source can modify skills"},
                "fullDescription": {
                    "text": "Detects when external sources can modify agent skill definitions."
                },
                "defaultConfiguration": {"level": "warning"},
                "help": {
                    "text": "Protect skill definitions from injection.",
                    "markdown": "## Remediation\n\n1. Use read-only skills\n2. Sign skill files",
                },
                "properties": {"security-severity": "8.0"},
            },
        ]
        return rules

    def _build_results(self, result: ScanResult) -> list[dict]:
        """Build SARIF results from findings."""
        results = []

        for finding in result.findings:
            rule_id = finding.get("id", "CFPE-UNKNOWN")
            severity = finding.get("severity", "info")
            description = finding.get("description", "")
            edges = finding.get("edges", [])

            # Build location from edges
            locations = []
            for edge in edges:
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"topology.yaml", "uriBaseId": "ROOT"},
                            "region": {"startLine": 1, "snippet": {"text": edge}},
                        },
                        "message": {"text": f"Edge: {edge}"},
                    }
                )

            # Add topology-level location if no edge locations
            if not locations:
                locations.append(
                    {
                        "physicalLocation": {"artifactLocation": {"uri": "topology.yaml"}},
                        "message": {"text": "Check topology configuration"},
                    }
                )

            sarif_result = {
                "ruleId": rule_id,
                "level": self._map_severity_to_sarif_level(severity),
                "message": {"text": description},
                "locations": locations,
                "properties": {
                    "category": finding.get("category", ""),
                    "indicators": finding.get("indicators", []),
                },
            }

            # Add remediation if available
            remediation = finding.get("remediation", {})
            if remediation:
                sarif_result["message"]["markdown"] = remediation.get("how_to_fix", "")

            results.append(sarif_result)

        return results

    def _map_severity_to_sarif_level(self, severity: str) -> str:
        """Map TESSERA severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "warning",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity.lower(), "note")


def format_to_sarif(
    findings: list[dict],
    system: str = "unknown",
    version: str = "1.0",
    scan_time_ns: int = 0,
    nodes: int = 0,
    edges: int = 0,
) -> dict:
    """Convenience function to format findings to SARIF.

    Args:
        findings: List of finding dictionaries
        system: System name
        version: System version
        scan_time_ns: Scan duration in nanoseconds
        nodes: Number of nodes in graph
        edges: Number of edges in graph

    Returns:
        SARIF v2.1.0 compliant dictionary
    """
    result = ScanResult(
        system=system,
        version=version,
        findings=findings,
        scan_time_ns=scan_time_ns,
        graph_nodes=nodes,
        graph_edges=edges,
    )
    formatter = SarifFormatter()
    return formatter.format(result)
