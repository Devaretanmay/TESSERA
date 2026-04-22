"""
Text output formatter for TESSERA CLI.
"""

from tessera.infra.output.base import OutputFormatter, ScanResult


class TextFormatter(OutputFormatter):
    """Formats TESSERA scan results to human-readable text."""

    SEVERITY_COLORS = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",  # Yellow
        "medium": "\033[94m",  # Blue
        "low": "\033[92m",  # Green
        "info": "\033[90m",  # Gray
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format_name(self) -> str:
        return "text"

    def format(self, result: ScanResult) -> str:
        """Format scan results to human-readable text.

        Args:
            result: ScanResult containing scan findings

        Returns:
            Formatted text output
        """
        findings = self._sort_by_severity(result.findings)

        output_lines = []

        # Header
        output_lines.append(self._format_header(result))
        output_lines.append("")

        # Summary
        output_lines.append(self._format_summary(findings))
        output_lines.append("")

        # Findings
        if findings:
            output_lines.append(self._format_findings(findings))
        else:
            output_lines.append(
                f"  {self.SEVERITY_COLORS['info']}No vulnerabilities detected.{self.RESET}"
            )

        return "\n".join(output_lines)

    def _format_header(self, result: ScanResult) -> str:
        """Format scan header."""
        return (
            f"{self.BOLD}TESSERA Security Scan{self.RESET}\n"
            f"{'=' * 40}\n"
            f"System: {result.system}\n"
            f"Version: {result.version}\n"
            f"Graph: {result.graph_nodes} nodes, {result.graph_edges} edges\n"
            f"Scan time: {result.scan_time_ns / 1_000_000:.2f}ms"
        )

    def _format_summary(self, findings: list[dict]) -> str:
        """Format findings summary."""
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in by_sev:
                by_sev[sev] += 1

        lines = [f"{self.BOLD}Summary:{self.RESET}"]

        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            count = by_sev[sev]
            if count > 0:
                color = self.SEVERITY_COLORS.get(sev, "")
                lines.append(f"  {color}{sev.upper()}: {count}{self.RESET}")

        return "\n".join(lines)

    def _format_findings(self, findings: list[dict]) -> str:
        """Format individual findings."""
        lines = [f"{self.BOLD}Findings:{self.RESET}"]

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "info").lower()
            finding_id = finding.get("id", "UNKNOWN")
            description = finding.get("description", "")
            category = finding.get("category", "")
            edges = finding.get("edges", [])

            color = self.SEVERITY_COLORS.get(severity, "")

            lines.append(f"\n{color}{i}. [{severity.upper()}] {finding_id}{self.RESET}")
            lines.append(f"   {description}")

            if category:
                lines.append(f"   Category: {category}")

            if edges:
                lines.append(f"   Affected edges:")
                for edge in edges:
                    lines.append(f"     - {edge}")

            # Add remediation if available
            remediation = finding.get("remediation", {})
            if remediation:
                how_to_fix = remediation.get("how_to_fix", "")
                if how_to_fix:
                    lines.append(f"   {self.BOLD}Remediation:{self.RESET}")
                    lines.append(f"   {how_to_fix}")

        return "\n".join(lines)


def format_to_text(
    findings: list[dict],
    system: str = "unknown",
    version: str = "1.0",
    scan_time_ns: int = 0,
    nodes: int = 0,
    edges: int = 0,
    use_color: bool = True,
) -> str:
    """Convenience function to format findings to text.

    Args:
        findings: List of finding dictionaries
        system: System name
        version: System version
        scan_time_ns: Scan duration in nanoseconds
        nodes: Number of nodes in graph
        edges: Number of edges in graph
        use_color: Whether to use ANSI colors

    Returns:
        Formatted text output
    """
    result = ScanResult(
        system=system,
        version=version,
        findings=findings,
        scan_time_ns=scan_time_ns,
        graph_nodes=nodes,
        graph_edges=edges,
    )
    formatter = TextFormatter()

    if not use_color:
        # Return uncolored version
        text = formatter.format(result)
        return (
            text.replace(formatter.SEVERITY_COLORS["critical"], "")
            .replace(formatter.SEVERITY_COLORS["high"], "")
            .replace(formatter.SEVERITY_COLORS["medium"], "")
            .replace(formatter.SEVERITY_COLORS["low"], "")
            .replace(formatter.SEVERITY_COLORS["info"], "")
            .replace(formatter.RESET, "")
            .replace(formatter.BOLD, "")
        )

    return formatter.format(result)
