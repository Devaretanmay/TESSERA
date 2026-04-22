"""
HTML output formatter for TESSERA.
"""

from tessera.infra.output.base import OutputFormatter, ScanResult


class HtmlFormatter(OutputFormatter):
    """Formats TESSERA scan results to HTML."""

    def format_name(self) -> str:
        return "html"

    def format(self, result: ScanResult) -> str:
        """Format scan results to HTML."""
        findings = self._sort_by_severity(result.findings)

        html = self._html_header(result)
        html += self._html_summary(findings)

        if findings:
            html += self._html_findings(findings)
        else:
            html += self._html_no_findings()

        html += self._html_footer()

        return html

    def _html_header(self, result: ScanResult) -> str:
        """HTML header with styling."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TESSERA Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .header .meta {{ opacity: 0.8; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card .label {{ color: #666; font-size: 14px; text-transform: uppercase; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; margin-top: 5px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .finding {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding .header {{ display: flex; justify-content: space-between; align-items: center; background: none; padding: 0; margin-bottom: 10px; }}
        .finding .id {{ font-weight: bold; font-size: 18px; }}
        .finding .severity {{ padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .finding .severity.critical {{ background: #dc3545; color: white; }}
        .finding .severity.high {{ background: #fd7e14; color: white; }}
        .finding .severity.medium {{ background: #ffc107; color: black; }}
        .finding .severity.low {{ background: #28a745; color: white; }}
        .finding .description {{ color: #333; margin-bottom: 15px; }}
        .finding .edges {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 13px; }}
        .finding .remediation {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin-top: 15px; }}
        .finding .remediation h4 {{ margin: 0 0 10px 0; color: #0066cc; }}
        .no-findings {{ text-align: center; padding: 40px; background: white; border-radius: 8px; }}
        .no-findings .icon {{ font-size: 48px; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ TESSERA Security Scan Report</h1>
        <div class="meta">
            System: {result.system} | Version: {result.version} | 
            Graph: {result.graph_nodes} nodes, {result.graph_edges} edges | 
            Scan time: {result.scan_time_ns / 1_000_000:.2f}ms
        </div>
    </div>
"""

    def _html_summary(self, findings: list[dict]) -> str:
        """HTML summary cards."""
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in by_sev:
                by_sev[sev] += 1

        return f"""
    <div class="summary">
        <div class="summary-card">
            <div class="label">Total Findings</div>
            <div class="value">{len(findings)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Critical</div>
            <div class="value critical">{by_sev["critical"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">High</div>
            <div class="value high">{by_sev["high"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">Medium</div>
            <div class="value medium">{by_sev["medium"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">Low</div>
            <div class="value low">{by_sev["low"]}</div>
        </div>
    </div>
"""

    def _html_findings(self, findings: list[dict]) -> str:
        """HTML findings list."""
        html = "<h2>Findings</h2>"

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "info").lower()
            finding_id = finding.get("id", "UNKNOWN")
            description = finding.get("description", "")
            category = finding.get("category", "")
            edges = finding.get("edges", [])
            remediation = finding.get("remediation", {})

            html += f"""
    <div class="finding">
        <div class="header">
            <span class="id">{i}. {finding_id}</span>
            <span class="severity {severity}">{severity}</span>
        </div>
        <div class="description">{description}</div>
"""
            if category:
                html += f"        <div><strong>Category:</strong> {category}</div>\n"

            if edges:
                html += "        <div><strong>Affected edges:</strong></div>\n"
                html += '        <div class="edges">\n'
                for edge in edges:
                    html += f"          {edge}<br>\n"
                html += "        </div>\n"

            if remediation:
                how_to_fix = remediation.get("how_to_fix", "")
                if how_to_fix:
                    html += f"""
        <div class="remediation">
            <h4>🔧 Remediation</h4>
            <pre style="white-space: pre-wrap; margin: 0;">{how_to_fix}</pre>
        </div>
"""

            html += "    </div>\n"

        return html

    def _html_no_findings(self) -> str:
        """HTML for no findings."""
        return """
    <div class="no-findings">
        <div class="icon">✅</div>
        <h2>No vulnerabilities detected!</h2>
        <p>Your agent topology appears to be secure.</p>
    </div>
"""

    def _html_footer(self) -> str:
        """HTML footer."""
        return """
    <div class="footer">
        Generated by TESSERA v2.0.0 | AI Security Scanner for Compound Attack Chains
    </div>
</body>
</html>
"""


def format_to_html(
    findings: list[dict],
    system: str = "unknown",
    version: str = "1.0",
    scan_time_ns: int = 0,
    nodes: int = 0,
    edges: int = 0,
) -> str:
    """Convenience function to format findings to HTML."""
    result = ScanResult(
        system=system,
        version=version,
        findings=findings,
        scan_time_ns=scan_time_ns,
        graph_nodes=nodes,
        graph_edges=edges,
    )
    formatter = HtmlFormatter()
    return formatter.format(result)
