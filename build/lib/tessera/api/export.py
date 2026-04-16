import json
from pathlib import Path
from typing import Any

from tessera.findings.models import Finding, FindingSeverity


class FindingExporter:
    @staticmethod
    def to_json(findings: list[Finding], path: Path) -> None:
        with open(path, "w") as f:
            json.dump([f.model_dump() for f in findings], f, indent=2)

    @staticmethod
    def to_jsonl(findings: list[Finding], path: Path) -> None:
        with open(path, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding.model_dump()) + "\n")

    @staticmethod
    def generate_sarif(findings: list[Finding]) -> dict:
        results = []
        for f in findings:
            results.append(
                {
                    "ruleId": f.failure_type.value,
                    "level": f.severity.value,
                    "message": {"text": f"{f.failure_type.value}: {' -> '.join(f.topology_path)}"},
                    "locations": [{"physicalLocation": {}}],
                }
            )

        return {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "TESSERA", "version": "0.1.0"}}, "results": results}
            ],
        }

    @staticmethod
    def to_sarif(findings: list[Finding], path: Path) -> None:
        sarif = FindingExporter.generate_sarif(findings)
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)

    @staticmethod
    def to_cef(findings: list[Finding], path: Path) -> None:
        severity_map = {
            FindingSeverity.CRITICAL: 10,
            FindingSeverity.HIGH: 8,
            FindingSeverity.MEDIUM: 6,
            FindingSeverity.LOW: 4,
            FindingSeverity.INFO: 1,
        }

        with open(path, "w") as f:
            for finding in findings:
                cef = f"CEF:0|TESSERA|0.1.0|{severity_map.get(finding.severity, 1)}|{finding.failure_type.value}|{finding.finding_id}| "
                cef += f"msg={finding.failure_type.value} "
                cef += f"cn1={finding.confidence}"
                f.write(cef + "\n")


class FindingFormatter:
    @staticmethod
    def format_table(findings: list[Finding]) -> str:
        if not findings:
            return "No findings"

        lines = ["Findings:"]
        for f in findings:
            path = " -> ".join(f.topology_path) if f.topology_path else "atomic"
            lines.append(
                f"  [{f.severity.value.upper()}] {f.finding_id[:8]} {f.failure_type.value}: {path}"
            )

        return "\n".join(lines)

    @staticmethod
    def format_summary(findings: list[Finding]) -> dict:
        by_severity = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total": len(findings),
            "by_severity": by_severity,
        }
