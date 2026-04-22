"""
Minimal in-memory metrics registry with Prometheus exposition.
"""

from __future__ import annotations

from collections import defaultdict
from threading import Lock


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        self._scan_findings_by_severity: dict[str, int] = defaultdict(int)
        self._counters: dict[str, int] = defaultdict(int)
        self._scan_latency_ms_sum = 0.0
        self._scan_latency_ms_count = 0

    def increment(self, metric: str, value: int = 1) -> None:
        with self._lock:
            self._counters[metric] += value

    def record_request(self, *, endpoint: str, method: str, status_code: int) -> None:
        with self._lock:
            self._request_counts[(endpoint, method, str(status_code))] += 1

    def record_scan(self, *, duration_ms: float, findings: list[dict]) -> None:
        with self._lock:
            self._scan_latency_ms_sum += duration_ms
            self._scan_latency_ms_count += 1
            for finding in findings:
                severity = finding.get("severity", "info")
                self._scan_findings_by_severity[severity] += 1

    def render(self) -> str:
        with self._lock:
            lines = [
                "# HELP tessera_requests_total Total API requests.",
                "# TYPE tessera_requests_total counter",
            ]
            for (endpoint, method, status), count in sorted(self._request_counts.items()):
                lines.append(
                    'tessera_requests_total{endpoint="%s",method="%s",status="%s"} %d'
                    % (endpoint, method, status, count)
                )

            lines.extend(
                [
                    "# HELP tessera_scan_latency_ms_sum Sum of scan latencies in milliseconds.",
                    "# TYPE tessera_scan_latency_ms_sum counter",
                    f"tessera_scan_latency_ms_sum {self._scan_latency_ms_sum}",
                    "# HELP tessera_scan_latency_ms_count Number of recorded scans.",
                    "# TYPE tessera_scan_latency_ms_count counter",
                    f"tessera_scan_latency_ms_count {self._scan_latency_ms_count}",
                    "# HELP tessera_findings_by_severity_total Findings produced by severity.",
                    "# TYPE tessera_findings_by_severity_total counter",
                ]
            )
            for severity, count in sorted(self._scan_findings_by_severity.items()):
                lines.append(
                    'tessera_findings_by_severity_total{severity="%s"} %d' % (severity, count)
                )

            for metric, count in sorted(self._counters.items()):
                lines.append(f"# HELP {metric} Internal TESSERA counter.")
                lines.append(f"# TYPE {metric} counter")
                lines.append(f"{metric} {count}")

        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()
