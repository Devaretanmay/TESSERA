from enum import Enum
from dataclasses import dataclass


class ScanTier(str, Enum):
    TIER_1 = "1"
    TIER_2 = "2"
    TIER_3 = "3"


class ExitCode:
    PASS = 0
    FAIL_CRITICAL = 2
    FAIL_HIGH = 3
    FAIL_MEDIUM = 4
    FAIL_LOW = 5
    ERROR = 1


class ScanResult:
    scan_id: str
    tier: ScanTier
    findings: list
    severity_counts: dict

    def has_blocking_findings(self, threshold: str = "high") -> bool:
        threshold_order = ["low", "medium", "high", "critical"]
        try:
            idx = threshold_order.index(threshold)
        except ValueError:
            idx = 1

        for sev in threshold_order[idx:]:
            if self.severity_counts.get(sev, 0) > 0:
                return True
        return False

    def exit_code(self, threshold: str = "high") -> int:
        if self.severity_counts.get("critical", 0) > 0:
            return ExitCode.FAIL_CRITICAL
        if self.severity_counts.get("high", 0) > 0:
            return ExitCode.FAIL_HIGH
        if self.severity_counts.get("medium", 0) > 0:
            return ExitCode.FAIL_MEDIUM
        if self.severity_counts.get("low", 0) > 0:
            return ExitCode.FAIL_LOW
        return ExitCode.PASS


class TierConfig:
    TIERS = {
        ScanTier.TIER_1: {
            "timeout": 30,
            "blocking": True,
            "description": "Pre-commit (<30s)",
        },
        ScanTier.TIER_2: {
            "timeout": 300,
            "blocking": True,
            "description": "Pre-deploy (<5m)",
        },
        ScanTier.TIER_3: {
            "timeout": 3600,
            "blocking": False,
            "description": "Nightly (<60m)",
        },
    }

    @classmethod
    def get_timeout(cls, tier: ScanTier) -> int:
        return cls.TIERS[tier]["timeout"]

    @classmethod
    def is_blocking(cls, tier: ScanTier) -> bool:
        return cls.TIERS[tier]["blocking"]
