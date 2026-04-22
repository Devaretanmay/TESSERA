"""
Canonical CFPE rule registry.
"""

from tessera.core.detection.rules.base import Category, DetectionRule, Finding, Severity
from tessera.core.detection.rules.cfpe_0001 import CFPE0001Rule
from tessera.core.detection.rules.cfpe_0002 import CFPE0002Rule
from tessera.core.detection.rules.cfpe_0003 import CFPE0003Rule
from tessera.core.detection.rules.cfpe_0004 import CFPE0004Rule
from tessera.core.detection.rules.cfpe_0005 import CFPE0005Rule
from tessera.core.detection.rules.cfpe_0006 import CFPE0006Rule
from tessera.core.detection.rules.cfpe_0007 import CFPE0007Rule
from tessera.core.detection.rules.cfpe_0008 import CFPE0008Rule
from tessera.core.detection.rules.cfpe_0009 import CFPE0009Rule
from tessera.core.detection.rules.cfpe_0010 import CFPE0010Rule


RULES: list[DetectionRule] = [
    CFPE0001Rule(),
    CFPE0002Rule(),
    CFPE0003Rule(),
    CFPE0004Rule(),
    CFPE0005Rule(),
    CFPE0006Rule(),
    CFPE0007Rule(),
    CFPE0008Rule(),
    CFPE0009Rule(),
    CFPE0010Rule(),
]


def detect(graph) -> list[Finding]:
    """Run all canonical rules against a graph."""
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.detect(graph))
    return findings


def detect_as_dicts(graph) -> list[dict]:
    """Run all canonical rules and serialize results."""
    return [finding.to_dict() for finding in detect(graph)]


__all__ = [
    "Category",
    "DetectionRule",
    "Finding",
    "Severity",
    "RULES",
    "detect",
    "detect_as_dicts",
]
