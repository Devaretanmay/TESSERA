"""
Compatibility facade for the canonical CFPE rule engine.

`patterns.py` remains part of the public surface in the current release line,
but the canonical implementation now lives under `core.detection.rules`.
"""

from tessera.core.detection.rules import (
    RULES,
    Category,
    DetectionRule,
    Finding,
    Severity,
    detect,
    detect_as_dicts,
)

__all__ = [
    "Category",
    "DetectionRule",
    "Finding",
    "RULES",
    "Severity",
    "detect",
    "detect_as_dicts",
]
