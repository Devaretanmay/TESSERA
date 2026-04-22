from __future__ import annotations

import tessera
from tessera.core.detection import patterns
from tessera.core.detection import rules


def test_public_package_exports_stable_surface():
    assert hasattr(tessera, "Tesseract")
    assert hasattr(tessera, "scan")
    assert hasattr(tessera, "OutputFormat")
    assert hasattr(tessera, "Finding")


def test_patterns_facade_uses_canonical_rules_registry():
    assert patterns.RULES
    assert len(patterns.RULES) == len(rules.RULES)
    assert [rule.id for rule in patterns.RULES] == [rule.id for rule in rules.RULES]
