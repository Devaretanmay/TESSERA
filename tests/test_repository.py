import sqlite3

from tessera.core.detection.rules import Category, Finding, Severity
from tessera.core.detection.rules.base import Remediation
from tessera.infra.db.repository import Repository


def test_repository_persists_canonical_findings():
    repo = Repository(sqlite3.connect(":memory:"))
    finding = Finding(
        id="CFPE-0002",
        severity=Severity.HIGH,
        category=Category.COMPOUND_CHAIN,
        description="Untrusted input reaches memory write path.",
        edges=["user -> llm", "llm -> memory"],
        indicators=["memory write", "user controlled input"],
        remediation=Remediation(
            summary="Restrict untrusted writes",
            how_to_fix="Gate writes behind policy checks.",
            references=["https://example.com/fix"],
        ),
    )

    repo.save_finding(finding, scan_id="scan-prod")
    stored = repo.get_findings("scan-prod")

    assert len(stored) == 1
    assert stored[0].id == "CFPE-0002"
    assert stored[0].category == Category.COMPOUND_CHAIN
    assert stored[0].edges == ["user -> llm", "llm -> memory"]
    assert stored[0].remediation.summary == "Restrict untrusted writes"


def test_repository_migrates_legacy_findings_schema():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE findings ("
        "finding_id TEXT PRIMARY KEY, "
        "scan_id TEXT NOT NULL, "
        "severity TEXT NOT NULL, "
        "failure_type TEXT NOT NULL, "
        "confidence REAL, "
        "created_at TEXT)"
    )
    conn.commit()

    repo = Repository(conn)
    finding = Finding(
        id="CFPE-0006",
        severity=Severity.MEDIUM,
        category=Category.TRUST_BOUNDARY_BYPASS,
        description="Tool chaining bypasses intended mediation.",
        edges=["tool_a -> tool_b"],
        indicators=["direct tool call"],
    )

    repo.save_finding(finding, scan_id="scan-migrated")
    stored = repo.get_findings("scan-migrated")

    assert len(stored) == 1
    assert stored[0].id == "CFPE-0006"
    assert stored[0].category == Category.TRUST_BOUNDARY_BYPASS
    assert stored[0].description == "Tool chaining bypasses intended mediation."
