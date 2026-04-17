"""
DB models - SQLite persistence.
"""

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from tessera.core.findings.models import Finding, FindingSeverity, FailureType


DB_PATH = Path.home() / ".tessera" / "scans.db"


def get_db() -> Path:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    import os

    os.chmod(DB_PATH.parent, 0o700)
    if DB_PATH.exists():
        os.chmod(DB_PATH, 0o600)
    return DB_PATH


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db())
    conn.execute("DROP TABLE IF EXISTS scans")
    conn.execute("DROP TABLE IF EXISTS findings")
    conn.execute("""
        CREATE TABLE scans (
            scan_id TEXT PRIMARY KEY,
            system TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            tenant_id TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            failure_type TEXT NOT NULL,
            confidence REAL,
            created_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)
    conn.commit()
    return conn


@dataclass
class ScanRecord:
    scan_id: str
    system: str
    tier: str
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: str | None = None
    tenant_id: str | None = None


class Repository:
    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or init_db()

    def save_scan(self, scan: ScanRecord) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan.scan_id,
                scan.system,
                scan.tier,
                scan.status,
                scan.created_at,
                scan.completed_at,
                scan.tenant_id,
            ),
        )
        self.conn.commit()

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        cursor = self.conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return ScanRecord(row[0], row[1], row[2], row[3], row[4], row[5], row[6])

    def save_finding(self, finding: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.scan_id,
                finding.severity.value,
                finding.failure_type.value,
                finding.confidence,
                finding.created_at,
            ),
        )
        self.conn.commit()

    def get_findings(self, scan_id: str) -> list[Finding]:
        cursor = self.conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        findings = []
        for row in rows:
            findings.append(
                Finding(
                    finding_id=row[0],
                    scan_id=row[1],
                    severity=FindingSeverity(row[2]),
                    failure_type=FailureType(row[3]),
                    confidence=row[4],
                    created_at=row[5],
                )
            )
        return findings

    def list_scans(self, limit: int = 10) -> list[ScanRecord]:
        cursor = self.conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        scans = []
        for row in rows:
            scans.append(ScanRecord(row[0], row[1], row[2], row[3], row[4], row[5], row[6]))
        return scans
