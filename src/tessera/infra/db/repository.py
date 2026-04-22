"""
DB models - SQLite persistence.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tessera.core.detection.rules import Category, Finding, Severity
from tessera.core.detection.rules.base import Remediation


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
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "scan_id TEXT PRIMARY KEY, "
        "system TEXT NOT NULL, "
        "tier TEXT NOT NULL, "
        "status TEXT NOT NULL, "
        "created_at TEXT NOT NULL, "
        "completed_at TEXT, "
        "tenant_id TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings ("
        "finding_id TEXT PRIMARY KEY, "
        "scan_id TEXT NOT NULL, "
        "severity TEXT NOT NULL, "
        "failure_type TEXT, "
        "category TEXT, "
        "description TEXT, "
        "edges_json TEXT, "
        "indicators_json TEXT, "
        "remediation_json TEXT, "
        "created_at TEXT, "
        "FOREIGN KEY (scan_id) REFERENCES scans(scan_id))"
    )
    _migrate_findings_schema(conn)
    conn.commit()


def _migrate_findings_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.execute("PRAGMA table_info(findings)")
    columns = {row[1] for row in cursor.fetchall()}
    additions = {
        "failure_type": "TEXT",
        "category": "TEXT",
        "description": "TEXT",
        "edges_json": "TEXT",
        "indicators_json": "TEXT",
        "remediation_json": "TEXT",
        "created_at": "TEXT",
    }
    for column, column_type in additions.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} {column_type}")

    if "failure_type" in columns or "failure_type" in additions:
        conn.execute(
            "UPDATE findings SET category = COALESCE(category, failure_type) "
            "WHERE failure_type IS NOT NULL"
        )


@dataclass
class ScanRecord:
    scan_id: str
    system: str
    tier: str
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None
    tenant_id: str | None = None


class Repository:
    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or init_db()
        _ensure_schema(self.conn)

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

    def save_finding(self, finding: Finding, scan_id: str = "adhoc") -> None:
        created_at = datetime.now(UTC).isoformat()
        remediation_json = json.dumps(
            finding.remediation.to_dict() if finding.remediation else {},
        )
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        values = {
            "finding_id": finding.id,
            "scan_id": scan_id,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "description": finding.description,
            "edges_json": json.dumps(finding.edges),
            "indicators_json": json.dumps(finding.indicators),
            "remediation_json": remediation_json,
            "created_at": created_at,
        }
        if "failure_type" in columns:
            values["failure_type"] = finding.category.value

        column_list = ", ".join(values.keys())
        placeholders = ", ".join("?" for _ in values)
        self.conn.execute(
            f"INSERT OR REPLACE INTO findings ({column_list}) VALUES ({placeholders})",
            tuple(values.values()),
        )
        self.conn.commit()

    def get_findings(self, scan_id: str) -> list[Finding]:
        cursor = self.conn.execute(
            "SELECT finding_id, severity, COALESCE(category, failure_type), "
            "description, edges_json, indicators_json, remediation_json "
            "FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        rows = cursor.fetchall()
        findings = []
        for row in rows:
            remediation_data = json.loads(row[6]) if row[6] else {}
            remediation = (
                Remediation(
                    summary=remediation_data.get("summary", "No remediation available"),
                    how_to_fix=remediation_data.get("how_to_fix", "Consult security team"),
                    references=remediation_data.get("references", []),
                )
                if remediation_data is not None
                else None
            )
            findings.append(
                Finding(
                    id=row[0],
                    severity=Severity(row[1]),
                    category=Category(row[2]),
                    description=row[3] or "",
                    edges=json.loads(row[4]) if row[4] else [],
                    indicators=json.loads(row[5]) if row[5] else [],
                    remediation=remediation,
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

    def resolve_scan_id(self, scan_id_prefix: str) -> str:
        """Resolve partial scan ID to full ID."""
        cursor = self.conn.execute(
            "SELECT scan_id FROM scans WHERE scan_id LIKE ?", (f"{scan_id_prefix}%",)
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        return scan_id_prefix
