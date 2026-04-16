import sqlite3
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass
import json


@dataclass
class UserRecord:
    user_id: str
    tenant_id: str
    name: str
    email: str
    role: str
    created_at: str
    last_login: Optional[str] = None


@dataclass
class APIKeyRecord:
    key_id: str
    tenant_id: str
    user_id: str
    key_hash: str
    name: str
    permissions: list[str]
    expires_at: Optional[str]
    created_at: str
    last_used: Optional[str] = None


DB_PATH = Path.home() / ".tessera" / "scans.db"


def get_db_path() -> Path:
    db_dir = DB_PATH.parent
    db_dir.mkdir(parents=True, exist_ok=True)
    return DB_PATH


def init_db(db_path: Path | None = None) -> None:
    path = db_path or get_db_path()
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            system TEXT NOT NULL,
            version TEXT,
            tier INTEGER,
            status TEXT,
            created_at TEXT,
            completed_at TEXT,
            findings_count INTEGER DEFAULT 0,
            severity_counts TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            severity TEXT,
            failure_type TEXT,
            topology_path TEXT,
            attack_trace TEXT,
            evidence TEXT,
            remediation TEXT,
            confidence REAL,
            timestamp TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            name TEXT,
            email TEXT,
            role TEXT,
            created_at TEXT,
            last_login TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            user_id TEXT,
            key_hash TEXT UNIQUE,
            name TEXT,
            permissions TEXT,
            expires_at TEXT,
            created_at TEXT,
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            baseline_id TEXT PRIMARY KEY,
            system TEXT NOT NULL,
            name TEXT,
            created_at TEXT,
            sample_count INTEGER,
            data TEXT
        )
    """)

    conn.commit()
    conn.close()


@dataclass
class ScanRecord:
    scan_id: str
    system: str
    version: str
    tier: int
    status: str
    created_at: str
    completed_at: str | None = None
    findings_count: int = 0
    severity_counts: dict | None = None


@dataclass
class FindingRecord:
    finding_id: str
    scan_id: str
    severity: str
    failure_type: str
    topology_path: list
    attack_trace: list
    evidence: dict
    remediation: dict
    confidence: float
    timestamp: str


class Persistence:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or get_db_path()
        init_db(db_path=self.db_path)

    def save_scan(self, scan: ScanRecord) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO scans 
            (scan_id, system, version, tier, status, created_at, completed_at, findings_count, severity_counts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan.scan_id,
                scan.system,
                scan.version,
                scan.tier,
                scan.status,
                scan.created_at,
                scan.completed_at,
                scan.findings_count,
                json.dumps(scan.severity_counts) if scan.severity_counts else None,
            ),
        )
        conn.commit()
        conn.close()

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return ScanRecord(
            scan_id=row[0],
            system=row[1],
            version=row[2],
            tier=row[3],
            status=row[4],
            created_at=row[5],
            completed_at=row[6],
            findings_count=row[7],
            severity_counts=json.loads(row[8]) if row[8] else None,
        )

    def list_scans(self, limit: int = 20) -> list[ScanRecord]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans 
            ORDER BY created_at DESC 
            LIMIT ?
        """,
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()

        return [
            ScanRecord(
                scan_id=row[0],
                system=row[1],
                version=row[2],
                tier=row[3],
                status=row[4],
                created_at=row[5],
                completed_at=row[6],
                findings_count=row[7],
                severity_counts=json.loads(row[8]) if row[8] else None,
            )
            for row in rows
        ]

    def save_findings(self, scan_id: str, findings: list[dict]) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for finding in findings:
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings
                (finding_id, scan_id, severity, failure_type, topology_path, attack_trace, evidence, remediation, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    finding.get("finding_id"),
                    scan_id,
                    finding.get("severity"),
                    finding.get("failure_type"),
                    json.dumps(finding.get("topology_path", [])),
                    json.dumps(finding.get("attack_trace", [])),
                    json.dumps(finding.get("evidence", {})),
                    json.dumps(finding.get("remediation", {})),
                    finding.get("confidence", 0.5),
                    finding.get("timestamp"),
                ),
            )

        conn.commit()
        conn.close()

    def get_findings(self, scan_id: str) -> list[FindingRecord]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        conn.close()

        return [
            FindingRecord(
                finding_id=row[0],
                scan_id=row[1],
                severity=row[2],
                failure_type=row[3],
                topology_path=json.loads(row[4]),
                attack_trace=json.loads(row[5]),
                evidence=json.loads(row[6]),
                remediation=json.loads(row[7]),
                confidence=row[8],
                timestamp=row[9],
            )
            for row in rows
        ]

    def save_user(self, user: UserRecord) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO users 
            (user_id, tenant_id, name, email, role, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user.user_id,
                user.tenant_id,
                user.name,
                user.email,
                user.role,
                user.created_at,
                user.last_login,
            ),
        )
        conn.commit()
        conn.close()

    def get_user(self, user_id: str) -> Optional[UserRecord]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return UserRecord(
            user_id=row[0],
            tenant_id=row[1],
            name=row[2],
            email=row[3],
            role=row[4],
            created_at=row[5],
            last_login=row[6],
        )

    def save_api_key(self, key: APIKeyRecord) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO api_keys 
            (key_id, tenant_id, user_id, key_hash, name, permissions, expires_at, created_at, last_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                key.key_id,
                key.tenant_id,
                key.user_id,
                key.key_hash,
                key.name,
                ",".join(key.permissions),
                key.expires_at,
                key.created_at,
                key.last_used,
            ),
        )
        conn.commit()
        conn.close()

    def list_api_keys(self, tenant_id: str) -> list[APIKeyRecord]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM api_keys WHERE tenant_id = ?", (tenant_id,))
        rows = cursor.fetchall()
        conn.close()
        return [
            APIKeyRecord(
                key_id=row[0],
                tenant_id=row[1],
                user_id=row[2],
                key_hash=row[3],
                name=row[4],
                permissions=row[5].split(",") if row[5] else [],
                expires_at=row[6],
                created_at=row[7],
                last_used=row[8],
            )
            for row in rows
        ]

    def get_api_key_by_hash(self, key_hash: str) -> Optional[APIKeyRecord]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return APIKeyRecord(
            key_id=row[0],
            tenant_id=row[1],
            user_id=row[2],
            key_hash=row[3],
            name=row[4],
            permissions=row[5].split(",") if row[5] else [],
            expires_at=row[6],
            created_at=row[7],
            last_used=row[8],
        )

    def revoke_api_key(self, key_id: str) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
        conn.commit()
        conn.close()
