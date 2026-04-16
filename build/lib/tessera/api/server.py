from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
import uuid
from datetime import datetime

from tessera.findings.models import Finding, FindingSeverity, FailureType, AttackTraceEntry

app = FastAPI(title="TESSERA Findings API", version="0.1.0")

findings_db: dict[str, dict] = {}
scans_db: dict[str, dict] = {}


class ScanCreate(BaseModel):
    topology_path: str
    tier: int = 1


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    created_at: str


class FindingCreate(BaseModel):
    """Request body for creating a finding - scan_id comes from URL path."""
    severity: str
    failure_type: str
    topology_path: list[str] = []
    attack_trace: list[dict] = []
    evidence: dict = {}
    remediation: dict = {}
    confidence: float = 0.5
    cve_refs: list[str] = []
    owasp_mapping: list[str] = []


class FindingResponse(BaseModel):
    finding_id: str
    severity: str
    failure_type: str
    topology_path: list[str]


@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(req: ScanCreate):
    scan_id = str(uuid.uuid4())
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "topology_path": req.topology_path,
        "tier": req.tier,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
    }
    return ScanResponse(
        scan_id=scan_id, status="pending", created_at=scans_db[scan_id]["created_at"]
    )


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_db[scan_id]


@app.get("/api/v1/scans/{scan_id}/findings")
async def list_findings(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [f for f in findings_db.values() if f.get("scan_id") == scan_id]


@app.post("/api/v1/scans/{scan_id}/findings", response_model=FindingResponse)
async def create_finding(scan_id: str, finding_req: FindingCreate):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    finding_id = str(uuid.uuid4())
    finding = Finding(
        finding_id=finding_id,
        scan_id=scan_id,
        severity=FindingSeverity(finding_req.severity),
        failure_type=FailureType(finding_req.failure_type),
        topology_path=finding_req.topology_path,
        attack_trace=[AttackTraceEntry(**t) for t in finding_req.attack_trace],
        evidence=finding_req.evidence,
        remediation=finding_req.remediation,
        confidence=finding_req.confidence,
        cve_refs=finding_req.cve_refs,
        owasp_mapping=finding_req.owasp_mapping,
    )
    findings_db[finding_id] = finding.model_dump()
    return FindingResponse(
        finding_id=finding.finding_id,
        severity=finding.severity.value,
        failure_type=finding.failure_type.value,
        topology_path=finding.topology_path,
    )


@app.get("/api/v1/findings/{finding_id}")
async def get_finding(finding_id: str):
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    return findings_db[finding_id]


@app.get("/health")
async def health():
    return {"status": "healthy"}


def run_server(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
