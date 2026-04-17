"""
API server - FastAPI endpoints.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field
from typing import Optional
from dataclasses import dataclass

from tessera.engine.scanner import Scanner, PipelineError
from tessera.infra.db.repository import Repository


app = FastAPI(title="TESSERA API", version="0.1.0")


class ScanRequest(BaseModel):
    topology_path: str = Field(..., min_length=1)
    tier: str = Field(default="2")
    system: str = Field(default="tessera")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    findings_count: int


@dataclass
class AuthContext:
    api_key: str
    tenant_id: str


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> AuthContext:
    if not x_api_key or len(x_api_key) < 16:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return AuthContext(api_key=x_api_key, tenant_id=f"tenant_{x_api_key[:8]}")


@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(req: ScanRequest, auth: AuthContext = Depends(verify_api_key)):
    try:
        repo = Repository()
        scanner = Scanner(repo)
        scan_id, findings = scanner.run(req.topology_path, req.tier, req.system)
        return ScanResponse(scan_id=scan_id, status="completed", findings_count=len(findings))
    except PipelineError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
