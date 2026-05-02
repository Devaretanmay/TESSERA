"""
Production API server for TESSERA.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from tessera.core.topology.loader import Loader, ValidationError
from tessera.engine.scanner import OutputFormat, Tessera
from tessera.infra.api.auth import APIPrincipal, verify_bearer_token
from tessera.infra.api.config import get_api_settings
from tessera.infra.api.errors import (
    APIError,
    InternalFailureError,
    ProviderUnavailableError,
    RateLimitExceededError,
    ScanTimeoutError,
    ValidationFailedError,
)
from tessera.infra.api.metrics import metrics
from tessera.infra.api.rate_limit import rate_limiter
from tessera.infra.logging_utils import configure_logging


settings = get_api_settings()
configure_logging(level=settings.log_level, json_logs=settings.json_logs)
logger = logging.getLogger("tessera.api")


class ScanRequest(BaseModel):
    topology_yaml: str = Field(..., min_length=1)
    output_format: Literal["json", "sarif", "text", "html"] = Field(default="json")
    llm_enabled: bool = Field(default=False)


class ScanResults(BaseModel):
    format: Literal["json", "sarif", "text", "html"]
    document: dict[str, Any] | None = None
    content: str | None = None


class ScanResponse(BaseModel):
    scan_id: str
    status: Literal["completed"]
    findings_count: int
    results: ScanResults


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


def _error_payload(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def get_loader() -> Loader:
    """Dependency for Loader injection."""
    return Loader()


def get_scanner() -> Tessera:
    """Dependency for Tessera injection."""
    return Tessera()


async def _run_scan(
    req: ScanRequest,
    scan_id: str,
    principal: APIPrincipal,
    scanner: Tessera,
    loader: Loader,
) -> ScanResponse:

    try:
        graph = loader.load_from_string(req.topology_yaml)
    except ValidationError as exc:
        metrics.increment("tessera_validation_failures_total")
        raise ValidationFailedError(str(exc))

    if len(graph.nodes) > settings.max_topology_nodes:
        metrics.increment("tessera_validation_failures_total")
        raise ValidationFailedError(
            f"Topology exceeds node limit ({len(graph.nodes)} > {settings.max_topology_nodes})"
        )
    if len(graph.edges) > settings.max_topology_edges:
        metrics.increment("tessera_validation_failures_total")
        raise ValidationFailedError(
            f"Topology exceeds edge limit ({len(graph.edges)} > {settings.max_topology_edges})"
        )

    if req.llm_enabled:
        llm_ok = scanner.enable_llm({"timeout": settings.llm_timeout_seconds})
        if not llm_ok:
            metrics.increment("tessera_llm_provider_failures_total")
            raise ProviderUnavailableError("Requested LLM provider is unavailable or not configured")

    try:
        structured_result = await asyncio.wait_for(
            asyncio.to_thread(
                scanner.build_scan_result,
                graph,
                include_remediation=True,
                llm_enabled=req.llm_enabled,
            ),
            timeout=settings.scan_timeout_seconds,
        )
    except TimeoutError as exc:
        raise ScanTimeoutError() from exc
    except Exception as exc:
        raise InternalFailureError("Scan execution failed") from exc

    findings_count = len(structured_result.findings)
    metrics.record_scan(
        duration_ms=structured_result.scan_time_ns / 1_000_000,
        findings=structured_result.findings,
    )

    output_format = OutputFormat(req.output_format)
    formatter = scanner.formatters[output_format]
    rendered = formatter.format(structured_result)

    if isinstance(rendered, dict):
        results = ScanResults(format=req.output_format, document=rendered)
    else:
        results = ScanResults(format=req.output_format, content=rendered)

    logger.info(
        "API scan completed",
        extra={
            "fields": {
                "scan_id": scan_id,
                "tenant_id": principal.tenant_id,
                "format": req.output_format,
                "finding_count": findings_count,
                "duration_ms": round(structured_result.scan_time_ns / 1_000_000, 3),
            }
        },
    )

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        findings_count=findings_count,
        results=results,
    )


def _enforce_rate_limit(principal: APIPrincipal, request: Request) -> None:
    limit = principal.rate_limit_per_minute or settings.default_rate_limit_per_minute
    client_ip = request.client.host if request.client else "unknown"
    bucket = principal.rate_limit_bucket or principal.label
    key = f"{bucket}:{principal.tenant_id}:{client_ip}"
    if not rate_limiter.allow(
        key,
        limit=limit,
        window_seconds=settings.rate_limit_window_seconds,
    ):
        metrics.increment("tessera_rate_limit_exceeded_total")
        raise RateLimitExceededError()


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(
        "TESSERA API starting",
        extra={
            "fields": {
                "port": settings.port,
                "body_limit_bytes": settings.request_body_limit_bytes,
                "max_topology_nodes": settings.max_topology_nodes,
                "max_topology_edges": settings.max_topology_edges,
            }
        },
    )
    yield


app = FastAPI(
    title="TESSERA API",
    version="2.0.0",
    lifespan=lifespan,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
        504: {"model": ErrorResponse},
    },
)


@app.middleware("http")
async def request_guardrails(request: Request, call_next):
    start = perf_counter()
    response = None
    endpoint = request.url.path

    if request.method in {"POST", "PUT", "PATCH"}:
        body = await request.body()
        if len(body) > settings.request_body_limit_bytes:
            metrics.increment("tessera_request_too_large_total")
            response = JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content=_error_payload(
                    "request_too_large",
                    "Request body exceeds configured limit",
                ),
            )
            metrics.record_request(
                endpoint=endpoint,
                method=request.method,
                status_code=response.status_code,
            )
            return response

    response = await call_next(request)
    duration_ms = round((perf_counter() - start) * 1000, 3)
    metrics.record_request(
        endpoint=endpoint,
        method=request.method,
        status_code=response.status_code,
    )
    logger.info(
        "HTTP request completed",
        extra={
            "fields": {
                "endpoint": endpoint,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            }
        },
    )
    return response


@app.exception_handler(APIError)
async def handle_api_error(_: Request, exc: APIError) -> JSONResponse:
    if exc.status_code == 401:
        metrics.increment("tessera_auth_failures_total")
    logger.warning(
        "API error",
        extra={
            "fields": {
                "error_code": exc.code,
                "status_code": exc.status_code,
                "message": exc.message,
            }
        },
    )
    return JSONResponse(status_code=exc.status_code, content=_error_payload(exc.code, exc.message))


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    metrics.increment("tessera_validation_failures_total")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=_error_payload("validation_failed", str(exc.errors())),
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled API failure", exc_info=exc)
    metrics.increment("tessera_internal_failures_total")
    failure = InternalFailureError()
    return JSONResponse(
        status_code=failure.status_code,
        content=_error_payload(failure.code, failure.message),
    )


@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(
    req: ScanRequest,
    request: Request,
    principal: APIPrincipal = Depends(verify_bearer_token),
    scanner: Tessera = Depends(get_scanner),
    loader: Loader = Depends(get_loader),
):
    _enforce_rate_limit(principal, request)
    scan_id = f"scan_{principal.tenant_id}_{uuid4().hex[:12]}"
    return await _run_scan(req, scan_id, principal, scanner, loader)


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready():
    return {
        "status": "ready",
        "configured_api_keys": len(settings.api_keys),
    }


@app.get("/health")
async def health():
    return {"status": "ready", "deprecated": True}


@app.get("/metrics")
async def get_metrics():
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "tessera.infra.api.server:app",
        host=settings.host,
        port=settings.port,
        workers=1,
    )
