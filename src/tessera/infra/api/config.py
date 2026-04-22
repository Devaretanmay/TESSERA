"""
Environment-backed API configuration.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


@dataclass(frozen=True)
class APIKeyConfig:
    token_sha256: str
    tenant_id: str
    label: str
    rate_limit_per_minute: int | None = None
    rate_limit_bucket: str | None = None


@dataclass(frozen=True)
class APISettings:
    host: str
    port: int
    log_level: str
    json_logs: bool
    request_body_limit_bytes: int
    max_topology_nodes: int
    max_topology_edges: int
    default_rate_limit_per_minute: int
    rate_limit_window_seconds: int
    scan_timeout_seconds: int
    llm_timeout_seconds: int
    api_keys: tuple[APIKeyConfig, ...]

    @classmethod
    def from_env(cls) -> "APISettings":
        raw_keys = os.getenv("TESSERA_API_KEYS_JSON", "[]")
        key_items = json.loads(raw_keys)
        api_keys = tuple(
            APIKeyConfig(
                token_sha256=item["token_sha256"].lower(),
                tenant_id=item["tenant_id"],
                label=item.get("label", item["tenant_id"]),
                rate_limit_per_minute=item.get("rate_limit_per_minute"),
                rate_limit_bucket=item.get("rate_limit_bucket"),
            )
            for item in key_items
        )
        return cls(
            host=os.getenv("TESSERA_API_HOST", "0.0.0.0"),
            port=_get_int("TESSERA_API_PORT", 8000),
            log_level=os.getenv("TESSERA_LOG_LEVEL", "INFO"),
            json_logs=_get_bool("TESSERA_API_JSON_LOGS", True),
            request_body_limit_bytes=_get_int("TESSERA_API_BODY_LIMIT_BYTES", 262144),
            max_topology_nodes=_get_int("TESSERA_API_MAX_TOPOLOGY_NODES", 200),
            max_topology_edges=_get_int("TESSERA_API_MAX_TOPOLOGY_EDGES", 500),
            default_rate_limit_per_minute=_get_int("TESSERA_API_RATE_LIMIT_PER_MINUTE", 60),
            rate_limit_window_seconds=_get_int("TESSERA_API_RATE_LIMIT_WINDOW_SECONDS", 60),
            scan_timeout_seconds=_get_int("TESSERA_API_SCAN_TIMEOUT_SECONDS", 15),
            llm_timeout_seconds=_get_int("TESSERA_LLM_TIMEOUT_SECONDS", 30),
            api_keys=api_keys,
        )


@lru_cache(maxsize=1)
def get_api_settings() -> APISettings:
    return APISettings.from_env()
