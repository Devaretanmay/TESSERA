"""
Bearer token authentication for the production API surface.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Header

from tessera.infra.api.config import APIKeyConfig, get_api_settings
from tessera.infra.api.errors import AuthenticationError, AuthorizationError


@dataclass(frozen=True)
class APIPrincipal:
    tenant_id: str
    label: str
    token_sha256: str
    rate_limit_per_minute: int | None
    rate_limit_bucket: str | None


def sha256_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise AuthorizationError("Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthorizationError("Authorization header must use Bearer token")
    return token.strip()


def _principal_from_config(config: APIKeyConfig) -> APIPrincipal:
    return APIPrincipal(
        tenant_id=config.tenant_id,
        label=config.label,
        token_sha256=config.token_sha256,
        rate_limit_per_minute=config.rate_limit_per_minute,
        rate_limit_bucket=config.rate_limit_bucket,
    )


def verify_bearer_token(authorization: str | None = Header(None)) -> APIPrincipal:
    token = _extract_bearer_token(authorization)
    token_hash = sha256_token(token)

    for config in get_api_settings().api_keys:
        if hmac.compare_digest(config.token_sha256, token_hash):
            return _principal_from_config(config)

    raise AuthenticationError("Bearer token is invalid")
