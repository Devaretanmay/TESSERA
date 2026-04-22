"""
Typed API errors with stable public error codes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class APIError(Exception):
    code: str
    message: str
    status_code: int

    def __str__(self) -> str:
        return self.message


class AuthenticationError(APIError):
    def __init__(self, message: str = "Authentication failed"):
        super().__init__("authentication_failed", message, 401)


class AuthorizationError(APIError):
    def __init__(self, message: str = "Authorization header is invalid"):
        super().__init__("authorization_invalid", message, 401)


class RateLimitExceededError(APIError):
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__("rate_limit_exceeded", message, 429)


class ValidationFailedError(APIError):
    def __init__(self, message: str):
        super().__init__("validation_failed", message, 400)


class RequestTooLargeError(APIError):
    def __init__(self, message: str = "Request body exceeds configured limit"):
        super().__init__("request_too_large", message, 413)


class ProviderUnavailableError(APIError):
    def __init__(self, message: str = "Requested provider is unavailable"):
        super().__init__("provider_unavailable", message, 503)


class ScanTimeoutError(APIError):
    def __init__(self, message: str = "Scan timed out"):
        super().__init__("scan_timeout", message, 504)


class InternalFailureError(APIError):
    def __init__(self, message: str = "Internal server error"):
        super().__init__("internal_failure", message, 500)
