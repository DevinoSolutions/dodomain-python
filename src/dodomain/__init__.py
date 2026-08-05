"""Official Python SDK for doDomain.

doDomain connects your customers' custom domains: you mint a connect session,
the customer finishes the DNS work on a hosted flow, and you get a webhook when
the domain goes live.

The public surface is intentionally small.
"""

from __future__ import annotations

__version__ = "0.1.0"

from ._client import AsyncDoDomain, DoDomain
from ._transport import DEFAULT_BASE_URL, RateLimitSnapshot
from .errors import (
    AuthenticationError,
    ConflictError,
    DoDomainAPIError,
    DoDomainConfigError,
    DoDomainConnectionError,
    DoDomainError,
    ExpiredError,
    InternalServerError,
    InvalidRequestError,
    InvalidResponseError,
    NotConfiguredError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "AsyncDoDomain",
    "AuthenticationError",
    "ConflictError",
    "DoDomain",
    "DoDomainAPIError",
    "DoDomainConfigError",
    "DoDomainConnectionError",
    "DoDomainError",
    "ExpiredError",
    "InternalServerError",
    "InvalidRequestError",
    "InvalidResponseError",
    "NotConfiguredError",
    "NotFoundError",
    "PermissionError_",
    "QuotaExceededError",
    "RateLimitError",
    "RateLimitSnapshot",
    "__version__",
]
