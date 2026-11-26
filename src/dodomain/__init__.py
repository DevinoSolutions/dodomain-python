"""Official Python SDK for doDomain.

doDomain connects your customers' custom domains: you mint a connect session,
the customer finishes the DNS work on a hosted flow, and you get a webhook when
the domain goes live.

The public surface is intentionally small — a sync client, an async client, a
webhook verifier, the models those return, and the exception hierarchy.

    >>> import os
    >>> from dodomain import DoDomain, DnsRecord
    >>> client = DoDomain(secret_key=os.environ["DODOMAIN_SECRET_KEY"])
    >>> session = client.sessions.create(
    ...     domain="app.customer.com",
    ...     records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
    ...     return_url="https://customer.com/settings/domains",
    ... )
    >>> print(session.connect_url)
"""

from __future__ import annotations

__version__ = "0.8.0"

from ._client import AsyncDoDomain, DoDomain
from ._transport import DEFAULT_BASE_URL, RateLimitSnapshot
from .errors import (
    AuthenticationError,
    ConflictError,
    DoDomainAPIError,
    DoDomainConfigError,
    DoDomainConnectionError,
    DoDomainError,
    DoDomainKeylessError,
    ExpiredError,
    InternalServerError,
    InvalidRequestError,
    InvalidResponseError,
    KeylessErrorCode,
    NotConfiguredError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
)
from .keyless import (
    KEYLESS_MAX_DIFFICULTY_BITS,
    AbortEvent,
    async_solve_keyless_proof,
    solve_keyless_proof,
)
from .models import (
    SANDBOX_DOMAINS,
    App,
    CheckDomainResult,
    ComposedRecord,
    Confidence,
    ConnectFontPreset,
    Connection,
    ConnectionPage,
    ConnectionStatus,
    ConnectSessionMode,
    ConnectSessionSummary,
    DeletedWebhookEndpoint,
    DetectResult,
    DisconnectResult,
    DnsRecord,
    DnsRecordType,
    DomainConnectDiscovery,
    DomainConnectRef,
    IntegratorSession,
    KeylessAllowance,
    KeylessSessionInfo,
    KeylessStatus,
    Method,
    ProviderGuide,
    PublicSession,
    ReverifyResult,
    RotatedSecretKey,
    RotationOverlapHours,
    Session,
    SessionWarning,
    Tier,
    TlsIssuanceAdvisory,
    TlsIssuanceAdvisoryCode,
    TlsIssuanceAdvisorySeverity,
    VerifyOutcome,
    VerifyRecord,
    VerifyResult,
    WebhookEndpoint,
    WebhookEndpointWithSecret,
)
from .webhooks import DEFAULT_TOLERANCE_MS, SIGNATURE_HEADER, verify_webhook

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TOLERANCE_MS",
    "KEYLESS_MAX_DIFFICULTY_BITS",
    "SANDBOX_DOMAINS",
    "SIGNATURE_HEADER",
    "AbortEvent",
    "App",
    "AsyncDoDomain",
    "AuthenticationError",
    "CheckDomainResult",
    "ComposedRecord",
    "Confidence",
    "ConflictError",
    "ConnectFontPreset",
    "Connection",
    "ConnectionPage",
    "ConnectionStatus",
    "ConnectSessionMode",
    "ConnectSessionSummary",
    "DeletedWebhookEndpoint",
    "DetectResult",
    "DisconnectResult",
    "DnsRecord",
    "DnsRecordType",
    "DoDomain",
    "DoDomainAPIError",
    "DoDomainConfigError",
    "DoDomainConnectionError",
    "DoDomainError",
    "DoDomainKeylessError",
    "DomainConnectDiscovery",
    "DomainConnectRef",
    "ExpiredError",
    "IntegratorSession",
    "InternalServerError",
    "InvalidRequestError",
    "InvalidResponseError",
    "KeylessAllowance",
    "KeylessErrorCode",
    "KeylessSessionInfo",
    "KeylessStatus",
    "Method",
    "NotConfiguredError",
    "NotFoundError",
    "PermissionError_",
    "ProviderGuide",
    "PublicSession",
    "QuotaExceededError",
    "RateLimitError",
    "RateLimitSnapshot",
    "ReverifyResult",
    "RotatedSecretKey",
    "RotationOverlapHours",
    "Session",
    "SessionWarning",
    "Tier",
    "TlsIssuanceAdvisory",
    "TlsIssuanceAdvisoryCode",
    "TlsIssuanceAdvisorySeverity",
    "VerifyOutcome",
    "VerifyRecord",
    "VerifyResult",
    "WebhookEndpoint",
    "WebhookEndpointWithSecret",
    "__version__",
    "async_solve_keyless_proof",
    "solve_keyless_proof",
    "verify_webhook",
]
