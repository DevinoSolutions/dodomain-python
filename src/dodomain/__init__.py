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

__version__ = "0.2.0"

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
from .models import (
    App,
    CheckDomainResult,
    ComposedRecord,
    Confidence,
    Connection,
    ConnectionPage,
    ConnectionStatus,
    DeletedWebhookEndpoint,
    DetectResult,
    DisconnectResult,
    DnsRecord,
    DnsRecordType,
    DomainConnectDiscovery,
    DomainConnectRef,
    IntegratorSession,
    Method,
    ProviderGuide,
    PublicSession,
    ReverifyResult,
    RotatedSecretKey,
    Session,
    SessionWarning,
    Tier,
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
    "SIGNATURE_HEADER",
    "App",
    "AsyncDoDomain",
    "AuthenticationError",
    "CheckDomainResult",
    "ComposedRecord",
    "Confidence",
    "ConflictError",
    "Connection",
    "ConnectionPage",
    "ConnectionStatus",
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
    "DomainConnectDiscovery",
    "DomainConnectRef",
    "ExpiredError",
    "IntegratorSession",
    "InternalServerError",
    "InvalidRequestError",
    "InvalidResponseError",
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
    "Session",
    "SessionWarning",
    "Tier",
    "VerifyOutcome",
    "VerifyRecord",
    "VerifyResult",
    "WebhookEndpoint",
    "WebhookEndpointWithSecret",
    "__version__",
    "verify_webhook",
]
