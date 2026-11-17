"""The sync and async clients.

``DoDomain`` and ``AsyncDoDomain`` expose the identical resource tree and return
the identical parsed objects; the only difference is that the async methods are
awaitable. Both share every piece of interpretation logic through
``_transport.py`` so the two can never disagree about what a response means.
"""

from __future__ import annotations

import asyncio
import math
import random
import re
import threading
import time
import uuid
from types import TracebackType
from typing import Any

import httpx

from ._transport import (
    DEFAULT_BASE_URL,
    RateLimitSnapshot,
    RequestSpec,
    backoff_delay,
    build_headers,
    map_error,
    parse_success,
    retry_delay_for_response,
)
from .errors import DoDomainConfigError, DoDomainConnectionError, DoDomainKeylessError
from .keyless import KEYLESS_PROOF_DEFAULT_TIMEOUT, KEYLESS_PROOF_MAX_TIMEOUT
from .resources.apps import Apps, AsyncApps
from .resources.connections import AsyncConnections, Connections
from .resources.domains import AsyncDomains, Domains
from .resources.keyless import AsyncKeyless, Keyless
from .resources.keys import AsyncKeys, Keys
from .resources.sessions import AsyncSessions, Sessions
from .resources.webhook_endpoints import AsyncWebhookEndpoints, WebhookEndpoints

__all__ = ["AsyncDoDomain", "DoDomain"]

SECRET_KEY_PREFIX = "dd_sk_"
KEYLESS_KEY_PREFIX = "dd_ks_"

# Structural discrimination between the two bearer shapes, copied from the API's
# own `isCompactJwt` (apps/web/src/lib/api/auth.ts): a compact JWS is exactly
# three base64url segments and its header segment always starts "eyJ". A dd_sk_
# key can never match it.
_COMPACT_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _default_user_agent() -> str:
    from dodomain import __version__

    return f"dodomain-python/{__version__}"


class _BaseClient:
    """Configuration and validation shared by both clients."""

    def __init__(
        self,
        *,
        secret_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        keyless: bool = False,
        keyless_key: str | None = None,
        proof_timeout: float = KEYLESS_PROOF_DEFAULT_TIMEOUT,
    ) -> None:
        #: Keyless mode only: the ``dd_ks_`` key, once a keyless start returned
        #: it (or from ``keyless_key``).
        self._keyless_key: str | None = None
        self._proof_timeout = KEYLESS_PROOF_DEFAULT_TIMEOUT
        self._secret_key: str | None
        if keyless is True:
            # Keyless start (T-18036): no account and no key. An explicit opt-in,
            # so a missing secret key still raises below and an unset environment
            # variable can never quietly turn a production client into a test app.
            if secret_key is not None:
                raise DoDomainConfigError(
                    "DoDomain: pass either secret_key or keyless=True, not both."
                )
            if keyless_key is not None and (
                not isinstance(keyless_key, str) or not keyless_key.startswith(KEYLESS_KEY_PREFIX)
            ):
                raise DoDomainConfigError(
                    f"DoDomain: keyless_key must be a keyless key ({KEYLESS_KEY_PREFIX}…)."
                )
            if (
                isinstance(proof_timeout, bool)
                or not isinstance(proof_timeout, (int, float))
                or not math.isfinite(proof_timeout)
                or proof_timeout <= 0
                or proof_timeout > KEYLESS_PROOF_MAX_TIMEOUT
            ):
                raise DoDomainConfigError(
                    "DoDomain: proof_timeout must be a number of seconds above 0 and at most "
                    f"{KEYLESS_PROOF_MAX_TIMEOUT:g} (a challenge lives 5 minutes)."
                )
            self._secret_key = None
            self._keyless_key = keyless_key
            self._proof_timeout = float(proof_timeout)
            self.is_oauth = False
        else:
            if keyless_key is not None:
                raise DoDomainConfigError(
                    "DoDomain: keyless_key needs keyless=True (it is a keyless app's key)."
                )
            if not isinstance(secret_key, str) or not secret_key.strip():
                raise DoDomainConfigError(
                    "DoDomain: a secret key is required: pass secret_key=os.environ"
                    '["DODOMAIN_SECRET_KEY"]. To try doDomain with no account, use '
                    "DoDomain(keyless=True)."
                )
            secret_key = secret_key.strip()
            # An OAuth access token is accepted as an escape hatch for the MCP/agent
            # path. It is TEAM-scoped rather than app-scoped, which makes `app_id`
            # required when creating a session — flagging it here turns a server 404
            # into a clear local error.
            self.is_oauth = bool(_COMPACT_JWT_RE.match(secret_key))
            if not self.is_oauth and not secret_key.startswith(SECRET_KEY_PREFIX):
                raise DoDomainConfigError(
                    f"DoDomain: a secret key must start with {SECRET_KEY_PREFIX!r} "
                    "(or be an OAuth access token). Get one from "
                    "https://app.dodomain.io -> your app -> API keys."
                )
            self._secret_key = secret_key
        if max_retries < 0:
            raise DoDomainConfigError("DoDomain: max_retries must be >= 0.")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = _default_user_agent()
        #: What the most recent response said about rate limits. All draft-11
        #: fields are ``None`` today; see :class:`RateLimitSnapshot`.
        self.last_rate_limit = RateLimitSnapshot()
        #: Learned from ``apps.list()``. A secret key is app-scoped, so once the
        #: SDK knows which app it belongs to it can reject a contradicting
        #: ``app_id`` locally instead of round-tripping for the identical 400.
        self._known_app_id: str | None = None
        self._rng = random.Random()

    @property
    def is_keyless(self) -> bool:
        """Whether this client was built with ``keyless=True``."""
        return self._secret_key is None

    @property
    def keyless_key(self) -> str | None:
        """Keyless mode only: the ``dd_ks_`` key of this client's keyless app.

        ``None`` before the first ``sessions.create`` returned one (and always on a
        secret-key client). It is returned once; persist it like a password and
        pass it back as ``keyless_key`` to keep using the same app from another
        process.
        """
        return self._keyless_key

    def _refuse_in_keyless_mode(self, spec: RequestSpec) -> None:
        """A call authorized by the secret key. A keyless client has none, and
        the API refuses its ``dd_ks_`` key everywhere but the keyless routes, so it
        fails here without a request. Token-public calls (no credential) pass."""
        if self._secret_key is None and spec.auth and spec.credential is None:
            raise DoDomainKeylessError(
                "KEYLESS_MODE",
                status_code=0,
                message=(
                    "A keyless client can only create sessions, read keyless.status() "
                    f"and call the token-public session routes. {spec.method} {spec.path} "
                    "needs a secret key: claim the keyless app (the claim_url on its "
                    "sessions) and use its dd_sk_ key."
                ),
            )

    @staticmethod
    def new_idempotency_key() -> str:
        """Mint a key for the optional ``idempotency_key`` argument.

        The doDomain API does not currently honour ``Idempotency-Key``; the header
        is accepted and forwarded for forward-compatibility only.
        """
        return str(uuid.uuid4())

    def _build_request(self, client: httpx.Client | httpx.AsyncClient, spec: RequestSpec):
        return client.build_request(
            spec.method,
            self.base_url + spec.path,
            params=spec.params,
            json=spec.json_body,
            headers=build_headers(spec, secret_key=self._secret_key, user_agent=self.user_agent),
        )

    def _connection_error(self, spec: RequestSpec, exc: BaseException) -> DoDomainConnectionError:
        return DoDomainConnectionError(
            f"doDomain request failed before a response was received: "
            f"{spec.method} {spec.path} ({type(exc).__name__}: {exc})",
            cause=exc,
        )


class DoDomain(_BaseClient):
    """Synchronous doDomain API client.

    Args:
        secret_key: An app secret key (``dd_sk_…``) or an OAuth 2.1 access token.
            Required unless ``keyless=True``.
        base_url: API origin. Defaults to ``https://app.dodomain.io`` — the one
            origin that actually serves ``/api/v1/*``.
        timeout: Per-request timeout in seconds.
        max_retries: Replays of an idempotent request. ``POST`` is never retried
            (the API has no server-side idempotency).
        http_client: Bring your own ``httpx.Client`` (custom transport, proxies,
            test doubles). The SDK will not close a client it did not create.
        keyless: Keyless mode: no account and no key. ``sessions.create`` calls
            ``POST /api/v1/keyless/sessions``, solves the proof of work the first
            call asks for, and keeps the returned ``dd_ks_`` key. Every call that
            needs a secret key raises ``DoDomainKeylessError`` (``KEYLESS_MODE``).
        keyless_key: Keyless mode only: a ``dd_ks_`` key from an earlier keyless
            start, to keep using that app.
        proof_timeout: Keyless mode only: the most one proof-of-work solve may
            take, in seconds, above 0 and at most 300. Default 120.

    Example:
        >>> import os
        >>> from dodomain import DoDomain, DnsRecord
        >>> client = DoDomain(secret_key=os.environ["DODOMAIN_SECRET_KEY"])
        >>> session = client.sessions.create(
        ...     domain="app.customer.com",
        ...     records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
        ... )
        >>> print(session.connect_url)
    """

    def __init__(
        self,
        *,
        secret_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        http_client: httpx.Client | None = None,
        keyless: bool = False,
        keyless_key: str | None = None,
        proof_timeout: float = KEYLESS_PROOF_DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(
            secret_key=secret_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            keyless=keyless,
            keyless_key=keyless_key,
            proof_timeout=proof_timeout,
        )
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)
        #: Held by the one thread starting a keyless app, so concurrent creates
        #: on a fresh keyless client start ONE app and reuse its key.
        self._keyless_start_lock = threading.Lock()

        self.sessions = Sessions(self)
        self.keyless = Keyless(self)
        self.connections = Connections(self)
        self.domains = Domains(self)
        self.apps = Apps(self)
        self.webhook_endpoints = WebhookEndpoints(self)
        self.keys = Keys(self)

    def request(self, spec: RequestSpec) -> Any:
        """Send one request, applying the retry policy, and return parsed JSON."""
        self._refuse_in_keyless_mode(spec)
        attempt = 0
        while True:
            request = self._build_request(self._http, spec)
            try:
                response = self._http.send(request)
            except httpx.TransportError as exc:
                if attempt < self.max_retries and spec.method in {"GET", "DELETE"}:
                    time.sleep(backoff_delay(attempt, self._rng))
                    attempt += 1
                    continue
                raise self._connection_error(spec, exc) from exc

            self.last_rate_limit = RateLimitSnapshot.from_headers(response.headers)
            if attempt < self.max_retries:
                delay = retry_delay_for_response(response, spec, attempt, self._rng)
                if delay is not None:
                    response.close()
                    time.sleep(delay)
                    attempt += 1
                    continue

            if response.status_code >= 400:
                raise map_error(response, spec)
            return parse_success(response, spec)

    def close(self) -> None:
        """Close the underlying transport, unless it was injected."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> DoDomain:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncDoDomain(_BaseClient):
    """Asynchronous doDomain API client.

    Method names, arguments and return types are identical to :class:`DoDomain`;
    every resource method is awaitable and ``connections.list_all`` is an async
    iterator.

    Example:
        >>> async with AsyncDoDomain(secret_key=key) as client:
        ...     async for connection in client.connections.list_all():
        ...         print(connection.id)
    """

    def __init__(
        self,
        *,
        secret_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        http_client: httpx.AsyncClient | None = None,
        keyless: bool = False,
        keyless_key: str | None = None,
        proof_timeout: float = KEYLESS_PROOF_DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(
            secret_key=secret_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            keyless=keyless,
            keyless_key=keyless_key,
            proof_timeout=proof_timeout,
        )
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)
        #: True while one task is starting a keyless app; see ``_keyless_start_lock``.
        self._keyless_starting = False

        self.sessions = AsyncSessions(self)
        self.keyless = AsyncKeyless(self)
        self.connections = AsyncConnections(self)
        self.domains = AsyncDomains(self)
        self.apps = AsyncApps(self)
        self.webhook_endpoints = AsyncWebhookEndpoints(self)
        self.keys = AsyncKeys(self)

    async def request(self, spec: RequestSpec) -> Any:
        """Send one request, applying the retry policy, and return parsed JSON."""
        self._refuse_in_keyless_mode(spec)
        attempt = 0
        while True:
            request = self._build_request(self._http, spec)
            try:
                response = await self._http.send(request)
            except httpx.TransportError as exc:
                if attempt < self.max_retries and spec.method in {"GET", "DELETE"}:
                    await asyncio.sleep(backoff_delay(attempt, self._rng))
                    attempt += 1
                    continue
                raise self._connection_error(spec, exc) from exc

            self.last_rate_limit = RateLimitSnapshot.from_headers(response.headers)
            if attempt < self.max_retries:
                delay = retry_delay_for_response(response, spec, attempt, self._rng)
                if delay is not None:
                    await response.aclose()
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue

            if response.status_code >= 400:
                raise map_error(response, spec)
            return parse_success(response, spec)

    async def close(self) -> None:
        """Close the underlying transport, unless it was injected."""
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncDoDomain:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()
