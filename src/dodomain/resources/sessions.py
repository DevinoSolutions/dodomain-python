"""Connect sessions — the heart of the API.

``create`` is authenticated with your app secret key. The other three
(``retrieve``, ``detect``, ``verify``) are **token-public**: the session token in
the path *is* the capability, and they are called with no ``Authorization``
header at all, so a browser or a customer-side process can drive the flow.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING
from urllib.parse import quote

from dodomain._transport import RequestSpec
from dodomain._validation import validate_create_session
from dodomain.models import DetectResult, DnsRecord, PublicSession, Session, VerifyResult

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncSessions", "Sessions"]


def _token_path(token: str, suffix: str = "") -> str:
    if not isinstance(token, str) or not token.strip():
        raise ValueError("a session token is required")
    return f"/api/v1/sessions/{quote(token, safe='')}{suffix}"


def _spec_create(
    *,
    domain: str,
    records: Sequence[DnsRecord] | Iterable[DnsRecord],
    app_id: str | None,
    recipe: str | None,
    return_url: str | None,
    is_oauth: bool,
    idempotency_key: str | None,
) -> RequestSpec:
    body = validate_create_session(
        domain=domain,
        records=records,
        app_id=app_id,
        recipe=recipe,
        return_url=return_url,
        is_oauth=is_oauth,
    )
    return RequestSpec("POST", "/api/v1/sessions", json_body=body, idempotency_key=idempotency_key)


class Sessions:
    """``client.sessions``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def create(
        self,
        *,
        domain: str,
        records: Sequence[DnsRecord] | Iterable[DnsRecord],
        app_id: str | None = None,
        recipe: str | None = None,
        return_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> Session:
        """Mint a connect session and get the URL to send the customer to.

        Args:
            domain: The hostname being connected, e.g. ``app.customer.com``. No
                scheme, port or trailing dot; at least two labels.
            records: The DNS records the customer must end up with. At least one.
                An ``MX`` record must carry a ``priority``.
            app_id: Which of your apps owns the session. **Required** when
                authenticating with an OAuth access token (team-scoped); omit it
                with a ``dd_sk_`` key, whose app is implicit.
            recipe: Accepted and stored for wire compatibility; consumed by
                nothing today.
            return_url: Where the hosted flow offers to send the customer back.
                ``http``/``https`` only, no embedded credentials, ≤2048 chars.
            idempotency_key: Forwarded as ``Idempotency-Key``. **The API does not
                currently honour it**, and this call is *not* idempotent — every
                call mints a new session, token and quota unit.

        Returns:
            The new :class:`~dodomain.models.Session`.

        Raises:
            InvalidRequestError: Locally, before any HTTP request, when the input
                cannot satisfy the API's schema.
            QuotaExceededError: The free plan's monthly connection cap is spent.
        """
        spec = _spec_create(
            domain=domain,
            records=records,
            app_id=app_id,
            recipe=recipe,
            return_url=return_url,
            is_oauth=self._client.is_oauth,
            idempotency_key=idempotency_key,
        )
        return Session._from_api(self._client.request(spec), base_url=self._client.base_url)

    def retrieve(self, token: str) -> PublicSession:
        """Read a session back through the token-public route.

        No ``Authorization`` header is sent: the token is the capability.

        Raises:
            NotFoundError: No such token.
            ExpiredError: The session's 24h TTL has elapsed.
        """
        return PublicSession._from_api(
            self._client.request(RequestSpec("GET", _token_path(token), auth=False))
        )

    def detect(self, token: str) -> DetectResult:
        """Detect the domain's DNS provider and the connect path it will take.

        Token-public. Persists the detected tier on the session.
        """
        return DetectResult._from_api(
            self._client.request(RequestSpec("POST", _token_path(token, "/detect"), auth=False))
        )

    def verify(self, token: str) -> VerifyResult:
        """Check the session's records against live DNS.

        Token-public, and idempotent by construction server-side: the atomic
        claim inside ``finalizeConnection`` makes a double-verify a no-op — no
        double metering, no duplicate webhook — so retrying it yourself is safe.
        """
        return VerifyResult._from_api(
            self._client.request(RequestSpec("POST", _token_path(token, "/verify"), auth=False))
        )


class AsyncSessions:
    """``client.sessions`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def create(
        self,
        *,
        domain: str,
        records: Sequence[DnsRecord] | Iterable[DnsRecord],
        app_id: str | None = None,
        recipe: str | None = None,
        return_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> Session:
        """Mint a connect session. See :meth:`Sessions.create`."""
        spec = _spec_create(
            domain=domain,
            records=records,
            app_id=app_id,
            recipe=recipe,
            return_url=return_url,
            is_oauth=self._client.is_oauth,
            idempotency_key=idempotency_key,
        )
        return Session._from_api(await self._client.request(spec), base_url=self._client.base_url)

    async def retrieve(self, token: str) -> PublicSession:
        """Read a session back. See :meth:`Sessions.retrieve`."""
        return PublicSession._from_api(
            await self._client.request(RequestSpec("GET", _token_path(token), auth=False))
        )

    async def detect(self, token: str) -> DetectResult:
        """Detect the DNS provider. See :meth:`Sessions.detect`."""
        return DetectResult._from_api(
            await self._client.request(
                RequestSpec("POST", _token_path(token, "/detect"), auth=False)
            )
        )

    async def verify(self, token: str) -> VerifyResult:
        """Check records against live DNS. See :meth:`Sessions.verify`."""
        return VerifyResult._from_api(
            await self._client.request(
                RequestSpec("POST", _token_path(token, "/verify"), auth=False)
            )
        )
