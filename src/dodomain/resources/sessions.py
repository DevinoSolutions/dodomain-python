"""Connect sessions — the heart of the API.

``create`` and ``get`` are authenticated with your app secret key. The other three
(``retrieve``, ``detect``, ``verify``) are **token-public**: the session token in
the path *is* the capability, and they are called with no ``Authorization``
header at all, so a browser or a customer-side process can drive the flow.

``retrieve`` and ``get`` share one server path with two arms, discriminated by the
shape of the segment — a ``dd_sess_`` token gets the public shape, a session id
gets the integrator shape — and this SDK keeps them as two methods rather than one
overloaded call, because they differ in credential, in return type, and in what
they do to an expired session. See :meth:`Sessions.get`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING
from urllib.parse import quote

from dodomain._transport import RequestSpec
from dodomain._validation import validate_create_session
from dodomain.errors import InvalidRequestError
from dodomain.models import (
    DetectResult,
    DnsRecord,
    IntegratorSession,
    PublicSession,
    Session,
    VerifyResult,
)

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncSessions", "Sessions"]

#: The literal prefix every session token is minted with (``SESSION_TOKEN_PREFIX``
#: in the app repo). Session ids are cuids — ``c`` + base36, never an underscore —
#: so the two key spaces cannot collide, which is exactly why the server can serve
#: both arms off one path.
SESSION_TOKEN_PREFIX = "dd_sess_"


def _token_path(token: str, suffix: str = "") -> str:
    if not isinstance(token, str) or not token.strip():
        raise ValueError("a session token is required")
    return f"/api/v1/sessions/{quote(token, safe='')}{suffix}"


def _session_id_path(session_id: str) -> str:
    """The authed arm's path, refusing a token before it can silently succeed.

    Passing a token here would *work* — the server would take the token arm and
    answer the public shape — and then fail deep inside the parser with a missing
    ``appId``. Refusing it up front says the useful thing instead.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="a session id is required."
        )
    if session_id.startswith(SESSION_TOKEN_PREFIX):
        raise InvalidRequestError(
            "invalid_request",
            status_code=0,
            message=(
                f"that is a session TOKEN ({SESSION_TOKEN_PREFIX}…), not a session id. "
                "Use sessions.retrieve(token) for the token-public shape, or pass the "
                "`sessionId` your webhook carried."
            ),
        )
    return f"/api/v1/sessions/{quote(session_id, safe='')}"


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

    def get(self, session_id: str) -> IntegratorSession:
        """Read a session back **by id**, with your credential.

        This is the arm to use from your server, and the only one that answers two
        questions :meth:`retrieve` cannot:

        * Webhooks carry ``sessionId``, never the token, so this is how a
          ``session.abandoned`` / ``session.completed`` receiver asks what state the
          session ended in without having stored the token at creation.
        * It reads an **expired** session. :meth:`retrieve` raises
          :class:`~dodomain.errors.ExpiredError` forever once the 24h TTL passes,
          which is right for a capability URL and useless for support.

        The returned :class:`~dodomain.models.IntegratorSession` is a different
        shape from :meth:`retrieve`'s — its ``records`` are composed names with
        **no ``value``**, and it adds ``app_id``, ``connection_id`` and ``expired``.

        Raises:
            InvalidRequestError: Locally, if handed a ``dd_sess_`` token instead of
                an id.
            NotFoundError: Unknown id — or one you do not own.
        """
        return IntegratorSession._from_api(
            self._client.request(RequestSpec("GET", _session_id_path(session_id)))
        )

    def retrieve(self, token: str) -> PublicSession:
        """Read a session back through the token-public route.

        No ``Authorization`` header is sent: the token is the capability. Reading by
        id with your own credential is :meth:`get`.

        Raises:
            NotFoundError: No such token.
            ExpiredError: The session's 24h TTL has elapsed.
            AuthenticationError: If ``token`` is not ``dd_sess_``-shaped. One server
                path serves both arms and picks between them *structurally* off that
                prefix, so a malformed value is routed to the authed arm — which this
                method sends no credential to. A garbled token therefore answers
                **401, not 404**; verified against production, and surprising enough
                to be worth knowing before you debug it as an auth problem.
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

    async def get(self, session_id: str) -> IntegratorSession:
        """Read a session back by id, authed. See :meth:`Sessions.get`."""
        return IntegratorSession._from_api(
            await self._client.request(RequestSpec("GET", _session_id_path(session_id)))
        )

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
