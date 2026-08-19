"""Connections — the live custom domains your customers have connected.

Ownership rule for every method here: a connection that belongs to another app
(secret key) or another team (OAuth) answers **404, never 403**. The API refuses
to confirm that someone else's id exists, and the SDK does not "helpfully"
reinterpret that as a permission problem.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING
from urllib.parse import quote

from dodomain._transport import RequestSpec
from dodomain._validation import check_app_id_against_key
from dodomain.errors import InvalidRequestError
from dodomain.models import Connection, ConnectionPage, DisconnectResult, ReverifyResult

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncConnections", "Connections"]

MIN_LIMIT = 1
MAX_LIMIT = 100
DEFAULT_LIMIT = 50
#: ``list_all`` pages as coarsely as the API allows — fewer round trips, and the
#: caller never sees the page boundary anyway.
LIST_ALL_LIMIT = 100


def _connection_path(connection_id: str, suffix: str = "") -> str:
    if not isinstance(connection_id, str) or not connection_id.strip():
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="a connection id is required."
        )
    return f"/api/v1/connections/{quote(connection_id, safe='')}{suffix}"


def _spec_list(
    *,
    app_id: str | None,
    domain: str | None,
    limit: int,
    cursor: str | None,
    include_disconnected: bool,
    is_oauth: bool,
    known_app_id: str | None,
) -> RequestSpec:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="limit must be an integer."
        )
    if not MIN_LIMIT <= limit <= MAX_LIMIT:
        raise InvalidRequestError(
            "invalid_request",
            status_code=0,
            message=f"limit must be between {MIN_LIMIT} and {MAX_LIMIT} (got {limit}).",
        )
    check_app_id_against_key(app_id, is_oauth=is_oauth, known_app_id=known_app_id)

    params: dict[str, str] = {
        "limit": str(limit),
        # Only the two canonical spellings coerce server-side; anything else is a
        # loud invalid_request there, so send exactly one of them.
        "includeDisconnected": "true" if include_disconnected else "false",
    }
    if app_id is not None:
        params["appId"] = app_id
    if domain is not None:
        params["domain"] = domain
    if cursor is not None:
        if not isinstance(cursor, str) or not cursor:
            raise InvalidRequestError(
                "invalid_request",
                status_code=0,
                message="cursor must be the non-empty next_cursor from a previous page.",
            )
        params["cursor"] = cursor
    return RequestSpec("GET", "/api/v1/connections", params=params)


class Connections:
    """``client.connections``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def get(self, connection_id: str) -> Connection:
        """Read one connection by the id every ``connection.*`` webhook carries.

        The body is byte-identical to one element of :meth:`list`, so a single
        parser serves both. Reach for this instead of listing-and-filtering when
        you already hold an id: past the paging ceiling, filtering means walking
        every cursor.

        Unlike :meth:`list`, a **disconnected** connection is returned — a caller
        naming an id already knows the row exists, and ``disconnected_at`` is
        exactly what it came to read.

        Raises:
            NotFoundError: Unknown id — or one you do not own. The two are
                deliberately indistinguishable.
        """
        return Connection._from_api(
            self._client.request(RequestSpec("GET", _connection_path(connection_id)))
        )

    def list(
        self,
        *,
        app_id: str | None = None,
        domain: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
        include_disconnected: bool = False,
    ) -> ConnectionPage:
        """Fetch one page of connections, newest first.

        Args:
            app_id: Narrow to one app. Only meaningful for OAuth callers — a
                ``dd_sk_`` key is already app-scoped.
            domain: Exact session-domain match.
            limit: 1–100, default 50.
            cursor: The ``next_cursor`` from a previous page. **Opaque** — never
                construct or parse one.
            include_disconnected: Include connections you have disconnected.
                Default ``False``: the honest default is "what is live".

        Returns:
            A :class:`~dodomain.models.ConnectionPage`.
        """
        spec = _spec_list(
            app_id=app_id,
            domain=domain,
            limit=limit,
            cursor=cursor,
            include_disconnected=include_disconnected,
            is_oauth=self._client.is_oauth,
            known_app_id=self._client._known_app_id,
        )
        return ConnectionPage._from_api(self._client.request(spec))

    def list_all(
        self,
        *,
        app_id: str | None = None,
        domain: str | None = None,
        limit: int = LIST_ALL_LIMIT,
        include_disconnected: bool = False,
    ) -> Iterator[Connection]:
        """Iterate every matching connection, following the cursor for you.

        The ergonomic default: pages are fetched lazily as you consume them, and
        iteration stops when the API returns ``nextCursor: null``.

        Example:
            >>> for connection in client.connections.list_all(domain="app.customer.com"):
            ...     print(connection.id, connection.status)
        """
        cursor: str | None = None
        while True:
            page = self.list(
                app_id=app_id,
                domain=domain,
                limit=limit,
                cursor=cursor,
                include_disconnected=include_disconnected,
            )
            yield from page.connections
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def reverify(self, connection_id: str, *, idempotency_key: str | None = None) -> ReverifyResult:
        """Ask for an on-demand DNS health recheck of one connection.

        Answers ``202`` — the check runs in a worker and the outcome arrives as a
        ``connection.verified`` / ``connection.failed`` webhook, not in this
        response.

        Raises:
            RateLimitError: With ``reason == "recently_checked"`` if this
                connection was checked inside its 10-minute cooldown. That is not
                a rate problem and the SDK deliberately does not retry it.
            NotFoundError: Unknown id — or one you do not own.
        """
        spec = RequestSpec(
            "POST", _connection_path(connection_id, "/reverify"), idempotency_key=idempotency_key
        )
        return ReverifyResult._from_api(self._client.request(spec))

    def disconnect(
        self, connection_id: str, *, idempotency_key: str | None = None
    ) -> DisconnectResult:
        """Disconnect a connection and stop monitoring its DNS.

        Idempotent by construction: a repeat returns the *original*
        ``disconnected_at`` with ``already_disconnected=True`` and emits no second
        webhook, which is why this SDK is willing to retry it.
        """
        spec = RequestSpec(
            "DELETE", _connection_path(connection_id), idempotency_key=idempotency_key
        )
        return DisconnectResult._from_api(self._client.request(spec))


class AsyncConnections:
    """``client.connections`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def get(self, connection_id: str) -> Connection:
        """Read one connection by id. See :meth:`Connections.get`."""
        return Connection._from_api(
            await self._client.request(RequestSpec("GET", _connection_path(connection_id)))
        )

    async def list(
        self,
        *,
        app_id: str | None = None,
        domain: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
        include_disconnected: bool = False,
    ) -> ConnectionPage:
        """Fetch one page of connections. See :meth:`Connections.list`."""
        spec = _spec_list(
            app_id=app_id,
            domain=domain,
            limit=limit,
            cursor=cursor,
            include_disconnected=include_disconnected,
            is_oauth=self._client.is_oauth,
            known_app_id=self._client._known_app_id,
        )
        return ConnectionPage._from_api(await self._client.request(spec))

    async def list_all(
        self,
        *,
        app_id: str | None = None,
        domain: str | None = None,
        limit: int = LIST_ALL_LIMIT,
        include_disconnected: bool = False,
    ) -> AsyncIterator[Connection]:
        """Iterate every matching connection. See :meth:`Connections.list_all`.

        Example:
            >>> async for connection in client.connections.list_all():
            ...     print(connection.id)
        """
        cursor: str | None = None
        while True:
            page = await self.list(
                app_id=app_id,
                domain=domain,
                limit=limit,
                cursor=cursor,
                include_disconnected=include_disconnected,
            )
            for connection in page.connections:
                yield connection
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def reverify(
        self, connection_id: str, *, idempotency_key: str | None = None
    ) -> ReverifyResult:
        """Request an on-demand recheck. See :meth:`Connections.reverify`."""
        spec = RequestSpec(
            "POST", _connection_path(connection_id, "/reverify"), idempotency_key=idempotency_key
        )
        return ReverifyResult._from_api(await self._client.request(spec))

    async def disconnect(
        self, connection_id: str, *, idempotency_key: str | None = None
    ) -> DisconnectResult:
        """Disconnect a connection. See :meth:`Connections.disconnect`."""
        spec = RequestSpec(
            "DELETE", _connection_path(connection_id), idempotency_key=idempotency_key
        )
        return DisconnectResult._from_api(await self._client.request(spec))
