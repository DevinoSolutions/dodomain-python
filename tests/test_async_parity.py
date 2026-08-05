"""Proof that ``AsyncDoDomain`` is the same client with ``await`` in front.

Each case runs the sync method and its async twin against *identical* respx
mocks and asserts the two return equal objects. If the async surface ever drifts
— a field left unmapped, a different path, a missing validation — a case here
fails rather than an integrator discovering it in production.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
import respx

from dodomain import AsyncDoDomain, DnsRecord, DoDomain, InvalidRequestError
from tests.helpers import (
    CHECK_DOMAIN_RESPONSE,
    CREATE_SESSION_RESPONSE,
    DETECT_RESPONSE,
    DISCONNECT_RESPONSE,
    LIST_APPS_RESPONSE,
    PUBLIC_SESSION_RESPONSE,
    VERIFY_RESPONSE,
    api,
    connection,
    make_async_client,
    make_client,
)

CNAME = DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")

SyncCall = Callable[[DoDomain], Any]
AsyncCall = Callable[[AsyncDoDomain], Awaitable[Any]]

# (label, respx setup, sync call, async call)
CASES: list[tuple[str, Callable[[], None], SyncCall, AsyncCall]] = [
    (
        "sessions.create",
        lambda: (
            respx.post(api("/api/v1/sessions")).mock(
                return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
            )
            and None
        ),
        lambda c: c.sessions.create(domain="app.customer.com", records=[CNAME]),
        lambda c: c.sessions.create(domain="app.customer.com", records=[CNAME]),
    ),
    (
        "sessions.retrieve",
        lambda: (
            respx.get(api("/api/v1/sessions/tok")).mock(
                return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
            )
            and None
        ),
        lambda c: c.sessions.retrieve("tok"),
        lambda c: c.sessions.retrieve("tok"),
    ),
    (
        "sessions.detect",
        lambda: (
            respx.post(api("/api/v1/sessions/tok/detect")).mock(
                return_value=httpx.Response(200, json=DETECT_RESPONSE)
            )
            and None
        ),
        lambda c: c.sessions.detect("tok"),
        lambda c: c.sessions.detect("tok"),
    ),
    (
        "sessions.verify",
        lambda: (
            respx.post(api("/api/v1/sessions/tok/verify")).mock(
                return_value=httpx.Response(200, json=VERIFY_RESPONSE)
            )
            and None
        ),
        lambda c: c.sessions.verify("tok"),
        lambda c: c.sessions.verify("tok"),
    ),
    (
        "domains.check",
        lambda: (
            respx.post(api("/api/v1/domains/check")).mock(
                return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
            )
            and None
        ),
        lambda c: c.domains.check(domain="app.customer.com"),
        lambda c: c.domains.check(domain="app.customer.com"),
    ),
    (
        "connections.list",
        lambda: (
            respx.get(api("/api/v1/connections")).mock(
                return_value=httpx.Response(
                    200, json={"connections": [connection()], "nextCursor": "cur_1"}
                )
            )
            and None
        ),
        lambda c: c.connections.list(limit=10, domain="app.customer.com"),
        lambda c: c.connections.list(limit=10, domain="app.customer.com"),
    ),
    (
        "connections.reverify",
        lambda: (
            respx.post(api("/api/v1/connections/conn_1/reverify")).mock(
                return_value=httpx.Response(202, json={"accepted": True})
            )
            and None
        ),
        lambda c: c.connections.reverify("conn_1"),
        lambda c: c.connections.reverify("conn_1"),
    ),
    (
        "connections.disconnect",
        lambda: (
            respx.delete(api("/api/v1/connections/conn_1")).mock(
                return_value=httpx.Response(200, json=DISCONNECT_RESPONSE)
            )
            and None
        ),
        lambda c: c.connections.disconnect("conn_1"),
        lambda c: c.connections.disconnect("conn_1"),
    ),
    (
        "apps.list",
        lambda: (
            respx.get(api("/api/v1/apps")).mock(
                return_value=httpx.Response(200, json=LIST_APPS_RESPONSE)
            )
            and None
        ),
        lambda c: c.apps.list(),
        lambda c: c.apps.list(),
    ),
]


@pytest.mark.parametrize(
    ("label", "setup", "sync_call", "async_call"), CASES, ids=[case[0] for case in CASES]
)
async def test_the_async_method_returns_the_same_object_as_its_sync_twin(
    label: str, setup: Callable[[], None], sync_call: SyncCall, async_call: AsyncCall
) -> None:
    with respx.mock:
        setup()
        with make_client() as sync_client:
            expected = sync_call(sync_client)
    with respx.mock:
        setup()
        async with make_async_client() as async_client:
            actual = await async_call(async_client)
    assert actual == expected, label


@respx.mock
async def test_the_async_list_all_iterates_pages_exactly_like_the_sync_one() -> None:
    pages = [
        httpx.Response(200, json={"connections": [connection(id="c1")], "nextCursor": "cur_1"}),
        httpx.Response(200, json={"connections": [connection(id="c2")], "nextCursor": "cur_2"}),
        httpx.Response(200, json={"connections": [connection(id="c3")], "nextCursor": None}),
    ]
    respx.get(api("/api/v1/connections")).mock(side_effect=list(pages))
    with make_client() as sync_client:
        sync_ids = [conn.id for conn in sync_client.connections.list_all()]

    respx.get(api("/api/v1/connections")).mock(side_effect=list(pages))
    async with make_async_client() as async_client:
        async_ids = [conn.id async for conn in async_client.connections.list_all()]

    assert async_ids == sync_ids == ["c1", "c2", "c3"]


@respx.mock
async def test_the_async_client_validates_input_locally_too() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    async with make_async_client() as client:
        with pytest.raises(InvalidRequestError):
            await client.sessions.create(domain="not a domain", records=[CNAME])
    assert route.call_count == 0


@respx.mock
async def test_the_async_client_sends_no_credential_on_token_public_routes() -> None:
    route = respx.post(api("/api/v1/sessions/tok/detect")).mock(
        return_value=httpx.Response(200, json=DETECT_RESPONSE)
    )
    async with make_async_client() as client:
        await client.sessions.detect("tok")
    assert "authorization" not in route.calls[0].request.headers


def test_no_sync_httpx_client_is_ever_constructed_on_the_async_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("AsyncDoDomain must never build a blocking httpx.Client")

    monkeypatch.setattr(httpx, "Client", _explode)
    client = AsyncDoDomain(secret_key="dd_sk_test_key")
    assert isinstance(client._http, httpx.AsyncClient)
