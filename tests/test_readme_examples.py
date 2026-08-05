"""The README's code blocks, executed.

Documentation that has never been run is a liability. Every snippet the README
shows a reader is exercised here against respx mocks, so a rename or a signature
change breaks the build instead of quietly breaking the docs.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re

import httpx
import respx

from dodomain import AsyncDoDomain, DnsRecord, DoDomain, verify_webhook
from dodomain.webhooks import sign_webhook
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

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


def test_every_symbol_the_readme_imports_exists_on_the_public_surface() -> None:
    import dodomain

    text = README.read_text(encoding="utf-8")
    imported: set[str] = set()
    for line in re.findall(r"^from dodomain import (.+)$", text, flags=re.MULTILINE):
        imported.update(name.strip() for name in line.split(","))
    assert imported, "the README must show at least one import"
    for name in imported:
        assert hasattr(dodomain, name), f"README imports dodomain.{name}, which does not exist"
        assert name in dodomain.__all__, f"dodomain.{name} is not in __all__"


def test_the_readme_never_mentions_the_origin_that_does_not_resolve() -> None:
    # A previous SDK shipped api.dodomain.io as its default and every call 404'd.
    assert "api.dodomain.io" not in README.read_text(encoding="utf-8")


@respx.mock
def test_the_quickstart_block_runs() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.create(
            domain="app.customer.com",
            records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
            return_url="https://customer.com/settings/domains",
        )
        assert session.connect_url.startswith("https://app.dodomain.io/connect/")
        assert session.expires_at.tzinfo is not None


@respx.mock
def test_the_token_public_block_runs() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    respx.get(api("/api/v1/sessions/tok_live_abc123")).mock(
        return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
    )
    respx.post(api("/api/v1/sessions/tok_live_abc123/detect")).mock(
        return_value=httpx.Response(200, json=DETECT_RESPONSE)
    )
    respx.post(api("/api/v1/sessions/tok_live_abc123/verify")).mock(
        return_value=httpx.Response(200, json=VERIFY_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.create(
            domain="app.customer.com",
            records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
        )
        public = client.sessions.retrieve(session.token)
        detected = client.sessions.detect(session.token)
        result = client.sessions.verify(session.token)
        rows = [(r.fqdn, r.type, r.outcome) for r in result.records]

    assert public.status == "pending"
    assert detected.provider == "cloudflare"
    assert rows[0] == ("app.customer.com", "CNAME", "verified")
    assert session.cloudflare_start_url.endswith("/cloudflare/start")
    assert session.domain_connect_start_url.endswith("/domain-connect/start")


def test_the_async_block_runs() -> None:
    async def main() -> tuple[str, list[str]]:
        with respx.mock:
            respx.post(api("/api/v1/sessions")).mock(
                return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
            )
            respx.get(api("/api/v1/connections")).mock(
                return_value=httpx.Response(
                    200, json={"connections": [connection()], "nextCursor": None}
                )
            )
            async with make_async_client() as client:
                session = await client.sessions.create(
                    domain="app.customer.com",
                    records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
                )
                ids = [c.id async for c in client.connections.list_all()]
            return session.connect_url, ids

    connect_url, ids = asyncio.run(main())
    assert connect_url.startswith("https://app.dodomain.io/connect/")
    assert ids == ["conn_1"]


@respx.mock
def test_the_connections_block_runs() -> None:
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [connection()], "nextCursor": None})
    )
    respx.post(api("/api/v1/connections/conn_123/reverify")).mock(
        return_value=httpx.Response(202, json={"accepted": True})
    )
    respx.delete(api("/api/v1/connections/conn_123")).mock(
        return_value=httpx.Response(200, json=DISCONNECT_RESPONSE)
    )
    with make_client() as client:
        page = client.connections.list(limit=100)
        assert page.next_cursor is None
        assert page.has_more is False
        assert [c.id for c in client.connections.list_all(domain="app.customer.com")] == ["conn_1"]
        assert [
            c.disconnected_at for c in client.connections.list_all(include_disconnected=True)
        ] == [None]
        assert client.connections.reverify("conn_123").accepted is True
        result = client.connections.disconnect("conn_123")
        assert result.already_disconnected is False
        assert result.disconnected_at is not None


@respx.mock
def test_the_domain_check_and_apps_blocks_run() -> None:
    respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
    )
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json=LIST_APPS_RESPONSE))
    with make_client() as client:
        check = client.domains.check(domain="app.customer.com")
        assert (check.zone, check.provider, check.tier) == ("customer.com", "cloudflare", 2)
        assert check.method == "domain-connect"
        assert check.confidence == "medium"
        assert check.guide.steps
        for app in client.apps.list():
            assert (app.id, app.name, app.public_key, app.sandbox) == (
                "app_1",
                "Acme",
                "pk_live_abc",
                False,
            )


def test_the_webhook_handler_block_runs() -> None:
    secret = "whsec_readme"
    raw = json.dumps({"event": "connection.verified", "data": {"domain": "app.customer.com"}})
    header = sign_webhook(secret, raw, 1786000000000)

    assert verify_webhook(secret, raw, header, now_ms=1786000000000) is True
    assert json.loads(raw)["event"] == "connection.verified"
    # The rejection path the README shows.
    assert verify_webhook(secret, raw, "garbage", now_ms=1786000000000) is False


@respx.mock
def test_the_client_options_block_runs() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json=LIST_APPS_RESPONSE))
    client = DoDomain(
        secret_key="dd_sk_test_0123456789",
        base_url="https://app.dodomain.io",
        timeout=30.0,
        max_retries=2,
        http_client=None,
    )
    with client:
        assert client.apps.list()[0].id == "app_1"
        assert client.new_idempotency_key() != client.new_idempotency_key()
        assert client.last_rate_limit.limit is None


def test_the_error_handling_block_type_names_all_resolve() -> None:
    import dodomain

    text = README.read_text(encoding="utf-8")
    table = re.findall(r"^\| `[a-z_]+` \| `(\w+)` \| \d+ \|$", text, flags=re.MULTILINE)
    assert len(table) == 10, "the README error table must cover all ten API codes"
    for name in table:
        assert hasattr(dodomain, name)


def test_the_async_client_named_in_the_readme_is_importable() -> None:
    assert AsyncDoDomain.__name__ == "AsyncDoDomain"
