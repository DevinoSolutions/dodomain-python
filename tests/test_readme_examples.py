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
    INTEGRATOR_SESSION_RESPONSE,
    LIST_APPS_RESPONSE,
    PUBLIC_SESSION_RESPONSE,
    ROTATED_KEY_RESPONSE,
    ROTATED_KEY_WITH_OVERLAP_RESPONSE,
    VERIFY_RESPONSE,
    api,
    connection,
    make_async_client,
    make_client,
    webhook_endpoint,
    webhook_endpoint_with_secret,
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
        # The block prints the composed name — the doubled-label check.
        assert [r.fqdn for r in session.records] == ["app.app.customer.com"]


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
def test_the_session_read_back_block_runs() -> None:
    respx.get(api("/api/v1/sessions/cs_01HZX")).mock(
        return_value=httpx.Response(200, json=INTEGRATOR_SESSION_RESPONSE)
    )
    with make_client() as client:
        state = client.sessions.get("cs_01HZX")
    assert state.status == "verified"
    assert state.expired is False
    assert state.connection_id == "conn_1"
    assert state.records[0].fqdn == "app.app.customer.com"


@respx.mock
def test_the_webhook_endpoints_block_runs() -> None:
    respx.post(api("/api/v1/webhook-endpoints")).mock(
        return_value=httpx.Response(201, json=webhook_endpoint_with_secret())
    )
    respx.get(api("/api/v1/webhook-endpoints")).mock(
        return_value=httpx.Response(200, json={"endpoints": [webhook_endpoint()]})
    )
    respx.patch(api("/api/v1/webhook-endpoints/whe_123")).mock(
        return_value=httpx.Response(200, json=webhook_endpoint(id="whe_123"))
    )
    respx.post(api("/api/v1/webhook-endpoints/whe_123/rotate-secret")).mock(
        return_value=httpx.Response(200, json=webhook_endpoint_with_secret(id="whe_123"))
    )
    respx.delete(api("/api/v1/webhook-endpoints/whe_123")).mock(
        return_value=httpx.Response(200, json={"id": "whe_123", "deleted": True})
    )
    with make_client() as client:
        endpoint = client.webhook_endpoints.create(url="https://acme.example/webhooks/dodomain")
        assert endpoint.secret.startswith("whsec_")
        assert [(e.id, e.url) for e in client.webhook_endpoints.list()] == [
            ("whe_1", "https://acme.example/webhooks/dodomain")
        ]
        client.webhook_endpoints.update("whe_123", url="https://acme.example/v2")
        rotated = client.webhook_endpoints.rotate_secret("whe_123")
        assert rotated.secret.startswith("whsec_")
        assert client.webhook_endpoints.delete("whe_123").deleted is True


@respx.mock
def test_the_key_rotation_block_runs() -> None:
    respx.post(api("/api/v1/keys/rotate")).mock(
        return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE)
    )
    with make_client() as client:
        rotated = client.keys.rotate()
    assert rotated.secret_key.startswith("dd_sk_")
    assert rotated.public_key == "dd_pk_live_abc"
    assert rotated.previous_key_expires_at is None


@respx.mock
def test_the_zero_downtime_rotation_block_runs() -> None:
    respx.post(api("/api/v1/keys/rotate")).mock(
        return_value=httpx.Response(200, json=ROTATED_KEY_WITH_OVERLAP_RESPONSE)
    )
    with make_client() as client:
        rotated = client.keys.rotate(overlap_hours=24)
    assert rotated.previous_key_expires_at is not None


@respx.mock
def test_the_connection_get_lines_in_the_connections_block_run() -> None:
    respx.get(api("/api/v1/connections/conn_123")).mock(
        return_value=httpx.Response(200, json=connection(id="conn_123"))
    )
    with make_client() as client:
        conn = client.connections.get("conn_123")
    assert conn.status in ("active", "broken")
    assert conn.record_fqdns == ("status.app.customer.com",)
    assert conn.disconnected_at is None


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


def test_the_webhook_handler_block_runs_against_the_body_actually_delivered() -> None:
    secret = "whsec_readme"
    # The post-cutover envelope the README documents, key order and all.
    raw = json.dumps(
        {
            "id": "whd_1",
            "type": "connection.verified",
            "occurredAt": "2026-08-17T10:00:00.000Z",
            "data": {"sessionId": "cs_01HZX", "connectionId": "conn_1"},
            "event": "connection.verified",
        }
    )
    header = sign_webhook(secret, raw, 1786000000000)

    assert verify_webhook(secret, raw, header, now_ms=1786000000000) is True
    event = json.loads(raw)
    assert event["type"] == "connection.verified"
    # The deprecated alias is byte-identical to `type`, which is the whole reason
    # a pre-cutover receiver keeps working.
    assert event["event"] == event["type"]
    assert event["data"]["connectionId"] == "conn_1"
    # The rejection path the README shows.
    assert verify_webhook(secret, raw, "garbage", now_ms=1786000000000) is False


def test_the_readme_no_longer_claims_the_legacy_webhook_body_is_current() -> None:
    # 0.1.0 documented `{event, data}` as what arrives. The cutover landed on
    # 2026-08-06 and a reader following the old text would build the wrong parser.
    text = README.read_text(encoding="utf-8")
    assert "still the legacy" not in text
    assert "waits on a deliberate cutover" not in text
    assert "occurredAt" in text


def test_the_readme_does_not_repeat_the_false_no_openapi_claim() -> None:
    # The spec is served at dodomain.io/docs/openapi.json; saying otherwise sent
    # readers looking for a contract that was published all along.
    assert "publishes no\nOpenAPI" not in README.read_text(encoding="utf-8")


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
