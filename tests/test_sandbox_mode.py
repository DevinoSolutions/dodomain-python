"""Sandbox sessions (0.8.0, parity with ``@dodomain/node`` 0.10.0, DoDomain T-18114).

Both create routes answer ``mode: "live" | "sandbox"``, and every connection and
session webhook for a sandbox session carries ``data.sandbox: true``. Every API
below is a respx MOCK of the wire shape the app repo's
``packages/core/src/schemas.ts`` publishes; nothing here reaches the network.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from dodomain import (
    SANDBOX_DOMAINS,
    DnsRecord,
    InvalidResponseError,
    verify_webhook,
)
from dodomain.webhooks import sign_webhook
from tests.helpers import (
    CREATE_SESSION_RESPONSE,
    LEGACY_CREATE_SESSION_RESPONSE,
    api,
    make_async_client,
    make_client,
)
from tests.test_keyless import (
    ScriptedKeylessApi,
    async_keyless_client,
    keyless_client,
    mock_keyless_routes,
)

CNAME = DnsRecord(type="CNAME", host="app", value="edge.example.com")
SESSIONS_URL = api("/api/v1/sessions")


def create_body(**overrides: Any) -> dict[str, Any]:
    return {**CREATE_SESSION_RESPONSE, **overrides}


def test_the_sandbox_names_match_the_five_reserved_in_the_app_repo() -> None:
    # packages/core/src/sandbox.ts is the one home; exact, lowercase names.
    assert SANDBOX_DOMAINS == (
        "verified.test",
        "pending.test",
        "slow.test",
        "wrong-record.test",
        "unsupported.test",
    )


@pytest.mark.parametrize("mode", ["live", "sandbox"])
@respx.mock
def test_a_secret_key_create_carries_the_mode_the_api_answered(mode: str) -> None:
    respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=create_body(mode=mode)))
    with make_client() as client:
        session = client.sessions.create(domain="verified.test", records=[CNAME])
    assert session.mode == mode


@pytest.mark.parametrize("mode", ["live", "sandbox"])
@respx.mock
async def test_the_async_create_carries_the_same_mode(mode: str) -> None:
    respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=create_body(mode=mode)))
    async with make_async_client() as client:
        session = await client.sessions.create(domain="verified.test", records=[CNAME])
    assert session.mode == mode


@respx.mock
def test_a_mode_the_api_adds_later_parses_as_its_string_instead_of_failing() -> None:
    respx.post(SESSIONS_URL).mock(
        return_value=httpx.Response(200, json=create_body(mode="preview"))
    )
    with make_client() as client:
        assert client.sessions.create(domain="acme.com", records=[CNAME]).mode == "preview"


@respx.mock
def test_a_response_from_before_the_field_existed_parses_with_mode_none() -> None:
    respx.post(SESSIONS_URL).mock(
        return_value=httpx.Response(200, json=LEGACY_CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        assert client.sessions.create(domain="acme.com", records=[CNAME]).mode is None


@respx.mock
def test_a_mode_that_is_not_a_string_is_contract_drift_and_fails_loudly() -> None:
    respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=create_body(mode=1)))
    with make_client() as client, pytest.raises(InvalidResponseError):
        client.sessions.create(domain="acme.com", records=[CNAME])


def sandbox_answer(request: httpx.Request) -> httpx.Response:
    """MOCK API: the scripted keyless stand-in, answering as the API does for a
    sandbox name (``mode: "sandbox"``)."""
    response = ScriptedKeylessApi()(request)
    if response.status_code != 200 or request.url.path != "/api/v1/keyless/sessions":
        return response
    return httpx.Response(200, json={**response.json(), "mode": "sandbox"})


def test_a_keyless_sandbox_session_parses_where_0_7_0_refused_it() -> None:
    # 0.7.0 pinned the keyless `mode` to "live" and raised InvalidResponseError on
    # the "sandbox" the API now answers for verified.test.
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, sandbox_answer)
        session = keyless_client().sessions.create(domain="verified.test", records=[CNAME])
    assert session.mode == "sandbox"
    assert session.keyless is not None


async def test_the_async_keyless_client_parses_a_sandbox_session_too() -> None:
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, sandbox_answer)
        async with async_keyless_client() as client:
            session = await client.sessions.create(domain="verified.test", records=[CNAME])
    assert session.mode == "sandbox"


def test_a_sandbox_webhook_verifies_and_carries_the_flag_in_data() -> None:
    secret = "whsec_sandbox"
    raw = json.dumps(
        {
            "id": "whd_1",
            "type": "connection.verified",
            "occurredAt": "2026-11-26T10:00:00.000Z",
            "data": {"sessionId": "cs_1", "connectionId": "conn_1", "sandbox": True},
            "event": "connection.verified",
        }
    )
    header = sign_webhook(secret, raw, 1786000000000)
    assert verify_webhook(secret, raw, header, now_ms=1786000000000) is True
    assert json.loads(raw)["data"].get("sandbox") is True
