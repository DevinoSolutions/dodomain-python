from __future__ import annotations

import httpx
import pytest
import respx

import dodomain
from dodomain import AsyncDoDomain, DoDomain, DoDomainConfigError
from dodomain._transport import RequestSpec
from tests.helpers import TEST_JWT, TEST_KEY, api, make_client


def test_secret_key_must_carry_the_dd_sk_prefix() -> None:
    with pytest.raises(DoDomainConfigError) as excinfo:
        DoDomain(secret_key="sk_live_nope")
    assert "dd_sk_" in str(excinfo.value)


def test_empty_secret_key_is_rejected_at_construction() -> None:
    with pytest.raises(DoDomainConfigError):
        DoDomain(secret_key="   ")


def test_negative_max_retries_is_rejected_at_construction() -> None:
    with pytest.raises(DoDomainConfigError):
        DoDomain(secret_key=TEST_KEY, max_retries=-1)


def test_a_compact_jwt_is_accepted_as_an_oauth_credential() -> None:
    client = DoDomain(secret_key=TEST_JWT)
    assert client.is_oauth is True


def test_a_secret_key_is_not_flagged_as_oauth() -> None:
    assert DoDomain(secret_key=TEST_KEY).is_oauth is False


def test_the_default_base_url_is_the_one_origin_that_resolves() -> None:
    # api.dodomain.io does not resolve; a previous SDK shipped it and every call
    # 404'd with no error surface.
    assert DoDomain(secret_key=TEST_KEY).base_url == "https://app.dodomain.io"


def test_a_trailing_slash_is_stripped_from_a_custom_base_url() -> None:
    client = DoDomain(secret_key=TEST_KEY, base_url="https://staging.dodomain.io/")
    assert client.base_url == "https://staging.dodomain.io"


@respx.mock
def test_every_request_carries_the_bearer_key_and_the_sdk_user_agent() -> None:
    route = respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"ok": True}))
    with make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    request = route.calls[0].request
    assert request.headers["authorization"] == f"Bearer {TEST_KEY}"
    assert request.headers["user-agent"] == f"dodomain-python/{dodomain.__version__}"
    assert request.headers["accept"] == "application/json"


@respx.mock
def test_a_token_public_request_sends_no_authorization_header() -> None:
    route = respx.get(api("/api/v1/sessions/tok")).mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    with make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/sessions/tok", auth=False))
    assert "authorization" not in route.calls[0].request.headers


@respx.mock
def test_a_json_body_sets_content_type_and_an_empty_one_does_not() -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bare = respx.post(api("/api/v1/sessions/tok/detect")).mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    with make_client() as client:
        client.request(RequestSpec("POST", "/api/v1/domains/check", json_body={"domain": "a.io"}))
        client.request(RequestSpec("POST", "/api/v1/sessions/tok/detect", auth=False))
    assert route.calls[0].request.headers["content-type"] == "application/json"
    assert "content-type" not in bare.calls[0].request.headers


@respx.mock
def test_an_idempotency_key_is_forwarded_verbatim() -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    with make_client() as client:
        client.request(
            RequestSpec(
                "POST",
                "/api/v1/domains/check",
                json_body={"domain": "a.io"},
                idempotency_key="key-1",
            )
        )
    assert route.calls[0].request.headers["idempotency-key"] == "key-1"


def test_new_idempotency_key_returns_a_distinct_uuid_each_time() -> None:
    client = make_client()
    assert client.new_idempotency_key() != client.new_idempotency_key()


@respx.mock
def test_an_injected_http_client_is_used_and_never_closed_by_the_sdk() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"ok": True}))
    injected = httpx.Client()
    client = DoDomain(secret_key=TEST_KEY, http_client=injected)
    client.request(RequestSpec("GET", "/api/v1/apps"))
    client.close()
    assert injected.is_closed is False
    injected.close()


@respx.mock
async def test_the_async_client_closes_its_own_transport_on_aexit() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"ok": True}))
    async with AsyncDoDomain(secret_key=TEST_KEY) as client:
        await client.request(RequestSpec("GET", "/api/v1/apps"))
        transport = client._http
    assert transport.is_closed is True


@respx.mock
async def test_an_injected_async_client_is_not_closed_by_the_sdk() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"ok": True}))
    injected = httpx.AsyncClient()
    client = AsyncDoDomain(secret_key=TEST_KEY, http_client=injected)
    await client.request(RequestSpec("GET", "/api/v1/apps"))
    await client.close()
    assert injected.is_closed is False
    await injected.aclose()
