from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import (
    InvalidRequestError,
    InvalidResponseError,
    NotFoundError,
    PermissionError_,
    WebhookEndpoint,
    WebhookEndpointWithSecret,
)
from tests.helpers import (
    api,
    make_client,
    webhook_endpoint,
    webhook_endpoint_with_secret,
)

COLLECTION = api("/api/v1/webhook-endpoints")


@respx.mock
def test_list_parses_every_endpoint_field() -> None:
    respx.get(COLLECTION).mock(
        return_value=httpx.Response(200, json={"endpoints": [webhook_endpoint()]})
    )
    with make_client() as client:
        endpoints = client.webhook_endpoints.list()
    assert len(endpoints) == 1
    assert endpoints[0].id == "whe_1"
    assert endpoints[0].app_id == "app_1"
    assert endpoints[0].url == "https://acme.example/webhooks/dodomain"
    assert endpoints[0].created_at == datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc)


@respx.mock
def test_list_never_yields_an_object_carrying_a_signing_secret() -> None:
    # The summary schema omits `secret` server-side. If a future deployment ever
    # leaked one into the list body, the SDK must still not surface it as a
    # secret-bearing type that a caller might log or persist.
    respx.get(COLLECTION).mock(
        return_value=httpx.Response(200, json={"endpoints": [webhook_endpoint_with_secret()]})
    )
    with make_client() as client:
        endpoint = client.webhook_endpoints.list()[0]
    assert isinstance(endpoint, WebhookEndpoint)
    assert not isinstance(endpoint, WebhookEndpointWithSecret)
    assert not hasattr(endpoint, "secret")


@respx.mock
def test_a_list_body_without_the_endpoints_array_is_an_invalid_response() -> None:
    respx.get(COLLECTION).mock(return_value=httpx.Response(200, json={"data": []}))
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.webhook_endpoints.list()


@respx.mock
def test_create_returns_the_show_once_secret_and_accepts_a_201() -> None:
    route = respx.post(COLLECTION).mock(
        return_value=httpx.Response(201, json=webhook_endpoint_with_secret())
    )
    with make_client() as client:
        created = client.webhook_endpoints.create(url="https://acme.example/webhooks/dodomain")
    assert created.secret == "whsec_shown_once"
    assert created.id == "whe_1"
    assert route.calls[0].request.method == "POST"


@respx.mock
def test_create_sends_the_url_as_the_whole_body() -> None:
    import json

    route = respx.post(COLLECTION).mock(
        return_value=httpx.Response(201, json=webhook_endpoint_with_secret())
    )
    with make_client() as client:
        client.webhook_endpoints.create(url="  https://acme.example/hook  ")
    assert json.loads(route.calls[0].request.content) == {"url": "https://acme.example/hook"}


@respx.mock
def test_the_secret_bearing_result_keeps_its_secret_out_of_its_repr() -> None:
    # A traceback or a debug print of this object must not spill the signing key.
    respx.post(COLLECTION).mock(
        return_value=httpx.Response(201, json=webhook_endpoint_with_secret())
    )
    with make_client() as client:
        created = client.webhook_endpoints.create(url="https://acme.example/hook")
    assert "whsec_shown_once" not in repr(created)
    assert created.secret == "whsec_shown_once"


@respx.mock
def test_the_secret_bearing_result_can_be_downgraded_to_a_loggable_summary() -> None:
    respx.post(COLLECTION).mock(
        return_value=httpx.Response(201, json=webhook_endpoint_with_secret())
    )
    with make_client() as client:
        created = client.webhook_endpoints.create(url="https://acme.example/hook")
    summary = created.endpoint
    assert isinstance(summary, WebhookEndpoint)
    assert (summary.id, summary.url) == (created.id, created.url)
    assert not hasattr(summary, "secret")


@respx.mock
def test_create_surfaces_the_plan_cap_as_a_quota_error() -> None:
    from dodomain import QuotaExceededError

    respx.post(COLLECTION).mock(return_value=httpx.Response(402, json={"error": "quota_exceeded"}))
    with pytest.raises(QuotaExceededError), make_client() as client:
        client.webhook_endpoints.create(url="https://acme.example/hook")


@respx.mock
def test_create_surfaces_a_duplicate_url_as_an_invalid_request() -> None:
    respx.post(COLLECTION).mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_request", "message": "this app already sends to that URL"},
        )
    )
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.webhook_endpoints.create(url="https://acme.example/hook")
    assert excinfo.value.status_code == 400


@respx.mock
def test_update_repoints_the_endpoint_with_a_patch_and_returns_no_secret() -> None:
    import json

    route = respx.patch(api("/api/v1/webhook-endpoints/whe_1")).mock(
        return_value=httpx.Response(200, json=webhook_endpoint(url="https://acme.example/v2"))
    )
    with make_client() as client:
        updated = client.webhook_endpoints.update("whe_1", url="https://acme.example/v2")
    assert route.calls[0].request.method == "PATCH"
    assert json.loads(route.calls[0].request.content) == {"url": "https://acme.example/v2"}
    assert updated.url == "https://acme.example/v2"
    assert not hasattr(updated, "secret")


@respx.mock
def test_delete_returns_what_it_removed_rather_than_an_empty_204() -> None:
    route = respx.delete(api("/api/v1/webhook-endpoints/whe_1")).mock(
        return_value=httpx.Response(200, json={"id": "whe_1", "deleted": True})
    )
    with make_client() as client:
        result = client.webhook_endpoints.delete("whe_1")
    assert route.calls[0].request.method == "DELETE"
    assert (result.id, result.deleted) == ("whe_1", True)


@respx.mock
def test_rotate_secret_posts_to_the_verb_subpath_and_returns_the_new_secret() -> None:
    route = respx.post(api("/api/v1/webhook-endpoints/whe_1/rotate-secret")).mock(
        return_value=httpx.Response(200, json=webhook_endpoint_with_secret(secret="whsec_v2"))
    )
    with make_client() as client:
        rotated = client.webhook_endpoints.rotate_secret("whe_1")
    assert route.calls[0].request.method == "POST"
    assert rotated.secret == "whsec_v2"
    assert rotated.id == "whe_1"


@respx.mock
def test_an_oauth_token_is_refused_with_a_readable_secret_key_required_signal() -> None:
    # 403 rather than 401: the token is valid, it just has no authority here, and
    # no scope exists that would grant it.
    respx.get(COLLECTION).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "forbidden",
                "message": "this endpoint requires the app's dd_sk_ secret key",
                "details": {"code": "SECRET_KEY_REQUIRED"},
            },
        )
    )
    with pytest.raises(PermissionError_) as excinfo, make_client() as client:
        client.webhook_endpoints.list()
    assert excinfo.value.secret_key_required is True
    assert excinfo.value.required_scope is None


@respx.mock
def test_a_scope_missing_403_is_not_mistaken_for_a_secret_key_requirement() -> None:
    respx.get(COLLECTION).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "forbidden",
                "details": {"code": "SCOPE_MISSING", "requiredScope": "connections:read"},
            },
        )
    )
    with pytest.raises(PermissionError_) as excinfo, make_client() as client:
        client.webhook_endpoints.list()
    assert excinfo.value.secret_key_required is False
    assert excinfo.value.required_scope == "connections:read"


@respx.mock
def test_another_apps_endpoint_id_is_a_404_not_a_403() -> None:
    respx.delete(api("/api/v1/webhook-endpoints/whe_someone_else")).mock(
        return_value=httpx.Response(404, json={"error": "not_found"})
    )
    with pytest.raises(NotFoundError), make_client() as client:
        client.webhook_endpoints.delete("whe_someone_else")


@respx.mock
def test_an_endpoint_id_is_url_encoded_into_the_path() -> None:
    route = respx.delete(api("/api/v1/webhook-endpoints/whe%2F1")).mock(
        return_value=httpx.Response(200, json={"id": "whe/1", "deleted": True})
    )
    with make_client() as client:
        client.webhook_endpoints.delete("whe/1")
    assert route.call_count == 1


@pytest.mark.parametrize("bad_id", ["", "   "])
def test_an_empty_endpoint_id_is_refused_locally(bad_id: str) -> None:
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.webhook_endpoints.delete(bad_id)


@respx.mock
def test_an_empty_url_is_refused_before_any_request() -> None:
    route = respx.post(COLLECTION).mock(return_value=httpx.Response(201, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.webhook_endpoints.create(url="   ")
    assert route.call_count == 0


# ── get(): a client-side lookup, because the API has no read-one route ───────


@respx.mock
def test_get_finds_the_endpoint_by_listing_because_there_is_no_read_one_route() -> None:
    route = respx.get(COLLECTION).mock(
        return_value=httpx.Response(
            200, json={"endpoints": [webhook_endpoint(id="whe_0"), webhook_endpoint(id="whe_1")]}
        )
    )
    with make_client() as client:
        found = client.webhook_endpoints.get("whe_1")
    assert found.id == "whe_1"
    # One LIST request — the SDK never invents a GET /webhook-endpoints/{id}.
    assert route.call_count == 1
    assert route.calls[0].request.url.path == "/api/v1/webhook-endpoints"


@respx.mock
def test_get_raises_a_not_found_the_sdk_itself_authored_for_an_unknown_id() -> None:
    respx.get(COLLECTION).mock(
        return_value=httpx.Response(200, json={"endpoints": [webhook_endpoint(id="whe_0")]})
    )
    with pytest.raises(NotFoundError) as excinfo, make_client() as client:
        client.webhook_endpoints.get("whe_missing")
    # status_code 0 says it plainly: no 404 ever came back from the server.
    assert excinfo.value.status_code == 0
    assert "whe_missing" in str(excinfo.value)


def test_get_refuses_an_empty_id_locally() -> None:
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.webhook_endpoints.get(" ")
