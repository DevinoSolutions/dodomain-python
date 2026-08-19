"""``keys.rotate`` — the one credential-lifecycle call the API exposes."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import PermissionError_
from tests.helpers import ROTATED_KEY_RESPONSE, TEST_JWT, api, make_client

ROTATE = api("/api/v1/keys/rotate")


@respx.mock
def test_rotate_posts_and_returns_the_new_secret_key() -> None:
    route = respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        rotated = client.keys.rotate()
    assert route.calls[0].request.method == "POST"
    assert rotated.app_id == "app_1"
    assert rotated.secret_key == "dd_sk_live_the_new_one"
    assert rotated.rotated_at == datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)


@respx.mock
def test_the_public_key_comes_back_unchanged_so_ci_can_assert_which_app_it_rewrote() -> None:
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        rotated = client.keys.rotate()
    assert rotated.public_key == "dd_pk_live_abc"


@respx.mock
def test_rotate_sends_a_body_less_post_with_the_callers_own_credential() -> None:
    # The app is implicit in the key — there is nothing to send, and nothing that
    # would let a caller name a DIFFERENT app to rotate.
    route = respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        client.keys.rotate()
    request = route.calls[0].request
    assert request.content == b""
    assert request.headers["authorization"] == "Bearer dd_sk_test_0123456789"


@respx.mock
def test_the_new_secret_key_stays_out_of_the_repr() -> None:
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        rotated = client.keys.rotate()
    assert "dd_sk_live_the_new_one" not in repr(rotated)
    assert rotated.secret_key == "dd_sk_live_the_new_one"


@respx.mock
def test_an_oauth_caller_is_refused_with_the_secret_key_required_signal() -> None:
    route = respx.post(ROTATE).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "forbidden",
                "message": "this endpoint requires the app's dd_sk_ secret key",
                "details": {"code": "SECRET_KEY_REQUIRED"},
            },
        )
    )
    with pytest.raises(PermissionError_) as excinfo, make_client(secret_key=TEST_JWT) as client:
        client.keys.rotate()
    assert excinfo.value.status_code == 403
    assert excinfo.value.secret_key_required is True
    # No scope fixes this, so the SDK must not report one.
    assert excinfo.value.required_scope is None
    assert route.call_count == 1


@respx.mock
def test_the_client_keeps_using_the_old_key_until_the_caller_rebuilds_it() -> None:
    # Silently re-keying a live client would hide a rotation the caller must act
    # on; the next call deliberately still carries the key it was constructed with.
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    apps = respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"apps": []}))
    with make_client() as client:
        client.keys.rotate()
        client.apps.list()
    assert apps.calls[0].request.headers["authorization"] == "Bearer dd_sk_test_0123456789"


@respx.mock
def test_a_rotate_response_missing_the_secret_key_is_an_invalid_response() -> None:
    from dodomain import InvalidResponseError

    body = {key: value for key, value in ROTATED_KEY_RESPONSE.items() if key != "secretKey"}
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.keys.rotate()
