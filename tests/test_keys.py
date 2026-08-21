"""``keys.rotate`` — the one credential-lifecycle call the API exposes."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import InvalidRequestError, PermissionError_
from tests.helpers import (
    LEGACY_ROTATED_KEY_RESPONSE,
    ROTATED_KEY_RESPONSE,
    ROTATED_KEY_WITH_OVERLAP_RESPONSE,
    TEST_JWT,
    api,
    make_async_client,
    make_client,
)

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
    # The app is implicit in the key — there is nothing to send that would let a
    # caller name a DIFFERENT app to rotate. The default cutover also stays
    # byte-for-byte the request every server version has always accepted, which
    # is why an omitted overlap must not become `{"overlapHours": 0}` on the wire.
    route = respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        client.keys.rotate()
    request = route.calls[0].request
    assert request.content == b""
    assert request.headers["authorization"] == "Bearer dd_sk_test_0123456789"


@respx.mock
def test_an_explicit_zero_overlap_is_the_same_body_less_request_as_the_default() -> None:
    # Spelling out the default must not take a different code path from omitting
    # it: `overlap_hours=0` IS the immediate cutover, and the kill switch that
    # ends a window an earlier rotation opened.
    route = respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        client.keys.rotate(overlap_hours=0)
    assert route.calls[0].request.content == b""


@respx.mock
@pytest.mark.parametrize("hours", [1, 24])
def test_a_requested_window_is_the_only_thing_that_puts_a_body_on_the_wire(hours: int) -> None:
    route = respx.post(ROTATE).mock(
        return_value=httpx.Response(200, json=ROTATED_KEY_WITH_OVERLAP_RESPONSE)
    )
    with make_client() as client:
        client.keys.rotate(overlap_hours=hours)  # type: ignore[arg-type]
    request = route.calls[0].request
    assert json.loads(request.content) == {"overlapHours": hours}
    assert request.headers["content-type"] == "application/json"


@respx.mock
def test_a_zero_overlap_rotation_reports_no_surviving_previous_key() -> None:
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with make_client() as client:
        rotated = client.keys.rotate()
    assert rotated.previous_key_expires_at is None


@respx.mock
def test_an_overlap_rotation_reports_when_the_previous_key_stops_authenticating() -> None:
    respx.post(ROTATE).mock(
        return_value=httpx.Response(200, json=ROTATED_KEY_WITH_OVERLAP_RESPONSE)
    )
    with make_client() as client:
        rotated = client.keys.rotate(overlap_hours=24)
    assert rotated.previous_key_expires_at == datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


@respx.mock
def test_a_response_recorded_before_overlap_windows_existed_still_parses() -> None:
    # The field is additive: a payload from a server that predates it must not
    # fail, and the honest answer for it is the same as a zero-overlap rotation.
    respx.post(ROTATE).mock(return_value=httpx.Response(200, json=LEGACY_ROTATED_KEY_RESPONSE))
    with make_client() as client:
        rotated = client.keys.rotate()
    assert rotated.previous_key_expires_at is None
    assert rotated.secret_key == "dd_sk_live_the_new_one"


@respx.mock
@pytest.mark.parametrize("hours", [2, -1, 25, 0.0, "24", None, True])
def test_a_window_the_api_does_not_offer_is_refused_before_a_key_is_minted(hours: object) -> None:
    # Rotating mints a credential, so a bad argument must never reach the server:
    # the least useful moment to learn it was wrong is while wondering whether
    # the old key is still alive. `True` is in here because `True == 1` would
    # otherwise buy a one-hour window nobody asked for.
    route = respx.post(ROTATE).mock(return_value=httpx.Response(200, json=ROTATED_KEY_RESPONSE))
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.keys.rotate(overlap_hours=hours)  # type: ignore[arg-type]
    assert excinfo.value.status_code == 0
    assert route.call_count == 0


@respx.mock
async def test_the_async_twin_sends_the_same_window_and_reads_the_same_expiry() -> None:
    route = respx.post(ROTATE).mock(
        return_value=httpx.Response(200, json=ROTATED_KEY_WITH_OVERLAP_RESPONSE)
    )
    async with make_async_client() as client:
        rotated = await client.keys.rotate(overlap_hours=1)
    assert json.loads(route.calls[0].request.content) == {"overlapHours": 1}
    assert rotated.previous_key_expires_at == datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


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
