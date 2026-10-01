from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import InvalidResponseError, PermissionError_
from dodomain.models import App
from tests.helpers import (
    LEGACY_LIST_APPS_RESPONSE,
    LIST_APPS_RESPONSE,
    TEST_JWT,
    TEST_KEY,
    api,
    make_client,
)

SECRET_FIELD_NAMES = ("secretKeyHash", "secretKey", "secret_key", "secret_key_hash")


@respx.mock
def test_list_returns_parsed_apps_with_a_tz_aware_created_at() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(200, json=LIST_APPS_RESPONSE)
    )
    with make_client() as client:
        apps = client.apps.list()
    assert route.calls[0].request.headers["authorization"] == f"Bearer {TEST_KEY}"
    assert len(apps) == 1
    assert apps[0].id == "app_1"
    assert apps[0].name == "Acme"
    assert apps[0].public_key == "pk_live_abc"
    assert apps[0].sandbox is False
    assert apps[0].logo_url is None
    assert apps[0].brand_color == "#0E6B4E"
    assert apps[0].created_at == datetime(2026, 7, 1, tzinfo=timezone.utc)


@respx.mock
def test_list_parses_the_white_label_connect_flow_settings() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json=LIST_APPS_RESPONSE))
    with make_client() as client:
        app = client.apps.list()[0]
    assert app.connect_headline == "Connect your domain to Acme"
    assert app.connect_subheadline is None
    assert app.connect_success_cta_label == "Back to Acme"
    assert app.connect_success_redirect_url == "https://acme.example/domains"
    assert app.connect_font_preset == "humanist"
    assert app.hide_connect_footer_help is True


def test_an_app_recorded_before_white_label_existed_parses_with_unset_settings() -> None:
    app = App._from_api(LEGACY_LIST_APPS_RESPONSE["apps"][0])
    assert app.connect_headline is None
    assert app.connect_font_preset is None
    assert app.hide_connect_footer_help is False


@pytest.mark.parametrize(
    ("key", "value"),
    [("connectFontPreset", "comic-sans"), ("hideConnectFooterHelp", "yes")],
)
def test_a_white_label_field_of_the_wrong_shape_fails_loudly(key: str, value: object) -> None:
    with pytest.raises(InvalidResponseError):
        App._from_api({**LIST_APPS_RESPONSE["apps"][0], key: value})


@respx.mock
def test_the_app_model_carries_no_secret_material_even_if_the_api_regressed() -> None:
    leaked = {**LIST_APPS_RESPONSE["apps"][0], "secretKeyHash": "should-never-be-modelled"}
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"apps": [leaked]}))
    with make_client() as client:
        app = client.apps.list()[0]
    for name in SECRET_FIELD_NAMES:
        assert not hasattr(app, name)


@respx.mock
def test_list_remembers_the_app_a_secret_key_belongs_to() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json=LIST_APPS_RESPONSE))
    with make_client() as client:
        assert client._known_app_id is None
        client.apps.list()
        assert client._known_app_id == "app_1"


@respx.mock
def test_an_oauth_client_listing_many_apps_learns_no_single_app_id() -> None:
    second = {**LIST_APPS_RESPONSE["apps"][0], "id": "app_2"}
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(200, json={"apps": [LIST_APPS_RESPONSE["apps"][0], second]})
    )
    with make_client(secret_key=TEST_JWT) as client:
        assert len(client.apps.list()) == 2
        assert client._known_app_id is None


@respx.mock
def test_a_missing_scope_surfaces_the_scope_that_was_needed() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "forbidden",
                "details": {"code": "SCOPE_MISSING", "requiredScope": "apps:read"},
            },
        )
    )
    with pytest.raises(PermissionError_) as excinfo, make_client(secret_key=TEST_JWT) as client:
        client.apps.list()
    assert excinfo.value.required_scope == "apps:read"


@respx.mock
def test_a_response_without_an_apps_array_is_an_invalid_response() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"items": []}))
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.apps.list()


@respx.mock
def test_an_empty_app_list_is_returned_as_an_empty_tuple() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"apps": []}))
    with make_client() as client:
        assert client.apps.list() == ()
