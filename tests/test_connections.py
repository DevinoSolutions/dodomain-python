from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import InvalidRequestError, InvalidResponseError, NotFoundError
from tests.helpers import DISCONNECT_RESPONSE, TEST_JWT, api, connection, make_client


@respx.mock
def test_list_sends_every_documented_query_parameter() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [], "nextCursor": None})
    )
    with make_client(secret_key=TEST_JWT) as client:
        client.connections.list(
            app_id="app_1",
            domain="app.customer.com",
            limit=25,
            cursor="cur_1",
            include_disconnected=True,
        )
    params = route.calls[0].request.url.params
    assert params["appId"] == "app_1"
    assert params["domain"] == "app.customer.com"
    assert params["limit"] == "25"
    assert params["cursor"] == "cur_1"
    assert params["includeDisconnected"] == "true"


@respx.mock
def test_get_reads_one_connection_by_the_id_webhooks_carry() -> None:
    route = respx.get(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=connection())
    )
    with make_client() as client:
        conn = client.connections.get("conn_1")
    assert route.calls[0].request.method == "GET"
    assert conn.id == "conn_1"
    assert conn.session_id == "cs_01HZX"
    assert conn.status == "active"


@respx.mock
def test_get_returns_the_same_shape_as_one_element_of_the_list() -> None:
    # The route promises a body byte-identical to a list element, so one parser
    # must serve both — if it ever stops being true, this fails.
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [connection()], "nextCursor": None})
    )
    respx.get(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=connection())
    )
    with make_client() as client:
        from_list = client.connections.list().connections[0]
        from_get = client.connections.get("conn_1")
    assert from_get == from_list


@respx.mock
def test_get_returns_a_disconnected_connection_which_list_hides_by_default() -> None:
    respx.get(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=connection(disconnectedAt="2026-08-05T12:00:00.000Z"))
    )
    with make_client() as client:
        conn = client.connections.get("conn_1")
    assert conn.disconnected_at == datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


@respx.mock
def test_get_on_a_connection_you_do_not_own_is_a_404_not_a_403() -> None:
    respx.get(api("/api/v1/connections/conn_x")).mock(
        return_value=httpx.Response(404, json={"error": "not_found"})
    )
    with pytest.raises(NotFoundError), make_client() as client:
        client.connections.get("conn_x")


def test_get_refuses_an_empty_connection_id_locally() -> None:
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.connections.get("")


# ── recordFqdns: the names actually monitored ───────────────────────────────


@respx.mock
def test_record_fqdns_carries_the_monitored_names_which_fqdn_does_not() -> None:
    # `fqdn` is the session DOMAIN, frozen that way on purpose. A caller reading it
    # as a record name gets the wrong answer, which is why recordFqdns exists.
    respx.get(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=connection())
    )
    with make_client() as client:
        conn = client.connections.get("conn_1")
    assert conn.fqdn == "app.customer.com"
    assert conn.record_fqdns == ("status.app.customer.com",)


@respx.mock
def test_a_connection_recorded_before_record_fqdns_existed_still_parses() -> None:
    legacy = connection()
    del legacy["recordFqdns"]
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [legacy], "nextCursor": None})
    )
    with make_client() as client:
        conn = client.connections.list().connections[0]
    assert conn.record_fqdns == ()
    assert conn.id == "conn_1"


@respx.mock
def test_a_session_with_several_records_reports_every_monitored_name() -> None:
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(
            200,
            json={
                "connections": [connection(recordFqdns=["app.customer.com", "_acme.customer.com"])],
                "nextCursor": None,
            },
        )
    )
    with make_client() as client:
        conn = client.connections.list().connections[0]
    assert conn.record_fqdns == ("app.customer.com", "_acme.customer.com")


@respx.mock
def test_a_non_array_record_fqdns_is_loud_rather_than_silently_empty() -> None:
    # Absence is history; a present-but-wrong type is drift, and drift must fail.
    respx.get(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=connection(recordFqdns="app.customer.com"))
    )
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.connections.get("conn_1")


@respx.mock
def test_list_defaults_to_live_connections_only() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [], "nextCursor": None})
    )
    with make_client() as client:
        client.connections.list()
    params = route.calls[0].request.url.params
    assert params["includeDisconnected"] == "false"
    assert params["limit"] == "50"
    assert "appId" not in params
    assert "cursor" not in params


@respx.mock
def test_list_parses_a_connection_with_every_timestamp_populated() -> None:
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(
            200,
            json={
                "connections": [connection(brokenAt="2026-08-04T08:00:00.000Z")],
                "nextCursor": "cur_2",
            },
        )
    )
    with make_client() as client:
        page = client.connections.list()
    conn = page.connections[0]
    assert conn.id == "conn_1"
    assert conn.app_id == "app_1"
    assert conn.session_id == "cs_01HZX"
    assert conn.status == "active"
    assert conn.verified_at == datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
    assert conn.last_checked_at is not None
    assert conn.broken_at == datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc)
    assert conn.disconnected_at is None
    assert conn.created_at.tzinfo is not None
    assert page.next_cursor == "cur_2"
    assert page.has_more is True


@respx.mock
def test_has_more_is_false_on_the_last_page() -> None:
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [connection()], "nextCursor": None})
    )
    with make_client() as client:
        assert client.connections.list().has_more is False


@respx.mock
def test_a_disconnected_connection_keeps_its_last_observed_status() -> None:
    respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(
            200,
            json={
                "connections": [
                    connection(status="broken", disconnectedAt="2026-08-05T12:00:00.000Z")
                ],
                "nextCursor": None,
            },
        )
    )
    with make_client() as client:
        conn = client.connections.list(include_disconnected=True).connections[0]
    assert conn.status == "broken"
    assert conn.disconnected_at is not None


@pytest.mark.parametrize("limit", [0, -1, 101, 1000])
@respx.mock
def test_list_rejects_an_out_of_range_limit_before_any_request(limit: int) -> None:
    route = respx.get(api("/api/v1/connections")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.connections.list(limit=limit)
    assert route.call_count == 0


@respx.mock
def test_list_rejects_a_non_integer_limit() -> None:
    route = respx.get(api("/api/v1/connections")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.connections.list(limit="50")  # type: ignore[arg-type]
    assert route.call_count == 0


@respx.mock
def test_list_rejects_an_empty_cursor() -> None:
    route = respx.get(api("/api/v1/connections")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.connections.list(cursor="")
    assert route.call_count == 0


@respx.mock
def test_a_secret_key_client_rejects_an_app_id_that_contradicts_its_own_app() -> None:
    # A dd_sk_ key is app-scoped. Once apps.list() has told the SDK which app the
    # key belongs to, a contradicting app_id is knowable locally.
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            200,
            json={
                "apps": [
                    {
                        "id": "app_1",
                        "name": "Acme",
                        "publicKey": "pk_1",
                        "sandbox": False,
                        "logoUrl": None,
                        "brandColor": None,
                        "createdAt": "2026-07-01T00:00:00.000Z",
                    }
                ]
            },
        )
    )
    listing = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [], "nextCursor": None})
    )
    with make_client() as client:
        client.apps.list()
        client.connections.list(app_id="app_1")  # matches: allowed
        with pytest.raises(InvalidRequestError) as excinfo:
            client.connections.list(app_id="app_someone_else")
    assert listing.call_count == 1
    assert "already app-scoped" in str(excinfo.value)


# ── pagination ──────────────────────────────────────────────────────────────


@respx.mock
def test_list_all_follows_the_cursor_across_three_pages_and_stops_on_null() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(200, json={"connections": [connection(id="c1")], "nextCursor": "cur_1"}),
            httpx.Response(200, json={"connections": [connection(id="c2")], "nextCursor": "cur_2"}),
            httpx.Response(200, json={"connections": [connection(id="c3")], "nextCursor": None}),
        ]
    )
    with make_client() as client:
        ids = [conn.id for conn in client.connections.list_all()]
    assert ids == ["c1", "c2", "c3"]
    assert route.call_count == 3
    assert route.calls[1].request.url.params["cursor"] == "cur_1"
    assert route.calls[2].request.url.params["cursor"] == "cur_2"


@respx.mock
def test_list_all_passes_the_cursor_back_untouched() -> None:
    opaque = "eyJpZCI6ImNvbm5fMSJ9=="
    route = respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(200, json={"connections": [], "nextCursor": opaque}),
            httpx.Response(200, json={"connections": [], "nextCursor": None}),
        ]
    )
    with make_client() as client:
        list(client.connections.list_all())
    assert route.calls[1].request.url.params["cursor"] == opaque


@respx.mock
def test_list_all_forwards_every_filter_to_each_page() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(200, json={"connections": [], "nextCursor": "cur_1"}),
            httpx.Response(200, json={"connections": [], "nextCursor": None}),
        ]
    )
    with make_client() as client:
        list(
            client.connections.list_all(
                domain="app.customer.com", include_disconnected=True, limit=100
            )
        )
    for call in route.calls:
        params = call.request.url.params
        assert params["domain"] == "app.customer.com"
        assert params["includeDisconnected"] == "true"
        assert params["limit"] == "100"


@respx.mock
def test_list_all_defaults_to_the_largest_page_the_api_allows() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(200, json={"connections": [], "nextCursor": None})
    )
    with make_client() as client:
        list(client.connections.list_all())
    assert route.calls[0].request.url.params["limit"] == "100"


@respx.mock
def test_list_all_is_lazy_and_does_not_fetch_the_next_page_until_asked() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(200, json={"connections": [connection(id="c1")], "nextCursor": "cur_1"}),
            httpx.Response(200, json={"connections": [connection(id="c2")], "nextCursor": None}),
        ]
    )
    with make_client() as client:
        iterator = client.connections.list_all()
        assert next(iterator).id == "c1"
        assert route.call_count == 1
        assert next(iterator).id == "c2"
        assert route.call_count == 2


# ── reverify / disconnect ───────────────────────────────────────────────────


@respx.mock
def test_reverify_accepts_a_202_as_success_not_an_error() -> None:
    route = respx.post(api("/api/v1/connections/conn_1/reverify")).mock(
        return_value=httpx.Response(202, json={"accepted": True})
    )
    with make_client() as client:
        result = client.connections.reverify("conn_1")
    assert result.accepted is True
    assert route.calls[0].request.method == "POST"


@respx.mock
def test_reverify_on_a_connection_you_do_not_own_is_a_404_not_a_403() -> None:
    respx.post(api("/api/v1/connections/conn_x/reverify")).mock(
        return_value=httpx.Response(404, json={"error": "not_found"})
    )
    with pytest.raises(NotFoundError), make_client() as client:
        client.connections.reverify("conn_x")


@respx.mock
def test_disconnect_surfaces_already_disconnected_and_the_original_timestamp() -> None:
    route = respx.delete(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json={**DISCONNECT_RESPONSE, "alreadyDisconnected": True})
    )
    with make_client() as client:
        result = client.connections.disconnect("conn_1")
    assert route.calls[0].request.method == "DELETE"
    assert result.id == "conn_1"
    assert result.already_disconnected is True
    assert result.disconnected_at == datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


@respx.mock
def test_disconnect_reports_the_first_call_as_not_already_disconnected() -> None:
    respx.delete(api("/api/v1/connections/conn_1")).mock(
        return_value=httpx.Response(200, json=DISCONNECT_RESPONSE)
    )
    with make_client() as client:
        assert client.connections.disconnect("conn_1").already_disconnected is False


@respx.mock
def test_a_connection_id_is_url_encoded_into_the_path() -> None:
    route = respx.delete(api("/api/v1/connections/conn%2F1")).mock(
        return_value=httpx.Response(200, json=DISCONNECT_RESPONSE)
    )
    with make_client() as client:
        client.connections.disconnect("conn/1")
    assert route.call_count == 1


def test_an_empty_connection_id_is_refused_locally() -> None:
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.connections.disconnect("  ")
