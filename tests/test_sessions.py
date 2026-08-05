from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
import respx

from dodomain import DnsRecord, InvalidRequestError, InvalidResponseError
from tests.helpers import (
    CREATE_SESSION_RESPONSE,
    DETECT_RESPONSE,
    PUBLIC_SESSION_RESPONSE,
    TEST_JWT,
    TEST_KEY,
    VERIFY_RESPONSE,
    api,
    make_client,
)

CNAME = DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")


@respx.mock
def test_create_sends_the_exact_documented_request() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        client.sessions.create(
            domain="app.customer.com",
            records=[CNAME, DnsRecord(type="MX", host="@", value="mx.io", priority=10, ttl=300)],
            return_url="https://customer.com/settings/domains",
            recipe="recipe-1",
        )
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.url.path == "/api/v1/sessions"
    assert request.headers["authorization"] == f"Bearer {TEST_KEY}"
    assert json.loads(request.content) == {
        "domain": "app.customer.com",
        "records": [
            {"type": "CNAME", "host": "app", "value": "cname.dodomain.io"},
            {"type": "MX", "host": "@", "value": "mx.io", "priority": 10, "ttl": 300},
        ],
        "recipe": "recipe-1",
        "returnUrl": "https://customer.com/settings/domains",
    }


@respx.mock
def test_create_maps_every_response_field_to_snake_case_with_a_tz_aware_datetime() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.create(domain="app.customer.com", records=[CNAME])
    assert session.id == "cs_01HZX"
    assert session.token == "tok_live_abc123"
    assert session.connect_url == "https://app.dodomain.io/connect/tok_live_abc123"
    assert session.expires_at == datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc)
    assert session.expires_at.tzinfo is not None


@respx.mock
def test_create_keeps_the_untouched_wire_body_on_raw() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json={**CREATE_SESSION_RESPONSE, "futureField": 1})
    )
    with make_client() as client:
        session = client.sessions.create(domain="app.customer.com", records=[CNAME])
    assert session.raw is not None
    assert session.raw["futureField"] == 1


@respx.mock
def test_create_ignores_response_fields_it_does_not_know() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json={**CREATE_SESSION_RESPONSE, "somethingNew": "x"})
    )
    with make_client() as client:
        assert client.sessions.create(domain="app.customer.com", records=[CNAME]).id == "cs_01HZX"


@respx.mock
def test_create_raises_invalid_response_when_a_required_field_is_missing() -> None:
    body = {k: v for k, v in CREATE_SESSION_RESPONSE.items() if k != "connectUrl"}
    respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.sessions.create(domain="app.customer.com", records=[CNAME])


@respx.mock
def test_the_session_exposes_both_browser_navigation_start_urls() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.create(domain="app.customer.com", records=[CNAME])
    assert session.cloudflare_start_url == (
        "https://app.dodomain.io/api/v1/sessions/tok_live_abc123/cloudflare/start"
    )
    assert session.domain_connect_start_url == (
        "https://app.dodomain.io/api/v1/sessions/tok_live_abc123/domain-connect/start"
    )


@respx.mock
def test_the_start_urls_follow_a_custom_base_url() -> None:
    respx.post("https://staging.dodomain.io/api/v1/sessions").mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client(base_url="https://staging.dodomain.io") as client:
        session = client.sessions.create(domain="app.customer.com", records=[CNAME])
    assert session.cloudflare_start_url.startswith("https://staging.dodomain.io/")


# ── client-side validation: no HTTP request may be issued ───────────────────


@pytest.mark.parametrize(
    "domain",
    [
        "https://app.customer.com",
        "app.customer.com:8080",
        "app.customer.com.",
        "localhost",
        "-bad.customer.com",
        "bad-.customer.com",
        "a" * 250 + ".customer.com",
        "",
    ],
)
@respx.mock
def test_create_rejects_a_bad_domain_before_any_request_is_issued(domain: str) -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.sessions.create(domain=domain, records=[CNAME])
    assert route.call_count == 0
    assert excinfo.value.status_code == 0


@respx.mock
def test_create_rejects_an_empty_record_list_locally() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.sessions.create(domain="app.customer.com", records=[])
    assert route.call_count == 0


@respx.mock
def test_create_rejects_an_mx_record_without_a_priority_locally() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.sessions.create(
            domain="app.customer.com",
            records=[DnsRecord(type="MX", host="@", value="mx.io")],
        )
    assert route.call_count == 0
    assert excinfo.value.reason == "missing_mx_priority"


@respx.mock
def test_create_rejects_an_unsupported_record_type_locally() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.sessions.create(
            domain="app.customer.com",
            records=[DnsRecord(type="SRV", host="a", value="b")],  # type: ignore[arg-type]
        )
    assert route.call_count == 0
    assert excinfo.value.reason == "unsupported_record_type"


@pytest.mark.parametrize(
    "return_url",
    [
        "javascript:alert(1)",
        "data:text/html,x",
        "ftp://customer.com/back",
        "https://user:pw@customer.com/back",
        "https://customer.com/" + "a" * 2100,
        "not a url",
    ],
)
@respx.mock
def test_create_rejects_a_dangerous_return_url_locally(return_url: str) -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.sessions.create(domain="app.customer.com", records=[CNAME], return_url=return_url)
    assert route.call_count == 0


@respx.mock
def test_create_rejects_a_non_record_object_in_the_record_list() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.sessions.create(
            domain="app.customer.com",
            records=[{"type": "CNAME", "host": "app", "value": "x"}],  # type: ignore[list-item]
        )
    assert route.call_count == 0


@respx.mock
def test_an_oauth_client_must_name_the_app_that_owns_the_session() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError) as excinfo, make_client(secret_key=TEST_JWT) as client:
        client.sessions.create(domain="app.customer.com", records=[CNAME])
    assert route.call_count == 0
    assert "app_id is required" in str(excinfo.value)


@respx.mock
def test_an_oauth_client_with_an_app_id_sends_it() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client(secret_key=TEST_JWT) as client:
        client.sessions.create(domain="app.customer.com", records=[CNAME], app_id="app_9")
    assert json.loads(route.calls[0].request.content)["appId"] == "app_9"


@respx.mock
def test_create_forwards_an_idempotency_key_even_though_the_api_ignores_it() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        client.sessions.create(
            domain="app.customer.com", records=[CNAME], idempotency_key="abc-123"
        )
    assert route.calls[0].request.headers["idempotency-key"] == "abc-123"


# ── token-public reads ──────────────────────────────────────────────────────


@respx.mock
def test_retrieve_reads_a_session_back_without_any_credential() -> None:
    route = respx.get(api("/api/v1/sessions/tok_live_abc123")).mock(
        return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.retrieve("tok_live_abc123")
    assert "authorization" not in route.calls[0].request.headers
    assert session.id == "cs_01HZX"
    assert session.domain == "app.customer.com"
    assert session.detected_provider == "Cloudflare"
    assert session.return_url == "https://customer.com/settings/domains"
    assert session.recipe is None
    assert session.tier == 1
    assert session.expires_at.tzinfo is not None


@respx.mock
def test_retrieve_round_trips_the_records_including_mx_priority_and_ttl() -> None:
    respx.get(api("/api/v1/sessions/tok_live_abc123")).mock(
        return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
    )
    with make_client() as client:
        records = client.sessions.retrieve("tok_live_abc123").records
    assert records[0] == DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")
    assert records[1].priority == 10
    assert records[1].ttl == 3600


@respx.mock
def test_a_token_is_url_encoded_into_the_path() -> None:
    route = respx.get(api("/api/v1/sessions/tok%2Fwith%20odd%20chars")).mock(
        return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
    )
    with make_client() as client:
        client.sessions.retrieve("tok/with odd chars")
    assert route.call_count == 1


def test_an_empty_token_is_refused_before_a_request_is_built() -> None:
    with pytest.raises(ValueError), make_client() as client:
        client.sessions.retrieve("  ")


@respx.mock
def test_detect_parses_the_full_detection_result() -> None:
    route = respx.post(api("/api/v1/sessions/tok_live_abc123/detect")).mock(
        return_value=httpx.Response(200, json=DETECT_RESPONSE)
    )
    with make_client() as client:
        result = client.sessions.detect("tok_live_abc123")
    assert "authorization" not in route.calls[0].request.headers
    assert result.zone == "customer.com"
    assert result.tier == 1
    assert result.method == "oauth"
    assert result.confidence == "high"
    assert result.name_servers == ("ns1.cloudflare.com", "ns2.cloudflare.com")
    assert result.domain_connect is not None
    assert result.domain_connect.provider_id == "cloudflare.com"
    assert result.domain_connect_ready is False
    assert result.guide.apex_token == "@"
    assert result.guide.steps == ("Open the DNS tab", "Add the record")
    assert result.guide.notes == ("Proxying must be off",)


@respx.mock
def test_detect_handles_a_null_domain_connect() -> None:
    respx.post(api("/api/v1/sessions/tok/detect")).mock(
        return_value=httpx.Response(200, json={**DETECT_RESPONSE, "domainConnect": None})
    )
    with make_client() as client:
        assert client.sessions.detect("tok").domain_connect is None


@respx.mock
def test_detect_rejects_a_tier_outside_the_documented_union() -> None:
    respx.post(api("/api/v1/sessions/tok/detect")).mock(
        return_value=httpx.Response(200, json={**DETECT_RESPONSE, "tier": 9})
    )
    with pytest.raises(InvalidResponseError), make_client() as client:
        client.sessions.detect("tok")


@respx.mock
def test_verify_parses_records_and_their_outcomes() -> None:
    route = respx.post(api("/api/v1/sessions/tok/verify")).mock(
        return_value=httpx.Response(200, json=VERIFY_RESPONSE)
    )
    with make_client() as client:
        result = client.sessions.verify("tok")
    assert "authorization" not in route.calls[0].request.headers
    assert result.verified is False
    assert result.records[0].outcome == "verified"
    assert result.records[0].authoritative_error is None
    assert result.records[1].outcome == "propagating"
    assert result.records[1].authoritative_error == "NS_RESOLUTION_FAILED"
