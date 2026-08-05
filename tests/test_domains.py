from __future__ import annotations

import json

import httpx
import pytest
import respx

from dodomain import InvalidRequestError
from tests.helpers import CHECK_DOMAIN_RESPONSE, TEST_KEY, api, make_client


@respx.mock
def test_check_posts_the_trimmed_domain_with_the_secret_key() -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
    )
    with make_client() as client:
        client.domains.check(domain="  app.customer.com  ")
    request = route.calls[0].request
    assert request.headers["authorization"] == f"Bearer {TEST_KEY}"
    assert json.loads(request.content) == {"domain": "app.customer.com"}


@respx.mock
def test_check_parses_every_field_of_the_pre_flight_result() -> None:
    respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
    )
    with make_client() as client:
        result = client.domains.check(domain="app.customer.com")
    assert result.domain == "app.customer.com"
    assert result.zone == "customer.com"
    assert result.tier == 2
    assert result.method == "domain-connect"
    assert result.confidence == "medium"
    assert result.name_servers == ("ns1.cloudflare.com",)
    assert result.domain_connect.discovered is True
    assert result.domain_connect.provider_name == "Cloudflare"
    assert result.guide.host_format == "{host}"
    assert result.guide.dashboard_url == "https://dash.cloudflare.com"


@respx.mock
def test_check_handles_an_undiscovered_domain_connect_provider() -> None:
    respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(
            200, json={**CHECK_DOMAIN_RESPONSE, "domainConnect": {"discovered": False}}
        )
    )
    with make_client() as client:
        result = client.domains.check(domain="app.customer.com")
    assert result.domain_connect.discovered is False
    assert result.domain_connect.provider_id is None


@pytest.mark.parametrize("domain", ["", "   ", "a" * 254])
@respx.mock
def test_check_rejects_an_out_of_bounds_domain_before_any_request(domain: str) -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.domains.check(domain=domain)
    assert route.call_count == 0


@respx.mock
def test_check_accepts_a_bare_apex_that_the_session_schema_would_also_accept() -> None:
    # zCheckDomainInput is deliberately looser than zCreateSessionInput: a
    # pre-flight should answer for anything worth checking.
    respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
    )
    with make_client() as client:
        assert client.domains.check(domain="customer.com").zone == "customer.com"


@respx.mock
def test_check_forwards_an_idempotency_key() -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(
        return_value=httpx.Response(200, json=CHECK_DOMAIN_RESPONSE)
    )
    with make_client() as client:
        client.domains.check(domain="customer.com", idempotency_key="k1")
    assert route.calls[0].request.headers["idempotency-key"] == "k1"


@respx.mock
def test_check_rejects_a_non_string_domain_before_any_request() -> None:
    route = respx.post(api("/api/v1/domains/check")).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(InvalidRequestError), make_client() as client:
        client.domains.check(domain=None)  # type: ignore[arg-type]
    assert route.call_count == 0
