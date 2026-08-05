from __future__ import annotations

import httpx
import pytest
import respx

from dodomain import (
    AuthenticationError,
    ConflictError,
    DoDomain,
    DoDomainAPIError,
    DoDomainConnectionError,
    ExpiredError,
    InternalServerError,
    InvalidRequestError,
    InvalidResponseError,
    NotConfiguredError,
    NotFoundError,
    PermissionError_,
    QuotaExceededError,
    RateLimitError,
)
from dodomain._transport import RequestSpec
from tests.helpers import api, make_client

CODE_TO_EXCEPTION = [
    ("unauthorized", 401, AuthenticationError),
    ("forbidden", 403, PermissionError_),
    ("not_found", 404, NotFoundError),
    ("expired", 410, ExpiredError),
    ("invalid_request", 400, InvalidRequestError),
    ("quota_exceeded", 402, QuotaExceededError),
    ("not_configured", 503, NotConfiguredError),
    ("conflict", 409, ConflictError),
    ("rate_limited", 429, RateLimitError),
    ("internal", 500, InternalServerError),
]


def _client() -> DoDomain:
    return make_client(max_retries=0)


@pytest.mark.parametrize(("code", "status", "expected"), CODE_TO_EXCEPTION)
@respx.mock
def test_every_documented_error_code_maps_to_its_own_exception(
    code: str, status: int, expected: type[DoDomainAPIError]
) -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(status, json={"error": code}))
    with pytest.raises(expected) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.code == code
    assert excinfo.value.status_code == status
    assert isinstance(excinfo.value, DoDomainAPIError)


@respx.mock
def test_an_error_with_no_message_field_still_produces_a_useful_str() -> None:
    # withRoute re-emits a thrown ApiError as jsonError(code, {details}) and
    # DROPS the message, so this is the shape most thrown errors actually take.
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(402, json={"error": "quota_exceeded"})
    )
    with pytest.raises(QuotaExceededError) as excinfo, _client() as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert str(excinfo.value) == (
        "doDomain API error: POST /api/v1/sessions returned HTTP 402 (quota_exceeded)"
    )


@respx.mock
def test_a_message_when_present_is_appended_to_str() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(400, json={"error": "invalid_request", "message": "bad domain"})
    )
    with pytest.raises(InvalidRequestError) as excinfo, _client() as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert str(excinfo.value).endswith("(invalid_request): bad domain")


@respx.mock
def test_details_are_shown_in_str_when_no_message_was_sent() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            403, json={"error": "forbidden", "details": {"code": "SCOPE_MISSING"}}
        )
    )
    with pytest.raises(PermissionError_) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert "details=" in str(excinfo.value)


@respx.mock
def test_an_unrecognized_error_code_degrades_to_the_base_api_error() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(418, json={"error": "teapot_engaged"})
    )
    with pytest.raises(DoDomainAPIError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert type(excinfo.value) is DoDomainAPIError
    assert excinfo.value.code == "teapot_engaged"


@respx.mock
def test_a_non_json_error_body_becomes_non_json_response_not_a_decode_error() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(502, text="<html>Bad Gateway</html>")
    )
    with pytest.raises(DoDomainAPIError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.code == "non_json_response"
    assert excinfo.value.body == "<html>Bad Gateway</html>"


@respx.mock
def test_a_json_array_error_body_is_also_non_json_response() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(500, json=["nope"]))
    with pytest.raises(DoDomainAPIError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.code == "non_json_response"


@respx.mock
def test_an_empty_error_body_still_maps_without_crashing() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(500, text=""))
    with pytest.raises(InternalServerError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.code == "internal"


@respx.mock
def test_an_rfc_9457_problem_json_body_is_parsed_for_forward_compatibility() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            404,
            headers={"content-type": "application/problem+json"},
            json={
                "type": "https://dodomain.io/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "no such connection",
            },
        )
    )
    with pytest.raises(NotFoundError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.code == "not_found"
    assert excinfo.value.message == "no such connection"


@respx.mock
def test_an_rfc_9457_body_with_an_explicit_code_field_wins_over_the_type_uri() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            402,
            headers={"content-type": "application/problem+json"},
            json={
                "type": "https://dodomain.io/errors/whatever",
                "title": "Payment Required",
                "code": "quota_exceeded",
            },
        )
    )
    with pytest.raises(QuotaExceededError), _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))


@respx.mock
def test_permission_error_surfaces_the_scope_the_call_needed() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "forbidden",
                "details": {"code": "SCOPE_MISSING", "requiredScope": "apps:read"},
            },
        )
    )
    with pytest.raises(PermissionError_) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.required_scope == "apps:read"


@respx.mock
def test_permission_error_without_scope_missing_reports_no_required_scope() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(403, json={"error": "forbidden", "details": {"code": "OTHER"}})
    )
    with pytest.raises(PermissionError_) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.required_scope is None


@respx.mock
def test_authentication_error_surfaces_a_revoked_oauth_consent() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            401, json={"error": "unauthorized", "details": {"code": "CONSENT_REVOKED"}}
        )
    )
    with pytest.raises(AuthenticationError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.consent_revoked is True


@respx.mock
def test_invalid_request_exposes_the_machine_readable_reason() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_request",
                "message": "MX records require a numeric priority",
                "details": {"reason": "missing_mx_priority", "host": "@"},
            },
        )
    )
    with pytest.raises(InvalidRequestError) as excinfo, _client() as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert excinfo.value.reason == "missing_mx_priority"


@respx.mock
def test_invalid_request_from_a_zod_flatten_payload_has_no_reason() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_request",
                "details": {"formErrors": [], "fieldErrors": {"domain": ["Enter a domain"]}},
            },
        )
    )
    with pytest.raises(InvalidRequestError) as excinfo, _client() as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert excinfo.value.reason is None


@respx.mock
def test_rate_limit_error_surfaces_reason_limit_and_retry_after() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "17"},
            json={
                "error": "rate_limited",
                "details": {"reason": "request_rate", "limit": 60, "retryAfterSeconds": 17},
            },
        )
    )
    with pytest.raises(RateLimitError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.reason == "request_rate"
    assert excinfo.value.limit == 60
    assert excinfo.value.retry_after == 17.0


@respx.mock
def test_rate_limit_retry_after_falls_back_to_details_when_the_header_is_absent() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            429,
            json={"error": "rate_limited", "details": {"retryAfterSeconds": 9}},
        )
    )
    with pytest.raises(RateLimitError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.retry_after == 9.0
    assert excinfo.value.limit is None


@respx.mock
def test_rate_limit_error_with_no_details_reports_nothing_rather_than_guessing() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(429, json={"error": "rate_limited"})
    )
    with pytest.raises(RateLimitError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.reason is None
    assert excinfo.value.retry_after is None


@respx.mock
def test_a_request_id_header_is_carried_onto_the_exception() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            500, headers={"x-request-id": "req_42"}, json={"error": "internal"}
        )
    )
    with pytest.raises(InternalServerError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert excinfo.value.request_id == "req_42"
    assert "req_42" in str(excinfo.value)


@respx.mock
def test_a_transport_failure_becomes_a_connection_error_wrapping_its_cause() -> None:
    respx.get(api("/api/v1/apps")).mock(side_effect=httpx.ConnectError("dns went dark"))
    with pytest.raises(DoDomainConnectionError) as excinfo, _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert isinstance(excinfo.value.cause, httpx.ConnectError)


@respx.mock
def test_a_timeout_becomes_a_connection_error_not_a_raw_httpx_error() -> None:
    respx.get(api("/api/v1/apps")).mock(side_effect=httpx.ReadTimeout("too slow"))
    with pytest.raises(DoDomainConnectionError), _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))


@respx.mock
def test_a_2xx_with_an_unparseable_body_raises_invalid_response_error() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, text="not json at all"))
    with pytest.raises(InvalidResponseError), _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))


@respx.mock
def test_a_2xx_with_an_empty_body_raises_invalid_response_error() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, text=""))
    with pytest.raises(InvalidResponseError), _client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
