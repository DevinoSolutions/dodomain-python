"""An API refusal's human text reaches ``exc.message`` (0.7.0, parity with
``@dodomain/node`` 0.9.2, T-18329).

Before, ``exc.message`` was the API's raw ``message`` field and often ``None``,
and a problem+json ``detail`` with no ``message`` beside it was lost. Now it is
``"<error>: <detail or message>"``, so a developer or an agent logging it sees
what was wrong and what to do next. Ported from
``packages/node/test/api-refusals-carry-their-readable-text.test.ts``; every
answer below is a MOCK served by respx, nothing reaches the network.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from dodomain import (
    DnsRecord,
    DoDomain,
    DoDomainAPIError,
    DoDomainKeylessError,
    InvalidRequestError,
    NotFoundError,
)
from tests.helpers import TEST_KEY, api

KEYLESS_KEY = "dd_ks_scripted_key"
RECORDS = [DnsRecord(type="CNAME", host="app", value="edge.example.net")]
PROBLEM_JSON = {"content-type": "application/problem+json"}

PLACEHOLDER_DETAIL = (
    '"customer.com" is a placeholder or reserved name, so its DNS records can never be '
    'added. Change "domain" to a domain whose DNS records you can add.'
)


def _keyed() -> DoDomain:
    return DoDomain(secret_key=TEST_KEY, http_client=httpx.Client(), max_retries=0)


def _keyless(keyless_key: str | None = None) -> DoDomain:
    return DoDomain(
        keyless=True, keyless_key=keyless_key, http_client=httpx.Client(), max_retries=0
    )


@respx.mock
def test_a_400_with_an_rfc_9457_detail_reads_as_the_machine_error_then_the_detail() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(
            400,
            headers=PROBLEM_JSON,
            json={
                "type": "about:blank",
                "title": "Bad Request",
                "status": 400,
                "detail": "records[0].host must be a hostname label.",
                "error": "invalid_request",
                "message": "records[0].host must be a hostname label.",
                "code": "INVALID_RECORD",
            },
        )
    )
    with pytest.raises(InvalidRequestError) as excinfo:
        _keyed().sessions.create(domain="acme.com", records=RECORDS)
    refusal = excinfo.value
    assert not isinstance(refusal, DoDomainKeylessError), "a non-keyless code stays a plain error"
    assert refusal.message == "invalid_request: records[0].host must be a hostname label."
    assert refusal.message.startswith("invalid_request"), "existing prefix checks keep working"
    assert refusal.error == "invalid_request"
    assert refusal.code == "INVALID_RECORD"
    assert refusal.detail == "records[0].host must be a hostname label."
    assert refusal.status_code == 400


@respx.mock
def test_a_detail_without_a_message_beside_it_still_reaches_the_message() -> None:
    respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(
            400,
            headers=PROBLEM_JSON,
            json={"type": "about:blank", "error": "invalid_request", "detail": "  bad host  "},
        )
    )
    with pytest.raises(InvalidRequestError) as excinfo:
        _keyed().sessions.create(domain="acme.com", records=RECORDS)
    assert excinfo.value.message == "invalid_request: bad host"


@respx.mock
def test_a_keyless_start_for_a_placeholder_domain_is_a_keyless_error_that_says_what_to_change() -> (
    None
):
    # The body exactly as prod answers it (problem+json, 2026-11-17).
    respx.post(api("/api/v1/keyless/sessions")).mock(
        return_value=httpx.Response(
            400,
            headers=PROBLEM_JSON,
            json={
                "type": "about:blank",
                "title": "Bad Request",
                "status": 400,
                "detail": PLACEHOLDER_DETAIL,
                "error": "invalid_request",
                "message": PLACEHOLDER_DETAIL,
                "details": {"reason": "placeholder_domain", "domain": "customer.com"},
                "code": "KEYLESS_PLACEHOLDER_DOMAIN",
                "docs": "https://dodomain.io/docs/getting-started#keyless-start",
            },
        )
    )
    with pytest.raises(DoDomainKeylessError) as excinfo:
        _keyless().sessions.create(domain="customer.com", records=RECORDS)
    refusal = excinfo.value
    assert refusal.code == "KEYLESS_PLACEHOLDER_DOMAIN"
    assert refusal.error == "invalid_request"
    assert refusal.message == f"invalid_request: {PLACEHOLDER_DETAIL}"
    assert refusal.details["domain"] == "customer.com"
    assert refusal.status_code == 400
    assert str(refusal).startswith(
        "doDomain API error: POST /api/v1/keyless/sessions returned HTTP 400 "
        "(invalid_request, KEYLESS_PLACEHOLDER_DOMAIN): "
    )


@respx.mock
def test_a_402_keyless_refusal_keeps_its_fair_share_explanation_and_its_retry_at() -> None:
    explanation = (
        "This network shares its keyless allowance with other developers and its share is "
        "used for today. It resets at 2026-11-18T00:00:00.000Z. Claim the app or sign up for "
        "your own allowance."
    )
    respx.post(api("/api/v1/keyless/sessions")).mock(
        return_value=httpx.Response(
            402,
            json={
                "error": "quota_exceeded",
                "code": "KEYLESS_LIMIT_REACHED",
                "message": explanation,
                "details": {
                    "reason": "keyless_limit_reached",
                    "scope": "network",
                    "sharedNetwork": True,
                    "retryAt": "2026-11-18T00:00:00.000Z",
                    "limit": 10,
                },
            },
        )
    )
    with pytest.raises(DoDomainKeylessError) as excinfo:
        _keyless(keyless_key=KEYLESS_KEY).sessions.create(domain="acme.com", records=RECORDS)
    refusal = excinfo.value
    assert refusal.message == f"quota_exceeded: {explanation}"
    assert refusal.error == "quota_exceeded"
    assert refusal.code == "KEYLESS_LIMIT_REACHED"
    assert refusal.retry_at == "2026-11-18T00:00:00.000Z"
    assert refusal.details["retryAt"] == "2026-11-18T00:00:00.000Z"
    assert refusal.details["sharedNetwork"] is True
    assert refusal.details["scope"] == "network"


@respx.mock
def test_a_dd_ks_key_inside_a_refusals_human_text_is_cut_to_its_prefix_in_the_message() -> None:
    secret = "dd_ks_live_secret_part_9f8e7d"
    respx.post(api("/api/v1/keyless/sessions")).mock(
        return_value=httpx.Response(
            402,
            json={
                "error": "quota_exceeded",
                "code": "KEYLESS_LIMIT_REACHED",
                "message": (
                    f"Claim it at https://app.dodomain.io/claim/keyless#{secret} to continue."
                ),
            },
        )
    )
    with pytest.raises(DoDomainKeylessError) as excinfo:
        _keyless(keyless_key=secret).sessions.create(domain="acme.com", records=RECORDS)
    refusal = excinfo.value
    assert refusal.message == (
        "quota_exceeded: Claim it at https://app.dodomain.io/claim/keyless#dd_ks_… to continue."
    )
    for text in (refusal.message, str(refusal), repr(refusal), repr(refusal.body)):
        assert secret not in text, f"the key leaked: {text}"


@respx.mock
def test_a_refusal_with_no_human_text_keeps_the_bare_machine_error_or_http_status() -> None:
    route = respx.get(api("/api/v1/sessions/sess_missing"))

    route.mock(return_value=httpx.Response(404, json={"error": "not_found"}))
    with pytest.raises(NotFoundError) as bare:
        _keyed().sessions.get("sess_missing")
    assert bare.value.message == "not_found"
    assert bare.value.error == "not_found"
    assert bare.value.code == "not_found"
    assert bare.value.detail is None

    route.mock(
        return_value=httpx.Response(
            404, json={"error": "not_found", "detail": "   ", "message": ""}
        )
    )
    with pytest.raises(NotFoundError) as blank:
        _keyed().sessions.get("sess_missing")
    assert blank.value.message == "not_found", "blank human text adds nothing"

    route.mock(return_value=httpx.Response(502, json={}))
    with pytest.raises(DoDomainAPIError) as nothing:
        _keyed().sessions.get("sess_missing")
    assert nothing.value.message == "HTTP 502"
    assert nothing.value.error is None


def test_an_error_this_sdk_raised_itself_reads_as_its_code_then_its_explanation() -> None:
    with pytest.raises(InvalidRequestError) as excinfo:
        _keyed().sessions.get("")
    assert excinfo.value.status_code == 0
    assert excinfo.value.error is None
    assert excinfo.value.message == "invalid_request: a session id is required."
