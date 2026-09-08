"""The TLS-issuance advisories the API grew in 2026-09 (`@dodomain/node` 0.6.0).

The same advisory shape rides on four surfaces. These tests pin all of them, plus
the property that matters most for a consumer that has never heard of them: an
advisory is advice about the NEXT step (issuing the certificate) and never moves
`verified` or `present`.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from dodomain import App, InvalidResponseError, TlsIssuanceAdvisory
from dodomain.models import IntegratorSession, VerifyResult
from tests.helpers import (
    INTEGRATOR_SESSION_RESPONSE,
    LEGACY_INTEGRATOR_SESSION_RESPONSE,
    LEGACY_LIST_APPS_RESPONSE,
    LEGACY_VERIFY_RESPONSE,
    LIST_APPS_RESPONSE,
    TLS_ISSUANCE_ADVISORY,
    VERIFY_RESPONSE,
    api,
    make_client,
)


def test_an_advisory_parses_every_field_the_wire_carries() -> None:
    advisory = TlsIssuanceAdvisory._from_api(TLS_ISSUANCE_ADVISORY)
    assert advisory.code == "caa_excludes_issuer"
    assert advisory.severity == "warning"
    assert advisory.fqdn == "app.customer.com"
    # The evidence was read on the PARENT — a CAA policy is inherited, so the name
    # the advisory is about and the name it was read from are routinely different.
    assert advisory.evidence_fqdn == "customer.com"
    assert advisory.evidence == ('issue "digicert.com"',)
    assert "letsencrypt.org" in advisory.note


def test_an_advisory_code_outside_the_documented_union_is_rejected() -> None:
    # The vocabulary is closed server-side; a value outside it is contract drift,
    # not an additive change, and must not reach a caller branching on `code`.
    with pytest.raises(InvalidResponseError):
        TlsIssuanceAdvisory._from_api({**TLS_ISSUANCE_ADVISORY, "code": "caa_is_weird"})


def test_an_advisory_severity_outside_the_documented_union_is_rejected() -> None:
    with pytest.raises(InvalidResponseError):
        TlsIssuanceAdvisory._from_api({**TLS_ISSUANCE_ADVISORY, "severity": "critical"})


@respx.mock
def test_verify_carries_the_advisories_without_changing_the_verdict() -> None:
    respx.post(api("/api/v1/sessions/tok/verify")).mock(
        return_value=httpx.Response(200, json=VERIFY_RESPONSE)
    )
    with make_client() as client:
        result = client.sessions.verify("tok")
    assert len(result.advisories) == 1
    assert result.advisories[0].code == "caa_excludes_issuer"
    # The advisory is about issuing a certificate later; the DNS verdict is
    # computed without it and the CNAME record is still `present`.
    assert result.verified is False
    assert result.records[0].present is True


@respx.mock
def test_verify_records_expose_what_the_nameservers_actually_answered() -> None:
    respx.post(api("/api/v1/sessions/tok/verify")).mock(
        return_value=httpx.Response(200, json=VERIFY_RESPONSE)
    )
    with make_client() as client:
        result = client.sessions.verify("tok")
    assert result.records[0].authoritative_found == ("cname.dodomain.io",)
    assert result.records[0].public_found == ("cname.dodomain.io",)
    # `propagating` in its healthy form: authoritative has it, public does not yet.
    assert result.records[1].authoritative_found == ("dodomain-verify=abc",)
    assert result.records[1].public_found == ()


@respx.mock
def test_the_authed_session_read_carries_the_last_pass_advisories() -> None:
    respx.get(api("/api/v1/sessions/cs_01HZX")).mock(
        return_value=httpx.Response(200, json=INTEGRATOR_SESSION_RESPONSE)
    )
    with make_client() as client:
        session = client.sessions.get("cs_01HZX")
    assert len(session.tls_issuance_advisories) == 1
    assert session.tls_issuance_advisories[0].evidence_fqdn == "customer.com"


@respx.mock
def test_an_app_reports_the_ca_its_certificates_are_issued_with() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json=LIST_APPS_RESPONSE))
    with make_client() as client:
        app = client.apps.list()[0]
    assert app.tls_issuer_ca == "letsencrypt.org"


# ── tolerance: bodies recorded before these fields existed ──────────────────


def test_a_verify_response_recorded_before_advisories_existed_still_parses() -> None:
    result = VerifyResult._from_api(LEGACY_VERIFY_RESPONSE)
    assert result.advisories == ()
    assert result.records[0].authoritative_found == ()
    assert result.records[0].public_found == ()


def test_a_session_read_recorded_before_advisories_existed_still_parses() -> None:
    session = IntegratorSession._from_api(LEGACY_INTEGRATOR_SESSION_RESPONSE)
    assert session.tls_issuance_advisories == ()


def test_an_app_recorded_before_the_issuer_ca_existed_still_parses() -> None:
    app = App._from_api(LEGACY_LIST_APPS_RESPONSE["apps"][0])
    assert app.tls_issuer_ca is None


def test_an_advisories_field_that_is_present_but_not_an_array_is_still_fatal() -> None:
    # Absence is history; a wrong type is drift. The distinction is the whole
    # point of `_opt_list`, so it gets its own test rather than being assumed.
    with pytest.raises(InvalidResponseError):
        VerifyResult._from_api({**VERIFY_RESPONSE, "advisories": "none"})
