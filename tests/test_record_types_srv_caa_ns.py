"""SRV, CAA and NS records, and a record type this build does not know.

The API accepts SRV, CAA and NS (below the zone apex) since 2026-10-29
(``record-capabilities.ts`` RECORD_TYPES, core ``zRecord``). 0.8.0 still pinned
the type to the original five, so reading back ANY session holding one of the
new records raised ``InvalidResponseError`` for the whole session. These cases
pin the wire shape of each new type, the local refusals that mirror the
server's, and the rule that a type the API adds later parses instead of
crashing the read.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from dodomain import DnsRecord, InvalidRequestError, InvalidResponseError
from dodomain.models import (
    CAA_TAGS,
    RECORD_TYPES,
    ComposedRecord,
    ConnectSessionSummary,
    IntegratorSession,
    PublicSession,
)
from tests.helpers import (
    CREATE_SESSION_RESPONSE,
    INTEGRATOR_SESSION_RESPONSE,
    PUBLIC_SESSION_RESPONSE,
    api,
    make_async_client,
    make_client,
)

SRV_WIRE: dict[str, Any] = {
    "type": "SRV",
    "host": "_sip._tcp",
    "value": "sip.dodomain.io",
    "priority": 10,
    "weight": 60,
    "port": 5060,
}
CAA_WIRE: dict[str, Any] = {
    "type": "CAA",
    "host": "@",
    "value": "letsencrypt.org",
    "flags": 0,
    "tag": "issue",
}
NS_WIRE: dict[str, Any] = {"type": "NS", "host": "dev", "value": "ns1.dodomain.io"}

SRV = DnsRecord(
    type="SRV", host="_sip._tcp", value="sip.dodomain.io", priority=10, weight=60, port=5060
)
CAA = DnsRecord(type="CAA", host="@", value="letsencrypt.org", flags=0, tag="issue")
NS = DnsRecord(type="NS", host="dev", value="ns1.dodomain.io")

SESSION_WITH_NEW_TYPES: dict[str, Any] = {
    **PUBLIC_SESSION_RESPONSE,
    "records": [*PUBLIC_SESSION_RESPONSE["records"], SRV_WIRE, CAA_WIRE, NS_WIRE],
}


def test_the_sdk_knows_every_record_type_and_caa_tag_the_api_accepts() -> None:
    # record-capabilities.ts RECORD_TYPES and CAA_TAGS, in their order.
    assert RECORD_TYPES == ("A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS")
    assert CAA_TAGS == ("issue", "issuewild", "iodef")


def test_an_srv_record_parses_priority_weight_port_and_its_target() -> None:
    record = DnsRecord._from_api(SRV_WIRE)
    assert record == SRV
    assert (record.priority, record.weight, record.port, record.value) == (
        10,
        60,
        5060,
        "sip.dodomain.io",
    )
    assert record.is_known_type


def test_a_caa_record_parses_flags_tag_and_its_property_value() -> None:
    record = DnsRecord._from_api(CAA_WIRE)
    assert record == CAA
    assert (record.flags, record.tag, record.value) == (0, "issue", "letsencrypt.org")
    assert record.is_known_type


def test_an_ns_record_parses_its_server_as_the_value() -> None:
    record = DnsRecord._from_api(NS_WIRE)
    assert record == NS
    assert record.is_known_type


@pytest.mark.parametrize("wire", [SRV_WIRE, CAA_WIRE, NS_WIRE], ids=["SRV", "CAA", "NS"])
def test_each_new_type_round_trips_through_the_exact_wire_shape(wire: dict[str, Any]) -> None:
    assert DnsRecord._from_api(wire).to_api() == wire


def test_a_mistyped_srv_field_is_still_an_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        DnsRecord._from_api({**SRV_WIRE, "port": "5060"})


@respx.mock
def test_retrieve_reads_a_session_holding_srv_caa_and_ns_records() -> None:
    respx.get(api("/api/v1/sessions/tok_live_abc123")).mock(
        return_value=httpx.Response(200, json=SESSION_WITH_NEW_TYPES)
    )
    with make_client() as client:
        records = client.sessions.retrieve("tok_live_abc123").records
    assert [r.type for r in records] == ["CNAME", "MX", "SRV", "CAA", "NS"]
    assert records[2:] == (SRV, CAA, NS)


@respx.mock
async def test_the_async_client_reads_the_same_session_to_an_equal_result() -> None:
    respx.get(api("/api/v1/sessions/tok_live_abc123")).mock(
        return_value=httpx.Response(200, json=SESSION_WITH_NEW_TYPES)
    )
    with make_client() as client:
        sync_session = client.sessions.retrieve("tok_live_abc123")
    async with make_async_client() as aclient:
        async_session = await aclient.sessions.retrieve("tok_live_abc123")
    assert async_session == sync_session
    assert async_session.records[2:] == (SRV, CAA, NS)


def test_create_and_integrator_responses_compose_names_for_the_new_types() -> None:
    composed = [
        {"type": "SRV", "host": "_sip._tcp", "fqdn": "_sip._tcp.app.customer.com"},
        {"type": "CAA", "host": "@", "fqdn": "app.customer.com"},
        {"type": "NS", "host": "dev", "fqdn": "dev.app.customer.com"},
    ]
    summary = ConnectSessionSummary._from_api(
        {**CREATE_SESSION_RESPONSE, "records": composed}, base_url="https://app.dodomain.io"
    )
    authed = IntegratorSession._from_api({**INTEGRATOR_SESSION_RESPONSE, "records": composed})
    for records in (summary.records, authed.records):
        assert [(r.type, r.fqdn) for r in records] == [
            ("SRV", "_sip._tcp.app.customer.com"),
            ("CAA", "app.customer.com"),
            ("NS", "dev.app.customer.com"),
        ]
        assert all(r.is_known_type for r in records)


# ── a record type the API adds after this build ─────────────────────────────


def test_an_unknown_future_record_type_does_not_crash_the_session_read() -> None:
    future = {"type": "HTTPS", "host": "@", "value": '1 . alpn="h2"', "svcPriority": 1}
    session = PublicSession._from_api(
        {**SESSION_WITH_NEW_TYPES, "records": [*SESSION_WITH_NEW_TYPES["records"], future]}
    )
    unknown = session.records[-1]
    assert unknown.type == "HTTPS"
    assert unknown.value == '1 . alpn="h2"'
    assert not unknown.is_known_type
    assert unknown.raw is not None
    assert unknown.raw["svcPriority"] == 1
    # Every record this build does know is still fully parsed beside it.
    assert session.records[2:5] == (SRV, CAA, NS)


def test_an_unknown_future_type_on_a_composed_record_parses_too() -> None:
    record = ComposedRecord._from_api({"type": "HTTPS", "host": "@", "fqdn": "app.customer.com"})
    assert record.type == "HTTPS"
    assert not record.is_known_type


def test_a_caa_tag_the_api_accepts_later_parses_as_its_string() -> None:
    assert DnsRecord._from_api({**CAA_WIRE, "tag": "issuemail"}).tag == "issuemail"


@pytest.mark.parametrize("bad_type", [None, "", 5], ids=["missing", "empty", "non-string"])
def test_a_missing_empty_or_non_string_type_is_still_an_invalid_response(bad_type: Any) -> None:
    payload = {k: v for k, v in CAA_WIRE.items() if k != "type"}
    if bad_type is not None:
        payload["type"] = bad_type
    with pytest.raises(InvalidResponseError):
        DnsRecord._from_api(payload)


# ── what sessions.create sends and refuses locally ──────────────────────────


@respx.mock
def test_create_sends_srv_caa_and_ns_records_in_the_exact_wire_shape() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(200, json=CREATE_SESSION_RESPONSE)
    )
    with make_client() as client:
        client.sessions.create(domain="app.customer.com", records=[SRV, CAA, NS])
    assert json.loads(route.calls[0].request.content)["records"] == [SRV_WIRE, CAA_WIRE, NS_WIRE]


def _refusal(record: DnsRecord) -> InvalidRequestError:
    with pytest.raises(InvalidRequestError) as excinfo, make_client() as client:
        client.sessions.create(domain="app.customer.com", records=[record])
    assert excinfo.value.status_code == 0
    return excinfo.value


def test_an_srv_record_without_weight_and_port_is_refused_locally_with_the_servers_reason() -> None:
    error = _refusal(DnsRecord(type="SRV", host="_sip._tcp", value="sip.io", priority=10))
    assert error.reason == "missing_srv_fields"
    assert "missing: weight, port" in str(error)


def test_a_caa_record_without_flags_and_tag_is_refused_locally_with_the_servers_reason() -> None:
    error = _refusal(DnsRecord(type="CAA", host="@", value="letsencrypt.org"))
    assert error.reason == "missing_caa_fields"
    assert "missing: flags, tag" in str(error)


def test_a_caa_tag_outside_rfc_8659_is_refused_locally() -> None:
    _refusal(DnsRecord(type="CAA", host="@", value="letsencrypt.org", flags=0, tag="issuemail"))


def test_a_caa_value_with_a_double_quote_is_refused_locally() -> None:
    _refusal(DnsRecord(type="CAA", host="@", value='lets"encrypt.org', flags=0, tag="issue"))


@pytest.mark.parametrize(
    "fields",
    [{"port": 65536}, {"weight": -1}, {"port": True}],
    ids=["port-too-big", "negative-weight", "bool-port"],
)
def test_an_srv_field_outside_its_range_is_refused_locally(fields: dict[str, Any]) -> None:
    base = {"priority": 10, "weight": 60, "port": 5060, **fields}
    _refusal(DnsRecord(type="SRV", host="_sip._tcp", value="sip.io", **base))


def test_a_caa_flags_byte_outside_0_to_255_is_refused_locally() -> None:
    _refusal(DnsRecord(type="CAA", host="@", value="letsencrypt.org", flags=256, tag="issue"))


def test_an_unknown_type_is_still_refused_on_create_because_the_api_would_refuse_it() -> None:
    error = _refusal(DnsRecord(type="HTTPS", host="@", value="x"))
    assert error.reason == "unsupported_record_type"
