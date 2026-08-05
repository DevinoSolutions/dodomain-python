from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from dodomain import Connection, DnsRecord, InvalidResponseError, ProviderGuide, Session
from dodomain.models import parse_datetime
from tests.helpers import CREATE_SESSION_RESPONSE, PROVIDER_GUIDE, connection


def test_a_trailing_z_timestamp_parses_to_utc_on_every_supported_python() -> None:
    # datetime.fromisoformat only learned "Z" in 3.11; the SDK supports 3.10.
    assert parse_datetime("2026-08-06T12:00:00.000Z") == datetime(
        2026, 8, 6, 12, 0, tzinfo=timezone.utc
    )


def test_an_explicit_offset_timestamp_keeps_its_offset() -> None:
    parsed = parse_datetime("2026-08-06T12:00:00+02:00")
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 7200  # type: ignore[union-attr]


def test_an_unparseable_timestamp_is_an_invalid_response_not_a_value_error() -> None:
    with pytest.raises(InvalidResponseError):
        parse_datetime("last tuesday")


def test_a_model_ignores_fields_it_does_not_know_and_keeps_them_on_raw() -> None:
    payload = {**connection(), "scope": "connection", "somethingAddedLater": True}
    conn = Connection._from_api(payload)
    assert conn.id == "conn_1"
    assert conn.raw is not None
    assert conn.raw["somethingAddedLater"] is True


def test_a_missing_required_field_raises_invalid_response() -> None:
    payload = {k: v for k, v in connection().items() if k != "fqdn"}
    with pytest.raises(InvalidResponseError) as excinfo:
        Connection._from_api(payload)
    assert "fqdn" in str(excinfo.value)


def test_a_mistyped_required_field_raises_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        Connection._from_api({**connection(), "status": "retired"})


def test_a_non_object_payload_raises_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        Connection._from_api(["not", "an", "object"])


def test_a_nullable_timestamp_stays_none_rather_than_becoming_an_epoch() -> None:
    conn = Connection._from_api(connection(verifiedAt=None, lastCheckedAt=None))
    assert conn.verified_at is None
    assert conn.last_checked_at is None


def test_a_mistyped_nullable_field_raises_invalid_response() -> None:
    with pytest.raises(InvalidResponseError):
        Connection._from_api(connection(verifiedAt=12345))


def test_a_dns_record_serializes_only_the_fields_it_has() -> None:
    assert DnsRecord(type="CNAME", host="app", value="x").to_api() == {
        "type": "CNAME",
        "host": "app",
        "value": "x",
    }
    assert DnsRecord(type="MX", host="@", value="mx", priority=5, ttl=60).to_api() == {
        "type": "MX",
        "host": "@",
        "value": "mx",
        "priority": 5,
        "ttl": 60,
    }


def test_a_dns_record_round_trips_through_the_wire_shape() -> None:
    original = DnsRecord(type="MX", host="@", value="mx.io", priority=10)
    assert DnsRecord._from_api(original.to_api()) == original


def test_models_are_frozen() -> None:
    record = DnsRecord(type="A", host="@", value="1.2.3.4")
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.value = "5.6.7.8"  # type: ignore[misc]


def test_raw_is_excluded_from_equality_so_additive_fields_do_not_break_comparisons() -> None:
    plain = DnsRecord._from_api({"type": "A", "host": "@", "value": "1.2.3.4"})
    enriched = DnsRecord._from_api({"type": "A", "host": "@", "value": "1.2.3.4", "extra": 1})
    assert plain == enriched


def test_an_optional_guide_field_may_be_absent() -> None:
    minimal = {k: v for k, v in PROVIDER_GUIDE.items() if k not in ("dashboardUrl", "notes")}
    guide = ProviderGuide._from_api(minimal)
    assert guide.dashboard_url is None
    assert guide.notes is None


def test_a_guide_apex_token_outside_the_documented_union_is_rejected() -> None:
    with pytest.raises(InvalidResponseError):
        ProviderGuide._from_api({**PROVIDER_GUIDE, "apexToken": "root"})


def test_the_session_url_builders_encode_an_awkward_token() -> None:
    session = Session._from_api(
        {**CREATE_SESSION_RESPONSE, "token": "a b/c"}, base_url="https://app.dodomain.io"
    )
    assert session.cloudflare_start_url.endswith("/sessions/a%20b%2Fc/cloudflare/start")
    assert session.domain_connect_start_url.endswith("/sessions/a%20b%2Fc/domain-connect/start")


def test_a_boolean_is_not_accepted_where_an_integer_is_required() -> None:
    with pytest.raises(InvalidResponseError):
        DnsRecord._from_api({"type": "A", "host": "@", "value": "x", "ttl": True})
