"""Edge cases of the local validators — every one raises before a socket opens."""

from __future__ import annotations

import pytest

from dodomain import DnsRecord, InvalidRequestError
from dodomain._validation import (
    validate_create_session,
    validate_domain,
    validate_overlap_hours,
    validate_records,
    validate_return_url,
)

CNAME = DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")


@pytest.mark.parametrize("value", [None, 42, ["app.customer.com"]])
def test_a_non_string_domain_is_rejected(value: object) -> None:
    with pytest.raises(InvalidRequestError):
        validate_domain(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [None, 42, object()])
def test_a_non_string_return_url_is_rejected(value: object) -> None:
    with pytest.raises(InvalidRequestError):
        validate_return_url(value)  # type: ignore[arg-type]


def test_an_ipv6_bracket_url_that_cannot_be_parsed_is_rejected() -> None:
    with pytest.raises(InvalidRequestError):
        validate_return_url("https://[::1")


def test_a_scheme_relative_url_is_rejected() -> None:
    with pytest.raises(InvalidRequestError):
        validate_return_url("//customer.com/back")


def test_a_valid_return_url_is_returned_trimmed() -> None:
    assert validate_return_url("  https://customer.com/back  ") == "https://customer.com/back"


def test_a_record_without_a_host_is_rejected() -> None:
    with pytest.raises(InvalidRequestError) as excinfo:
        validate_records([DnsRecord(type="A", host="", value="1.2.3.4")])
    assert "host" in str(excinfo.value)


def test_a_record_without_a_value_is_rejected() -> None:
    with pytest.raises(InvalidRequestError) as excinfo:
        validate_records([DnsRecord(type="A", host="@", value="")])
    assert "value" in str(excinfo.value)


def test_records_may_be_any_iterable_not_just_a_list() -> None:
    body = validate_records(iter([CNAME]))
    assert body == [{"type": "CNAME", "host": "app", "value": "cname.dodomain.io"}]


@pytest.mark.parametrize("value", ["", "   ", 7])
def test_a_blank_app_id_is_rejected(value: object) -> None:
    with pytest.raises(InvalidRequestError):
        validate_create_session(
            domain="app.customer.com",
            records=[CNAME],
            app_id=value,  # type: ignore[arg-type]
            recipe=None,
            return_url=None,
            is_oauth=False,
        )


def test_a_non_string_recipe_is_rejected() -> None:
    with pytest.raises(InvalidRequestError):
        validate_create_session(
            domain="app.customer.com",
            records=[CNAME],
            app_id=None,
            recipe=123,  # type: ignore[arg-type]
            return_url=None,
            is_oauth=False,
        )


def test_a_valid_body_contains_only_the_fields_that_were_supplied() -> None:
    assert validate_create_session(
        domain="  app.customer.com  ",
        records=[CNAME],
        app_id=None,
        recipe=None,
        return_url=None,
        is_oauth=False,
    ) == {
        "domain": "app.customer.com",
        "records": [{"type": "CNAME", "host": "app", "value": "cname.dodomain.io"}],
    }


@pytest.mark.parametrize("value", [0, 1, 24])
def test_the_three_rotation_windows_the_api_offers_are_returned_unchanged(value: int) -> None:
    assert validate_overlap_hours(value) == value


@pytest.mark.parametrize("value", [2, 12, 25, -1, 48])
def test_a_rotation_window_the_api_does_not_offer_is_rejected(value: int) -> None:
    with pytest.raises(InvalidRequestError):
        validate_overlap_hours(value)


@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_overlap_is_rejected_despite_being_an_int_in_python(value: bool) -> None:
    # `True == 1` and `False == 0`, so a plain membership test would quietly read
    # `overlap_hours=True` as a one-hour window the caller never named.
    with pytest.raises(InvalidRequestError):
        validate_overlap_hours(value)


@pytest.mark.parametrize("value", [None, "24", 24.0, object()])
def test_a_non_integer_overlap_is_rejected(value: object) -> None:
    with pytest.raises(InvalidRequestError):
        validate_overlap_hours(value)
