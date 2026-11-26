"""Client-side input validation, mirroring the server's own zod schemas.

A bad ``sessions.create`` call fails here, immediately, with ``status_code == 0``
— rather than round-tripping to the API for the identical 400. The rules below
are transcriptions of ``zCreateSessionInput`` and the record-capability guard in
``apps/web/src/app/api/v1/sessions/route.ts``; when they disagree with the server
the server always wins, so they are kept deliberately conservative and are never
the only thing standing between a caller and a clear error.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit

from .errors import InvalidRequestError
from .models import CAA_TAGS, OVERLAP_HOURS_VALUES, RECORD_TYPES, DnsRecord

__all__ = [
    "validate_create_keyless_session",
    "validate_create_session",
    "validate_overlap_hours",
]

# Two-or-more DNS labels, <=63 chars each, no leading/trailing hyphen. Case is
# accepted as sent (DNS is case-insensitive) but a trailing root dot is not: the
# value is stored and compared as-is against verify's fqdns. Transcribed from
# `zDomainName` in packages/core/src/schemas.ts.
_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)

MAX_DOMAIN_LENGTH = 253
MAX_RETURN_URL_LENGTH = 2048


def _reject(message: str, *, reason: str | None = None) -> InvalidRequestError:
    details = {"reason": reason} if reason else None
    return InvalidRequestError("invalid_request", status_code=0, message=message, details=details)


def validate_domain(domain: str) -> str:
    """Return the trimmed domain, or raise before any request is sent."""
    if not isinstance(domain, str):
        raise _reject("domain must be a string.")
    value = domain.strip()
    if len(value) > MAX_DOMAIN_LENGTH:
        raise _reject("Domain is too long (253 characters max).")
    if not _DOMAIN_RE.match(value):
        raise _reject("Enter a domain like app.customer.com (no scheme, port, or trailing dot).")
    return value


def validate_return_url(return_url: str) -> str:
    """Return the return URL, or raise.

    ``http``/``https`` only — a bare URL validator accepts ``javascript:``,
    ``data:`` and ``vbscript:``, and this string is rendered as an ``<a href>`` on
    doDomain's own origin. Embedded credentials are refused for the same reason
    the API refuses them: they travel with the request and are never needed.
    """
    if not isinstance(return_url, str):
        raise _reject("return_url must be a string.")
    value = return_url.strip()
    if len(value) > MAX_RETURN_URL_LENGTH:
        raise _reject("returnUrl is too long (2048 characters max).")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise _reject("returnUrl must be an http:// or https:// URL.") from exc
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise _reject("returnUrl must be an http:// or https:// URL.")
    if parts.username or parts.password:
        raise _reject("returnUrl must not contain embedded credentials.")
    return value


def validate_overlap_hours(overlap_hours: object) -> int:
    """Return the requested rotation overlap, or raise before any request is sent.

    The API takes ``0 | 1 | 24`` and nothing else, so an arbitrary number is a
    mistake worth naming here rather than as a server-side 400 — this call mints
    a credential, and the least useful moment to learn the argument was wrong is
    while wondering whether the old key is still alive.

    ``True`` is refused despite ``True == 1``: a boolean here is a caller who
    meant "yes, overlap" and would silently get a one-hour window they never
    named.
    """
    if isinstance(overlap_hours, bool) or not isinstance(overlap_hours, int):
        raise _reject(
            f"overlap_hours must be one of {OVERLAP_HOURS_VALUES} "
            f"(got {type(overlap_hours).__name__})."
        )
    if overlap_hours not in OVERLAP_HOURS_VALUES:
        raise _reject(
            f"overlap_hours must be one of {OVERLAP_HOURS_VALUES}; "
            f"{overlap_hours} is not a window doDomain offers."
        )
    return overlap_hours


def validate_records(records: Sequence[DnsRecord] | Iterable[DnsRecord]) -> list[dict[str, object]]:
    """Return the wire shape of a session's records, or raise.

    An empty list is refused: a session with nothing to verify parses server-side
    but dead-ends at ``POST /verify`` with "no verifiable records on this
    session", which is a worse place to discover the mistake.
    """
    items = list(records)
    if not items:
        raise _reject("records must contain at least one DNS record.")
    payload: list[dict[str, object]] = []
    for record in items:
        if not isinstance(record, DnsRecord):
            raise _reject(
                "records must contain DnsRecord instances "
                f"(got {type(record).__name__}); build one with "
                "DnsRecord(type=..., host=..., value=...)."
            )
        if record.type not in RECORD_TYPES:
            raise _reject(
                f"unsupported record type: {record.type}", reason="unsupported_record_type"
            )
        if not record.host:
            raise _reject("each record needs a host ('@' for the domain apex).")
        if not record.value:
            raise _reject("each record needs a value.")
        # RFC 5321 requires the preference and the API refuses an MX without one
        # rather than defaulting it, so a missing one is never a silent mistake.
        if record.type == "MX" and record.priority is None:
            raise _reject("MX records require a numeric priority", reason="missing_mx_priority")
        _validate_type_fields(record)
        payload.append(record.to_api())
    return payload


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_type_fields(record: DnsRecord) -> None:
    """The SRV/CAA field rules, transcribed from core ``zRecord`` and
    ``missingRecordFields`` (``record-capabilities.ts``), with the server's own
    messages. NS needs nothing beyond ``value``; its apex rule (``ns_at_zone_apex``)
    needs the public suffix list and stays server-side.
    """
    for name, low, high in (("weight", 0, 65535), ("port", 0, 65535), ("flags", 0, 255)):
        value = getattr(record, name)
        if value is not None and (not _is_int(value) or not low <= value <= high):
            raise _reject(f"{name} must be an integer from {low} to {high}.")
    if record.type == "SRV":
        missing = [n for n in ("priority", "weight", "port") if getattr(record, n) is None]
        if missing:
            raise _reject(
                "SRV records require priority, weight and port "
                f"(missing: {', '.join(missing)}); value is the target host",
                reason="missing_srv_fields",
            )
    if record.type == "CAA":
        missing = [n for n in ("flags", "tag") if getattr(record, n) is None]
        if missing:
            raise _reject(
                "CAA records require flags and tag "
                f"(missing: {', '.join(missing)}); value is the property value",
                reason="missing_caa_fields",
            )
        if any(ch == '"' or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in record.value):
            raise _reject("A CAA value may not contain a double quote or a control character")
    if record.tag is not None and record.tag not in CAA_TAGS:
        raise _reject(f"tag must be one of {', '.join(CAA_TAGS)}.")


def validate_create_session(
    *,
    domain: str,
    records: Sequence[DnsRecord] | Iterable[DnsRecord],
    app_id: str | None,
    recipe: str | None,
    return_url: str | None,
    is_oauth: bool,
) -> dict[str, object]:
    """Build and validate the ``POST /api/v1/sessions`` body."""
    body: dict[str, object] = {
        "domain": validate_domain(domain),
        "records": validate_records(records),
    }
    if app_id is not None:
        if not isinstance(app_id, str) or not app_id.strip():
            raise _reject("app_id must be a non-empty string.")
        body["appId"] = app_id
    elif is_oauth:
        # An OAuth token is team-scoped, so the API cannot infer which app owns
        # the session. Saying so here beats a server-side invalid_request.
        raise _reject(
            "app_id is required when authenticating with an OAuth access token "
            "(the token is team-scoped, so doDomain cannot infer the app). "
            "Call apps.list() to find it."
        )
    if recipe is not None:
        if not isinstance(recipe, str):
            raise _reject("recipe must be a string.")
        body["recipe"] = recipe
    if return_url is not None:
        body["returnUrl"] = validate_return_url(return_url)
    return body


#: Bounds of the optional keyless ``appName`` (``zCreateKeylessSessionInput``).
KEYLESS_APP_NAME_MAX = 60


def validate_create_keyless_session(
    *,
    domain: str,
    records: Sequence[DnsRecord] | Iterable[DnsRecord],
    app_id: str | None,
    app_name: str | None,
    recipe: str | None,
    return_url: str | None,
) -> dict[str, object]:
    """Build and validate the ``POST /api/v1/keyless/sessions`` body.

    The create body minus ``appId`` (a keyless client's ``dd_ks_`` key is its
    app), plus the optional ``appName``, trimmed as the API stores it.
    Transcribed from ``zCreateKeylessSessionInput`` in
    ``packages/core/src/schemas.ts``.
    """
    if app_id is not None:
        raise _reject("a keyless client has no app_id to pass: its dd_ks_ key is its app.")
    body = validate_create_session(
        domain=domain,
        records=records,
        app_id=None,
        recipe=recipe,
        return_url=return_url,
        is_oauth=False,
    )
    if app_name is not None:
        if not isinstance(app_name, str):
            raise _reject("app_name must be a string.")
        name = app_name.strip()
        if not name:
            raise _reject("appName cannot be empty.")
        if len(name) > KEYLESS_APP_NAME_MAX:
            raise _reject(f"appName is too long ({KEYLESS_APP_NAME_MAX} characters max).")
        body["appName"] = name
    return body


def check_app_id_against_key(
    app_id: str | None, *, is_oauth: bool, known_app_id: str | None
) -> None:
    """Refuse an ``app_id`` that a secret key provably cannot mean.

    A ``dd_sk_`` key is app-scoped: the app is implicit in the credential, and the
    API rejects a mismatching ``appId`` with a 400. The SDK cannot read the app id
    out of an opaque key, but ``apps.list()`` returns exactly the key's own app,
    so once that has been called the contradiction is knowable locally.
    """
    if app_id is None or is_oauth:
        return
    if known_app_id is not None and app_id != known_app_id:
        raise _reject(
            f"app_id={app_id!r} does not match the app this secret key belongs to "
            f"({known_app_id!r}). A dd_sk_ key is already app-scoped — omit app_id."
        )
