"""Request building, error mapping and the retry policy.

Everything in here is transport-shaped but I/O-free: the sync and async clients
in ``_client.py`` own the actual sending and sleeping, and call these helpers so
the two paths can never drift on how a response is interpreted.

WHY POST IS NEVER RETRIED
-------------------------
The doDomain API has **no server-side idempotency**. No route, middleware or lib
in the app repo reads an ``Idempotency-Key`` header; the SDK forwards one purely
so the eventual server-side landing is a non-event. Until the server honours it,
a retried ``POST /api/v1/sessions`` mints a *second* session and burns a second
unit of the caller's plan quota. ``GET`` and ``DELETE`` are safe (``DELETE
/v1/connections/{id}`` is idempotent by construction — a repeat returns the
original ``disconnectedAt`` with ``alreadyDisconnected: true``), so those are the
only methods this module will replay. Do not "fix" this by enabling POST retries
on the strength of a header the server ignores.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import (
    ERROR_CODE_TO_EXCEPTION,
    DoDomainAPIError,
    InvalidResponseError,
    RateLimitError,
)

__all__ = ["DEFAULT_BASE_URL", "RateLimitSnapshot", "RequestSpec"]

#: The one production origin. ``api.dodomain.io`` and ``connect.dodomain.io`` are
#: cosmetic names for the same deployment and **do not resolve** — a previous SDK
#: shipped ``https://api.dodomain.io`` as its default and every call 404'd with no
#: error surface. See ``packages/core/src/origin.ts`` in the app repo.
DEFAULT_BASE_URL = "https://app.dodomain.io"

#: Statuses worth replaying on an idempotent method.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

#: The only methods this SDK replays. See the module docstring.
RETRYABLE_METHODS = frozenset({"GET", "DELETE"})

BACKOFF_BASE_SECONDS = 0.5
BACKOFF_CAP_SECONDS = 8.0

#: A ``Retry-After`` longer than this is reported to the caller rather than
#: silently slept through — a minute of blocked thread is already generous.
MAX_HONOURED_RETRY_AFTER_SECONDS = 60.0

_REQUEST_ID_HEADERS = ("x-request-id", "x-vercel-id", "cf-ray")


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """One outbound call, fully described and not yet sent."""

    method: str
    path: str
    params: dict[str, str] | None = None
    json_body: Any = None
    #: ``False`` for the token-public routes, whose capability is the session
    #: token in the path — they must be called with no ``Authorization`` header.
    auth: bool = True
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class RateLimitSnapshot:
    """What the last response said about rate limits.

    The API emits **only** ``Retry-After`` today: a repo-wide grep for the IETF
    draft-11 ``RateLimit-*`` names returns zero hits in source, tests or docs. The
    draft-11 fields below are read opportunistically so the day the API adds them
    the SDK already reports them; until then they are ``None`` and only
    :attr:`retry_after` is ever populated.
    """

    limit: int | None = None
    remaining: int | None = None
    reset: float | None = None
    policy: str | None = None
    retry_after: float | None = None

    @classmethod
    def from_headers(cls, headers: httpx.Headers) -> RateLimitSnapshot:
        return cls(
            limit=_int_header(headers, "RateLimit-Limit"),
            remaining=_int_header(headers, "RateLimit-Remaining"),
            reset=_float_header(headers, "RateLimit-Reset"),
            policy=headers.get("RateLimit-Policy"),
            retry_after=_float_header(headers, "Retry-After"),
        )


def _int_header(headers: httpx.Headers, name: str) -> int | None:
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


def _float_header(headers: httpx.Headers, name: str) -> float | None:
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        return float(raw.strip())
    except ValueError:
        return None


def build_headers(
    spec: RequestSpec,
    *,
    secret_key: str,
    user_agent: str,
) -> dict[str, str]:
    """Assemble the exact headers for one request.

    Headers are built per request rather than pinned to the ``httpx`` client so
    the token-public routes can be called with no credential at all, even when
    the caller injected their own ``http_client``.
    """
    headers: dict[str, str] = {"accept": "application/json", "user-agent": user_agent}
    if spec.auth:
        headers["authorization"] = f"Bearer {secret_key}"
    if spec.json_body is not None:
        headers["content-type"] = "application/json"
    if spec.idempotency_key is not None:
        headers["idempotency-key"] = spec.idempotency_key
    return headers


def _code_from_type_uri(type_uri: str) -> str:
    """Best-effort RFC 9457 ``type`` URI -> doDomain error code."""
    slug = type_uri.rstrip("/").rsplit("/", 1)[-1]
    slug = slug.split("#", 1)[0].split("?", 1)[0]
    return slug.replace("-", "_") or "internal"


def parse_error_body(body: dict[str, Any]) -> tuple[str, str | None, Any]:
    """Read a code, message and details out of either error envelope.

    The API ships ``{"error", "message"?, "details"?}`` today. The Devino public
    API standard is RFC 9457 problem+json, which this API has not adopted; both
    shapes are handled now so the SDK survives that cutover without a breaking
    release.
    """
    if "error" not in body and ("title" in body or "type" in body):
        raw_code = body.get("code")
        code = (
            raw_code
            if isinstance(raw_code, str)
            else _code_from_type_uri(str(body.get("type", "")))
        )
        detail = body.get("detail") or body.get("title")
        return code, detail if isinstance(detail, str) else None, body
    code = body.get("error")
    message = body.get("message")
    return (
        code if isinstance(code, str) else "internal",
        message if isinstance(message, str) else None,
        body.get("details"),
    )


def _request_id(headers: httpx.Headers) -> str | None:
    for name in _REQUEST_ID_HEADERS:
        value = headers.get(name)
        if value:
            return value
    return None


def _looks_like_problem_json(response: httpx.Response) -> bool:
    return "application/problem+json" in response.headers.get("content-type", "").lower()


def map_error(response: httpx.Response, spec: RequestSpec) -> DoDomainAPIError:
    """Turn a non-2xx response into the right exception. Never raises itself."""
    request_id = _request_id(response.headers)
    text = response.text
    try:
        body = json.loads(text) if text.strip() else {}
    except ValueError:
        # A proxy's HTML 502 must never escape as a raw JSONDecodeError.
        return DoDomainAPIError(
            "non_json_response",
            status_code=response.status_code,
            message=None,
            details=None,
            request_id=request_id,
            method=spec.method,
            path=spec.path,
            body=text,
        )

    if not isinstance(body, dict):
        return DoDomainAPIError(
            "non_json_response",
            status_code=response.status_code,
            request_id=request_id,
            method=spec.method,
            path=spec.path,
            body=body,
        )

    # `_looks_like_problem_json` is the explicit signal; `parse_error_body`
    # shape-detects when the header is absent, so both routes agree.
    code, message, details = parse_error_body(body)
    if _looks_like_problem_json(response) and "error" in body and isinstance(body.get("code"), str):
        code = body["code"]

    exc_class = ERROR_CODE_TO_EXCEPTION.get(code, DoDomainAPIError)
    error = exc_class(
        code,
        status_code=response.status_code,
        message=message,
        details=details,
        request_id=request_id,
        method=spec.method,
        path=spec.path,
        body=body,
    )
    if isinstance(error, RateLimitError):
        error._retry_after_header = _float_header(response.headers, "Retry-After")
    return error


def parse_success(response: httpx.Response, spec: RequestSpec) -> Any:
    """Decode a 2xx body, or raise :class:`InvalidResponseError`."""
    text = response.text
    if not text.strip():
        raise InvalidResponseError(
            f"doDomain returned an empty body for {spec.method} {spec.path}",
            payload=text,
        )
    try:
        return json.loads(text)
    except ValueError as exc:
        raise InvalidResponseError(
            f"doDomain returned a non-JSON body for {spec.method} {spec.path}",
            payload=text,
        ) from exc


def backoff_delay(attempt: int, rng: random.Random) -> float:
    """Exponential backoff with full jitter, base 0.5s, capped at 8s."""
    ceiling = min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2**attempt))
    return rng.uniform(0.0, ceiling)


def retry_delay_for_response(
    response: httpx.Response,
    spec: RequestSpec,
    attempt: int,
    rng: random.Random,
) -> float | None:
    """Seconds to wait before replaying, or ``None`` to raise instead.

    ``None`` is returned for every non-retryable situation, including the 429
    whose ``details.reason`` is ``recently_checked``: that is a per-connection
    10-minute cooldown, not a rate problem, and a backoff loop would only burn
    the caller's plan quota against the *other* limiter.
    """
    if spec.method not in RETRYABLE_METHODS:
        return None
    if response.status_code not in RETRY_STATUSES:
        return None

    if response.status_code == 429:
        if _rate_limit_reason(response) == "recently_checked":
            return None
        retry_after = _float_header(response.headers, "Retry-After")
        if retry_after is not None:
            if retry_after > MAX_HONOURED_RETRY_AFTER_SECONDS:
                return None
            return max(retry_after, 0.0)
    return backoff_delay(attempt, rng)


def _rate_limit_reason(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    details = body.get("details")
    if isinstance(details, dict):
        reason = details.get("reason")
        return reason if isinstance(reason, str) else None
    return None
