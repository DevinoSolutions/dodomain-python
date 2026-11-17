"""The exception hierarchy every doDomain SDK failure is expressed in.

Nothing this package raises escapes ``DoDomainError``: a proxy's HTML 502, a
socket timeout, a response body that does not match the contract, and every one
of the API's ten error codes all arrive as a subclass of it.

The API's error envelope is ``{"error": <code>, "message"?, "details"?}``, plus
the RFC 9457 ``type``/``title``/``status``/``detail`` members on the routes that
opted into problem+json and a stable denial ``code`` when the thrower attached
one; see ``apps/web/src/lib/api/errors.ts`` in the app repo. Three facts about
it drive the design here:

* The human text is frequently **absent**. ``withRoute`` re-emits a thrown
  ``ApiError`` as ``jsonError(code, {details, headers})`` and drops ``message``
  on the way, so many *thrown* errors (the rate limiter's 429, the
  ``SCOPE_MISSING`` 403) arrive without one. ``message`` therefore falls back to
  the machine error, or ``HTTP <status>``, and ``__str__`` adds the method,
  path, status and code.
* The code vocabulary is documented as fixed at ten values, but an unrecognized
  eleventh must never crash the mapper; it degrades to ``DoDomainAPIError``.
* A keyless refusal can echo the caller's ``dd_ks_`` key (a claim link carries
  it after its ``#``). Every error redacts any ``dd_ks_`` key to ``dd_ks_…``
  (:func:`redact_keyless_keys`), in its message, details and body alike.
"""

from __future__ import annotations

import re
from typing import Any, Literal

__all__ = [
    "API_KEYLESS_CODES",
    "SDK_KEYLESS_CODES",
    "AuthenticationError",
    "ConflictError",
    "DoDomainAPIError",
    "DoDomainConfigError",
    "DoDomainConnectionError",
    "DoDomainError",
    "DoDomainKeylessError",
    "ExpiredError",
    "InternalServerError",
    "InvalidRequestError",
    "InvalidResponseError",
    "KeylessErrorCode",
    "NotConfiguredError",
    "NotFoundError",
    "PermissionError_",
    "QuotaExceededError",
    "RateLimitError",
    "redact_keyless_keys",
]

#: A keyless key anywhere in a string: the prefix and its secret part.
_KEYLESS_KEY_PATTERN = re.compile(r"dd_ks_[A-Za-z0-9_-]+")

#: What a redacted keyless key reads as: the prefix only.
REDACTED_KEYLESS_KEY = "dd_ks_…"


def redact_keyless_keys(value: Any) -> Any:
    """A copy of ``value`` with every ``dd_ks_`` key cut to ``dd_ks_…``.

    Applied to every string at any depth (a refusal's
    ``details.unlock.claimUrl`` carries the key after its ``#``). Errors are
    logged, reported and pasted into issues; the key is a bearer credential for
    the keyless app, so an error must never carry it whole. Successful responses
    are left alone: the caller needs the key and the claim link from those.
    Mirrors ``redactKeylessKeys`` in ``@dodomain/node``.
    """
    if isinstance(value, str):
        return _KEYLESS_KEY_PATTERN.sub(REDACTED_KEYLESS_KEY, value)
    if isinstance(value, list):
        return [redact_keyless_keys(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_keyless_keys(item) for item in value)
    if isinstance(value, dict):
        return {name: redact_keyless_keys(inner) for name, inner in value.items()}
    return value


class DoDomainError(Exception):
    """Base class for every error this SDK raises."""


class DoDomainConfigError(DoDomainError):
    """The client was constructed with unusable options (e.g. a bad secret key)."""


class InvalidResponseError(DoDomainError):
    """A 2xx response did not match the contract this SDK was written against.

    Raised instead of returning a silently mistyped object — the Python twin of
    the TypeScript SDK's ``invalid_response_shape``.
    """

    def __init__(self, message: str, *, payload: Any = None) -> None:
        # The payload is attached for debugging; a keyless start's carries the
        # dd_ks_ key, which never belongs in an error.
        super().__init__(redact_keyless_keys(message))
        self.payload = redact_keyless_keys(payload)


class DoDomainConnectionError(DoDomainError):
    """The request never produced an HTTP response (timeout, DNS, TLS, reset)."""

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class DoDomainAPIError(DoDomainError):
    """The API answered with a non-2xx status, or the SDK refused a call itself.

    Attributes:
        message: What went wrong, in one line: the machine error followed by the
            API's own human text (``'invalid_request: "customer.com" is a
            placeholder ...'``), so a logged ``exc.message`` says what to do.
            With no human text it is the machine error alone, or
            ``HTTP <status>`` when the body named none. Since 0.7.0, the twin of
            ``@dodomain/node`` 0.9.2; before, it was the API's raw ``message``
            field and often ``None``. That text is :attr:`detail` now.
        detail: The API's human text alone (RFC 9457 ``detail``, else the house
            ``message``), or ``None`` when it sent none.
        error: The machine error (``body.error``, e.g. ``"invalid_request"``,
            ``"quota_exceeded"``). ``None`` on errors this SDK raised itself
            (``status_code == 0``) and on bodies that carry none.
        code: The value to branch on. The machine error, except where the API
            sent a stable denial code on a problem+json answer (every keyless
            refusal does), which then wins: ``"KEYLESS_LIMIT_REACHED"``. On a
            :class:`DoDomainKeylessError` it is always the ``KEYLESS_*`` code;
            ``"non_json_response"`` when the body was not JSON at all.
        status_code: The HTTP status, or ``0`` when no request was sent.
        details: The API's ``details`` field (``dd_ks_`` keys redacted).
        request_id: The value of an ``x-request-id``/``x-vercel-id`` response
            header when the deployment sets one.
        method: HTTP method of the failing request, when known.
        path: Path of the failing request, when known.
        body: The decoded response body (or raw text for a non-JSON body),
            ``dd_ks_`` keys redacted.
    """

    def __init__(
        self,
        code: str,
        *,
        status_code: int = 0,
        message: str | None = None,
        details: Any = None,
        request_id: str | None = None,
        method: str | None = None,
        path: str | None = None,
        body: Any = None,
        error: str | None = None,
    ) -> None:
        # Every field is built from redacted values, so no rendering of the error
        # (str, repr, args, a traceback) can carry a whole dd_ks_ key.
        code = redact_keyless_keys(code)
        error = redact_keyless_keys(error)
        super().__init__(code)
        self.code = code
        self.error = error
        self.status_code = status_code
        self.detail = _human_text(message)
        self.details = redact_keyless_keys(details)
        self.request_id = request_id
        self.method = method
        self.path = path
        self.body = redact_keyless_keys(body)
        if error is not None:
            machine = error
        elif status_code == 0 or code == "non_json_response":
            machine = code
        else:
            machine = f"HTTP {status_code}"
        self.message = (
            machine
            if self.detail is None or self.detail == machine
            else f"{machine}: {self.detail}"
        )

    def __str__(self) -> str:
        where = f"{self.method} {self.path} " if self.method and self.path else ""
        label = self.code if self.error in (None, self.code) else f"{self.error}, {self.code}"
        if self.status_code:
            text = f"doDomain API error: {where}returned HTTP {self.status_code} ({label})"
        else:
            text = f"doDomain API error: {label} (no HTTP request was sent)"
        if self.detail:
            text += f": {self.detail}"
        elif self.details is not None:
            text += f": details={self.details!r}"
        if self.request_id:
            text += f" [request_id={self.request_id}]"
        return text

    def _detail_field(self, key: str) -> Any:
        if isinstance(self.details, dict):
            return self.details.get(key)
        return None


def _human_text(text: Any) -> str | None:
    """A refusal's human text, trimmed and redacted; ``None`` when blank."""
    if not isinstance(text, str) or not text.strip():
        return None
    return redact_keyless_keys(text.strip())


class AuthenticationError(DoDomainAPIError):
    """401 ``unauthorized`` — the credential is missing, malformed, or rejected."""

    @property
    def consent_revoked(self) -> bool:
        """True when an OAuth caller's consent was revoked (``details.code``)."""
        return self._detail_field("code") == "CONSENT_REVOKED"


class PermissionError_(DoDomainAPIError):
    """403 ``forbidden`` — authenticated, but not allowed to do this.

    Named with a trailing underscore so it never shadows the builtin
    ``PermissionError``.
    """

    @property
    def required_scope(self) -> str | None:
        """The OAuth scope the call needed, when the API named one."""
        if self._detail_field("code") == "SCOPE_MISSING":
            scope = self._detail_field("requiredScope")
            return scope if isinstance(scope, str) else None
        return None

    @property
    def secret_key_required(self) -> bool:
        """True when the endpoint refuses OAuth tokens and wants a ``dd_sk_`` key.

        The webhook-endpoint and key-rotation routes are secret-key-only, and the
        API says so with 403 + ``details.code == "SECRET_KEY_REQUIRED"`` rather than
        401 — the token is perfectly valid, it simply has no authority here, and a
        401 would send you off re-minting a token that was never the problem. There
        is no scope that fixes this: build a client from the app's secret key.
        """
        return self._detail_field("code") == "SECRET_KEY_REQUIRED"


class NotFoundError(DoDomainAPIError):
    """404 ``not_found``.

    A resource owned by another app or team collapses to this rather than 403 —
    the API refuses to confirm that someone else's id exists. Do not reinterpret
    it as a permission problem.
    """


class ExpiredError(DoDomainAPIError):
    """410 ``expired`` — the connect session's 24h TTL has elapsed."""


class InvalidRequestError(DoDomainAPIError):
    """400 ``invalid_request``, or a local validation failure (status ``0``)."""

    @property
    def reason(self) -> str | None:
        """``details.reason`` when the API sent a machine-readable one.

        Known values: ``"unsupported_record_type"``, ``"missing_mx_priority"``.
        A zod ``flatten()`` payload has no ``reason`` and returns ``None``.
        """
        reason = self._detail_field("reason")
        return reason if isinstance(reason, str) else None


class QuotaExceededError(DoDomainAPIError):
    """402 ``quota_exceeded`` — the free plan's monthly connection cap is spent."""


class NotConfiguredError(DoDomainAPIError):
    """503 ``not_configured`` — an optional integration is off on this deployment."""


class ConflictError(DoDomainAPIError):
    """409 ``conflict``."""


class RateLimitError(DoDomainAPIError):
    """429 ``rate_limited`` — two very different situations share this code.

    Branch on :attr:`reason`:

    * ``"request_rate"`` — you are calling the API too fast. :attr:`limit`
      carries the per-minute cap. Backing off and retrying is correct, and the
      SDK does it for you on idempotent methods.
    * ``"recently_checked"`` — only from ``connections.reverify``. This one
      connection was DNS-checked inside its 10-minute cooldown. Nothing global
      is throttled, so the SDK never retries it; surface "checked recently, try
      again in N minutes" to your user instead.
    """

    #: Seconds parsed out of the ``Retry-After`` response header, set by the
    #: transport when it builds this exception.
    _retry_after_header: float | None = None

    @property
    def reason(self) -> str | None:
        reason = self._detail_field("reason")
        return reason if isinstance(reason, str) else None

    @property
    def limit(self) -> int | None:
        """The per-minute cap, on the ``request_rate`` arm."""
        limit = self._detail_field("limit")
        return limit if isinstance(limit, int) else None

    @property
    def retry_after(self) -> float | None:
        """Seconds to wait, from the ``Retry-After`` header or ``details``.

        The header wins when both are present.
        """
        if self._retry_after_header is not None:
            return self._retry_after_header
        seconds = self._detail_field("retryAfterSeconds")
        if isinstance(seconds, (int, float)):
            return float(seconds)
        return None


class InternalServerError(DoDomainAPIError):
    """500 ``internal``."""


#: The codes a keyless failure carries (``KeylessErrorCode`` in
#: ``@dodomain/node``): the API's own eight, then the five this SDK raises itself
#: before or instead of a request, always with ``status_code == 0``.
KeylessErrorCode = Literal[
    "KEYLESS_PROOF_REQUIRED",
    "KEYLESS_LIMIT_REACHED",
    "KEYLESS_START_RATE_LIMITED",
    "KEYLESS_CAPACITY_REACHED",
    "KEYLESS_KEY_CLAIMED",
    "KEYLESS_KEY_NOT_ACCEPTED",
    "KEYLESS_DISABLED",
    "KEYLESS_PLACEHOLDER_DOMAIN",
    "KEYLESS_PROOF_TIMEOUT",
    "KEYLESS_PROOF_ABORTED",
    "KEYLESS_PROOF_UNSUPPORTED",
    "KEYLESS_KEY_MISSING",
    "KEYLESS_MODE",
]

#: Every keyless denial code the API answers with (``body.code``). Transcribed
#: from the app repo, where it must equal the ``"KEYLESS_*"`` literals under
#: ``apps/web/src`` (``KEYLESS_DENIAL_CODES`` in
#: ``apps/web/src/lib/api/keyless-errors.ts`` plus ``KEYLESS_LIMIT_REACHED`` in
#: ``apps/web/src/lib/plan-quota.ts``); its ``scripts/check-keyless-bans.sh``
#: rule 11 holds ``@dodomain/node`` to the same list, and
#: ``tests/test_keyless.py`` holds this one to it.
API_KEYLESS_CODES: frozenset[str] = frozenset(
    {
        "KEYLESS_PROOF_REQUIRED",
        "KEYLESS_LIMIT_REACHED",
        "KEYLESS_START_RATE_LIMITED",
        "KEYLESS_CAPACITY_REACHED",
        "KEYLESS_KEY_CLAIMED",
        "KEYLESS_KEY_NOT_ACCEPTED",
        "KEYLESS_DISABLED",
        "KEYLESS_PLACEHOLDER_DOMAIN",
    }
)

#: The keyless codes this SDK raises itself (``status_code == 0``, no request).
SDK_KEYLESS_CODES: frozenset[str] = frozenset(
    {
        "KEYLESS_PROOF_TIMEOUT",
        "KEYLESS_PROOF_ABORTED",
        "KEYLESS_PROOF_UNSUPPORTED",
        "KEYLESS_KEY_MISSING",
        "KEYLESS_MODE",
    }
)


class DoDomainKeylessError(DoDomainAPIError):
    """A keyless-start failure: a ``KEYLESS_*`` refusal from the API, or one this
    SDK raised itself (``status_code == 0``, no request sent).

    Still a :class:`DoDomainAPIError` (and a :class:`DoDomainError`), so an
    existing ``except`` keeps catching it; branch on :attr:`code` for the keyless
    specifics. :attr:`details` is the refusal's ``details`` object (the limit,
    what unlocks more, ``claimUrl`` / ``signUpUrl``, ``retryAt``), when the API
    sent one, with any ``dd_ks_`` key redacted.
    """

    #: Seconds parsed out of the ``Retry-After`` response header, set by the
    #: transport when it builds this exception.
    _retry_after_header: float | None = None

    @property
    def retry_at(self) -> str | None:
        """``details.retryAt``: when the limit lifts (ISO 8601 UTC), if it does.

        Set on the fair-share refusals (``KEYLESS_LIMIT_REACHED`` with
        ``scope == "network"``, ``KEYLESS_START_RATE_LIMITED``,
        ``KEYLESS_CAPACITY_REACHED``); ``None`` on a spent lifetime allowance,
        which only claiming the app lifts.
        """
        retry_at = self._detail_field("retryAt")
        return retry_at if isinstance(retry_at, str) else None

    @property
    def retry_after(self) -> float | None:
        """Seconds to wait, from the ``Retry-After`` header or
        ``details.retryAfterSeconds``. The header wins when both are present."""
        if self._retry_after_header is not None:
            return self._retry_after_header
        seconds = self._detail_field("retryAfterSeconds")
        if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
            return float(seconds)
        return None


#: The API's fixed ten-code vocabulary mapped onto this package's exceptions.
#: An unrecognized code falls back to :class:`DoDomainAPIError` — the fallback is
#: one line and stops a future eleventh code from breaking every installed SDK.
ERROR_CODE_TO_EXCEPTION: dict[str, type[DoDomainAPIError]] = {
    "unauthorized": AuthenticationError,
    "forbidden": PermissionError_,
    "not_found": NotFoundError,
    "expired": ExpiredError,
    "invalid_request": InvalidRequestError,
    "quota_exceeded": QuotaExceededError,
    "not_configured": NotConfiguredError,
    "conflict": ConflictError,
    "rate_limited": RateLimitError,
    "internal": InternalServerError,
}
