"""The exception hierarchy every doDomain SDK failure is expressed in.

Nothing this package raises escapes ``DoDomainError``: a proxy's HTML 502, a
socket timeout, a response body that does not match the contract, and every one
of the API's ten error codes all arrive as a subclass of it.

The API's error envelope is ``{"error": <code>, "message"?, "details"?}`` — see
``apps/web/src/lib/api/errors.ts`` in the app repo. Two facts about it drive the
design here:

* ``message`` is frequently **absent**. ``withRoute`` re-emits a thrown
  ``ApiError`` as ``jsonError(code, {details, headers})`` and drops ``message``
  on the way, so every *thrown* error (the rate limiter's 429, the
  ``SCOPE_MISSING`` 403) arrives without one. ``__str__`` therefore synthesizes
  a useful description from the method, path, status and code instead of
  assuming a message exists.
* The code vocabulary is documented as fixed at ten values, but an unrecognized
  eleventh must never crash the mapper — it degrades to ``DoDomainAPIError``.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AuthenticationError",
    "ConflictError",
    "DoDomainAPIError",
    "DoDomainConfigError",
    "DoDomainConnectionError",
    "DoDomainError",
    "ExpiredError",
    "InternalServerError",
    "InvalidRequestError",
    "InvalidResponseError",
    "NotConfiguredError",
    "NotFoundError",
    "PermissionError_",
    "QuotaExceededError",
    "RateLimitError",
]


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
        super().__init__(message)
        self.payload = payload


class DoDomainConnectionError(DoDomainError):
    """The request never produced an HTTP response (timeout, DNS, TLS, reset)."""

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class DoDomainAPIError(DoDomainError):
    """The API answered with a non-2xx status.

    Attributes:
        code: The API's ``error`` code, or ``"non_json_response"`` when the body
            was not JSON at all. ``status_code`` is ``0`` for failures this SDK
            raised locally without ever sending a request.
        status_code: The HTTP status, or ``0`` when no request was sent.
        message: The API's ``message`` field. **Often ``None``** — see the module
            docstring.
        details: The API's ``details`` field, unmodified.
        request_id: The value of an ``x-request-id``/``x-vercel-id`` response
            header when the deployment sets one.
        method: HTTP method of the failing request, when known.
        path: Path of the failing request, when known.
        body: The decoded response body (or raw text for a non-JSON body).
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
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.details = details
        self.request_id = request_id
        self.method = method
        self.path = path
        self.body = body

    def __str__(self) -> str:
        where = f"{self.method} {self.path} " if self.method and self.path else ""
        if self.status_code:
            text = f"doDomain API error: {where}returned HTTP {self.status_code} ({self.code})"
        else:
            text = f"doDomain API error: {self.code} (no HTTP request was sent)"
        if self.message:
            text += f": {self.message}"
        elif self.details is not None:
            text += f": details={self.details!r}"
        if self.request_id:
            text += f" [request_id={self.request_id}]"
        return text

    def _detail_field(self, key: str) -> Any:
        if isinstance(self.details, dict):
            return self.details.get(key)
        return None


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
