"""Webhook signature verification.

doDomain signs every delivery Stripe-style::

    x-dodomain-signature: t=<unix millis>,v1=<hex sha256 hmac>
    x-dodomain-event: connection.verified
    x-dodomain-delivery-id: whd_…

The signed payload is ``f"{t}.{raw_body}"``, HMAC-SHA256 with your endpoint
secret, lowercase hex.

Verify against the **raw** request body, before any JSON parsing: re-serializing
a parsed body changes the bytes and the signature will not match.

THE WIRE BODY
-------------
The envelope cutover landed on 2026-08-06, so a delivery today looks like::

    {
      "id": "whd_…",            # stable across retries — dedupe on this
      "type": "connection.verified",
      "occurredAt": "2026-08-17T10:00:00.000Z",
      "data": {"sessionId": "…", "connectionId": "…", …},
      "event": "connection.verified"   # DEPRECATED alias for `type`
    }

``event`` is byte-identical to ``type`` and exists only so receivers written
before the cutover keep parsing. Read ``type``, dedupe on ``id`` — the same
value as the ``x-dodomain-delivery-id`` header, so you can dedupe before parsing
the body at all — and treat ``event`` as legacy.

``data`` always carries ``sessionId`` as your correlation handle, and every
payload that announces a connection also carries ``connectionId`` — the id
``connections.get`` / ``reverify`` / ``disconnect`` are keyed by.

**Still no typed event parser, and still on purpose.** The event vocabulary and
the payload fields both grow additively, so a strict parser here would reject a
delivery the day the API adds a type — exactly the failure a webhook receiver
must not have. :func:`verify_webhook` checks the HMAC and nothing else, which is
what makes it safe across every additive change; parse ``json.loads(raw)``
yourself and ignore what you do not recognise.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time

__all__ = ["DEFAULT_TOLERANCE_MS", "SIGNATURE_HEADER", "verify_webhook"]

SIGNATURE_HEADER = "x-dodomain-signature"
EVENT_HEADER = "x-dodomain-event"

#: Replay window, five minutes, matching the TypeScript implementation.
DEFAULT_TOLERANCE_MS = 5 * 60 * 1000

# A valid v1 is always exactly 64 lowercase hex characters. This gate runs BEFORE
# any bytes are built, and it is load-bearing: `bytes.fromhex` raises ValueError
# on non-hex input, so an attacker-controlled header could otherwise turn into an
# exception inside YOUR request handler — a 500 where a `False` belongs. A
# malformed signature is a failed verification, not an error.
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def _as_bytes(value: str | bytes | bytearray) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


def _parse_header(header: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    for chunk in header.split(","):
        key, sep, value = chunk.partition("=")
        if sep:
            parts[key.strip()] = value.strip()
    return parts


def verify_webhook(
    secret: str | bytes,
    body: str | bytes,
    header: str,
    tolerance_ms: int = DEFAULT_TOLERANCE_MS,
    now_ms: int | None = None,
) -> bool:
    """Check a doDomain webhook signature.

    Args:
        secret: The endpoint's signing secret.
        body: The **raw** request body, exactly as received.
        header: The value of the ``x-dodomain-signature`` header.
        tolerance_ms: Replay window in milliseconds. Default five minutes.
        now_ms: Current time in Unix milliseconds; defaults to now. Useful for
            tests and for replaying archived deliveries.

    Returns:
        ``True`` only for a signature this secret could have produced, inside the
        replay window. Every other outcome — wrong secret, tampered body, stale
        or missing timestamp, malformed or absent ``v1``, garbage header, wrong
        type — is ``False``.

    This function **never raises**. A verification failure and a malformed header
    are the same answer, so an attacker cannot turn a crafted header into an
    exception inside your handler.

    Example:
        >>> from dodomain import verify_webhook
        >>> if not verify_webhook(secret, request.body, request.headers["x-dodomain-signature"]):
        ...     return Response(status=400)
    """
    try:
        if not isinstance(header, str):
            return False
        parts = _parse_header(header)

        raw_timestamp = parts.get("t", "")
        if not raw_timestamp:
            return False
        try:
            timestamp = int(raw_timestamp)
        except ValueError:
            return False
        if timestamp <= 0:
            return False

        current = int(time.time() * 1000) if now_ms is None else int(now_ms)
        if abs(current - timestamp) > int(tolerance_ms):
            return False

        got = parts.get("v1", "")
        if not _HEX_64_RE.match(got):
            return False

        payload = f"{timestamp}.".encode() + _as_bytes(body)
        expected = hmac.new(_as_bytes(secret), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(got, expected)
    except Exception:  # noqa: BLE001 - a malformed input is a failed verification
        return False


def sign_webhook(secret: str | bytes, body: str | bytes, timestamp_ms: int) -> str:
    """Produce a signature header the way doDomain does.

    Provided for building test fixtures against your own handler; you never need
    it to receive webhooks.
    """
    payload = f"{int(timestamp_ms)}.".encode() + _as_bytes(body)
    digest = hmac.new(_as_bytes(secret), payload, hashlib.sha256).hexdigest()
    return f"t={int(timestamp_ms)},v1={digest}"
