"""Keyless start: ``client.keyless`` and the keyless arm of ``sessions.create``.

A keyless client (``DoDomain(keyless=True)``) has no account and no key. Its
first ``sessions.create`` calls ``POST /api/v1/keyless/sessions`` with no key,
gets the API's ``428`` proof-of-work challenge, solves it, and sends the same
request again with the proof. If that retry is refused because the network now
needs a harder proof or the challenge expired while solving, it solves the fresh
challenge once more, never more. The client then keeps the returned ``dd_ks_``
key, so later calls need no proof. The Python twin of the keyless arm of
``@dodomain/node`` 0.9.x (``createKeylessSession`` in ``packages/node/src/index.ts``).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from dodomain._transport import RequestSpec
from dodomain.errors import DoDomainKeylessError
from dodomain.keyless import (
    KEYLESS_MAX_SOLVES,
    AbortEvent,
    async_solve_keyless_proof,
    is_retryable_proof_refusal,
    read_proof_challenge,
    solve_keyless_proof,
)
from dodomain.models import ConnectSessionSummary, KeylessStatus

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain, _BaseClient

__all__ = ["AsyncKeyless", "Keyless"]

KEYLESS_SESSIONS_PATH = "/api/v1/keyless/sessions"
KEYLESS_STATUS_PATH = "/api/v1/keyless"

#: How often a create waiting on another create's keyless start checks again.
_WAIT_POLL_SECONDS = 0.01


def _key_missing(client: _BaseClient) -> DoDomainKeylessError:
    return DoDomainKeylessError(
        "KEYLESS_KEY_MISSING",
        status_code=0,
        message=(
            "This keyless client has no dd_ks_ key yet: create a session first, or pass "
            "keyless_key."
            if client.is_keyless
            else "keyless.status() reads a keyless app; this client uses a secret key."
        ),
    )


def _wait_aborted() -> DoDomainKeylessError:
    return DoDomainKeylessError(
        "KEYLESS_PROOF_ABORTED",
        status_code=0,
        message="Aborted while waiting for another call's keyless start.",
    )


def _spec(
    body: dict[str, object],
    *,
    credential: str | None,
    proof: tuple[str, str] | None,
    idempotency_key: str | None,
) -> RequestSpec:
    return RequestSpec(
        "POST",
        KEYLESS_SESSIONS_PATH,
        json_body=body,
        auth=credential is not None,
        credential=credential,
        headers=(proof,) if proof is not None else (),
        idempotency_key=idempotency_key,
    )


def _accept(client: _BaseClient, payload: Any) -> ConnectSessionSummary:
    session = ConnectSessionSummary._from_keyless_api(payload, base_url=client.base_url)
    if session.keyless is not None and session.keyless.key is not None:
        client._keyless_key = session.keyless.key
    return session


# ── sync ────────────────────────────────────────────────────────────────────


def create_keyless_session(
    client: DoDomain,
    body: dict[str, object],
    *,
    abort: AbortEvent | None,
    idempotency_key: str | None,
) -> ConnectSessionSummary:
    """The keyless arm of :meth:`Sessions.create`."""
    lock = client._keyless_start_lock
    # A fresh client with a start already in flight (another thread) waits for
    # it, so N concurrent creates start ONE keyless app, then reuse its key. The
    # wait honours this call's own abort event.
    while not lock.acquire(timeout=_WAIT_POLL_SECONDS):
        if abort is not None and abort.is_set():
            raise _wait_aborted()
    try:
        key = client._keyless_key
        if key is None:
            return _start_keyless_app(client, body, abort, idempotency_key)
    finally:
        lock.release()
    return _accept(
        client,
        client.request(_spec(body, credential=key, proof=None, idempotency_key=idempotency_key)),
    )


def _start_keyless_app(
    client: DoDomain,
    body: dict[str, object],
    abort: AbortEvent | None,
    idempotency_key: str | None,
) -> ConnectSessionSummary:
    """An anonymous start: the 428 challenge, the solve, the retry with the
    proof, and at most ONE more solve when that retry is refused as
    ``proof_too_easy`` or ``proof_expired``."""
    try:
        return _accept(
            client,
            client.request(
                _spec(body, credential=None, proof=None, idempotency_key=idempotency_key)
            ),
        )
    except DoDomainKeylessError as error:
        if error.code != "KEYLESS_PROOF_REQUIRED":
            raise
        refusal = error
    solves = 1
    while True:
        challenge = read_proof_challenge(refusal)
        proof = solve_keyless_proof(
            challenge.challenge,
            challenge.difficulty_bits,
            timeout=client._proof_timeout,
            abort=abort,
        )
        try:
            return _accept(
                client,
                client.request(
                    _spec(
                        body,
                        credential=None,
                        proof=(challenge.header, proof),
                        idempotency_key=idempotency_key,
                    )
                ),
            )
        except DoDomainKeylessError as error:
            # Anything else, or a third 428, propagates: retrying forever would
            # hide a network that is being throttled or a proof that never holds.
            if solves >= KEYLESS_MAX_SOLVES or not is_retryable_proof_refusal(error):
                raise
            refusal = error
        solves += 1


class Keyless:
    """``client.keyless``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def status(self) -> KeylessStatus:
        """``GET /api/v1/keyless``: the keyless app's allowance and claim link.

        Keyless mode only, and only once the client holds a ``dd_ks_`` key (after
        the first ``sessions.create``, or from ``keyless_key``).

        Raises:
            DoDomainKeylessError: ``KEYLESS_KEY_MISSING`` (``status_code == 0``,
                no request sent) before the client holds a key.
        """
        key = self._client._keyless_key
        if key is None:
            raise _key_missing(self._client)
        return KeylessStatus._from_api(
            self._client.request(RequestSpec("GET", KEYLESS_STATUS_PATH, credential=key))
        )


# ── async ───────────────────────────────────────────────────────────────────


async def async_create_keyless_session(
    client: AsyncDoDomain,
    body: dict[str, object],
    *,
    abort: AbortEvent | None,
    idempotency_key: str | None,
) -> ConnectSessionSummary:
    """The keyless arm of :meth:`AsyncSessions.create`. One event loop runs one
    task at a time, so a plain flag is the start's lock."""
    while client._keyless_key is None and client._keyless_starting:
        if abort is not None and abort.is_set():
            raise _wait_aborted()
        await asyncio.sleep(_WAIT_POLL_SECONDS)
    key = client._keyless_key
    if key is not None:
        return _accept(
            client,
            await client.request(
                _spec(body, credential=key, proof=None, idempotency_key=idempotency_key)
            ),
        )
    client._keyless_starting = True
    try:
        return await _async_start_keyless_app(client, body, abort, idempotency_key)
    finally:
        client._keyless_starting = False


async def _async_start_keyless_app(
    client: AsyncDoDomain,
    body: dict[str, object],
    abort: AbortEvent | None,
    idempotency_key: str | None,
) -> ConnectSessionSummary:
    """See :func:`_start_keyless_app`."""
    try:
        return _accept(
            client,
            await client.request(
                _spec(body, credential=None, proof=None, idempotency_key=idempotency_key)
            ),
        )
    except DoDomainKeylessError as error:
        if error.code != "KEYLESS_PROOF_REQUIRED":
            raise
        refusal = error
    solves = 1
    while True:
        challenge = read_proof_challenge(refusal)
        proof = await async_solve_keyless_proof(
            challenge.challenge,
            challenge.difficulty_bits,
            timeout=client._proof_timeout,
            abort=abort,
        )
        try:
            return _accept(
                client,
                await client.request(
                    _spec(
                        body,
                        credential=None,
                        proof=(challenge.header, proof),
                        idempotency_key=idempotency_key,
                    )
                ),
            )
        except DoDomainKeylessError as error:
            if solves >= KEYLESS_MAX_SOLVES or not is_retryable_proof_refusal(error):
                raise
            refusal = error
        solves += 1


class AsyncKeyless:
    """``client.keyless`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def status(self) -> KeylessStatus:
        """The keyless app's allowance and claim link. See :meth:`Keyless.status`."""
        key = self._client._keyless_key
        if key is None:
            raise _key_missing(self._client)
        return KeylessStatus._from_api(
            await self._client.request(RequestSpec("GET", KEYLESS_STATUS_PATH, credential=key))
        )
