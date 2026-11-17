"""Keyless start: the proof of work an anonymous ``POST /api/v1/keyless/sessions``
must carry, solved on this machine.

The API answers a first call without a key ``428 KEYLESS_PROOF_REQUIRED`` with a
challenge: find a decimal nonce such that SHA-256 over the UTF-8 bytes of
``<challenge>:<nonce>`` starts with ``difficultyBits`` zero bits, then send the
same request again with the header ``DoDomain-Keyless-Proof:
<challenge>:<nonce>``. The server asks for 20 bits normally, 22 when busy and
never more than 24 (``apps/web/src/lib/keyless-proof.ts`` in the app repo),
which is about 1 to 30 seconds on one core. The search runs in slices: between
two slices it checks the deadline and the abort event, and the async solver
yields to the event loop, so a search can always be stopped and never blocks an
event loop for more than a few milliseconds.

The Python twin of ``packages/node/src/keyless.ts`` (``@dodomain/node`` 0.9.x).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import DoDomainKeylessError

__all__ = [
    "KEYLESS_MAX_DIFFICULTY_BITS",
    "KEYLESS_PROOF_DEFAULT_TIMEOUT",
    "KEYLESS_PROOF_MAX_TIMEOUT",
    "AbortEvent",
    "async_solve_keyless_proof",
    "solve_keyless_proof",
]

#: The hardest proof the API ever asks for. A challenge above it is refused here
#: rather than searched for minutes.
KEYLESS_MAX_DIFFICULTY_BITS = 24

#: How long a solve may take by default, in seconds: past the worst case at 24
#: bits on a slow core, inside the challenge's 5-minute life.
KEYLESS_PROOF_DEFAULT_TIMEOUT = 120.0

#: The longest ``proof_timeout`` a client accepts, in seconds: a challenge lives 5
#: minutes, so a proof found later is refused as expired anyway.
KEYLESS_PROOF_MAX_TIMEOUT = 300.0

#: Hashes per slice between two deadline/abort checks (and, async, two yields).
_SLICE = 4096


class AbortEvent(Protocol):
    """Anything with ``is_set()``: a :class:`threading.Event` or an
    :class:`asyncio.Event`. Set it to stop a proof-of-work search."""

    def is_set(self) -> bool: ...


def _unsupported(message: str) -> DoDomainKeylessError:
    return DoDomainKeylessError("KEYLESS_PROOF_UNSUPPORTED", status_code=0, message=message)


def _aborted(message: str = "The proof-of-work search was aborted.") -> DoDomainKeylessError:
    return DoDomainKeylessError("KEYLESS_PROOF_ABORTED", status_code=0, message=message)


def _timed_out(timeout: float, difficulty_bits: int) -> DoDomainKeylessError:
    return DoDomainKeylessError(
        "KEYLESS_PROOF_TIMEOUT",
        status_code=0,
        message=(
            f"No proof found within {timeout:g} s at {difficulty_bits} bits. Retry later, "
            "or create a free account and use an API key."
        ),
    )


def _check(challenge: Any, difficulty_bits: Any) -> None:
    if not isinstance(challenge, str) or challenge == "":
        raise _unsupported("The challenge is empty.")
    if (
        isinstance(difficulty_bits, bool)
        or not isinstance(difficulty_bits, int)
        or difficulty_bits < 0
        or difficulty_bits > KEYLESS_MAX_DIFFICULTY_BITS
    ):
        raise _unsupported(
            f"difficulty_bits must be a whole number from 0 to {KEYLESS_MAX_DIFFICULTY_BITS}, "
            f"got {difficulty_bits!r}."
        )


def _search_slice(prefix: bytes, start: int, difficulty_bits: int) -> int | None:
    """The first nonce in ``[start, start + _SLICE)`` whose digest starts with
    ``difficulty_bits`` zero bits (1 to 24), or ``None``."""
    shift = 32 - difficulty_bits
    sha256 = hashlib.sha256
    from_bytes = int.from_bytes
    for nonce in range(start, start + _SLICE):
        digest = sha256(prefix + str(nonce).encode("ascii")).digest()
        if from_bytes(digest[:4], "big") >> shift == 0:
            return nonce
    return None


def solve_keyless_proof(
    challenge: str,
    difficulty_bits: int,
    *,
    timeout: float = KEYLESS_PROOF_DEFAULT_TIMEOUT,
    abort: AbortEvent | None = None,
) -> str:
    """Solve one keyless proof-of-work challenge, blocking this thread.

    Returns the FULL header value, ``<challenge>:<nonce>``, for the smallest
    nonce that works. Raises :class:`~dodomain.errors.DoDomainKeylessError`
    (``status_code == 0``): ``KEYLESS_PROOF_UNSUPPORTED`` for an empty challenge
    or a difficulty outside 0 to 24, ``KEYLESS_PROOF_ABORTED`` once ``abort`` is
    set, ``KEYLESS_PROOF_TIMEOUT`` past ``timeout`` seconds.
    """
    _check(challenge, difficulty_bits)
    prefix = f"{challenge}:"
    if difficulty_bits == 0:
        return f"{prefix}0"
    encoded = prefix.encode("utf-8")
    deadline = time.monotonic() + timeout
    nonce = 0
    while True:
        if abort is not None and abort.is_set():
            raise _aborted()
        if time.monotonic() > deadline:
            raise _timed_out(timeout, difficulty_bits)
        found = _search_slice(encoded, nonce, difficulty_bits)
        if found is not None:
            return f"{prefix}{found}"
        nonce += _SLICE


async def async_solve_keyless_proof(
    challenge: str,
    difficulty_bits: int,
    *,
    timeout: float = KEYLESS_PROOF_DEFAULT_TIMEOUT,
    abort: AbortEvent | None = None,
) -> str:
    """:func:`solve_keyless_proof` for an event loop: it yields between slices, so
    other tasks keep running, and cancelling the awaiting task stops the search
    too. Same result, same errors."""
    _check(challenge, difficulty_bits)
    prefix = f"{challenge}:"
    if difficulty_bits == 0:
        return f"{prefix}0"
    encoded = prefix.encode("utf-8")
    deadline = time.monotonic() + timeout
    nonce = 0
    while True:
        if abort is not None and abort.is_set():
            raise _aborted()
        if time.monotonic() > deadline:
            raise _timed_out(timeout, difficulty_bits)
        found = _search_slice(encoded, nonce, difficulty_bits)
        if found is not None:
            return f"{prefix}{found}"
        nonce += _SLICE
        await asyncio.sleep(0)


@dataclass(frozen=True, slots=True)
class ProofChallenge:
    """The fields of a ``428 KEYLESS_PROOF_REQUIRED`` answer the solver needs."""

    challenge: str
    difficulty_bits: int
    #: The request header the proof goes in (``DoDomain-Keyless-Proof``).
    header: str


def read_proof_challenge(error: DoDomainKeylessError) -> ProofChallenge:
    """Read the challenge out of a 428's ``details``, or re-raise the error
    unchanged when it does not carry one the solver can use."""
    details = error.details if isinstance(error.details, dict) else {}
    challenge = details.get("challenge")
    difficulty_bits = details.get("difficultyBits")
    header = details.get("header")
    algorithm = details.get("algorithm")
    if (
        not isinstance(challenge, str)
        or isinstance(difficulty_bits, bool)
        or not isinstance(difficulty_bits, int)
        or not isinstance(header, str)
        or header == ""
        or (algorithm is not None and algorithm != "sha256")
    ):
        raise error
    return ProofChallenge(challenge=challenge, difficulty_bits=difficulty_bits, header=header)


#: A keyless start solves at most this many proofs: the first challenge, and one
#: fresh one when the proved retry is refused as too easy or expired.
KEYLESS_MAX_SOLVES = 2


def is_retryable_proof_refusal(error: BaseException) -> bool:
    """A proved retry the API refused because the proof went stale, not because
    it was wrong: worth exactly one fresh solve."""
    if not isinstance(error, DoDomainKeylessError) or error.code != "KEYLESS_PROOF_REQUIRED":
        return False
    details = error.details if isinstance(error.details, dict) else {}
    return details.get("reason") in ("proof_too_easy", "proof_expired")
