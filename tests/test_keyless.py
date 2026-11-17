"""Keyless mode (0.7.0, parity with ``@dodomain/node`` 0.9.x, T-18036).

The proof-of-work solver against known vectors, and the 428-then-200 flow against
a SCRIPTED STAND-IN for the API. Every fake below is named for what it is and
says so in a comment; nothing here reaches the network. Ported case by case from
``packages/node/test/keyless.test.ts`` in the app repo.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import traceback
import typing
from typing import Any

import httpx
import pytest
import respx

from dodomain import (
    KEYLESS_MAX_DIFFICULTY_BITS,
    AsyncDoDomain,
    DnsRecord,
    DoDomain,
    DoDomainAPIError,
    DoDomainConfigError,
    DoDomainError,
    DoDomainKeylessError,
    InvalidRequestError,
    InvalidResponseError,
    KeylessErrorCode,
    async_solve_keyless_proof,
    solve_keyless_proof,
)
from dodomain.errors import API_KEYLESS_CODES, SDK_KEYLESS_CODES, redact_keyless_keys
from tests.helpers import BASE_URL, TEST_KEY, api

# Known vectors, computed independently of this SDK:
#   next(n for n in itertools.count()
#        if int.from_bytes(sha256(f"{c}:{n}".encode()).digest(), "big") >> (256 - d) == 0)
# The SAME three vectors @dodomain/node's suite pins, so both SDKs agree.
VECTORS = [
    ("ARQAAAGa-test-vector", 8, 309),
    ("ARQAAAGa-test-vector", 12, 1996),
    ("dodomain-known-vector", 16, 64049),
]


def proof_holds(header_value: str, bits: int) -> bool:
    """An independent check of a proof: the leading bits of the FULL digest."""
    digest = hashlib.sha256(header_value.encode("utf-8")).digest()
    return int.from_bytes(digest, "big") >> (256 - bits) == 0


@pytest.mark.parametrize(("challenge", "bits", "nonce"), VECTORS)
def test_the_solver_finds_the_smallest_nonce_for_a_known_vector(
    challenge: str, bits: int, nonce: int
) -> None:
    proof = solve_keyless_proof(challenge, bits)
    assert proof == f"{challenge}:{nonce}"
    assert proof_holds(proof, bits)


@pytest.mark.parametrize(("challenge", "bits", "nonce"), VECTORS)
async def test_the_async_solver_finds_the_same_smallest_nonce(
    challenge: str, bits: int, nonce: int
) -> None:
    assert await async_solve_keyless_proof(challenge, bits) == f"{challenge}:{nonce}"


@pytest.mark.parametrize("bits", [25, -1, 1.5, float("nan"), True, "20"])
def test_the_solver_refuses_a_difficulty_outside_0_to_24(bits: Any) -> None:
    with pytest.raises(DoDomainKeylessError) as excinfo:
        solve_keyless_proof("c", bits)
    assert excinfo.value.code == "KEYLESS_PROOF_UNSUPPORTED"
    assert excinfo.value.status_code == 0


def test_the_solver_answers_nonce_0_at_zero_bits_and_refuses_an_empty_challenge() -> None:
    assert solve_keyless_proof("anything", 0) == "anything:0"
    assert KEYLESS_MAX_DIFFICULTY_BITS == 24
    with pytest.raises(DoDomainKeylessError) as excinfo:
        solve_keyless_proof("", 8)
    assert excinfo.value.code == "KEYLESS_PROOF_UNSUPPORTED"


# "dodomain-slow-vector" has no 24-bit answer below nonce 200 000, so both
# searches are still running when the abort or the deadline lands.
SLOW = "dodomain-slow-vector"


def test_an_aborted_solve_raises_aborted_and_a_slow_one_times_out() -> None:
    abort = threading.Event()
    threading.Timer(0.005, abort.set).start()
    with pytest.raises(DoDomainKeylessError) as aborted:
        solve_keyless_proof(SLOW, 24, abort=abort)
    assert aborted.value.code == "KEYLESS_PROOF_ABORTED"
    assert aborted.value.status_code == 0

    with pytest.raises(DoDomainKeylessError) as timed_out:
        solve_keyless_proof(SLOW, 24, timeout=0.02)
    assert timed_out.value.code == "KEYLESS_PROOF_TIMEOUT"
    assert "No proof found within 0.02 s at 24 bits" in timed_out.value.message


async def test_the_async_solver_honours_its_abort_event_its_timeout_and_cancellation() -> None:
    abort = asyncio.Event()
    asyncio.get_running_loop().call_later(0.005, abort.set)
    with pytest.raises(DoDomainKeylessError) as aborted:
        await async_solve_keyless_proof(SLOW, 24, abort=abort)
    assert aborted.value.code == "KEYLESS_PROOF_ABORTED"

    with pytest.raises(DoDomainKeylessError) as timed_out:
        await async_solve_keyless_proof(SLOW, 24, timeout=0.02)
    assert timed_out.value.code == "KEYLESS_PROOF_TIMEOUT"

    # It yields between slices, so the loop stays live and a cancel lands.
    task = asyncio.ensure_future(async_solve_keyless_proof(SLOW, 24))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ── the flow, against a scripted stand-in for the API ─────────────────────────

RECORDS = [DnsRecord(type="CNAME", host="app", value="edge.example.com")]
INPUT_WIRE = {
    "domain": "acme.com",
    "records": [{"type": "CNAME", "host": "app", "value": "edge.example.com"}],
}
KEY = "dd_ks_scripted_key"
CHALLENGE = "ARQAAAGa-test-vector"
BITS = 8
SESSIONS_URL = api("/api/v1/keyless/sessions")
STATUS_URL = api("/api/v1/keyless")


def proof_required(challenge: str = CHALLENGE, reason: str = "proof_missing") -> httpx.Response:
    return httpx.Response(
        428,
        headers={"content-type": "application/problem+json"},
        json={
            "type": "about:blank",
            "status": 428,
            "error": "proof_required",
            "code": "KEYLESS_PROOF_REQUIRED",
            "message": "Starting a keyless app without a key needs a small proof of work.",
            "details": {
                "reason": reason,
                "challenge": challenge,
                "algorithm": "sha256",
                "difficultyBits": BITS,
                "expiresAt": "2026-11-17T09:05:00.000Z",
                "header": "DoDomain-Keyless-Proof",
                "signUpUrl": "https://app.dodomain.io/signin?mode=signup",
            },
        },
    )


def keyless_session(with_key: bool, used: int = 0) -> httpx.Response:
    block: dict[str, Any] = {
        "appId": "app_keyless_1",
        "allowance": {"limit": 10, "used": used, "open": 1, "remaining": 9 - used},
        "claimUrl": f"https://app.dodomain.io/claim/keyless#{KEY}",
        "unlock": "Create a free account and claim this app for 50 verified connections a month.",
        "docs": "https://dodomain.io/docs/getting-started#keyless-start",
    }
    if with_key:
        block["key"] = KEY
    return httpx.Response(
        200,
        json={
            "id": "sess_1",
            "token": "dd_sess_abc",
            "expiresAt": "2026-11-17T09:00:00.000Z",
            "connectUrl": "https://app.dodomain.io/connect/dd_sess_abc",
            "records": [{"type": "CNAME", "host": "app", "fqdn": "app.acme.com"}],
            "mode": "live",
            "keyless": block,
        },
    )


class ScriptedKeylessApi:
    """MOCK API: a scripted stand-in for the keyless routes. It answers a call
    with no key 428 (or 200 once it carries a proof that really holds), and a call
    with the scripted dd_ks_ key 200, recording every request it saw."""

    def __init__(self, on_proof: typing.Callable[[str], httpx.Response] | None = None) -> None:
        self.seen: list[httpx.Request] = []
        self.on_proof = on_proof
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.seen.append(request)
        auth = request.headers.get("authorization")
        if request.url == STATUS_URL and auth == f"Bearer {KEY}":
            return httpx.Response(
                200,
                json={
                    "appId": "app_keyless_1",
                    "allowance": {"limit": 10, "used": 1, "open": 0, "remaining": 9},
                    "claimUrl": f"https://app.dodomain.io/claim/keyless#{KEY}",
                    "unlock": "Create a free account and claim this app.",
                    "docs": "https://dodomain.io/docs/getting-started#keyless-start",
                    "createdAt": "2026-11-16T09:00:00.000Z",
                    "lastUsedAt": None,
                },
            )
        if auth == f"Bearer {KEY}":
            return keyless_session(False, 1)
        proof = request.headers.get("dodomain-keyless-proof")
        if proof is None:
            return proof_required()
        if self.on_proof is not None:
            return self.on_proof(proof)
        if proof_holds(proof, BITS) and proof.startswith(f"{CHALLENGE}:"):
            return keyless_session(True)
        return proof_required("ARQAAAGa-fresh-challenge")

    def anonymous(self) -> list[httpx.Request]:
        return [r for r in self.seen if "authorization" not in r.headers]


def keyless_client(**kwargs: Any) -> DoDomain:
    kwargs.setdefault("http_client", httpx.Client())
    return DoDomain(keyless=True, **kwargs)


def async_keyless_client(**kwargs: Any) -> AsyncDoDomain:
    kwargs.setdefault("http_client", httpx.AsyncClient())
    return AsyncDoDomain(keyless=True, **kwargs)


def mock_keyless_routes(router: respx.MockRouter, side_effect: Any) -> None:
    router.post(SESSIONS_URL).mock(side_effect=side_effect)
    router.get(STATUS_URL).mock(side_effect=side_effect)


def test_a_keyless_client_solves_the_428_keeps_the_key_and_needs_no_proof_after() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = keyless_client()
        assert client.keyless_key is None
        assert client.is_keyless is True

        first = client.sessions.create(domain="acme.com", records=RECORDS)
        assert first.connect_url == "https://app.dodomain.io/connect/dd_sess_abc"
        assert first.mode == "live"
        assert first.keyless is not None
        assert first.keyless.claim_url == f"https://app.dodomain.io/claim/keyless#{KEY}"
        assert first.keyless.allowance.remaining == 9
        assert first.keyless.key == KEY
        assert client.keyless_key == KEY

        assert len(scripted.seen) == 2
        challenged, proved = scripted.seen
        assert challenged.url == SESSIONS_URL
        assert "authorization" not in challenged.headers
        assert proved.headers["dodomain-keyless-proof"] == f"{CHALLENGE}:309"
        assert json.loads(proved.content) == INPUT_WIRE

        second = client.sessions.create(domain="acme.com", records=RECORDS)
        assert second.keyless is not None and second.keyless.key is None
        assert len(scripted.seen) == 3
        assert scripted.seen[2].headers["authorization"] == f"Bearer {KEY}"
        assert "dodomain-keyless-proof" not in scripted.seen[2].headers

        status = client.keyless.status()
        assert status.allowance.remaining == 9
        assert status.last_used_at is None
        assert scripted.seen[3].method == "GET"
        assert scripted.seen[3].url == STATUS_URL


async def test_the_async_client_runs_the_same_keyless_flow() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = async_keyless_client()
        first = await client.sessions.create(domain="acme.com", records=RECORDS)
        assert first.keyless is not None and first.keyless.key == KEY
        assert client.keyless_key == KEY
        assert scripted.seen[1].headers["dodomain-keyless-proof"] == f"{CHALLENGE}:309"
        await client.sessions.create(domain="acme.com", records=RECORDS)
        assert scripted.seen[2].headers["authorization"] == f"Bearer {KEY}"
        assert (await client.keyless.status()).allowance.limit == 10
        assert len(scripted.seen) == 4


def test_concurrent_creates_on_a_fresh_keyless_client_start_one_keyless_app() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = keyless_client()
        errors: list[BaseException] = []

        def create() -> None:
            try:
                client.sessions.create(domain="acme.com", records=RECORDS)
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=create) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert errors == []
        assert len(scripted.anonymous()) == 2, "one 428 and one proved retry, not three starts"
        assert len(scripted.seen) == 4


async def test_concurrent_async_creates_on_a_fresh_keyless_client_start_one_keyless_app() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = async_keyless_client()
        await asyncio.gather(
            *(client.sessions.create(domain="acme.com", records=RECORDS) for _ in range(3))
        )
        assert len(scripted.anonymous()) == 2
        assert len(scripted.seen) == 4


def test_a_428_refusing_the_proof_as_invalid_is_raised_with_no_third_attempt() -> None:
    scripted = ScriptedKeylessApi(
        on_proof=lambda _: proof_required("ARQAAAGa-harder", "proof_invalid")
    )
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = keyless_client()
        with pytest.raises(DoDomainKeylessError) as excinfo:
            client.sessions.create(domain="acme.com", records=RECORDS)
    error = excinfo.value
    assert isinstance(error, DoDomainError), "still a DoDomainError for existing except blocks"
    assert isinstance(error, DoDomainAPIError)
    assert error.code == "KEYLESS_PROOF_REQUIRED"
    assert error.error == "proof_required"
    assert error.status_code == 428
    assert error.details["challenge"] == "ARQAAAGa-harder"
    assert len(scripted.seen) == 2
    assert client.keyless_key is None


@pytest.mark.parametrize("reason", ["proof_too_easy", "proof_expired"])
def test_a_retry_refused_as_stale_solves_the_fresh_challenge_once_more(reason: str) -> None:
    fresh = "ARQAAAGa-fresh-challenge"
    scripted = ScriptedKeylessApi(
        on_proof=lambda proof: (
            keyless_session(True)
            if proof.startswith(f"{fresh}:") and proof_holds(proof, BITS)
            else proof_required(fresh, reason)
        )
    )
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = keyless_client()
        session = client.sessions.create(domain="acme.com", records=RECORDS)
    assert session.connect_url == "https://app.dodomain.io/connect/dd_sess_abc"
    assert len(scripted.seen) == 3, "the 428, the first proof, the fresh proof"
    assert scripted.seen[1].headers["dodomain-keyless-proof"].startswith(f"{CHALLENGE}:")
    assert scripted.seen[2].headers["dodomain-keyless-proof"].startswith(f"{fresh}:")
    assert client.keyless_key == KEY


def test_a_second_stale_proof_refusal_propagates_after_at_most_two_solves() -> None:
    counter = iter(range(1, 10))
    scripted = ScriptedKeylessApi(
        on_proof=lambda _: proof_required(f"ARQAAAGa-fresh-{next(counter)}", "proof_too_easy")
    )
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        with pytest.raises(DoDomainKeylessError) as excinfo:
            keyless_client().sessions.create(domain="acme.com", records=RECORDS)
    assert excinfo.value.code == "KEYLESS_PROOF_REQUIRED"
    assert excinfo.value.details["challenge"] == "ARQAAAGa-fresh-2"
    assert len(scripted.seen) == 3


@respx.mock
def test_a_spent_allowance_surfaces_as_a_typed_keyless_limit_reached_with_the_unlock_details() -> (
    None
):
    # MOCK API: answers every call with the API's 402 allowance refusal.
    respx.post(SESSIONS_URL).mock(
        return_value=httpx.Response(
            402,
            json={
                "error": "quota_exceeded",
                "code": "KEYLESS_LIMIT_REACHED",
                "message": "This keyless app used its 10 verified connections.",
                "details": {
                    "reason": "keyless_limit_reached",
                    "scope": "app",
                    "limit": 10,
                    "unlock": {
                        "action": "claim_and_create_api_key",
                        "claimUrl": "https://app.dodomain.io/claim/keyless",
                    },
                },
            },
        )
    )
    with pytest.raises(DoDomainKeylessError) as excinfo:
        keyless_client(keyless_key=KEY).sessions.create(domain="acme.com", records=RECORDS)
    error = excinfo.value
    assert error.code == "KEYLESS_LIMIT_REACHED"
    assert error.message == "quota_exceeded: This keyless app used its 10 verified connections."
    assert error.error == "quota_exceeded"
    assert error.status_code == 402
    assert error.details["limit"] == 10
    assert error.retry_at is None, "a spent lifetime allowance has no retry moment"


def test_a_keyless_client_refuses_secret_key_calls_app_id_and_early_status_locally() -> None:
    calls: list[httpx.Request] = []

    def fake_api_that_must_not_be_called(request: httpx.Request) -> httpx.Response:
        # MOCK API: records calls; any call at all fails this test.
        calls.append(request)
        return httpx.Response(200, json={})

    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=fake_api_that_must_not_be_called)
        client = keyless_client()
        with pytest.raises(DoDomainKeylessError) as mode:
            client.apps.list()
        assert mode.value.code == "KEYLESS_MODE"
        assert mode.value.status_code == 0
        assert "GET /api/v1/apps needs a secret key" in mode.value.message

        with pytest.raises(InvalidRequestError) as app_id:
            client.sessions.create(domain="acme.com", records=RECORDS, app_id="app_1")
        assert app_id.value.status_code == 0

        with pytest.raises(DoDomainKeylessError) as missing:
            client.keyless.status()
        assert missing.value.code == "KEYLESS_KEY_MISSING"
        assert missing.value.status_code == 0

        with pytest.raises(DoDomainKeylessError) as secret_key_client:
            DoDomain(secret_key=TEST_KEY, http_client=httpx.Client()).keyless.status()
        assert secret_key_client.value.code == "KEYLESS_KEY_MISSING"
    assert calls == []


@respx.mock
def test_a_keyless_client_may_still_call_the_token_public_session_routes() -> None:
    from tests.helpers import PUBLIC_SESSION_RESPONSE

    route = respx.get(api("/api/v1/sessions/dd_sess_abc")).mock(
        return_value=httpx.Response(200, json=PUBLIC_SESSION_RESPONSE)
    )
    keyless_client().sessions.retrieve("dd_sess_abc")
    assert "authorization" not in route.calls.last.request.headers


def test_keyless_mode_is_an_explicit_opt_in_and_the_two_modes_cannot_be_mixed() -> None:
    with pytest.raises(DoDomainConfigError) as missing:
        DoDomain()
    assert "DoDomain(keyless=True)" in str(missing.value)
    with pytest.raises(DoDomainConfigError):
        DoDomain(secret_key=None)
    with pytest.raises(DoDomainConfigError):
        DoDomain(keyless=True, secret_key="dd_sk_x")
    with pytest.raises(DoDomainConfigError):
        DoDomain(keyless=True, keyless_key="dd_sk_not_keyless")
    with pytest.raises(DoDomainConfigError):
        DoDomain(secret_key=TEST_KEY, keyless_key=KEY)
    assert DoDomain(keyless=True, keyless_key=KEY).keyless_key == KEY
    assert AsyncDoDomain(keyless=True, keyless_key=KEY).keyless_key == KEY
    assert DoDomain(secret_key=TEST_KEY).is_keyless is False


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), 300.001, True, "60"])
def test_proof_timeout_must_be_a_finite_number_of_seconds_above_0_and_at_most_5_minutes(
    bad: Any,
) -> None:
    with pytest.raises(DoDomainConfigError) as excinfo:
        DoDomain(keyless=True, proof_timeout=bad)
    assert "proof_timeout must be a number of seconds above 0 and at most 300" in str(excinfo.value)


def test_proof_timeout_accepts_the_bounds() -> None:
    DoDomain(keyless=True, proof_timeout=300)
    DoDomain(keyless=True, proof_timeout=0.001)


def test_a_keyless_create_sends_its_trimmed_app_name_and_a_secret_key_client_refuses_one() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        keyless_client().sessions.create(
            domain="acme.com", records=RECORDS, app_name="  Acme Sites  "
        )
        assert json.loads(scripted.seen[1].content) == {**INPUT_WIRE, "appName": "Acme Sites"}

        for bad in ["   ", "x" * 61]:
            with pytest.raises(InvalidRequestError):
                keyless_client().sessions.create(domain="acme.com", records=RECORDS, app_name=bad)

        seen_before = len(scripted.seen)
        keyed = DoDomain(secret_key=TEST_KEY, http_client=httpx.Client())
        with pytest.raises(InvalidRequestError) as excinfo:
            keyed.sessions.create(domain="acme.com", records=RECORDS, app_name="Acme Sites")
        assert excinfo.value.status_code == 0
        assert len(scripted.seen) == seen_before


def test_an_error_never_carries_a_whole_dd_ks_key() -> None:
    secret = "dd_ks_live_secret_part_9f8e7d"
    with respx.mock(assert_all_called=False) as router:
        # MOCK API: a 402 whose error, message, claimUrl and nested strings all
        # echo the key, with a request id header so __str__ prints everything.
        router.post(SESSIONS_URL).mock(
            return_value=httpx.Response(
                402,
                headers={"x-request-id": "req_1"},
                json={
                    "error": f"quota_exceeded for {secret}",
                    "code": "KEYLESS_LIMIT_REACHED",
                    "message": f"Claim {secret} to continue.",
                    "details": {
                        "limit": 10,
                        "unlock": {"claimUrl": f"https://app.dodomain.io/claim/keyless#{secret}"},
                        "seen": [secret],
                    },
                },
            )
        )
        client = keyless_client(keyless_key=secret)
        with pytest.raises(DoDomainKeylessError) as excinfo:
            client.sessions.create(domain="acme.com", records=RECORDS)
    refusal = excinfo.value
    assert refusal.code == "KEYLESS_LIMIT_REACHED"
    assert refusal.details["unlock"] == {
        "claimUrl": "https://app.dodomain.io/claim/keyless#dd_ks_…"
    }
    rendered = [
        str(refusal),
        repr(refusal),
        refusal.message,
        repr(refusal.details),
        repr(refusal.body),
        repr(refusal.args),
        "".join(traceback.format_exception(type(refusal), refusal, refusal.__traceback__)),
    ]
    for text in rendered:
        assert secret not in text, f"the key leaked: {text}"
    assert "dd_ks_…" in str(refusal), "the prefix stays, so the field is recognisable"

    with respx.mock(assert_all_called=False) as router:
        # MOCK API: a 200 that carries the key but not the session shape the SDK checks.
        router.post(SESSIONS_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "keyless": {
                        "key": secret,
                        "claimUrl": f"https://app.dodomain.io/claim/keyless#{secret}",
                    }
                },
            )
        )
        with pytest.raises(InvalidResponseError) as malformed:
            keyless_client(keyless_key=secret).sessions.create(domain="acme.com", records=RECORDS)
    for text in [str(malformed.value), repr(malformed.value.payload)]:
        assert secret not in text, f"the key leaked: {text}"


def test_a_successful_keyless_response_is_left_whole_and_its_repr_hides_the_credentials() -> None:
    scripted = ScriptedKeylessApi()
    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, scripted)
        client = keyless_client()
        session = client.sessions.create(domain="acme.com", records=RECORDS)
        status = client.keyless.status()
    assert session.keyless is not None
    assert session.keyless.key == KEY
    assert session.keyless.claim_url.endswith(f"#{KEY}")
    for text in (repr(session), repr(session.keyless), repr(status)):
        assert KEY not in text, f"repr shows a credential: {text}"


def test_redact_keyless_keys_walks_every_container_and_leaves_other_values_alone() -> None:
    value = {"a": ["dd_ks_abc-DEF_1", ("x dd_ks_q",)], "n": 3, "none": None}
    assert redact_keyless_keys(value) == {"a": ["dd_ks_…", ("x dd_ks_…",)], "n": 3, "none": None}


def test_a_create_waiting_on_another_threads_keyless_start_honours_its_own_abort_event() -> None:
    scripted = ScriptedKeylessApi()
    release = threading.Event()
    entered = threading.Event()

    def slow_start(request: httpx.Request) -> httpx.Response:
        # MOCK API: holds the very first (anonymous) call until the test releases it.
        if not scripted.seen:
            entered.set()
            release.wait(timeout=10)
        return scripted(request)

    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, slow_start)
        client = keyless_client()
        started: list[Any] = []
        starter = threading.Thread(
            target=lambda: started.append(
                client.sessions.create(domain="acme.com", records=RECORDS)
            )
        )
        starter.start()
        assert entered.wait(timeout=10)

        abort = threading.Event()
        abort.set()
        with pytest.raises(DoDomainKeylessError) as excinfo:
            client.sessions.create(domain="acme.com", records=RECORDS, abort=abort)
        assert excinfo.value.code == "KEYLESS_PROOF_ABORTED"

        release.set()
        starter.join(timeout=30)
    assert started[0].keyless.key == KEY, "the start the waiter left still finishes"
    assert len(scripted.seen) == 2, "the aborted waiter sent nothing"


async def test_an_async_create_waiting_on_another_tasks_start_honours_its_own_abort_event() -> None:
    scripted = ScriptedKeylessApi()
    release = asyncio.Event()

    async def slow_start(request: httpx.Request) -> httpx.Response:
        # MOCK API: holds the very first (anonymous) call until the test releases it.
        if not scripted.seen:
            scripted.seen.append(request)
            await release.wait()
            return proof_required()
        return scripted(request)

    with respx.mock(assert_all_called=False) as router:
        mock_keyless_routes(router, slow_start)
        client = async_keyless_client()
        starter = asyncio.ensure_future(client.sessions.create(domain="acme.com", records=RECORDS))
        await asyncio.sleep(0.02)

        abort = asyncio.Event()
        abort.set()
        with pytest.raises(DoDomainKeylessError) as excinfo:
            await client.sessions.create(domain="acme.com", records=RECORDS, abort=abort)
        assert excinfo.value.code == "KEYLESS_PROOF_ABORTED"

        release.set()
        started = await starter
    assert started.keyless is not None and started.keyless.key == KEY
    assert len(scripted.seen) == 2, "the aborted waiter sent nothing"


@respx.mock
def test_a_rate_limited_keyless_start_exposes_retry_after_and_retry_at_and_is_never_replayed() -> (
    None
):
    route = respx.post(SESSIONS_URL).mock(
        return_value=httpx.Response(
            429,
            headers={"content-type": "application/problem+json", "Retry-After": "42"},
            json={
                "error": "rate_limited",
                "code": "KEYLESS_START_RATE_LIMITED",
                "message": "Too many keyless calls without a key from this network.",
                "details": {"retryAt": "2026-11-17T10:00:42Z", "retryAfterSeconds": 42},
            },
        )
    )
    with pytest.raises(DoDomainKeylessError) as excinfo:
        keyless_client(max_retries=2).sessions.create(domain="acme.com", records=RECORDS)
    assert excinfo.value.code == "KEYLESS_START_RATE_LIMITED"
    assert excinfo.value.retry_after == 42.0
    assert excinfo.value.retry_at == "2026-11-17T10:00:42Z"
    assert route.call_count == 1, "a POST is never replayed"


# ── the code list, held to the API's ───────────────────────────────────────────

#: The keyless denial codes the API answers with: every "KEYLESS_*" literal under
#: apps/web/src in the dodomain app repo (KEYLESS_DENIAL_CODES in
#: apps/web/src/lib/api/keyless-errors.ts plus KEYLESS_LIMIT_REACHED in
#: apps/web/src/lib/plan-quota.ts). The app repo's scripts/check-keyless-bans.sh
#: rule 11 holds @dodomain/node's API_KEYLESS_CODES to that same set; this is the
#: Python twin. A separate repo cannot grep the API, so the list is pinned here:
#: when the API adds a code, add it here AND in dodomain.errors.API_KEYLESS_CODES,
#: or the API's new refusal reaches Python users as a plain DoDomainAPIError.
API_CODES_AS_OF_NODE_0_9_2 = {
    "KEYLESS_PROOF_REQUIRED",
    "KEYLESS_LIMIT_REACHED",
    "KEYLESS_START_RATE_LIMITED",
    "KEYLESS_CAPACITY_REACHED",
    "KEYLESS_KEY_CLAIMED",
    "KEYLESS_KEY_NOT_ACCEPTED",
    "KEYLESS_DISABLED",
    "KEYLESS_PLACEHOLDER_DOMAIN",
}

#: The five codes @dodomain/node 0.9.2 raises itself (status 0).
SDK_CODES_AS_OF_NODE_0_9_2 = {
    "KEYLESS_PROOF_TIMEOUT",
    "KEYLESS_PROOF_ABORTED",
    "KEYLESS_PROOF_UNSUPPORTED",
    "KEYLESS_KEY_MISSING",
    "KEYLESS_MODE",
}


def test_every_keyless_code_the_api_answers_with_is_a_typed_error() -> None:
    assert set(API_KEYLESS_CODES) == API_CODES_AS_OF_NODE_0_9_2
    assert set(SDK_KEYLESS_CODES) == SDK_CODES_AS_OF_NODE_0_9_2
    assert set(typing.get_args(KeylessErrorCode)) == (
        API_CODES_AS_OF_NODE_0_9_2 | SDK_CODES_AS_OF_NODE_0_9_2
    )


@pytest.mark.parametrize("code", sorted(API_CODES_AS_OF_NODE_0_9_2))
def test_each_api_keyless_code_maps_to_dodomain_keyless_error(code: str) -> None:
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/v1/keyless/sessions").mock(
            return_value=httpx.Response(400, json={"error": "invalid_request", "code": code})
        )
        with pytest.raises(DoDomainKeylessError) as excinfo:
            keyless_client(keyless_key=KEY).sessions.create(domain="acme.com", records=RECORDS)
    assert excinfo.value.code == code
