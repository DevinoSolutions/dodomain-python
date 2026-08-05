"""The retry policy, which is deliberately conservative.

The API has no server-side idempotency, so a replayed ``POST /v1/sessions``
would mint a second session and burn a second unit of plan quota. Only ``GET``
and ``DELETE`` are ever replayed.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from dodomain import (
    DoDomainConnectionError,
    InternalServerError,
    NotConfiguredError,
    QuotaExceededError,
    RateLimitError,
)
from dodomain._transport import RequestSpec, backoff_delay
from tests.helpers import api, make_async_client, make_client


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite fast without weakening what it asserts."""
    monkeypatch.setattr("dodomain._client.time.sleep", lambda _seconds: None)

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr("dodomain._client.asyncio.sleep", _instant)


@respx.mock
def test_a_get_is_retried_on_503_and_the_eventual_success_is_returned() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        side_effect=[
            httpx.Response(503, json={"error": "not_configured"}),
            httpx.Response(200, json={"apps": []}),
        ]
    )
    with make_client(max_retries=2) as client:
        assert client.request(RequestSpec("GET", "/api/v1/apps")) == {"apps": []}
    assert route.call_count == 2


@respx.mock
def test_a_delete_is_retried_because_disconnect_is_idempotent_server_side() -> None:
    route = respx.delete(api("/api/v1/connections/conn_1")).mock(
        side_effect=[
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(200, json={"id": "conn_1"}),
        ]
    )
    with make_client(max_retries=2) as client:
        client.request(RequestSpec("DELETE", "/api/v1/connections/conn_1"))
    assert route.call_count == 2


@respx.mock
def test_a_failing_post_issues_exactly_one_request() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    with pytest.raises(InternalServerError), make_client(max_retries=5) as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert route.call_count == 1


@respx.mock
def test_a_rate_limited_post_is_not_retried_either() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(
            429, headers={"Retry-After": "1"}, json={"error": "rate_limited"}
        )
    )
    with pytest.raises(RateLimitError), make_client(max_retries=5) as client:
        client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert route.call_count == 1


@respx.mock
def test_a_request_rate_429_is_retried_and_honours_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr("dodomain._client.time.sleep", slept.append)
    route = respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(
                429,
                headers={"Retry-After": "3"},
                json={
                    "error": "rate_limited",
                    "details": {"reason": "request_rate", "limit": 60, "retryAfterSeconds": 3},
                },
            ),
            httpx.Response(200, json={"connections": [], "nextCursor": None}),
        ]
    )
    with make_client(max_retries=2) as client:
        client.request(RequestSpec("GET", "/api/v1/connections"))
    assert route.call_count == 2
    assert slept == [3.0]


@respx.mock
def test_a_recently_checked_429_raises_immediately_with_no_retry() -> None:
    # This is a per-connection 10-minute cooldown, not a rate problem: a backoff
    # loop would only burn plan quota against the other limiter.
    route = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "420"},
            json={
                "error": "rate_limited",
                "details": {"reason": "recently_checked", "retryAfterSeconds": 420},
            },
        )
    )
    with pytest.raises(RateLimitError) as excinfo, make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/connections"))
    assert route.call_count == 1
    assert excinfo.value.reason == "recently_checked"


@respx.mock
def test_a_retry_after_longer_than_a_minute_is_raised_rather_than_slept_through() -> None:
    route = respx.get(api("/api/v1/connections")).mock(
        return_value=httpx.Response(
            429, headers={"Retry-After": "600"}, json={"error": "rate_limited"}
        )
    )
    with pytest.raises(RateLimitError), make_client(max_retries=3) as client:
        client.request(RequestSpec("GET", "/api/v1/connections"))
    assert route.call_count == 1


@respx.mock
def test_a_429_without_retry_after_falls_back_to_jittered_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr("dodomain._client.time.sleep", slept.append)
    respx.get(api("/api/v1/connections")).mock(
        side_effect=[
            httpx.Response(429, json={"error": "rate_limited"}),
            httpx.Response(200, json={"connections": [], "nextCursor": None}),
        ]
    )
    with make_client(max_retries=2) as client:
        client.request(RequestSpec("GET", "/api/v1/connections"))
    assert len(slept) == 1
    assert 0.0 <= slept[0] <= 0.5


@respx.mock
def test_max_retries_zero_disables_replay_entirely() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(503, json={"error": "not_configured"})
    )
    with pytest.raises(NotConfiguredError), make_client(max_retries=0) as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert route.call_count == 1


@respx.mock
def test_retries_are_bounded_and_the_last_failure_is_raised() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    with pytest.raises(InternalServerError), make_client(max_retries=2) as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert route.call_count == 3


@respx.mock
def test_a_transport_error_is_retried_on_a_get_then_surfaces_as_a_connection_error() -> None:
    route = respx.get(api("/api/v1/apps")).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(DoDomainConnectionError), make_client(max_retries=2) as c:
        c.request(RequestSpec("GET", "/api/v1/apps"))
    assert route.call_count == 3


@respx.mock
def test_a_transport_error_on_a_post_is_not_retried() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(DoDomainConnectionError), make_client(max_retries=3) as c:
        c.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert route.call_count == 1


@respx.mock
def test_a_non_retryable_status_is_raised_on_the_first_response() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(402, json={"error": "quota_exceeded"})
    )
    with pytest.raises(QuotaExceededError), make_client(max_retries=3) as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
    assert route.call_count == 1


@respx.mock
def test_the_rate_limit_snapshot_reads_draft_11_headers_when_they_appear() -> None:
    # The API emits only Retry-After today; these fields exist so the SDK already
    # reports them the day the API adopts draft-11.
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            200,
            headers={
                "RateLimit-Limit": "60",
                "RateLimit-Remaining": "59",
                "RateLimit-Reset": "42",
                "RateLimit-Policy": "60;w=60",
            },
            json={"apps": []},
        )
    )
    with make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
        assert client.last_rate_limit.limit == 60
        assert client.last_rate_limit.remaining == 59
        assert client.last_rate_limit.reset == 42.0
        assert client.last_rate_limit.policy == "60;w=60"


@respx.mock
def test_the_rate_limit_snapshot_is_all_none_against_todays_api() -> None:
    respx.get(api("/api/v1/apps")).mock(return_value=httpx.Response(200, json={"apps": []}))
    with make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
        assert client.last_rate_limit.limit is None
        assert client.last_rate_limit.retry_after is None


@respx.mock
def test_unparseable_rate_limit_headers_are_ignored_rather_than_crashing() -> None:
    respx.get(api("/api/v1/apps")).mock(
        return_value=httpx.Response(
            200,
            headers={"RateLimit-Limit": "lots", "RateLimit-Reset": "soon", "Retry-After": "later"},
            json={"apps": []},
        )
    )
    with make_client() as client:
        client.request(RequestSpec("GET", "/api/v1/apps"))
        assert client.last_rate_limit.limit is None
        assert client.last_rate_limit.reset is None
        assert client.last_rate_limit.retry_after is None


def test_backoff_is_exponential_with_full_jitter_and_a_hard_cap() -> None:
    import random

    rng = random.Random(0)
    assert all(0.0 <= backoff_delay(0, rng) <= 0.5 for _ in range(20))
    assert all(0.0 <= backoff_delay(3, rng) <= 4.0 for _ in range(20))
    assert all(0.0 <= backoff_delay(50, rng) <= 8.0 for _ in range(20))


@respx.mock
async def test_the_async_client_retries_a_get_without_blocking_the_loop() -> None:
    route = respx.get(api("/api/v1/apps")).mock(
        side_effect=[
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(200, json={"apps": []}),
        ]
    )
    async with make_async_client(max_retries=2) as client:
        assert await client.request(RequestSpec("GET", "/api/v1/apps")) == {"apps": []}
    assert route.call_count == 2


@respx.mock
async def test_the_async_client_never_retries_a_post() -> None:
    route = respx.post(api("/api/v1/sessions")).mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    async with make_async_client(max_retries=3) as client:
        with pytest.raises(InternalServerError):
            await client.request(RequestSpec("POST", "/api/v1/sessions", json_body={}))
    assert route.call_count == 1


@respx.mock
async def test_the_async_client_wraps_a_transport_failure() -> None:
    respx.get(api("/api/v1/apps")).mock(side_effect=httpx.ConnectError("boom"))
    async with make_async_client(max_retries=1) as client:
        with pytest.raises(DoDomainConnectionError):
            await client.request(RequestSpec("GET", "/api/v1/apps"))
