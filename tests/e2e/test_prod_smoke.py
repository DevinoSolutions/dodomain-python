"""Real end-to-end smoke test against production — ``https://app.dodomain.io``.

A skipped e2e is not a green e2e. Without ``DODOMAIN_SECRET_KEY`` this module
skips **loudly**: the reason below is printed by ``pytest -v`` / ``-ra`` and reads
as a visible amber in CI, never as a silent pass.

The flow is read-mostly and self-cleaning. The one session it creates is never
verified, so it expires naturally in 24 hours and the reaper emits
``session.abandoned`` — no production row needs deleting, and
``connections.disconnect`` is never called against a real customer connection.
Budget: roughly a dozen requests, far under the 60/min plan cap.

TWO THINGS THIS SUITE DELIBERATELY DOES NOT DO
----------------------------------------------
``keys.rotate()`` and the webhook-endpoint *writes* are never exercised live.
Rotation has no grace window, so a live call would invalidate the very
``DODOMAIN_SECRET_KEY`` this job authenticates with and break every subsequent CI
run — the response is the only copy of the replacement and nothing here could
store it. Endpoint creation would leave a real delivery target on a production
app. Both are covered by the unit suite against ``respx``; what is proven here
instead is that the routes are deployed and reject an unauthenticated caller,
which is the part a mock cannot tell you.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from dodomain import (
    AuthenticationError,
    DnsRecord,
    DoDomain,
    NotFoundError,
)

DODOMAIN_SECRET_KEY = os.environ.get("DODOMAIN_SECRET_KEY")

pytestmark = pytest.mark.skipif(
    not DODOMAIN_SECRET_KEY,
    reason=(
        "LOUD SKIP: DODOMAIN_SECRET_KEY is not set, so the real prod e2e cannot run. "
        "Set DODOMAIN_SECRET_KEY (a dd_sk_ key for the SDK e2e app on app.dodomain.io) "
        "to exercise create-session -> read-back -> detect -> list -> disconnect against prod."
    ),
)

PROD_BASE_URL = "https://app.dodomain.io"
E2E_DOMAIN_SUFFIX = "dodomain-e2e.io"

# Fields that must never appear on an app payload. The contract has no secret
# material and must never grow any.
FORBIDDEN_APP_FIELDS = ("secretKeyHash", "secretKey", "secret", "apiKey")


@pytest.fixture(scope="module")
def client() -> DoDomain:
    assert DODOMAIN_SECRET_KEY is not None
    with DoDomain(secret_key=DODOMAIN_SECRET_KEY, base_url=PROD_BASE_URL) as live:
        yield live


@pytest.fixture(scope="module")
def created_session(client: DoDomain):
    """One connect session on prod, reused by the read-back and detect steps."""
    domain = f"e2e-{uuid.uuid4().hex[:8]}.{E2E_DOMAIN_SUFFIX}"
    session = client.sessions.create(
        domain=domain,
        records=[DnsRecord(type="CNAME", host="@", value="cname.dodomain.io")],
        return_url="https://dodomain.io/",
    )
    print(f"\n[e2e] created prod session id={session.id} domain={domain}")
    return session


def test_the_prod_base_url_is_the_origin_that_actually_resolves(client: DoDomain) -> None:
    # api.dodomain.io does not resolve. A previous SDK shipped it as the default
    # and every call 404'd with no error surface.
    assert client.base_url == "https://app.dodomain.io"


def test_apps_list_returns_at_least_one_app_and_leaks_no_secret_material(
    client: DoDomain,
) -> None:
    apps = client.apps.list()
    assert len(apps) >= 1
    for app in apps:
        assert app.id
        assert app.public_key.startswith("dd_pk_")
        assert app.created_at.tzinfo is not None
        assert app.raw is not None
        for forbidden in FORBIDDEN_APP_FIELDS:
            assert forbidden not in app.raw, f"{forbidden} must never appear on an app payload"
            assert not hasattr(app, forbidden)


def test_domains_check_answers_for_a_well_known_domain(client: DoDomain) -> None:
    result = client.domains.check(domain="example.com")
    assert result.domain == "example.com"
    assert result.zone == "example.com"
    assert result.tier in (1, 2, 3)
    assert result.method in ("oauth", "domain-connect", "guided")
    assert result.confidence in ("high", "medium", "low")
    assert result.guide.steps, "a provider guide must always carry manual steps"


def test_create_session_returns_a_hosted_connect_url_that_expires_in_24h(
    created_session,
) -> None:
    assert created_session.id
    assert created_session.token
    assert created_session.connect_url.startswith("https://app.dodomain.io/connect/")
    expected = datetime.now(timezone.utc) + timedelta(hours=24)
    assert abs((created_session.expires_at - expected).total_seconds()) < 600


def test_the_session_can_be_read_back_through_the_public_api(
    client: DoDomain, created_session
) -> None:
    # Prove it exists by reading it back; never trust the write's own response.
    fetched = client.sessions.retrieve(created_session.token)
    assert fetched.id == created_session.id
    assert fetched.status == "pending"
    assert len(fetched.records) == 1
    assert fetched.records[0].type == "CNAME"
    assert fetched.records[0].value == "cname.dodomain.io"
    assert fetched.return_url == "https://dodomain.io/"


def test_detect_works_on_the_token_public_path_with_no_credential(
    client: DoDomain, created_session
) -> None:
    result = client.sessions.detect(created_session.token)
    assert result.provider
    assert result.tier in (1, 2, 3)
    assert result.zone.endswith(E2E_DOMAIN_SUFFIX)
    assert result.guide.steps


def test_the_start_urls_point_at_the_prod_origin(created_session) -> None:
    assert created_session.cloudflare_start_url.startswith(
        f"{PROD_BASE_URL}/api/v1/sessions/{created_session.token}/"
    )
    assert created_session.domain_connect_start_url.endswith("/domain-connect/start")


def test_connections_list_returns_a_well_formed_page(client: DoDomain) -> None:
    page = client.connections.list(limit=1)
    assert isinstance(page.next_cursor, (str, type(None)))
    assert page.has_more is (page.next_cursor is not None)
    assert len(page.connections) <= 1
    for conn in page.connections:
        assert conn.status in ("active", "broken")
        assert conn.created_at.tzinfo is not None


def test_the_authed_arm_reads_the_session_back_by_its_id(client: DoDomain, created_session) -> None:
    # The id arm, addressed by the same id a webhook would carry — and a genuinely
    # different shape from the token arm, which is what this proves against prod.
    state = client.sessions.get(created_session.id)
    assert state.id == created_session.id
    assert state.app_id
    # Deliberately NOT pinned to a literal: `created_session` is module-scoped and
    # the detect step above persists `status: "detected"` on it, so the value here
    # depends on test order. The sibling test below asserts the thing that actually
    # matters — that both read arms report the SAME status at the same moment.
    assert state.status
    assert state.expired is False
    assert state.connection_id is None, "an unverified session has no connection yet"
    assert state.records, "the authed arm always composes the record names"
    assert state.records[0].fqdn.endswith(E2E_DOMAIN_SUFFIX)
    # Composed records carry no value — the server omits it on this arm.
    assert "value" not in (state.records[0].raw or {})


def test_the_two_session_read_arms_agree_on_the_facts_they_share(
    client: DoDomain, created_session
) -> None:
    public = client.sessions.retrieve(created_session.token)
    authed = client.sessions.get(created_session.id)
    assert (authed.id, authed.domain, authed.status) == (public.id, public.domain, public.status)


def test_a_session_id_that_is_not_yours_is_a_404(client: DoDomain) -> None:
    with pytest.raises(NotFoundError) as excinfo:
        client.sessions.get("cthisisnotarealsessionid")
    assert excinfo.value.status_code == 404


def test_reading_one_connection_by_id_matches_what_the_list_returned(
    client: DoDomain,
) -> None:
    page = client.connections.list(limit=1, include_disconnected=True)
    if not page.connections:
        pytest.skip(
            "LOUD SKIP: the e2e app has no connections on prod yet, so connections.get "
            "cannot be proven against a real row. The route's deployment is still "
            "proven by test_an_unknown_connection_id_is_a_404 below."
        )
    listed = page.connections[0]
    fetched = client.connections.get(listed.id)
    # The route promises a body byte-identical to a list element.
    assert fetched == listed
    assert isinstance(fetched.record_fqdns, tuple)


def test_an_unknown_connection_id_is_a_404(client: DoDomain) -> None:
    with pytest.raises(NotFoundError) as excinfo:
        client.connections.get("cthisisnotarealconnectionid")
    assert excinfo.value.status_code == 404


def test_webhook_endpoints_list_never_returns_a_signing_secret(client: DoDomain) -> None:
    for endpoint in client.webhook_endpoints.list():
        assert endpoint.id and endpoint.app_id and endpoint.url
        assert endpoint.created_at.tzinfo is not None
        assert not hasattr(endpoint, "secret")
        assert "secret" not in (endpoint.raw or {}), "a read surface must never carry the secret"


def test_the_secret_key_only_routes_are_deployed_and_reject_a_bad_credential() -> None:
    # A route that did not exist would answer 404. A 401 proves it is deployed AND
    # that it refuses an unusable credential — the only way to touch keys.rotate
    # in production without destroying the key this suite runs on.
    with DoDomain(secret_key="dd_sk_bogus", base_url=PROD_BASE_URL) as bogus:
        with pytest.raises(AuthenticationError) as rotate_error:
            bogus.keys.rotate()
        with pytest.raises(AuthenticationError) as endpoints_error:
            bogus.webhook_endpoints.list()
    assert rotate_error.value.status_code == 401
    assert endpoints_error.value.status_code == 401


def test_an_unknown_session_token_raises_not_found(client: DoDomain) -> None:
    # The value must be dd_sess_-SHAPED. `GET /v1/sessions/:tokenOrId` picks its
    # arm structurally off that prefix, so a segment without it is routed to the
    # AUTHED arm instead — see the test below, which pins that consequence.
    with pytest.raises(NotFoundError) as excinfo:
        client.sessions.retrieve("dd_sess_definitely-not-a-real-token")
    assert excinfo.value.status_code == 404


def test_a_token_that_is_not_token_shaped_reaches_the_authed_arm_and_401s(
    client: DoDomain,
) -> None:
    """The consequence of one path serving two arms, pinned against the real API.

    Regression guard: this suite used to pass a bare ``"definitely-not-a-token"``
    to ``retrieve`` and expect 404. It was correct until the API grew the
    integrator-authed id arm, after which that segment stops looking like a token,
    is routed to the arm that requires a credential, and — because ``retrieve``
    sends none — answers 401. Nothing in the SDK changed; the API's behavior did,
    and only a live run could tell us.
    """
    with pytest.raises(AuthenticationError) as excinfo:
        client.sessions.retrieve("definitely-not-a-token")
    assert excinfo.value.status_code == 401


def test_a_bogus_secret_key_raises_an_authentication_error() -> None:
    with (
        DoDomain(secret_key="dd_sk_bogus", base_url=PROD_BASE_URL) as bogus,
        pytest.raises(AuthenticationError) as excinfo,
    ):
        bogus.apps.list()
    assert excinfo.value.status_code == 401
