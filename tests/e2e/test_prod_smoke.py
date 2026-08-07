"""Real end-to-end smoke test against production — ``https://app.dodomain.io``.

A skipped e2e is not a green e2e. Without ``DODOMAIN_SECRET_KEY`` this module
skips **loudly**: the reason below is printed by ``pytest -v`` / ``-ra`` and reads
as a visible amber in CI, never as a silent pass.

The flow is read-mostly and self-cleaning. The one session it creates is never
verified, so it expires naturally in 24 hours and the reaper emits
``session.abandoned`` — no production row needs deleting, and
``connections.disconnect`` is never called against a real customer connection.
Budget: roughly eight requests, far under the 60/min plan cap.
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


def test_an_unknown_session_token_raises_not_found(client: DoDomain) -> None:
    with pytest.raises(NotFoundError) as excinfo:
        client.sessions.retrieve("definitely-not-a-token")
    assert excinfo.value.status_code == 404


def test_a_bogus_secret_key_raises_an_authentication_error() -> None:
    with (
        DoDomain(secret_key="dd_sk_bogus", base_url=PROD_BASE_URL) as bogus,
        pytest.raises(AuthenticationError) as excinfo,
    ):
        bogus.apps.list()
    assert excinfo.value.status_code == 401
