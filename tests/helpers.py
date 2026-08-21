"""Shared fixtures and canned payloads for the unit suite.

Every payload here is the *wire* shape (camelCase, ISO-8601 strings) exactly as
``apps/web/src/app/api/v1/**/route.ts`` builds it — so a test that passes proves
the SDK parses the real contract, not a Python-flavoured paraphrase of it.
"""

from __future__ import annotations

from typing import Any

import httpx

from dodomain import AsyncDoDomain, DoDomain

TEST_KEY = "dd_sk_test_0123456789"
TEST_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.c2lnbmF0dXJl"
BASE_URL = "https://app.dodomain.io"


def api(path: str) -> str:
    return f"{BASE_URL}{path}"


# One transport for the whole suite. respx patches at the transport layer, so a
# shared client is fully mocked either way — and building a fresh httpx.Client
# per test is pure overhead (pathologically so on some Windows hosts).
_SHARED_SYNC_TRANSPORT = httpx.Client(timeout=30.0)
_SHARED_ASYNC_TRANSPORT = httpx.AsyncClient(timeout=30.0)


def make_client(**kwargs: Any) -> DoDomain:
    """A sync client wired to the shared transport, with test defaults."""
    kwargs.setdefault("secret_key", TEST_KEY)
    kwargs.setdefault("http_client", _SHARED_SYNC_TRANSPORT)
    return DoDomain(**kwargs)


def make_async_client(**kwargs: Any) -> AsyncDoDomain:
    """An async client wired to the shared transport, with test defaults."""
    kwargs.setdefault("secret_key", TEST_KEY)
    kwargs.setdefault("http_client", _SHARED_ASYNC_TRANSPORT)
    return AsyncDoDomain(**kwargs)


CREATE_SESSION_RESPONSE: dict[str, Any] = {
    "id": "cs_01HZX",
    "token": "tok_live_abc123",
    "expiresAt": "2026-08-06T12:00:00.000Z",
    "connectUrl": "https://app.dodomain.io/connect/tok_live_abc123",
    # `records` is required on the wire today; it and `warnings` arrived after the
    # SDK's first release, which is why LEGACY_CREATE_SESSION_RESPONSE below still
    # has to parse.
    "records": [{"type": "CNAME", "host": "app", "fqdn": "app.app.customer.com"}],
}

#: A create response exactly as the API shipped it before `records`/`warnings`
#: existed — the shape a cached or archived payload still has.
LEGACY_CREATE_SESSION_RESPONSE: dict[str, Any] = {
    key: value for key, value in CREATE_SESSION_RESPONSE.items() if key != "records"
}

#: The authed-by-id read (`sessions.get`) — a DIFFERENT shape from the
#: token-public one: composed records with no `value`, plus appId/connectionId/
#: expired and no returnUrl.
INTEGRATOR_SESSION_RESPONSE: dict[str, Any] = {
    "id": "cs_01HZX",
    "appId": "app_1",
    "domain": "app.customer.com",
    "records": [{"type": "CNAME", "host": "app", "fqdn": "app.app.customer.com"}],
    "recipe": None,
    "status": "verified",
    "tier": 2,
    "detectedProvider": "Cloudflare",
    "connectionId": "conn_1",
    "createdAt": "2026-08-05T12:00:00.000Z",
    "expiresAt": "2026-08-06T12:00:00.000Z",
    "expired": False,
}

PUBLIC_SESSION_RESPONSE: dict[str, Any] = {
    "id": "cs_01HZX",
    "domain": "app.customer.com",
    "records": [
        {"type": "CNAME", "host": "app", "value": "cname.dodomain.io"},
        {"type": "MX", "host": "@", "value": "mx.dodomain.io", "priority": 10, "ttl": 3600},
    ],
    "recipe": None,
    "status": "pending",
    "tier": 1,
    "detectedProvider": "Cloudflare",
    "returnUrl": "https://customer.com/settings/domains",
    "expiresAt": "2026-08-06T12:00:00.000Z",
}

PROVIDER_GUIDE: dict[str, Any] = {
    "provider": "cloudflare",
    "label": "Cloudflare",
    "dashboardUrl": "https://dash.cloudflare.com",
    "hostFormat": "{host}",
    "apexToken": "@",
    "steps": ["Open the DNS tab", "Add the record"],
    "notes": ["Proxying must be off"],
}

DETECT_RESPONSE: dict[str, Any] = {
    "provider": "cloudflare",
    "label": "Cloudflare",
    "zone": "customer.com",
    "tier": 1,
    "method": "oauth",
    "confidence": "high",
    "nameServers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "domainConnect": {"providerId": "cloudflare.com", "providerName": "Cloudflare"},
    "domainConnectReady": False,
    "guide": PROVIDER_GUIDE,
}

CHECK_DOMAIN_RESPONSE: dict[str, Any] = {
    "domain": "app.customer.com",
    "zone": "customer.com",
    "provider": "cloudflare",
    "label": "Cloudflare",
    "tier": 2,
    "method": "domain-connect",
    "confidence": "medium",
    "nameServers": ["ns1.cloudflare.com"],
    "domainConnect": {
        "discovered": True,
        "providerId": "cloudflare.com",
        "providerName": "Cloudflare",
    },
    "guide": PROVIDER_GUIDE,
}

VERIFY_RESPONSE: dict[str, Any] = {
    "verified": False,
    "records": [
        {
            "fqdn": "app.customer.com",
            "type": "CNAME",
            "present": True,
            "note": "matches",
            "outcome": "verified",
        },
        {
            "fqdn": "customer.com",
            "type": "TXT",
            "present": False,
            "note": "not visible yet",
            "outcome": "propagating",
            "authoritativeError": "NS_RESOLUTION_FAILED",
        },
    ],
}


def connection(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "conn_1",
        "appId": "app_1",
        "sessionId": "cs_01HZX",
        "domain": "app.customer.com",
        # `fqdn` really is the session DOMAIN on the wire, not a record name —
        # the field the API froze rather than repaired. `recordFqdns` carries the
        # names actually monitored, which is why the two differ here on purpose.
        "fqdn": "app.customer.com",
        "recordFqdns": ["status.app.customer.com"],
        "status": "active",
        "verifiedAt": "2026-08-01T10:00:00.000Z",
        "lastCheckedAt": "2026-08-05T10:00:00.000Z",
        "brokenAt": None,
        "disconnectedAt": None,
        "createdAt": "2026-08-01T09:59:00.000Z",
    }
    payload.update(overrides)
    return payload


def webhook_endpoint(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "whe_1",
        "appId": "app_1",
        "url": "https://acme.example/webhooks/dodomain",
        "createdAt": "2026-08-01T09:00:00.000Z",
    }
    payload.update(overrides)
    return payload


def webhook_endpoint_with_secret(**overrides: Any) -> dict[str, Any]:
    overrides.setdefault("secret", "whsec_shown_once")
    return webhook_endpoint(**overrides)


#: A default (zero-overlap) rotation: `previousKeyExpiresAt` is present and null
#: because the old key is already dead.
ROTATED_KEY_RESPONSE: dict[str, Any] = {
    "appId": "app_1",
    "publicKey": "dd_pk_live_abc",
    "secretKey": "dd_sk_live_the_new_one",
    "rotatedAt": "2026-08-17T12:00:00.000Z",
    "previousKeyExpiresAt": None,
}

#: The same rotation asked for a 24h window — the only field that differs.
ROTATED_KEY_WITH_OVERLAP_RESPONSE: dict[str, Any] = {
    **ROTATED_KEY_RESPONSE,
    "previousKeyExpiresAt": "2026-08-18T12:00:00.000Z",
}

#: A rotate response exactly as the API shipped it before overlap windows
#: existed — the shape a cached or archived payload still has.
LEGACY_ROTATED_KEY_RESPONSE: dict[str, Any] = {
    key: value for key, value in ROTATED_KEY_RESPONSE.items() if key != "previousKeyExpiresAt"
}


LIST_APPS_RESPONSE: dict[str, Any] = {
    "apps": [
        {
            "id": "app_1",
            "name": "Acme",
            "publicKey": "pk_live_abc",
            "sandbox": False,
            "logoUrl": None,
            "brandColor": "#0E6B4E",
            "createdAt": "2026-07-01T00:00:00.000Z",
        }
    ]
}

DISCONNECT_RESPONSE: dict[str, Any] = {
    "id": "conn_1",
    "disconnectedAt": "2026-08-05T12:00:00.000Z",
    "alreadyDisconnected": False,
}
