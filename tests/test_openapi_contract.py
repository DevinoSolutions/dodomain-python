"""The mechanical guard that this SDK models the API's ACTUAL `/v1` contract.

`tests/fixtures/openapi_v1_shapes.json` is a verbatim extract of the component
schemas from the monorepo's committed `apps/docs/public/openapi.json`, which is
itself generated from `packages/core/src/schemas.ts` — the same zod schemas the
handlers validate with. So the required-field lists in that fixture are not a
Python-flavoured paraphrase of the contract; they are the contract.

Two things are asserted per schema:

1. **Every required wire field is mapped to a model attribute.** The mapping is
   spelled out here by hand, and its key set must EQUAL the schema's `required`
   list. A field the API makes required and this SDK does not read fails the
   suite the moment the fixture is regenerated — which is the whole point, and
   the same job `tests/fixtures/webhook_vectors.json` does for the signer.
2. **A payload synthesized from the schema round-trips through the model.** Each
   mapped attribute must come back holding the synthesized value, so a mapping
   entry cannot be satisfied by a field that silently parses to its default.

Regenerating the fixture (run from a checkout of the `dodomain` monorepo, whose
`apps/docs/public/openapi.json` is the source of truth)::

    node -e "const fs=require('fs');
      const spec=JSON.parse(fs.readFileSync('apps/docs/public/openapi.json','utf8'));
      const want=['CreateSessionResponse','PublicSession','IntegratorSession',
                  'VerifySessionResponse','ListAppsResponse',
                  'WebhookEndpointSummary','WebhookEndpointSecretResponse'];
      const old=JSON.parse(fs.readFileSync(DEST,'utf8'));
      fs.writeFileSync(DEST, JSON.stringify({...old, apiVersion: spec.info.version,
        schemas: Object.fromEntries(want.map(k=>[k,spec.components.schemas[k]]))}, null, 2)+'\\n');"
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from dodomain.models import (
    App,
    ConnectSessionSummary,
    IntegratorSession,
    PublicSession,
    VerifyResult,
    WebhookEndpoint,
    WebhookEndpointWithSecret,
)

SCHEMAS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "openapi_v1_shapes.json").read_text(encoding="utf-8")
)["schemas"]

#: Wire key -> the model attribute that must hold it. One entry per REQUIRED
#: field of the schema; the equality assertion below is what makes the list
#: exhaustive rather than aspirational.
REQUIRED_FIELD_MAP: dict[str, dict[str, str]] = {
    "CreateSessionResponse": {
        "id": "id",
        "token": "token",
        "expiresAt": "expires_at",
        "connectUrl": "connect_url",
        "records": "records",
    },
    "PublicSession": {
        "id": "id",
        "domain": "domain",
        "records": "records",
        "recipe": "recipe",
        "status": "status",
        "tier": "tier",
        "detectedProvider": "detected_provider",
        "returnUrl": "return_url",
        "expiresAt": "expires_at",
    },
    "IntegratorSession": {
        "id": "id",
        "appId": "app_id",
        "domain": "domain",
        "records": "records",
        "recipe": "recipe",
        "status": "status",
        "tier": "tier",
        "detectedProvider": "detected_provider",
        "connectionId": "connection_id",
        "createdAt": "created_at",
        "expiresAt": "expires_at",
        "expired": "expired",
        "tlsIssuanceAdvisories": "tls_issuance_advisories",
    },
    "VerifySessionResponse": {
        "verified": "verified",
        "records": "records",
        "advisories": "advisories",
    },
    # ListAppsResponse's only required field is the envelope's `apps` array; the
    # shape that matters is its item, which `App` models.
    "ListAppsResponse.apps.items": {
        "id": "id",
        "name": "name",
        "publicKey": "public_key",
        "sandbox": "sandbox",
        "logoUrl": "logo_url",
        "brandColor": "brand_color",
        "connectHeadline": "connect_headline",
        "connectSubheadline": "connect_subheadline",
        "connectSuccessCtaLabel": "connect_success_cta_label",
        "connectSuccessRedirectUrl": "connect_success_redirect_url",
        "connectFontPreset": "connect_font_preset",
        "hideConnectFooterHelp": "hide_connect_footer_help",
        "tlsIssuerCa": "tls_issuer_ca",
        "createdAt": "created_at",
    },
    "WebhookEndpointSummary": {
        "id": "id",
        "appId": "app_id",
        "url": "url",
        "createdAt": "created_at",
        "pausedAt": "paused_at",
    },
    "WebhookEndpointSecretResponse": {
        "id": "id",
        "appId": "app_id",
        "url": "url",
        "createdAt": "created_at",
        "pausedAt": "paused_at",
        "secret": "secret",
    },
}


def _schema(name: str) -> dict[str, Any]:
    """Resolve a dotted fixture path like ``ListAppsResponse.apps.items``."""
    head, _, rest = name.partition(".")
    node: dict[str, Any] = SCHEMAS[head]
    for segment in filter(None, rest.split(".")):
        node = node["items"] if segment == "items" else node["properties"][segment]
    return node


def _sample(node: dict[str, Any], key: str) -> Any:
    """One value satisfying this schema node, distinctive enough to trace back.

    Nullable fields deliberately get their NON-null branch: a null would parse
    into the same `None` an unread field leaves behind, which is exactly the
    silent-default failure this suite exists to catch.
    """
    if "anyOf" in node:
        branches = [b for b in node["anyOf"] if b.get("type") != "null"]
        return _sample(branches[0], key)
    if "enum" in node:
        return node["enum"][0]
    node_type = node.get("type")
    if node_type == "array":
        return [_sample(node["items"], key)]
    if node_type == "object":
        return {k: _sample(node["properties"][k], k) for k in node.get("required", [])}
    if node_type == "boolean":
        return True
    if node_type in ("integer", "number"):
        return 1
    if node.get("format") == "date-time":
        return "2026-09-08T12:00:00.000Z"
    return f"sample-{key}"


def _synthesize(name: str) -> dict[str, Any]:
    schema = _schema(name)
    return {k: _sample(schema["properties"][k], k) for k in schema["required"]}


@pytest.mark.parametrize("name", sorted(REQUIRED_FIELD_MAP))
def test_every_required_field_of_the_published_contract_has_a_model_field(name: str) -> None:
    # An API field this SDK does not read is invisible until an integrator needs
    # it. Equality (not a subset check) is what makes a newly-required field a
    # failing test the moment the fixture is regenerated.
    assert set(_schema(name)["required"]) == set(REQUIRED_FIELD_MAP[name])


PARSERS = {
    "CreateSessionResponse": lambda p: ConnectSessionSummary._from_api(
        p, base_url="https://app.dodomain.io"
    ),
    "PublicSession": PublicSession._from_api,
    "IntegratorSession": IntegratorSession._from_api,
    "VerifySessionResponse": VerifyResult._from_api,
    "ListAppsResponse.apps.items": App._from_api,
    "WebhookEndpointSummary": WebhookEndpoint._from_api,
    "WebhookEndpointSecretResponse": WebhookEndpointWithSecret._from_api,
}


@pytest.mark.parametrize("name", sorted(REQUIRED_FIELD_MAP))
def test_a_body_built_from_the_published_schema_round_trips_into_the_model(name: str) -> None:
    payload = _synthesize(name)
    model = PARSERS[name](payload)
    for wire_key, attribute in REQUIRED_FIELD_MAP[name].items():
        value = getattr(model, attribute)
        wire_value = payload[wire_key]
        if isinstance(wire_value, list):
            # Nested models are parsed, not passed through, so compare arity —
            # an empty tuple here means the field was dropped on the floor.
            assert len(value) == len(wire_value), f"{name}.{wire_key} lost its items"
        elif isinstance(value, datetime):
            assert value.isoformat() == "2026-09-08T12:00:00+00:00"
        else:
            assert value == wire_value, f"{name}.{wire_key} did not reach .{attribute}"


def test_the_fixture_is_pinned_to_the_v1_surface() -> None:
    # A fixture regenerated against some future /v2 document would silently start
    # asserting the wrong contract.
    contract = json.loads(
        (Path(__file__).parent / "fixtures" / "openapi_v1_shapes.json").read_text(encoding="utf-8")
    )
    assert contract["apiVersion"] == "v1"
