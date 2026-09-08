# Changelog

Notable changes to `dodomain-sdk`. The import package is `dodomain`.

## 0.4.0

Parity with `@dodomain/node` 0.5.0 and 0.6.0, and with the `/v1` contract changes
those tracked. Additive apart from one rename that keeps a working alias, so
upgrading from 0.3.0 is a drop-in.

### Added

* **`TlsIssuanceAdvisory`** — why a certificate issuance for a *verified* name may
  still fail. Every verify pass now reads the domain's own nameservers for a CAA
  policy and a stale `_acme-challenge` record and reports what it found:
  `caa_excludes_issuer`, `caa_restricts_issuance`, `stale_acme_challenge`, or
  `tls_issuance_unchecked` when the check itself could not complete (unknown is
  not the same answer as clean). Carries a `severity`, the `fqdn` it is about, the
  `evidence_fqdn` it was read from — routinely a *parent*, since CAA is inherited
  — the published `evidence` verbatim, and one human-readable `note`.

  **An advisory never changes the verdict.** `verified` and `present` are computed
  without it, so ignoring the field leaves you with exactly the 0.3.0 contract.
* **`VerifyResult.advisories`** — the advisories for this session's
  TLS-terminating records, read on the same pass as the verify.
* **`IntegratorSession.tls_issuance_advisories`** — the same shape on
  `sessions.get`, as a snapshot of what the LAST verify pass computed. Empty until
  a verify has run; not a live read.
* **`VerifyRecord.authoritative_found` / `.public_found`** — what the domain's own
  nameservers answered, and what a public recursive resolver sees. The first is
  the set `present` is decided from, and the answer to "what did they put there
  instead"; the second never gates anything, and trailing the first is the
  ordinary, healthy meaning of `outcome == "propagating"`.
* **`App.tls_issuer_ca`** — the CA issuer-domain your end-user certificates are
  issued with, or `None` until it is configured in the dashboard. It is what turns
  a CAA policy into the actionable `caa_excludes_issuer` rather than the vaguer
  `caa_restricts_issuance`.
* `connection.verified` and `session.completed` webhook payloads now carry
  `tlsIssuanceAdvisories` **when there is at least one** — absent, not empty, when
  there is nothing to say. There is still deliberately no typed event parser (see
  `dodomain.webhooks`), so this is a documentation change on the SDK side.
* **`tests/fixtures/openapi_v1_shapes.json` + `tests/test_openapi_contract.py`** —
  a mechanical parity guard, in the spirit of `webhook_vectors.json`. The fixture
  is a verbatim extract of the published OpenAPI component schemas; the test fails
  if a *required* wire field of `POST /v1/sessions`, `GET /v1/sessions/{token}`
  (both arms), `POST /v1/sessions/{token}/verify` or `GET /v1/apps` has no field on
  the matching model, and again if a mapped field does not survive a round trip.

### Changed

* **`Session` is now `ConnectSessionSummary`.** It is the summary of ONE connect
  session, and "session" already meant two other things in the platform (the
  dashboard login session, and the server-side `ConnectSession` row).
  `@dodomain/node` 0.5.0 made the identical rename; this SDK follows so the two
  keep answering to the same vocabulary. **`Session` still works** — it is an
  alias bound to the same class object, so `isinstance`, equality and existing
  imports are unaffected. It is deprecated and will be REMOVED in the next major;
  switch your imports now.

### Notes

* All new response fields parse tolerantly: a body recorded before the field
  existed still reads (as `()` / `None`), while a field that is *present* with the
  wrong type still fails loudly. Same rule as `records` / `recordFqdns` /
  `previousKeyExpiresAt` before them.

## 0.3.0

Parity with the rotation-overlap contract the API shipped on 2026-08-20 (and
`@dodomain/node` 0.4.0). Purely additive: `keys.rotate()` with no argument sends
the identical body-less request it always did and still means an immediate
cutover, so upgrading from 0.2.0 is a drop-in.

### Added

* **`keys.rotate(overlap_hours=...)`** — `0` (the default), `1` or `24`. A window
  keeps the **old key authenticating alongside the new one** until it closes, so
  a rotator can deploy the new key with zero downtime instead of racing its own
  cutover. Only a requested window puts a body on the wire; the default stays the
  request every server version has always accepted. A value the API does not
  offer is refused locally with `InvalidRequestError` and `status_code == 0`,
  before the call that would mint a credential — including `True`, which `== 1`
  would otherwise have bought as an unasked-for one-hour window.
* **`RotatedSecretKey.previous_key_expires_at`** — when the previous key stops
  authenticating, or `None` if it already has. Parses tolerantly, so a response
  recorded before the field existed still reads as a zero-overlap rotation.
* **`RotationOverlapHours`** — the `Literal[0, 1, 24]` alias, exported so callers
  can type a configured window rather than pass a bare `int`.

### Changed

* The docs for `keys.rotate` no longer say rotation has no grace window
  unconditionally: the **default** has none, and it is also the kill switch — a
  zero-overlap rotation terminates a window still running from an earlier one.
  **Exactly one previous key is ever kept**, so rotating twice in a row kills key
  n-1 immediately regardless of its remaining window.

## 0.2.0

Full parity with the API's current `/v1` surface: every callable REST operation
now has a method, sync and async. Nothing was removed and no existing return value
changed shape, so upgrading from 0.1.0 is a drop-in.

### Added

* **`connections.get(connection_id)`** — read one connection by the id every
  `connection.*` webhook carries, instead of listing and filtering (which is
  impossible past the paging ceiling without walking every cursor). Returns a
  connection even after it was disconnected, unlike the list default.
* **`sessions.get(session_id)`** — the integrator-authed session read, and the
  only one that answers after a session expired (`sessions.retrieve` raises
  `ExpiredError` forever once the TTL passes). Addressable by the `sessionId`
  webhooks carry. Returns the new `IntegratorSession`, which is a genuinely
  different shape from `PublicSession`: composed records with **no `value`**, plus
  `app_id`, `connection_id` and a server-derived `expired`.
* **`client.webhook_endpoints`** — `list`, `create`, `get`, `update`, `delete`,
  `rotate_secret`. Secret-key only; an OAuth token is refused with a 403 you can
  now recognise via `PermissionError_.secret_key_required`. The signing secret is
  show-once, so it appears only on `create` and `rotate_secret` results and is
  kept out of their `repr`. `get` is a client-side lookup over `list` — the API
  has no read-one route — and says so in its docstring and its `status_code == 0`
  `NotFoundError`.
* **`client.keys.rotate()`** — self-rotate the calling app's secret key, the
  automatable half of credential lifecycle. No grace window: the old key stops
  working the instant the response is produced, and the response is the only copy
  of the new one. There is deliberately no create/list/revoke.
* **`Connection.record_fqdns`** — the names doDomain actually monitors.
  `Connection.fqdn` has always held the session *domain* rather than a record
  name; it keeps its value for compatibility, and this is the honest answer.
* **`Session.records` and `Session.warnings`** — the composed names a create will
  be verified at (where a doubled label like `links.links.acme.com` becomes
  visible immediately) and any advisory attached to an accepted request.
* **`PermissionError_.secret_key_required`** — distinguishes "this endpoint needs
  a `dd_sk_` key" from a missing OAuth scope. No scope fixes the former.
* New models: `ComposedRecord`, `SessionWarning`, `IntegratorSession`,
  `WebhookEndpoint`, `WebhookEndpointWithSecret`, `DeletedWebhookEndpoint`,
  `RotatedSecretKey`.

### Changed

* **Webhook documentation now describes the body that is actually delivered.**
  0.1.0 documented the pre-cutover `{event, data}` shape; the wire envelope has
  been `{id, type, occurredAt, data}` plus a deprecated `event` alias since
  2026-08-06. Read `type`, dedupe on `id`, treat `event` as legacy.
  `verify_webhook` itself is unchanged — it was wire-format agnostic by design and
  needed no cutover.
* Additive response fields parse tolerantly: a payload recorded before `records`
  or `recordFqdns` existed still parses, while a field that is *present* with the
  wrong type still fails loudly.
* The README's claim that doDomain publishes no OpenAPI document was false; it is
  served at <https://dodomain.io/docs/openapi.json>.

## 0.1.0

First release. Sync and async clients, connect sessions, connections, domain
pre-flight, apps, webhook signature verification, the full error hierarchy, and a
retry policy that never replays a `POST`.
