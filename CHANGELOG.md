# Changelog

Notable changes to `dodomain-sdk`. The import package is `dodomain`.

## 0.8.1

The record types the API has accepted since 2026-10-29 (DoDomain commit
2c5a9650): `SRV`, `CAA` and `NS` (below the zone apex).

### Fixed

* **Reading back a session that holds an `SRV`, `CAA` or `NS` record no longer
  raises `InvalidResponseError`.** 0.8.0 pinned a record's `type` to the
  original five (`A`, `AAAA`, `CNAME`, `TXT`, `MX`), so `sessions.retrieve`,
  `sessions.get` and a create response failed as a whole for any such session.

### Added

* **`DnsRecord` carries the new types' fields**, the exact core `zRecord` wire
  shape: `weight` and `port` (SRV, 0-65535; `value` is the target host, the
  RFC 2782 priority rides `priority`), `flags` (CAA, 0-255) and `tag` (CAA:
  `issue`, `issuewild` or `iodef`; `value` is the property value). Appended
  after `raw`, so positional construction keeps working. `DnsRecordType` gains
  `SRV`, `CAA` and `NS`; new `CaaTag` literal.
* **Local refusals that mirror the API's**: an SRV without `priority`, `weight`
  and `port` (`reason == "missing_srv_fields"`), a CAA without `flags` and `tag`
  (`"missing_caa_fields"`), a CAA tag outside the three, a CAA value with a
  double quote or control character, and an out-of-range `weight`/`port`/
  `flags` all raise `InvalidRequestError` (`status_code == 0`) before a request
  is sent, with the server's messages. An apex `NS` (`ns_at_zone_apex`) stays
  server-side: it needs the public suffix list.
* **A record type the API adds later parses instead of failing the read.**
  `DnsRecord.type` and `ComposedRecord.type` are now a plain `str` on read (the
  `DnsRecordType` literal stays for annotations), and `is_known_type` tells a
  type this build knows from a newer one; `value` and `raw` stay intact. Same
  for a CAA `tag`. A missing, empty or non-string `type` still raises. This is
  more forgiving than `@dodomain/node`, which validates the response against
  the API's closed enum and refuses the whole body: the published OpenAPI v1
  contract grows its record-type enum additively (5 types, then 8), and this
  SDK's rule since 0.1.0 is that additive API changes never break a read (the
  `mode` field follows the same rule since 0.8.0). `sessions.create` still
  refuses a type outside the eight, since the API would refuse it too.

## 0.8.0

Parity with `@dodomain/node` 0.10.0: sandbox sessions (DoDomain PR #827,
T-18114).

### Added

* **`ConnectSessionSummary.mode` on every create response**, from both
  `POST /api/v1/sessions` and `POST /api/v1/keyless/sessions`: `"live"` (real
  DNS) or `"sandbox"`. Typed `str` (with the `ConnectSessionMode` literal for
  annotations) so a mode the API adds later parses; `None` only on a response
  from a deployment older than the field. A non-string `mode` still raises
  `InvalidResponseError`.
* **`SANDBOX_DOMAINS`**: the five reserved sandbox names (`verified.test`,
  `pending.test`, `slow.test`, `wrong-record.test`, `unsupported.test`). A
  session for one of them is simulated (no DNS, no provider call) and never
  counted against a plan or the keyless allowance. README "Sandbox domains".
* **Webhooks**: every connection and session event for a sandbox session carries
  `"sandbox": true` in `data` (absent, never `false`, on a live session's
  event). Documented in the README and `dodomain.webhooks`; `verify_webhook` is
  unchanged.

### Fixed

* **A keyless client no longer refuses a sandbox session.** 0.7.0 pinned the
  keyless response's `mode` to `"live"` and raised `InvalidResponseError` on the
  `"sandbox"` the API answers for a sandbox name.

### Internal

* `tests/fixtures/openapi_v1_shapes.json` regenerated from the monorepo's
  `apps/docs/public/openapi.json` (`mode` is now required on
  `CreateSessionResponse`); the prod e2e asserts a real domain's session is
  `live`.

## 0.7.0

Parity with `@dodomain/node` 0.9.2: keyless mode (node 0.9.0/0.9.1, DoDomain
T-18036) and API refusals that carry their readable text (node 0.9.2, DoDomain
PR #819, T-18329).

### Added

* **Keyless mode**: `DoDomain(keyless=True)` / `AsyncDoDomain(keyless=True)`,
  no account and no key. `sessions.create` calls
  `POST /api/v1/keyless/sessions`, answers the API's `428` with a solved
  SHA-256 proof of work (`DoDomain-Keyless-Proof`; never above 24 bits), solves
  a fresh challenge at most once more when the proved retry is refused as
  `proof_too_easy` / `proof_expired`, and keeps the returned `dd_ks_` key
  (`client.keyless_key`) so later calls need no proof. Concurrent creates on a
  fresh client start ONE keyless app. `keyless_key=` reuses an app across
  processes, `proof_timeout=` (seconds, above 0 and at most 300, default 120)
  bounds one solve, `app_name=` names the test app, and `abort=` (a
  `threading.Event`, or an `asyncio.Event` on the async client) stops the solve
  and the wait for another call's start. An explicit opt-in: a missing
  `secret_key` still raises.
* **`client.keyless.status()`**: `GET /api/v1/keyless`, the keyless app's
  allowance and claim link (`KeylessStatus`).
* **`ConnectSessionSummary.mode` / `.keyless`** (`KeylessSessionInfo`:
  `app_id`, `allowance`, `claim_url`, `unlock`, `docs`, `key`). The key and the
  claim link are kept out of `repr()`.
* **`DoDomainKeylessError`** (a `DoDomainAPIError`): every `KEYLESS_*` refusal
  from the API (`KEYLESS_PROOF_REQUIRED`, `KEYLESS_LIMIT_REACHED`,
  `KEYLESS_START_RATE_LIMITED`, `KEYLESS_CAPACITY_REACHED`,
  `KEYLESS_KEY_CLAIMED`, `KEYLESS_KEY_NOT_ACCEPTED`, `KEYLESS_DISABLED`,
  `KEYLESS_PLACEHOLDER_DOMAIN`) and the five the SDK raises itself with
  `status_code == 0` (`KEYLESS_PROOF_TIMEOUT`, `KEYLESS_PROOF_ABORTED`,
  `KEYLESS_PROOF_UNSUPPORTED`, `KEYLESS_KEY_MISSING`, `KEYLESS_MODE`). `code`
  is the `KEYLESS_*` code, `details` the refusal's details, and `retry_at` /
  `retry_after` read `details.retryAt` and `Retry-After` (else
  `details.retryAfterSeconds`). A keyless client refuses every secret-key call
  locally with `KEYLESS_MODE`.
* **`solve_keyless_proof` / `async_solve_keyless_proof`** and
  `KEYLESS_MAX_DIFFICULTY_BITS`, for callers that drive the REST API directly.
* **`DoDomainAPIError.error`** (the machine error, `body.error`) and
  **`.detail`** (the API's human text alone).

### Changed

* **`DoDomainAPIError.message`** is now one readable line: the machine error
  followed by the API's own text (RFC 9457 `detail`, else `message`), e.g.
  `'invalid_request: "customer.com" is a placeholder or reserved name, ...'`;
  the machine error alone when there is no text, or `HTTP <status>` when the
  body named no error. It used to be the raw `message` field and often `None`;
  that text is `.detail` now. `str(exc)` keeps its shape.
* **Every `dd_ks_` key in an error is redacted to `dd_ks_…`**, at any depth:
  `message`, `detail`, `details`, `body`, `code`, `error`, and
  `InvalidResponseError.payload`. Successful responses are left whole.
* A problem+json refusal that carries both `error` and a denial `code` now
  raises the exception class of its `error` (a 403 with
  `code: "SCOPE_MISSING"` is a `PermissionError_`, no longer the bare
  `DoDomainAPIError`); `.code` is unchanged.

## 0.6.0

Parity with `@dodomain/node` 0.8.0.

### Added

* **`CheckDomainResult.one_click_available`** (wire key `oneClickAvailable`,
  DoDomain PR #402) — `True` when the domain's DNS provider actually offers
  DoDomain's one-click: tier 1 (Cloudflare OAuth), or tier 2 where the provider
  serves at least one of DoDomain's Domain Connect templates. `tier == 2` alone
  only means the provider speaks Domain Connect (GoDaddy does and serves none,
  so `False`). `None` against a server that predates the field, so upgrading is
  a drop-in.

## 0.5.0

Parity with `@dodomain/node` 0.7.0 and the `/v1` contract changes it tracked:
webhook-endpoint auto-pause (DoDomain PR #342) and the apps list's white-label
connect-flow settings. Purely additive, so upgrading from 0.4.0 is a drop-in.

### Added

* **`webhook_endpoints.resume(endpoint_id)`** (sync and async) —
  `POST /api/v1/webhook-endpoints/{endpointId}/resume`. doDomain now pauses an
  endpoint by itself once it has had no successful delivery for 7 days and at
  least 5 dead-lettered deliveries in that span; this clears the pause and
  restarts the 7-day clock. Idempotent: an endpoint that is not paused comes back
  unchanged with a 200. It does not resend the deliveries skipped while paused —
  redrive those from the dashboard. Another app's endpoint id is a 404, as
  everywhere else.
* **`WebhookEndpoint.paused_at` / `WebhookEndpointWithSecret.paused_at`** — when
  the endpoint was auto-paused, or `None` while it is delivering. Carried through
  `WebhookEndpointWithSecret.endpoint`.
* **`App.connect_headline`, `.connect_subheadline`, `.connect_success_cta_label`,
  `.connect_success_redirect_url`, `.connect_font_preset`,
  `.hide_connect_footer_help`** — the white-label connect-flow settings the
  apps list has returned since 2026-09-23, as stored (`None` / `False` until
  configured). They render on the hosted flow only while the plan includes
  white-label.
* **`ConnectFontPreset`** — the `Literal["system", "humanist", "serif", "rounded"]`
  alias for `App.connect_font_preset`.

### Changed

* `webhook_endpoints.update` documents that a url which actually changes also
  resumes an auto-paused endpoint.
* The OpenAPI contract guard (`tests/test_openapi_contract.py`) now also pins
  `WebhookEndpointSummary` and `WebhookEndpointSecretResponse`, so a new required
  field on either fails the suite when the fixture is regenerated.

### Notes

* New response fields parse tolerantly, as before: a body recorded before the
  field existed reads as `None` / `False`, while a field present with the wrong
  type still fails loudly.
* Delivery statuses (including the new `skipped`) are not part of the public
  `/v1` contract and are not modelled by this SDK.

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
