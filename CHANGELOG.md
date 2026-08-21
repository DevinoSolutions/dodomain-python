# Changelog

Notable changes to `dodomain-sdk`. The import package is `dodomain`.

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
