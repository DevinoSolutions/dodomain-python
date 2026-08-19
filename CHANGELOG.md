# Changelog

Notable changes to `dodomain-sdk`. The import package is `dodomain`.

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
