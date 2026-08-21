# doDomain Python SDK

Official Python SDK for [doDomain](https://dodomain.io) — connect your customers'
custom domains without becoming a DNS support desk.

You mint a **connect session**, send the customer to a hosted flow that detects
their DNS provider and walks them through (or one-clicks) the records, and you get
a signed webhook when the domain goes live.

This SDK covers **all 16 callable REST operations**, sync and async, plus webhook
signature verification. (The API's other four routes are browser navigations that
answer `302` on every path; the SDK exposes them as URL builders and never fetches
them.)

## Install

```bash
pip install dodomain-sdk
```

Requires Python 3.10+. The only runtime dependency is `httpx`.

> The distribution is published as **`dodomain-sdk`**, but the import package is
> **`dodomain`** — `pip install dodomain-sdk`, then `from dodomain import DoDomain`.

## Authentication

Every authenticated call takes your app's **secret key** — a `dd_sk_…` value from
the doDomain dashboard (your app → API keys). Keep it server-side and read it from
the environment:

```bash
export DODOMAIN_SECRET_KEY="dd_sk_live_…"
```

```python
import os
from dodomain import DoDomain

client = DoDomain(secret_key=os.environ["DODOMAIN_SECRET_KEY"])
```

A secret key is **app-scoped** — the app is implicit in the key. If you are
integrating through OAuth instead (the MCP/agent path), pass the access token as
`secret_key`; the SDK detects it, and `app_id` then becomes required on
`sessions.create` because an OAuth token is team-scoped.

## Quickstart

```python
import os
from dodomain import DoDomain, DnsRecord

client = DoDomain(secret_key=os.environ["DODOMAIN_SECRET_KEY"])

session = client.sessions.create(
    domain="app.customer.com",
    records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
    return_url="https://customer.com/settings/domains",
)

print(session.connect_url)  # send your customer here
print(session.expires_at)  # 24 hours from now, timezone-aware

for record in session.records:
    print(record.fqdn)  # the name we will actually verify — check this
```

Render `session.connect_url` as a link or redirect. When the customer finishes,
doDomain fires a `connection.verified` webhook carrying `session.id` as
`sessionId`, so you can correlate it back to the row you just wrote.

**Read `session.records` before you show the customer anything.** The API composes
each `host` under your `domain`, so `domain="links.acme.com"` with `host="links"`
is verified at `links.links.acme.com` — a doubled label that used to surface only
as a mysteriously failing verify. `session.warnings` carries advisories about a
request that was accepted anyway (`duplicate_host_label` is the one that exists
today); a warning never changes the status code.

### Reading a session back

Two different reads, and the difference matters. **From your server, use
`sessions.get(session_id)`** — it takes your credential, it is addressable by the
`sessionId` every webhook carries, and it still answers after the session expired:

```python
state = client.sessions.get("cs_01HZX")
state.status  # "verified"
state.expired  # True once the 24h TTL passed — even before the reaper catches up
state.connection_id  # the DomainConnection id, or None if it never finalized
state.records  # composed names (type/host/fqdn) — no `value` on this arm
```

The **token-public** routes are the other read: they take the session token in the
path as the capability, send no credential at all, and are what a browser or a
customer-side process can call:

```python
public = client.sessions.retrieve(session.token)  # status, records, detected tier
detected = client.sessions.detect(session.token)  # provider, tier, manual guide
result = client.sessions.verify(session.token)  # check live DNS now

for record in result.records:
    print(record.fqdn, record.type, record.outcome)
```

`retrieve` raises `ExpiredError` forever once the TTL passes — correct for a
capability URL, useless for support, which is exactly why `get` exists.

Two endpoints are **browser navigations**, not API calls — they answer `302` on
every path. The SDK exposes them as URL builders so you can render your own CTA,
and never fetches them:

```python
session.cloudflare_start_url  # tier-1 Cloudflare OAuth flow
session.domain_connect_start_url  # tier-2 Domain Connect one-click
```

### Async

`AsyncDoDomain` has the identical resource tree, arguments and return types —
every method is awaitable and `list_all` is an async iterator.

```python
import asyncio
import os
from dodomain import AsyncDoDomain, DnsRecord


async def main() -> None:
    async with AsyncDoDomain(secret_key=os.environ["DODOMAIN_SECRET_KEY"]) as client:
        session = await client.sessions.create(
            domain="app.customer.com",
            records=[DnsRecord(type="CNAME", host="app", value="cname.dodomain.io")],
        )
        print(session.connect_url)

        async for connection in client.connections.list_all():
            print(connection.id, connection.status)


asyncio.run(main())
```

## Connections

A connection is a customer domain that went live. doDomain keeps checking its DNS
and tells you when it drifts.

```python
# Hold an id from a webhook? Read that one connection directly.
conn = client.connections.get("conn_123")
conn.status  # "active" | "broken"
conn.record_fqdns  # ("status.customer.com",) — the names we actually monitor
conn.disconnected_at  # not None => monitoring stopped

page = client.connections.list(limit=100)
page.connections  # tuple[Connection, ...]
page.next_cursor  # str | None — opaque, pass it straight back
page.has_more  # bool

# Auto-paginating iterator — the ergonomic default.
for connection in client.connections.list_all(domain="app.customer.com"):
    print(connection.id, connection.status, connection.verified_at)

# Include the ones you disconnected, to reconcile against the archive.
for connection in client.connections.list_all(include_disconnected=True):
    print(connection.id, connection.disconnected_at)
```

The cursor is **opaque by contract**. Pass `next_cursor` back unchanged; never
construct, parse or persist its internals.

```python
# Ask for an on-demand DNS re-check. Answers 202 — the outcome arrives as a
# connection.verified / connection.failed webhook, not in this response.
client.connections.reverify("conn_123")

# Stop monitoring a domain the customer removed from your product.
result = client.connections.disconnect("conn_123")
result.disconnected_at  # datetime
result.already_disconnected  # False on the call that did it, True on a repeat
```

`disconnect` is idempotent by construction: a repeat returns the *original*
`disconnected_at` and emits no second webhook.

A connection owned by another app or team answers **404, never 403** — the API
refuses to confirm that someone else's id exists, and this SDK does not
reinterpret that as a permission problem. `get` is the exception to the list's
default in one way: it *does* return a disconnected connection, because a caller
naming an id already knows the row exists.

> **Read `record_fqdns`, not `fqdn`.** `Connection.fqdn` has always been written
> as the session's *domain*, so a connection verified for `status.acme.com`
> reports `fqdn="acme.com"`. It cannot be fixed in place — a session may carry
> several records, so there is no single honest "the" fqdn — and it keeps its
> value for the integrators already reading it. `record_fqdns` carries the real
> answer: every name doDomain monitors for that connection.

## Webhook endpoints

Manage delivery targets from CI or IaC instead of the dashboard. **Secret-key
only** — an OAuth token is refused with a 403 whose
`exc.secret_key_required` is `True`.

```python
endpoint = client.webhook_endpoints.create(url="https://acme.example/webhooks/dodomain")
endpoint.secret  # "whsec_…" — SHOWN ONCE. Store it now.

for e in client.webhook_endpoints.list():
    print(e.id, e.url)  # never carries a secret

client.webhook_endpoints.update("whe_123", url="https://acme.example/v2")  # secret unchanged
rotated = client.webhook_endpoints.rotate_secret("whe_123")
rotated.secret  # the new one, also shown once

client.webhook_endpoints.delete("whe_123")
```

Three things that will bite if assumed away:

* **The signing secret is show-once.** `create` and `rotate_secret` return it and
  nothing else ever does. It is kept out of the object's `repr` so a traceback
  cannot spill it into your logs; read it off `.secret`.
* **Rotation is an immediate cutover.** There is no dual-secret window: signatures
  switch the moment the call returns, including retries of deliveries created
  before it. Deploy the new secret to your receiver first.
* **`get(endpoint_id)` is a client-side lookup over `list()`** — the API has no
  read-one route — so it costs one list request, and the `NotFoundError` it raises
  carries `status_code == 0` because no 404 came back from the server.

## Rotating your secret key

```python
rotated = client.keys.rotate()
rotated.secret_key  # the NEW dd_sk_… — the only copy that will ever exist
rotated.public_key  # unchanged, so CI can assert it rewrote the right app
rotated.previous_key_expires_at  # None: the old key is already dead
```

**The default is an immediate cutover.** The key you authenticated the call with
stops working the instant the response is produced. Write `rotated.secret_key` to
your secret store before doing anything else — drop it and you are locked out
until you rotate again from the dashboard. The client you called it on still
holds the old key; build a new one from the result.

### Rotating with no downtime

If you cannot deploy the new key in the same breath, ask for an overlap window
and **both keys authenticate** until it closes:

```python
rotated = client.keys.rotate(overlap_hours=24)  # 0 (default), 1 or 24
rotated.previous_key_expires_at  # when the OLD key stops working
```

Rotate, ship `rotated.secret_key` everywhere, and let the old one lapse on its
own. Three things to hold on to:

* **Exactly one previous key is ever kept.** Rotating again overwrites that slot
  and kills key n-1 immediately, whatever was left of its window — so the safe
  rhythm is rotate, deploy, *then* rotate again, never two rotations in a row.
* **A zero-overlap rotation is the kill switch.** `keys.rotate()` with the
  default also terminates a window still running from an earlier rotation, which
  is how you revoke a previous key early.
* The client you called it on keeps using the key it was built with, so within a
  window it keeps working; past the window its next call is a `401`.

There is deliberately no `keys.create`, `keys.list` or `keys.revoke`: key
inventory stays behind a human dashboard session, so a stolen key can never mint a
second hidden credential that survives you rotating the one you know about.
Rotating *is* the revoke.

## Domain pre-flight check

Find out how a domain would connect before you create anything. Stateless,
persists nothing, available on every plan:

```python
check = client.domains.check(domain="app.customer.com")

check.zone  # "customer.com" — the registrable apex DNS is managed at
check.provider  # "cloudflare"
check.tier  # 1 | 2 | 3
check.method  # "oauth" | "domain-connect" | "guided"
check.confidence  # "high" | "medium" | "low"
check.guide.steps  # copy-ready manual instructions
```

## Your apps

```python
for app in client.apps.list():
    print(app.id, app.name, app.public_key, app.sandbox)
```

A secret key sees exactly its own app — listing siblings would widen a single
leaked key into team-wide reconnaissance. The model carries no secret material.

## Verifying webhooks

doDomain signs every delivery Stripe-style:

```
x-dodomain-signature: t=<unix millis>,v1=<hex sha256 hmac>
x-dodomain-event: connection.verified
x-dodomain-delivery-id: whd_…
```

Verify against the **raw** request body, before any JSON parsing — re-serializing
a parsed body changes the bytes and the signature will not match.

```python
import json
import os
from dodomain import verify_webhook


@app.post("/webhooks/dodomain")
async def handle(request):
    raw = await request.body()
    signature = request.headers.get("x-dodomain-signature", "")

    if not verify_webhook(os.environ["DODOMAIN_WEBHOOK_SECRET"], raw, signature):
        return Response(status_code=400)

    event = json.loads(raw)
    ...
```

`verify_webhook(secret, body, header, tolerance_ms=300_000, now_ms=None) -> bool`

* `body` may be `str` or `bytes`; `secret` too.
* The replay window is five minutes by default.
* It **never raises**. A wrong secret, a tampered body, a stale timestamp, a
  malformed or missing `v1`, and outright garbage are all just `False` — an
  attacker cannot turn a crafted header into a 500 inside your handler.
* Comparison is constant-time.

### The delivered body

```json
{
  "id": "whd_…",
  "type": "connection.verified",
  "occurredAt": "2026-08-17T10:00:00.000Z",
  "data": { "sessionId": "cs_…", "connectionId": "conn_…" },
  "event": "connection.verified"
}
```

Read `type`. **Dedupe on `id`** — it is stable across retries and is the same
value as the `x-dodomain-delivery-id` header, so you can dedupe before parsing the
body at all. `event` is a **deprecated** alias of `type`, byte-identical to it,
kept only so receivers written before the 2026-08-06 envelope cutover keep
parsing; do not write new code against it.

`data` always carries `sessionId` as your correlation handle, and every payload
that announces a connection also carries `connectionId` — the id
`connections.get` / `reverify` / `disconnect` are keyed by.

Event types: `connection.verified`, `connection.failed`,
`connection.disconnected`, `session.completed`, `session.abandoned`. A receiver
that does not recognise a type must ignore it — the vocabulary grows additively.

> **No typed event parser ships, on purpose.** Both the event vocabulary and the
> payload fields grow additively, so a strict parser would reject a delivery the
> day the API adds a type — exactly the failure a webhook receiver must not have.
> `verify_webhook` checks the HMAC and nothing else, which is what makes it safe
> across every additive change.

## Error handling

Every failure is a subclass of `DoDomainError`. Nothing raw — not a
`JSONDecodeError` from a proxy's HTML 502, not an `httpx` timeout — escapes.

```python
from dodomain import DoDomainAPIError, NotFoundError, RateLimitError

try:
    client.connections.reverify("conn_123")
except NotFoundError:
    ...  # unknown id, or one you do not own
except RateLimitError as exc:
    print(exc.reason, exc.retry_after)
except DoDomainAPIError as exc:
    print(exc.code, exc.status_code, exc.message, exc.details)
```

| API `error` code | Exception | Status |
|---|---|---|
| `unauthorized` | `AuthenticationError` | 401 |
| `forbidden` | `PermissionError_` | 403 |
| `not_found` | `NotFoundError` | 404 |
| `expired` | `ExpiredError` | 410 |
| `invalid_request` | `InvalidRequestError` | 400 |
| `quota_exceeded` | `QuotaExceededError` | 402 |
| `not_configured` | `NotConfiguredError` | 503 |
| `conflict` | `ConflictError` | 409 |
| `rate_limited` | `RateLimitError` | 429 |
| `internal` | `InternalServerError` | 500 |
| *(anything else)* | `DoDomainAPIError` | as sent |

Plus, outside the HTTP layer: `DoDomainConfigError` (bad constructor options),
`DoDomainConnectionError` (no response was ever received), and
`InvalidResponseError` (a 2xx body that does not match the contract).

**`exc.message` is frequently `None`.** The API drops the message field on most
*thrown* errors, so do not build your user-facing string from it. `str(exc)`
synthesizes a useful one for you:

```
doDomain API error: POST /api/v1/sessions returned HTTP 402 (quota_exceeded)
```

An `InvalidRequestError` raised by the SDK's own input validation carries
`status_code == 0`: no request was sent.

## Rate limits

The plan cap starts at 60 requests/minute, in fixed 60-second windows. A 429
carries `Retry-After`, and — importantly — **two different meanings**:

```python
except RateLimitError as exc:
    if exc.reason == "recently_checked":
        # This ONE connection was DNS-checked inside its 10-minute cooldown.
        # Nothing global is throttled. Do NOT retry — show "checked recently,
        # try again in a few minutes". A backoff loop here only burns your plan
        # quota against the other limiter.
        show_cooldown_notice(exc.retry_after)
    else:                       # reason == "request_rate"
        # You are calling too fast. exc.limit is the per-minute cap.
        back_off(exc.retry_after)
```

The SDK already does the right thing for you: it retries `request_rate`
(honouring `Retry-After`) and raises `recently_checked` immediately.

`client.last_rate_limit` holds a snapshot of the most recent response's rate-limit
headers. The API emits only `Retry-After` today, so the IETF draft-11
`RateLimit-*` fields are `None`; they are read opportunistically so the SDK
already reports them the day the API adopts them.

## Client options

```python
client = DoDomain(
    secret_key="dd_sk_…",
    base_url="https://app.dodomain.io",  # the only origin that serves /api/v1
    timeout=30.0,
    max_retries=2,
    http_client=None,  # bring your own httpx.Client
)
```

* **Retries** apply to `GET` and `DELETE` only, on `429`/`5xx`/transport errors,
  with exponential backoff and full jitter (base 0.5s, cap 8s). A `Retry-After`
  above 60 seconds is raised rather than slept through.
* **`POST` is never retried.** The API has no server-side idempotency, so a
  replayed `POST /v1/sessions` would mint a second session and burn a second unit
  of plan quota. `sessions.verify` and `connections.disconnect` *are* idempotent
  server-side, so retrying those yourself is safe.
* **`idempotency_key`** is accepted on every write method and forwarded as
  `Idempotency-Key`. The API does not currently honour it; the plumbing is there
  so the eventual server-side landing is a non-event.
  `client.new_idempotency_key()` mints one.
* Both clients are context managers (`with` / `async with`) and expose `.close()`.
  An injected `http_client` is never closed by the SDK.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check . && ruff format --check . && ty check
pytest tests --ignore=tests/e2e --cov=dodomain --cov-fail-under=90
```

The unit suite mocks the wire with `respx` and asserts on the actual request —
URL, method, headers, JSON body — as well as the parsed return value, so it tests
the protocol rather than the mock.

`tests/fixtures/webhook_vectors.json` is generated by the **TypeScript**
`signWebhook` in the doDomain monorepo (`packages/core/src/webhook.ts`), executed
directly with `node --experimental-strip-types`. It is the guard against the
Python and TypeScript verifiers drifting apart.

`tests/e2e/` runs against production and **skips loudly** without
`DODOMAIN_SECRET_KEY`:

```bash
DODOMAIN_SECRET_KEY="dd_sk_…" pytest tests/e2e -v
```

This SDK is hand-written, not generated. doDomain does publish an OpenAPI 3.1
document — <https://dodomain.io/docs/openapi.json>, generated from the same zod
schemas the route handlers validate with — and it is the right thing to check this
SDK's shapes against, but the hand-written surface is deliberate: the naming, the
sync/async twins, the local validation and the docstrings that explain *why* an
endpoint behaves the way it does are the product here, and none of them survive a
generator.

## License

MIT © 2026 Devino Solutions Inc.
