# doDomain Python SDK

Official Python SDK for [doDomain](https://dodomain.io) — connect your customers'
custom domains without becoming a DNS support desk.

You mint a **connect session**, send the customer to a hosted flow that detects
their DNS provider and walks them through (or one-clicks) the records, and you get
a signed webhook when the domain goes live.

This SDK covers **all 9 REST operations**, sync and async, plus webhook signature
verification.

## Install

```bash
pip install dodomain
```

Requires Python 3.10+. The only runtime dependency is `httpx`.

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
```

Render `session.connect_url` as a link or redirect. When the customer finishes,
doDomain fires a `connection.verified` webhook carrying `session.id` as
`sessionId`, so you can correlate it back to the row you just wrote.

You can also drive the flow yourself with the **token-public** routes — they take
the session token in the path as the capability and send no credential at all:

```python
public = client.sessions.retrieve(session.token)  # status, records, detected tier
detected = client.sessions.detect(session.token)  # provider, tier, manual guide
result = client.sessions.verify(session.token)  # check live DNS now

for record in result.records:
    print(record.fqdn, record.type, record.outcome)
```

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
reinterpret that as a permission problem.

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

Event types: `connection.verified`, `connection.failed`,
`connection.disconnected`, `session.completed`, `session.abandoned`. A receiver
that does not recognise a type must ignore it — the vocabulary grows additively.

> **No typed event parser ships in 0.1.0, on purpose.** The delivered body is
> still the legacy `{event, data}` shape while the versioned `{id, type,
> occurredAt, data}` envelope waits on a deliberate cutover. `verify_webhook`
> only checks the HMAC and is wire-format agnostic, so it is safe across that
> change; a typed parser would not be.

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

This SDK is hand-written against the API's zod contract
(`packages/core/src/schemas.ts`) and its route handlers — doDomain publishes no
OpenAPI document, so there is nothing to generate from.

## License

MIT © 2026 Devino Solutions Inc.
