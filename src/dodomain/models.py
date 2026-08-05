"""Frozen dataclasses for every shape the API returns.

Three rules hold everywhere in this module:

1. **Explicit field mapping.** Each model has a ``_from_api`` classmethod that
   names every wire key it reads. There is no magic ``camelCase`` -> ``snake_case``
   converter, so an API field rename surfaces as a failing test rather than a
   silently-``None`` attribute.
2. **Unknown fields are ignored, never fatal.** The API adds fields additively
   (``scope`` on ``connection.failed``, ``disconnectedAt`` on connections). Models
   never splat ``**payload`` into a constructor, and the untouched wire dict stays
   available on ``.raw``.
3. **A missing or mistyped *required* field is fatal.** It raises
   :class:`~dodomain.errors.InvalidResponseError` instead of handing back an
   object that lies about the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from urllib.parse import quote

from .errors import InvalidResponseError

__all__ = [
    "App",
    "CheckDomainResult",
    "Confidence",
    "Connection",
    "ConnectionPage",
    "ConnectionStatus",
    "DetectResult",
    "DisconnectResult",
    "DnsRecord",
    "DnsRecordType",
    "DomainConnectDiscovery",
    "DomainConnectRef",
    "Method",
    "ProviderGuide",
    "PublicSession",
    "ReverifyResult",
    "Session",
    "Tier",
    "VerifyOutcome",
    "VerifyRecord",
    "VerifyResult",
]

DnsRecordType = Literal["A", "AAAA", "CNAME", "TXT", "MX"]
Tier = Literal[1, 2, 3]
Method = Literal["oauth", "domain-connect", "guided"]
Confidence = Literal["high", "medium", "low"]
ConnectionStatus = Literal["active", "broken"]
VerifyOutcome = Literal["verified", "propagating", "absent", "indeterminate", "domain_not_found"]
ApexToken = Literal["@", "(blank)", "%domain%"]

#: Every DNS record type a connect session may request, from the app repo's one
#: record-type home (``packages/core/src/record-capabilities.ts``).
RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "TXT", "MX")


# ── payload readers ─────────────────────────────────────────────────────────


def _fail(message: str, payload: Any) -> InvalidResponseError:
    return InvalidResponseError(f"doDomain response: {message}", payload=payload)


def _obj(payload: Any, where: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _fail(f"expected an object for {where}, got {type(payload).__name__}", payload)
    return payload


def _req_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise _fail(f"missing or non-string field {key!r}", payload)
    return value


def _opt_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _fail(f"field {key!r} should be a string or null", payload)
    return value


def _req_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise _fail(f"missing or non-boolean field {key!r}", payload)
    return value


def _req_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"missing or non-integer field {key!r}", payload)
    return value


def _opt_int(payload: dict[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"field {key!r} should be an integer or null", payload)
    return value


def _req_list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise _fail(f"missing or non-array field {key!r}", payload)
    return value


def _str_list(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    return tuple(str(item) for item in _req_list(payload, key))


def _opt_str_list(payload: dict[str, Any], key: str) -> tuple[str, ...] | None:
    if payload.get(key) is None:
        return None
    return _str_list(payload, key)


def parse_datetime(value: str, *, payload: Any = None) -> datetime:
    """Parse an API timestamp into a timezone-aware ``datetime``.

    Every timestamp the API emits is ``z.iso.datetime()`` — ISO-8601 UTC with a
    trailing ``Z``. Python 3.11+ parses that natively; 3.10 needs the ``Z``
    rewritten first, which is why this helper exists instead of a bare
    ``fromisoformat`` call at each site.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise _fail(f"unparseable timestamp {value!r}", payload) from exc


def _req_datetime(payload: dict[str, Any], key: str) -> datetime:
    return parse_datetime(_req_str(payload, key), payload=payload)


def _opt_datetime(payload: dict[str, Any], key: str) -> datetime | None:
    value = _opt_str(payload, key)
    return None if value is None else parse_datetime(value, payload=payload)


def _literal(payload: dict[str, Any], key: str, allowed: tuple[Any, ...]) -> Any:
    value = payload.get(key)
    if value not in allowed:
        raise _fail(f"field {key!r} was {value!r}, expected one of {allowed!r}", payload)
    return value


# ── models ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DnsRecord:
    """One DNS record the customer has to end up with.

    Used both as input to :meth:`dodomain.resources.sessions.Sessions.create` and
    as output on :class:`PublicSession`.

    Args:
        type: One of ``A``, ``AAAA``, ``CNAME``, ``TXT``, ``MX``.
        host: The name relative to the session's domain. ``"@"`` is the apex.
        value: The record's value (for ``MX``, the mail exchange).
        priority: Required for ``MX`` and rejected for nothing else — RFC 5321
            requires the preference and the API refuses an ``MX`` without one
            rather than defaulting it.
        ttl: Optional TTL in seconds.
    """

    type: DnsRecordType
    host: str
    value: str
    priority: int | None = None
    ttl: int | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    def to_api(self) -> dict[str, Any]:
        """The wire shape this record is sent as."""
        payload: dict[str, Any] = {"type": self.type, "host": self.host, "value": self.value}
        if self.priority is not None:
            payload["priority"] = self.priority
        if self.ttl is not None:
            payload["ttl"] = self.ttl
        return payload

    @classmethod
    def _from_api(cls, payload: Any) -> DnsRecord:
        data = _obj(payload, "record")
        return cls(
            type=_literal(data, "type", RECORD_TYPES),
            host=_req_str(data, "host"),
            value=_req_str(data, "value"),
            priority=_opt_int(data, "priority"),
            ttl=_opt_int(data, "ttl"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class Session:
    """A freshly minted connect session — the response of ``sessions.create``.

    Attributes:
        id: Stable session id; it is also the ``sessionId`` on every webhook.
        token: The capability for the token-public routes and the hosted flow.
        expires_at: 24 hours after creation.
        connect_url: Send the customer here.
    """

    id: str
    token: str
    expires_at: datetime
    connect_url: str
    base_url: str = "https://app.dodomain.io"
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @property
    def cloudflare_start_url(self) -> str:
        """URL that starts the Cloudflare OAuth (tier-1) connect flow.

        This is a **browser navigation** endpoint: it answers ``302`` on every
        path, success and failure alike. Render it as a link or redirect the
        customer to it — never fetch it with an HTTP client.
        """
        return f"{self.base_url}/api/v1/sessions/{quote(self.token, safe='')}/cloudflare/start"

    @property
    def domain_connect_start_url(self) -> str:
        """URL that starts the Domain Connect (tier-2) one-click flow.

        Browser navigation only, exactly like :attr:`cloudflare_start_url`.
        """
        return f"{self.base_url}/api/v1/sessions/{quote(self.token, safe='')}/domain-connect/start"

    @classmethod
    def _from_api(cls, payload: Any, *, base_url: str) -> Session:
        data = _obj(payload, "session")
        return cls(
            id=_req_str(data, "id"),
            token=_req_str(data, "token"),
            expires_at=_req_datetime(data, "expiresAt"),
            connect_url=_req_str(data, "connectUrl"),
            base_url=base_url,
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class PublicSession:
    """A session read back through the token-public ``GET /v1/sessions/{token}``.

    ``status`` and ``tier`` are deliberately loose (``str`` / ``int | None``): the
    server types them as a bare string and a nullable int, and pinning a
    ``Literal`` here would make an additive server-side status a client crash.
    """

    id: str
    domain: str
    records: tuple[DnsRecord, ...]
    recipe: str | None
    status: str
    tier: int | None
    detected_provider: str | None
    return_url: str | None
    expires_at: datetime
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> PublicSession:
        data = _obj(payload, "session")
        return cls(
            id=_req_str(data, "id"),
            domain=_req_str(data, "domain"),
            records=tuple(DnsRecord._from_api(item) for item in _req_list(data, "records")),
            recipe=_opt_str(data, "recipe"),
            status=_req_str(data, "status"),
            tier=_opt_int(data, "tier"),
            detected_provider=_opt_str(data, "detectedProvider"),
            return_url=_opt_str(data, "returnUrl"),
            expires_at=_req_datetime(data, "expiresAt"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class ProviderGuide:
    """Copy-ready manual instructions for the detected DNS provider."""

    provider: str
    label: str
    host_format: str
    apex_token: ApexToken
    steps: tuple[str, ...]
    dashboard_url: str | None = None
    notes: tuple[str, ...] | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> ProviderGuide:
        data = _obj(payload, "guide")
        return cls(
            provider=_req_str(data, "provider"),
            label=_req_str(data, "label"),
            host_format=_req_str(data, "hostFormat"),
            apex_token=_literal(data, "apexToken", ("@", "(blank)", "%domain%")),
            steps=_str_list(data, "steps"),
            dashboard_url=_opt_str(data, "dashboardUrl"),
            notes=_opt_str_list(data, "notes"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class DomainConnectRef:
    """The Domain Connect provider behind a detected zone."""

    provider_id: str
    provider_name: str
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> DomainConnectRef:
        data = _obj(payload, "domainConnect")
        return cls(
            provider_id=_req_str(data, "providerId"),
            provider_name=_req_str(data, "providerName"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class DomainConnectDiscovery:
    """Domain Connect discovery outcome on ``domains.check``.

    ``discovered=False`` means the provider ids are absent, not empty.
    """

    discovered: bool
    provider_id: str | None = None
    provider_name: str | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> DomainConnectDiscovery:
        data = _obj(payload, "domainConnect")
        return cls(
            discovered=_req_bool(data, "discovered"),
            provider_id=_opt_str(data, "providerId"),
            provider_name=_opt_str(data, "providerName"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class DetectResult:
    """Which provider hosts this session's domain and how it can be connected.

    Attributes:
        zone: The registrable apex (eTLD+1) the customer manages DNS at —
            ``customer.com`` for a session connecting ``app.customer.com``.
        domain_connect_ready: ``True`` only when this exact session can one-click
            through Domain Connect. Fail-closed: any probe failure answers
            ``False`` and the manual-records flow stands.
    """

    provider: str
    label: str
    zone: str
    tier: Tier
    method: Method
    confidence: Confidence
    name_servers: tuple[str, ...]
    domain_connect: DomainConnectRef | None
    domain_connect_ready: bool
    guide: ProviderGuide
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> DetectResult:
        data = _obj(payload, "detect result")
        dc = data.get("domainConnect")
        return cls(
            provider=_req_str(data, "provider"),
            label=_req_str(data, "label"),
            zone=_req_str(data, "zone"),
            tier=_literal(data, "tier", (1, 2, 3)),
            method=_literal(data, "method", ("oauth", "domain-connect", "guided")),
            confidence=_literal(data, "confidence", ("high", "medium", "low")),
            name_servers=_str_list(data, "nameServers"),
            domain_connect=None if dc is None else DomainConnectRef._from_api(dc),
            domain_connect_ready=_req_bool(data, "domainConnectReady"),
            guide=ProviderGuide._from_api(data.get("guide")),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class CheckDomainResult:
    """Stateless pre-flight: what would happen if you connected this domain."""

    domain: str
    zone: str
    provider: str
    label: str
    tier: Tier
    method: Method
    confidence: Confidence
    name_servers: tuple[str, ...]
    domain_connect: DomainConnectDiscovery
    guide: ProviderGuide
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> CheckDomainResult:
        data = _obj(payload, "check result")
        return cls(
            domain=_req_str(data, "domain"),
            zone=_req_str(data, "zone"),
            provider=_req_str(data, "provider"),
            label=_req_str(data, "label"),
            tier=_literal(data, "tier", (1, 2, 3)),
            method=_literal(data, "method", ("oauth", "domain-connect", "guided")),
            confidence=_literal(data, "confidence", ("high", "medium", "low")),
            name_servers=_str_list(data, "nameServers"),
            domain_connect=DomainConnectDiscovery._from_api(data.get("domainConnect")),
            guide=ProviderGuide._from_api(data.get("guide")),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class VerifyRecord:
    """One record's live-DNS outcome.

    ``outcome`` distinguishes "we looked and it is not there" (``absent``) from
    "the authoritative lookup itself failed" (``indeterminate``) and from "the
    domain does not resolve at all" (``domain_not_found``) — a retry helps only
    for ``propagating``.
    """

    fqdn: str
    type: str
    present: bool
    note: str
    outcome: VerifyOutcome
    authoritative_error: str | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> VerifyRecord:
        data = _obj(payload, "verify record")
        return cls(
            fqdn=_req_str(data, "fqdn"),
            type=_req_str(data, "type"),
            present=_req_bool(data, "present"),
            note=_req_str(data, "note"),
            outcome=_literal(
                data,
                "outcome",
                ("verified", "propagating", "absent", "indeterminate", "domain_not_found"),
            ),
            authoritative_error=_opt_str(data, "authoritativeError"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The result of checking a session's records against live DNS."""

    verified: bool
    records: tuple[VerifyRecord, ...]
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> VerifyResult:
        data = _obj(payload, "verify result")
        return cls(
            verified=_req_bool(data, "verified"),
            records=tuple(VerifyRecord._from_api(item) for item in _req_list(data, "records")),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class Connection:
    """A live (or archived) custom-domain connection.

    ``status`` keeps the last observed DNS health even after a disconnect — read
    ``disconnected_at is not None`` as "monitoring stopped", not ``status``.
    """

    id: str
    app_id: str
    session_id: str
    domain: str
    fqdn: str
    status: ConnectionStatus
    verified_at: datetime | None
    last_checked_at: datetime | None
    broken_at: datetime | None
    disconnected_at: datetime | None
    created_at: datetime
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> Connection:
        data = _obj(payload, "connection")
        return cls(
            id=_req_str(data, "id"),
            app_id=_req_str(data, "appId"),
            session_id=_req_str(data, "sessionId"),
            domain=_req_str(data, "domain"),
            fqdn=_req_str(data, "fqdn"),
            status=_literal(data, "status", ("active", "broken")),
            verified_at=_opt_datetime(data, "verifiedAt"),
            last_checked_at=_opt_datetime(data, "lastCheckedAt"),
            broken_at=_opt_datetime(data, "brokenAt"),
            disconnected_at=_opt_datetime(data, "disconnectedAt"),
            created_at=_req_datetime(data, "createdAt"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class ConnectionPage:
    """One page of connections plus the opaque cursor for the next.

    The cursor is opaque **by contract**. Pass ``next_cursor`` straight back to
    ``connections.list``; never construct, parse or persist its internals.
    """

    connections: tuple[Connection, ...]
    next_cursor: str | None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @property
    def has_more(self) -> bool:
        """``True`` when another page exists."""
        return self.next_cursor is not None

    @classmethod
    def _from_api(cls, payload: Any) -> ConnectionPage:
        data = _obj(payload, "connection page")
        return cls(
            connections=tuple(
                Connection._from_api(item) for item in _req_list(data, "connections")
            ),
            next_cursor=_opt_str(data, "nextCursor"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class App:
    """One of your doDomain apps. Carries no secret material and never will."""

    id: str
    name: str
    public_key: str
    sandbox: bool
    logo_url: str | None
    brand_color: str | None
    created_at: datetime
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> App:
        data = _obj(payload, "app")
        return cls(
            id=_req_str(data, "id"),
            name=_req_str(data, "name"),
            public_key=_req_str(data, "publicKey"),
            sandbox=_req_bool(data, "sandbox"),
            logo_url=_opt_str(data, "logoUrl"),
            brand_color=_opt_str(data, "brandColor"),
            created_at=_req_datetime(data, "createdAt"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class DisconnectResult:
    """The outcome of ``connections.disconnect``.

    ``already_disconnected`` is how you tell "I just disconnected it" from "it was
    already gone": a repeat DELETE returns the *original* ``disconnected_at`` and
    emits no second webhook.
    """

    id: str
    disconnected_at: datetime
    already_disconnected: bool
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> DisconnectResult:
        data = _obj(payload, "disconnect result")
        return cls(
            id=_req_str(data, "id"),
            disconnected_at=_req_datetime(data, "disconnectedAt"),
            already_disconnected=_req_bool(data, "alreadyDisconnected"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class ReverifyResult:
    """The 202 acknowledgement of ``connections.reverify``.

    Deliberately not a job id: the check may coalesce with an already-queued one.
    The real result arrives as a ``connection.verified`` / ``connection.failed``
    webhook.
    """

    accepted: bool
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> ReverifyResult:
        data = _obj(payload, "reverify result")
        return cls(accepted=_req_bool(data, "accepted"), raw=data)
