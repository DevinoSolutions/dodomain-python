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
    "ComposedRecord",
    "Confidence",
    "ConnectFontPreset",
    "Connection",
    "ConnectionPage",
    "ConnectionStatus",
    "ConnectSessionSummary",
    "DeletedWebhookEndpoint",
    "DetectResult",
    "DisconnectResult",
    "DnsRecord",
    "DnsRecordType",
    "DomainConnectDiscovery",
    "DomainConnectRef",
    "IntegratorSession",
    "Method",
    "ProviderGuide",
    "PublicSession",
    "ReverifyResult",
    "RotatedSecretKey",
    "RotationOverlapHours",
    "Session",
    "SessionWarning",
    "Tier",
    "TlsIssuanceAdvisory",
    "TlsIssuanceAdvisoryCode",
    "TlsIssuanceAdvisorySeverity",
    "VerifyOutcome",
    "VerifyRecord",
    "VerifyResult",
    "WebhookEndpoint",
    "WebhookEndpointWithSecret",
]

DnsRecordType = Literal["A", "AAAA", "CNAME", "TXT", "MX"]
Tier = Literal[1, 2, 3]
Method = Literal["oauth", "domain-connect", "guided"]
Confidence = Literal["high", "medium", "low"]
ConnectionStatus = Literal["active", "broken"]
VerifyOutcome = Literal["verified", "propagating", "absent", "indeterminate", "domain_not_found"]
ApexToken = Literal["@", "(blank)", "%domain%"]
WarningCode = Literal["duplicate_host_label"]

#: Why a certificate issuance for a verified name may still fail. Transcribed
#: from ``TLS_ISSUANCE_ADVISORY_CODES`` in the app repo
#: (``packages/core/src/tls-issuance-advisories.ts``).
TlsIssuanceAdvisoryCode = Literal[
    "caa_excludes_issuer",
    "caa_restricts_issuance",
    "stale_acme_challenge",
    "tls_issuance_unchecked",
]

#: ``warning`` plausibly breaks issuance; ``info`` is a fact without a verdict.
TlsIssuanceAdvisorySeverity = Literal["warning", "info"]

#: How long the *previous* secret key keeps authenticating after a rotation.
#: ``0`` — the default — is an immediate cutover; ``1`` and ``24`` are the only
#: windows the API offers. Transcribed from ``zRotateAppSecretKeyInput`` in
#: ``packages/core/src/schemas.ts``; the server refuses anything else.
RotationOverlapHours = Literal[0, 1, 24]

#: The hosted connect flow's white-label typeface. Transcribed from
#: ``CONNECT_FONT_PRESETS`` in the app repo (``packages/core/src/schemas.ts``).
ConnectFontPreset = Literal["system", "humanist", "serif", "rounded"]

#: Every DNS record type a connect session may request, from the app repo's one
#: record-type home (``packages/core/src/record-capabilities.ts``).
RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "TXT", "MX")

#: The advisory codes and severities, for the runtime check the ``Literal``s
#: above only make at type-check time.
TLS_ISSUANCE_ADVISORY_CODES: tuple[str, ...] = (
    "caa_excludes_issuer",
    "caa_restricts_issuance",
    "stale_acme_challenge",
    "tls_issuance_unchecked",
)
TLS_ISSUANCE_ADVISORY_SEVERITIES: tuple[str, ...] = ("warning", "info")

#: The overlap windows ``keys.rotate`` accepts, for the runtime check the
#: ``Literal`` above only makes at type-check time.
OVERLAP_HOURS_VALUES: tuple[int, ...] = (0, 1, 24)

#: The font presets, for the runtime check :data:`ConnectFontPreset` only makes
#: at type-check time.
CONNECT_FONT_PRESETS: tuple[str, ...] = ("system", "humanist", "serif", "rounded")


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


def _opt_bool(payload: dict[str, Any], key: str) -> bool | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise _fail(f"field {key!r} should be a boolean or null", payload)
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


def _opt_list(payload: dict[str, Any], key: str) -> list[Any]:
    """Read an *additive* array field, treating absence as empty.

    Every array the API has grown since this SDK's first release — ``records`` and
    ``warnings`` on a create response, ``recordFqdns`` on a connection — arrived
    additively, so a body written before the field existed (a cached response, an
    archived payload, an older deployment) must still parse. A field that is
    *present* but not an array is still fatal: that is contract drift, not history.
    """
    if payload.get(key) is None:
        return []
    return _req_list(payload, key)


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
class ComposedRecord:
    """A requested record paired with the name doDomain will actually look up.

    The API composes ``host`` under the session's ``domain`` — a session for
    ``links.acme.com`` with ``host="links"`` is verified at
    ``links.links.acme.com``, which is the mistake this shape exists to make
    visible at create time rather than at the first failing verify.

    It deliberately carries **no** ``value``: the server omits it (``zComposedRecord``
    picks only ``type`` and ``host`` off the record schema), because these are the
    *names* being monitored, not the record contents. Read the value back off the
    :class:`DnsRecord` you sent, or off :attr:`PublicSession.records`.
    """

    type: DnsRecordType
    host: str
    fqdn: str
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> ComposedRecord:
        data = _obj(payload, "composed record")
        return cls(
            type=_literal(data, "type", RECORD_TYPES),
            host=_req_str(data, "host"),
            fqdn=_req_str(data, "fqdn"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class SessionWarning:
    """A non-fatal advisory on an *accepted* ``sessions.create``.

    A warning never changes the status code — the session was created either way.
    Branch on :attr:`code`; the vocabulary is closed and grows additively, so an
    unrecognised code must be treated as advisory rather than as an error.
    """

    code: str
    message: str
    host: str
    fqdn: str
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> SessionWarning:
        data = _obj(payload, "session warning")
        return cls(
            code=_req_str(data, "code"),
            message=_req_str(data, "message"),
            host=_req_str(data, "host"),
            fqdn=_req_str(data, "fqdn"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class TlsIssuanceAdvisory:
    """Why a certificate issuance for a verified name may still fail.

    Read from the domain's own nameservers on every verify pass (CAA policy plus
    a stale ``_acme-challenge`` record) and carried on four surfaces: the
    :class:`VerifyResult`, the :class:`IntegratorSession` read, and the
    ``connection.verified`` / ``session.completed`` webhook payloads.

    **It is advice about YOUR next step — issuing the certificate — and never
    part of the verify verdict.** ``verified`` and ``present`` are computed
    without it, so a consumer that ignores this field sees exactly the
    pre-advisory contract.

    An empty list means "we looked and found nothing". A check that could not
    complete is itself an entry (``tls_issuance_unchecked``), never silence —
    unknown is not the same answer as clean.

    Attributes:
        code: ``caa_excludes_issuer`` — a CAA policy leaves out the CA configured
            on the app (:attr:`App.tls_issuer_ca`).
            ``caa_restricts_issuance`` — a CAA policy exists and no CA is
            configured to judge it against.
            ``stale_acme_challenge`` — ``_acme-challenge.<fqdn>`` already holds a
            TXT or CNAME.
            ``tls_issuance_unchecked`` — the check itself could not complete.
        severity: ``warning`` plausibly breaks issuance for you; ``info`` is a
            fact we could not turn into a verdict.
        fqdn: The name the certificate is for.
        evidence_fqdn: Where the evidence was read — the CAA owner name (which may
            be a parent of ``fqdn``), or ``_acme-challenge.<fqdn>``.
        evidence: The published values behind the verdict, verbatim.
        note: One human-readable sentence.
    """

    code: TlsIssuanceAdvisoryCode
    severity: TlsIssuanceAdvisorySeverity
    fqdn: str
    evidence_fqdn: str
    evidence: tuple[str, ...]
    note: str
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> TlsIssuanceAdvisory:
        data = _obj(payload, "tls issuance advisory")
        return cls(
            code=_literal(data, "code", TLS_ISSUANCE_ADVISORY_CODES),
            severity=_literal(data, "severity", TLS_ISSUANCE_ADVISORY_SEVERITIES),
            fqdn=_req_str(data, "fqdn"),
            evidence_fqdn=_req_str(data, "evidenceFqdn"),
            evidence=_str_list(data, "evidence"),
            note=_req_str(data, "note"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class ConnectSessionSummary:
    """A freshly minted connect session — the response of ``sessions.create``.

    Named for what it is: the summary of ONE connect session. The old name,
    ``Session``, was the third meaning of "session" in the platform (there is
    also the dashboard login session and the server-side ``ConnectSession`` row),
    so ``@dodomain/node`` 0.5.0 renamed its twin to ``ConnectSessionSummary`` and
    this SDK follows. :data:`Session` remains as a deprecated alias.

    Attributes:
        id: Stable session id; it is also the ``sessionId`` on every webhook.
        token: The capability for the token-public routes and the hosted flow.
        expires_at: 24 hours after creation.
        connect_url: Send the customer here.
        records: The fully-qualified names this session will be verified at — one
            per record you sent. Check these before showing the customer anything:
            they are where a doubled label (``links.links.acme.com``) becomes
            obvious.
        warnings: Advisories about the request that was nonetheless accepted.
            Empty for a clean create.
    """

    id: str
    token: str
    expires_at: datetime
    connect_url: str
    #: Both additive fields carry defaults and therefore sit after the four
    #: original ones — a Python dataclass cannot put a defaulted field before an
    #: undefaulted one, and reordering the originals would break positional
    #: construction for anyone who already writes ``Session(...)`` in a test.
    records: tuple[ComposedRecord, ...] = ()
    warnings: tuple[SessionWarning, ...] = ()
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
    def _from_api(cls, payload: Any, *, base_url: str) -> ConnectSessionSummary:
        data = _obj(payload, "session")
        return cls(
            id=_req_str(data, "id"),
            token=_req_str(data, "token"),
            expires_at=_req_datetime(data, "expiresAt"),
            connect_url=_req_str(data, "connectUrl"),
            records=tuple(ComposedRecord._from_api(item) for item in _opt_list(data, "records")),
            warnings=tuple(SessionWarning._from_api(item) for item in _opt_list(data, "warnings")),
            base_url=base_url,
            raw=data,
        )


#: Deprecated alias for :class:`ConnectSessionSummary`, kept so existing
#: ``from dodomain import Session`` imports and ``isinstance`` checks keep
#: working. It is the SAME class object, not a subclass or a copy, so equality
#: and ``repr`` are unchanged. ``@dodomain/node`` 0.5.0 made the same move and
#: marked its alias for removal in the next major; this one goes at the same
#: time. Switch your imports now.
Session = ConnectSessionSummary


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
class IntegratorSession:
    """A session read back **by its id, with your credential** — ``sessions.get``.

    The same path as :meth:`~dodomain.resources.sessions.Sessions.retrieve` serves
    both arms, discriminated by the shape of the segment, and the two answer
    genuinely different shapes. Two things only this one can do:

    * **It is addressable by the id webhooks carry.** Every payload names
      ``sessionId``, never the token, so a ``session.abandoned`` receiver can ask
      what actually happened without having stored the token at creation.
    * **It reads an expired session.** The token arm answers 410 forever once the
      TTL passes — correct for a capability URL, useless for support, because the
      moment you most want the final state is after the session died.

    Two shape differences from :class:`PublicSession` that will bite if assumed away:

    * :attr:`records` are :class:`ComposedRecord`s — ``type``/``host``/``fqdn``, and
      **no ``value``**. The server omits it here.
    * There is no ``return_url``; there is an ``app_id``, a ``connection_id`` and a
      derived :attr:`expired`.

    ``status`` and ``tier`` stay loose (``str`` / ``int | None``) for the same reason
    they do on :class:`PublicSession`: the server types them as a bare string and a
    nullable int, and a ``Literal`` here would turn an additive server-side status
    into a client crash.
    """

    id: str
    app_id: str
    domain: str
    records: tuple[ComposedRecord, ...]
    recipe: str | None
    status: str
    tier: int | None
    detected_provider: str | None
    #: The ``DomainConnection.id`` once the session finalized; ``None`` until then.
    connection_id: str | None
    created_at: datetime
    expires_at: datetime
    #: Derived server-side at read (``expires_at <= now``), so it is already ``True``
    #: in the window before the reaper persists ``status == "expired"``. Trust this
    #: over ``status`` when you need to know whether the session is over.
    expired: bool
    #: The TLS-issuance advisories the LAST verify pass computed — a snapshot of
    #: DNS at that moment, not a live read, and empty until a verify has run.
    #: Additive on the wire, so it carries a default and sits after the original
    #: fields; see :class:`TlsIssuanceAdvisory`.
    tls_issuance_advisories: tuple[TlsIssuanceAdvisory, ...] = ()
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> IntegratorSession:
        data = _obj(payload, "session")
        return cls(
            id=_req_str(data, "id"),
            app_id=_req_str(data, "appId"),
            domain=_req_str(data, "domain"),
            records=tuple(ComposedRecord._from_api(item) for item in _req_list(data, "records")),
            recipe=_opt_str(data, "recipe"),
            status=_req_str(data, "status"),
            tier=_opt_int(data, "tier"),
            detected_provider=_opt_str(data, "detectedProvider"),
            connection_id=_opt_str(data, "connectionId"),
            created_at=_req_datetime(data, "createdAt"),
            expires_at=_req_datetime(data, "expiresAt"),
            expired=_req_bool(data, "expired"),
            tls_issuance_advisories=tuple(
                TlsIssuanceAdvisory._from_api(item)
                for item in _opt_list(data, "tlsIssuanceAdvisories")
            ),
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
    #: What the domain's OWN nameservers answered for this name. This is the set
    #: ``present`` is decided from; when it disagrees with what you asked for, it
    #: is the answer to "what did they put there instead". Additive on the wire.
    authoritative_found: tuple[str, ...] = ()
    #: The same answers from a public recursive resolver. Informational only — it
    #: never gates ``present``, and trailing :attr:`authoritative_found` is the
    #: ordinary, healthy meaning of ``outcome == "propagating"``. Additive.
    public_found: tuple[str, ...] = ()
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
            authoritative_found=tuple(str(item) for item in _opt_list(data, "authoritativeFound")),
            public_found=tuple(str(item) for item in _opt_list(data, "publicFound")),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The result of checking a session's records against live DNS.

    :attr:`advisories` is about the certificate you will issue NEXT, not about
    whether the records are there — it never feeds :attr:`verified`. Ignoring it
    leaves you with exactly the pre-advisory contract.
    """

    verified: bool
    records: tuple[VerifyRecord, ...]
    #: TLS-issuance advisories for this session's TLS-terminating records
    #: (A/AAAA/CNAME), read on the same pass. Empty means "we looked and found
    #: nothing"; a check that could not complete is an entry, not silence.
    #: Additive on the wire, so it carries a default.
    advisories: tuple[TlsIssuanceAdvisory, ...] = ()
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> VerifyResult:
        data = _obj(payload, "verify result")
        return cls(
            verified=_req_bool(data, "verified"),
            records=tuple(VerifyRecord._from_api(item) for item in _req_list(data, "records")),
            advisories=tuple(
                TlsIssuanceAdvisory._from_api(item) for item in _opt_list(data, "advisories")
            ),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class Connection:
    """A live (or archived) custom-domain connection.

    ``status`` keeps the last observed DNS health even after a disconnect — read
    ``disconnected_at is not None`` as "monitoring stopped", not ``status``.

    **Read :attr:`record_fqdns`, not :attr:`fqdn`.** ``fqdn`` has always been
    written as the session's *domain*, so a connection verified for the record
    ``status.acme.com`` reports ``fqdn="acme.com"``. It is not fixable in place (a
    session may carry several records, so there is no single honest "the" fqdn) and
    it keeps its value for the integrators already reading it. Treat it as an
    alias of :attr:`domain`.
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
    #: Every fully-qualified name doDomain actually monitors for this connection.
    #: Additive on the wire, so it carries a default and sits after the original
    #: fields; empty only for a session whose records are missing or malformed, or
    #: for a payload recorded before the API grew the field.
    record_fqdns: tuple[str, ...] = ()
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
            record_fqdns=tuple(str(item) for item in _opt_list(data, "recordFqdns")),
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
    #: The CAA issuer-domain your end-user certificates are issued with (e.g.
    #: ``"letsencrypt.org"``); ``None`` until it is configured in the dashboard.
    #: It is what turns a CAA policy into a ``caa_excludes_issuer`` advisory
    #: rather than the weaker ``caa_restricts_issuance``. Additive on the wire,
    #: so it carries a default and sits after the original fields.
    tls_issuer_ca: str | None = None
    #: White-label connect-flow settings (Pro and Scale), as stored; ``None`` until
    #: configured. They render on the hosted connect flow only while your plan
    #: includes white-label. Additive on the wire, so they carry defaults.
    connect_headline: str | None = None
    connect_subheadline: str | None = None
    connect_success_cta_label: str | None = None
    #: Where the success button goes when a session has no ``return_url`` of its own.
    connect_success_redirect_url: str | None = None
    connect_font_preset: ConnectFontPreset | None = None
    hide_connect_footer_help: bool = False
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
            tls_issuer_ca=_opt_str(data, "tlsIssuerCa"),
            connect_headline=_opt_str(data, "connectHeadline"),
            connect_subheadline=_opt_str(data, "connectSubheadline"),
            connect_success_cta_label=_opt_str(data, "connectSuccessCtaLabel"),
            connect_success_redirect_url=_opt_str(data, "connectSuccessRedirectUrl"),
            connect_font_preset=_literal(data, "connectFontPreset", (*CONNECT_FONT_PRESETS, None)),
            hide_connect_footer_help=_opt_bool(data, "hideConnectFooterHelp") or False,
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


@dataclass(frozen=True, slots=True)
class WebhookEndpoint:
    """One delivery target for your app's webhooks.

    **No ``secret`` field, ever.** The signing secret is returned once, by
    ``create`` and by ``rotate_secret``, on :class:`WebhookEndpointWithSecret`. A
    secret on this shape would turn "list your endpoints" into a
    secret-disclosure endpoint, so no read surface carries one.
    """

    id: str
    app_id: str
    #: The *normalized* URL the server stored, not the string you sent — a
    #: trailing-slash variant comes back canonical.
    url: str
    created_at: datetime
    #: When doDomain AUTO-PAUSED this endpoint — no successful delivery for 7 days
    #: and at least 5 dead-lettered deliveries in that span — or ``None`` while it
    #: is delivering normally. While paused, new events are recorded as *skipped*
    #: deliveries and never sent, until ``webhook_endpoints.resume`` (or an
    #: ``update`` that actually changes the url) clears it.
    paused_at: datetime | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> WebhookEndpoint:
        data = _obj(payload, "webhook endpoint")
        return cls(
            id=_req_str(data, "id"),
            app_id=_req_str(data, "appId"),
            url=_req_str(data, "url"),
            created_at=_req_datetime(data, "createdAt"),
            paused_at=_opt_datetime(data, "pausedAt"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class WebhookEndpointWithSecret:
    """An endpoint plus its plaintext signing secret — **shown once**.

    Returned only by ``webhook_endpoints.create`` and
    ``webhook_endpoints.rotate_secret``. Persist :attr:`secret` from this object
    now: no read surface returns it again, and rotation is the only way back.

    A sibling of :class:`WebhookEndpoint` rather than a subclass of it, so that a
    value carrying a secret can never be passed where a secret-free summary is
    expected — and so ``isinstance(x, WebhookEndpoint)`` stays a reliable "this one
    is safe to log".

    Rotation is an **immediate cutover** — the worker reads the secret live at
    delivery time, so signatures switch at once, including retries of deliveries
    created before the rotation. There is no dual-secret window, so deploy the new
    secret to your receiver promptly.
    """

    id: str
    app_id: str
    url: str
    created_at: datetime
    #: ``whsec_…`` — store it now. Kept out of ``repr`` so an exception traceback
    #: or a debug print of this object cannot spill the signing secret into a log.
    secret: str = field(repr=False)
    #: See :attr:`WebhookEndpoint.paused_at`.
    paused_at: datetime | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @property
    def endpoint(self) -> WebhookEndpoint:
        """The same endpoint without the secret, safe to hand onward or log."""
        return WebhookEndpoint(
            id=self.id,
            app_id=self.app_id,
            url=self.url,
            created_at=self.created_at,
            paused_at=self.paused_at,
            raw=self.raw,
        )

    @classmethod
    def _from_api(cls, payload: Any) -> WebhookEndpointWithSecret:
        data = _obj(payload, "webhook endpoint")
        return cls(
            id=_req_str(data, "id"),
            app_id=_req_str(data, "appId"),
            url=_req_str(data, "url"),
            created_at=_req_datetime(data, "createdAt"),
            secret=_req_str(data, "secret"),
            paused_at=_opt_datetime(data, "pausedAt"),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class DeletedWebhookEndpoint:
    """The acknowledgement of ``webhook_endpoints.delete``.

    A body rather than a bare 204 so an automated caller can log *what* it removed.
    Past deliveries survive as evidence, but a failed one can no longer be
    redriven — deleting an endpoint is not reversible.
    """

    id: str
    deleted: bool
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> DeletedWebhookEndpoint:
        data = _obj(payload, "delete result")
        return cls(id=_req_str(data, "id"), deleted=_req_bool(data, "deleted"), raw=data)


@dataclass(frozen=True, slots=True)
class RotatedSecretKey:
    """The result of ``keys.rotate`` — a new secret key, **shown once**.

    :attr:`secret_key` is the only copy that will ever exist, whichever overlap you
    asked for. With the default immediate cutover the previous key stopped
    authenticating the instant this response was produced, so a caller that drops
    the new one has locked itself out of the API and must rotate again from the
    dashboard.

    :attr:`previous_key_expires_at` is the whole difference an overlap window
    makes: ``None`` when the old key is already dead, otherwise the moment it
    stops authenticating.

    :attr:`public_key` is echoed *unchanged* — it identifies the app in the widget
    and is not rotated here. Assert on it to prove a CI job rewrote the right app's
    secret.
    """

    app_id: str
    public_key: str
    #: Kept out of ``repr`` for the same reason the webhook secret is: a traceback
    #: that prints this object must not put a live credential in your logs.
    secret_key: str = field(repr=False)
    rotated_at: datetime
    #: When the PREVIOUS key stops authenticating, or ``None`` if it already has
    #: (a zero-overlap rotation, which is the default). Only ever one previous
    #: key exists — a later rotation replaces it and kills key n-1 immediately.
    #: Also ``None`` on a response recorded before the field existed.
    previous_key_expires_at: datetime | None = None
    raw: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def _from_api(cls, payload: Any) -> RotatedSecretKey:
        data = _obj(payload, "rotated key")
        return cls(
            app_id=_req_str(data, "appId"),
            public_key=_req_str(data, "publicKey"),
            secret_key=_req_str(data, "secretKey"),
            rotated_at=_req_datetime(data, "rotatedAt"),
            previous_key_expires_at=_opt_datetime(data, "previousKeyExpiresAt"),
            raw=data,
        )
