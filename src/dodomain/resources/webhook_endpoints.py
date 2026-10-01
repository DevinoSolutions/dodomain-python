"""Webhook endpoints — where doDomain delivers your events.

The REST half of what the dashboard's Webhooks card does, so endpoints can be
managed from CI or IaC instead of clicked.

**Secret-key only.** Every method here needs the app's own ``dd_sk_`` key; an
OAuth access token is refused with ``403 forbidden`` and ``details.code ==
"SECRET_KEY_REQUIRED"`` (read it off
:attr:`~dodomain.errors.PermissionError_.secret_key_required`). That is a
deliberate refusal rather than a scope nobody invented: endpoint lifecycle is
credential lifecycle, and an agent token must not be able to repoint your
webhooks.

**The signing secret is show-once.** ``create`` and ``rotate_secret`` return it;
:meth:`WebhookEndpoints.list` and :meth:`WebhookEndpoints.update` never do,
because a summary that carried a secret would make "list my endpoints" a
disclosure endpoint.

Ownership is the usual non-enumerating stance: another app's endpoint id and a
nonexistent one both answer **404**.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from dodomain._transport import RequestSpec
from dodomain.errors import InvalidRequestError, InvalidResponseError, NotFoundError
from dodomain.models import (
    DeletedWebhookEndpoint,
    WebhookEndpoint,
    WebhookEndpointWithSecret,
)

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncWebhookEndpoints", "WebhookEndpoints"]

_COLLECTION = "/api/v1/webhook-endpoints"


def _require_id(endpoint_id: str) -> str:
    if not isinstance(endpoint_id, str) or not endpoint_id.strip():
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="a webhook endpoint id is required."
        )
    return endpoint_id


def _endpoint_path(endpoint_id: str, suffix: str = "") -> str:
    return f"{_COLLECTION}/{quote(_require_id(endpoint_id), safe='')}{suffix}"


def _validate_url(url: str) -> str:
    """Refuse an obviously unusable URL locally; leave the real policy to the API.

    The URL rule (https-only, no localhost or private literals, normalization) has
    ONE home, server-side, and a second weaker copy here would drift from it. So
    this checks only what cannot possibly be right — an empty or non-string value —
    and lets the API answer for everything else with its own message.
    """
    if not isinstance(url, str) or not url.strip():
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="a webhook endpoint url is required."
        )
    return url.strip()


def _spec_create(url: str, idempotency_key: str | None) -> RequestSpec:
    return RequestSpec(
        "POST", _COLLECTION, json_body={"url": _validate_url(url)}, idempotency_key=idempotency_key
    )


def _spec_update(endpoint_id: str, url: str, idempotency_key: str | None) -> RequestSpec:
    return RequestSpec(
        "PATCH",
        _endpoint_path(endpoint_id),
        json_body={"url": _validate_url(url)},
        idempotency_key=idempotency_key,
    )


def _spec_resume(endpoint_id: str, idempotency_key: str | None) -> RequestSpec:
    # A verb sub-path with no body, like rotate-secret: resuming is an action, not a
    # property you set.
    return RequestSpec(
        "POST", _endpoint_path(endpoint_id, "/resume"), idempotency_key=idempotency_key
    )


def _parse_list(payload: Any) -> tuple[WebhookEndpoint, ...]:
    items = payload.get("endpoints") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise InvalidResponseError(
            "doDomain response: missing or non-array field 'endpoints'", payload=payload
        )
    return tuple(WebhookEndpoint._from_api(item) for item in items)


def _pick(endpoints: tuple[WebhookEndpoint, ...], endpoint_id: str) -> WebhookEndpoint:
    """Find one endpoint in the app's own list, or raise the 404 the API would.

    ``status_code == 0`` marks this as the SDK's own answer: no ``GET
    /v1/webhook-endpoints/{id}`` request was ever sent, because the API has no such
    route (see :meth:`WebhookEndpoints.get`).
    """
    for endpoint in endpoints:
        if endpoint.id == endpoint_id:
            return endpoint
    raise NotFoundError(
        "not_found",
        status_code=0,
        message=(
            f"no webhook endpoint {endpoint_id!r} belongs to this app. "
            "An id that exists under another app is indistinguishable from one that "
            "does not exist at all — the same answer the API gives."
        ),
    )


class WebhookEndpoints:
    """``client.webhook_endpoints``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def list(self) -> tuple[WebhookEndpoint, ...]:
        """Every endpoint this app delivers to. Never carries a signing secret."""
        return _parse_list(self._client.request(RequestSpec("GET", _COLLECTION)))

    def get(self, endpoint_id: str) -> WebhookEndpoint:
        """One endpoint, by id.

        **This is a client-side lookup over** :meth:`list` **— the API has no
        ``GET /v1/webhook-endpoints/{id}`` route.** It therefore costs one list
        request, and the :class:`~dodomain.errors.NotFoundError` it raises for an
        unknown id carries ``status_code == 0`` because no 404 ever came back from
        the server. The answer is the same either way: the list contains exactly
        this app's endpoints, so an id missing from it is either someone else's or
        nobody's, which is precisely what the API refuses to distinguish.
        """
        # Validated BEFORE the list call, not inside the argument list: Python
        # evaluates arguments left to right, so `_pick(self.list(), _require_id(x))`
        # would spend a request before rejecting an obviously empty id.
        wanted = _require_id(endpoint_id)
        return _pick(self.list(), wanted)

    def create(self, *, url: str, idempotency_key: str | None = None) -> WebhookEndpointWithSecret:
        """Register an endpoint and receive its signing secret — **once**.

        Store ``result.secret`` now: no read surface returns it again, and the only
        way to a known secret afterwards is :meth:`rotate_secret`, which invalidates
        the old one immediately.

        Raises:
            InvalidRequestError: The URL policy rejected it, or this app already
                delivers to that URL.
            QuotaExceededError: The plan's endpoint cap is spent.
        """
        return WebhookEndpointWithSecret._from_api(
            self._client.request(_spec_create(url, idempotency_key))
        )

    def update(
        self, endpoint_id: str, *, url: str, idempotency_key: str | None = None
    ) -> WebhookEndpoint:
        """Repoint an endpoint at a new URL.

        The signing secret is untouched — moving hosts must not force a receiver to
        re-key. ``url`` is the only mutable field an endpoint has. A ``url`` that
        actually changes also resumes an auto-paused endpoint (see :meth:`resume`).
        """
        return WebhookEndpoint._from_api(
            self._client.request(_spec_update(endpoint_id, url, idempotency_key))
        )

    def delete(
        self, endpoint_id: str, *, idempotency_key: str | None = None
    ) -> DeletedWebhookEndpoint:
        """Stop delivering to an endpoint.

        Past deliveries survive as history, but a *failed* delivery to a deleted
        endpoint can no longer be redriven. This is not reversible.
        """
        return DeletedWebhookEndpoint._from_api(
            self._client.request(
                RequestSpec("DELETE", _endpoint_path(endpoint_id), idempotency_key=idempotency_key)
            )
        )

    def rotate_secret(
        self, endpoint_id: str, *, idempotency_key: str | None = None
    ) -> WebhookEndpointWithSecret:
        """Mint a new signing secret for one endpoint and receive it — **once**.

        **Immediate cutover, no dual-secret window.** The delivery worker reads the
        secret live, so signatures switch the moment this returns — including
        retries of deliveries created before the rotation. Deploy the new secret to
        your receiver before you rotate, or accept a gap of rejected deliveries.
        """
        return WebhookEndpointWithSecret._from_api(
            self._client.request(
                RequestSpec(
                    "POST",
                    _endpoint_path(endpoint_id, "/rotate-secret"),
                    idempotency_key=idempotency_key,
                )
            )
        )

    def resume(self, endpoint_id: str, *, idempotency_key: str | None = None) -> WebhookEndpoint:
        """Resume an endpoint doDomain paused automatically.

        doDomain pauses an endpoint once it has had no successful delivery for 7
        days **and** at least 5 dead-lettered deliveries in that span;
        :attr:`~dodomain.models.WebhookEndpoint.paused_at` is set while it is. This
        clears ``paused_at`` and restarts the 7-day clock.

        **Idempotent:** an endpoint that is not paused comes back unchanged (a 200,
        not an error). Events that happened while it was paused were recorded as
        *skipped* deliveries and are **not** resent by this call — redrive them
        from the dashboard. An :meth:`update` that changes the url resumes the
        endpoint too.
        """
        return WebhookEndpoint._from_api(
            self._client.request(_spec_resume(endpoint_id, idempotency_key))
        )


class AsyncWebhookEndpoints:
    """``client.webhook_endpoints`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def list(self) -> tuple[WebhookEndpoint, ...]:
        """Every endpoint this app delivers to. See :meth:`WebhookEndpoints.list`."""
        return _parse_list(await self._client.request(RequestSpec("GET", _COLLECTION)))

    async def get(self, endpoint_id: str) -> WebhookEndpoint:
        """One endpoint, by id. See :meth:`WebhookEndpoints.get`."""
        wanted = _require_id(endpoint_id)
        return _pick(await self.list(), wanted)

    async def create(
        self, *, url: str, idempotency_key: str | None = None
    ) -> WebhookEndpointWithSecret:
        """Register an endpoint. See :meth:`WebhookEndpoints.create`."""
        return WebhookEndpointWithSecret._from_api(
            await self._client.request(_spec_create(url, idempotency_key))
        )

    async def update(
        self, endpoint_id: str, *, url: str, idempotency_key: str | None = None
    ) -> WebhookEndpoint:
        """Repoint an endpoint. See :meth:`WebhookEndpoints.update`."""
        return WebhookEndpoint._from_api(
            await self._client.request(_spec_update(endpoint_id, url, idempotency_key))
        )

    async def delete(
        self, endpoint_id: str, *, idempotency_key: str | None = None
    ) -> DeletedWebhookEndpoint:
        """Stop delivering to an endpoint. See :meth:`WebhookEndpoints.delete`."""
        return DeletedWebhookEndpoint._from_api(
            await self._client.request(
                RequestSpec("DELETE", _endpoint_path(endpoint_id), idempotency_key=idempotency_key)
            )
        )

    async def rotate_secret(
        self, endpoint_id: str, *, idempotency_key: str | None = None
    ) -> WebhookEndpointWithSecret:
        """Mint a new signing secret. See :meth:`WebhookEndpoints.rotate_secret`."""
        return WebhookEndpointWithSecret._from_api(
            await self._client.request(
                RequestSpec(
                    "POST",
                    _endpoint_path(endpoint_id, "/rotate-secret"),
                    idempotency_key=idempotency_key,
                )
            )
        )

    async def resume(
        self, endpoint_id: str, *, idempotency_key: str | None = None
    ) -> WebhookEndpoint:
        """Resume an auto-paused endpoint. See :meth:`WebhookEndpoints.resume`."""
        return WebhookEndpoint._from_api(
            await self._client.request(_spec_resume(endpoint_id, idempotency_key))
        )
