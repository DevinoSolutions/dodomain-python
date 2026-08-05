"""Your doDomain apps.

A ``dd_sk_`` key sees exactly its **own** app — listing siblings would widen a
single leaked key into team-wide reconnaissance. An OAuth token with ``apps:read``
sees every app in the team.

The response carries no secret material (``secretKeyHash`` is deliberately absent
from the contract and must never appear), so :class:`~dodomain.models.App` has no
field for one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dodomain._transport import RequestSpec
from dodomain.errors import InvalidResponseError
from dodomain.models import App

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["Apps", "AsyncApps"]

_LIST_SPEC = RequestSpec("GET", "/api/v1/apps")


def _parse_apps(payload: object) -> tuple[App, ...]:
    items = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise InvalidResponseError(
            "doDomain response: missing or non-array field 'apps'", payload=payload
        )
    return tuple(App._from_api(item) for item in items)


class Apps:
    """``client.apps``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def list(self) -> tuple[App, ...]:
        """List the apps this credential can see.

        With a secret key this returns exactly one app, and the SDK remembers its
        id so a later contradicting ``app_id`` argument fails locally instead of
        round-tripping for a 400.
        """
        apps = _parse_apps(self._client.request(_LIST_SPEC))
        if not self._client.is_oauth and len(apps) == 1:
            self._client._known_app_id = apps[0].id
        return apps


class AsyncApps:
    """``client.apps`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def list(self) -> tuple[App, ...]:
        """List the apps this credential can see. See :meth:`Apps.list`."""
        apps = _parse_apps(await self._client.request(_LIST_SPEC))
        if not self._client.is_oauth and len(apps) == 1:
            self._client._known_app_id = apps[0].id
        return apps
