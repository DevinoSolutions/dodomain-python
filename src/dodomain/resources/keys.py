"""Credential rotation — the automatable half of key lifecycle.

One method, and the narrowness is the design. There is no ``keys.create``,
``keys.list`` or ``keys.revoke`` in this SDK because the API has none: key
*inventory* stays behind a human dashboard session on purpose. A stolen ``dd_sk_``
can already do everything your app can do until it is rotated, but it must not be
able to mint a second, hidden credential that survives you rotating the one you
know about. Self-rotation gives an attacker nothing new and gives you an
automatable kill switch — rotating *is* the revoke.

**Secret-key only.** An OAuth access token is refused with ``403 forbidden`` and
``details.code == "SECRET_KEY_REQUIRED"``; nothing in the scope grammar covers
credential lifecycle, and an agent token minting app credentials is not a
capability to hand out as a side effect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dodomain._transport import RequestSpec
from dodomain.models import RotatedSecretKey

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncKeys", "Keys"]

_ROTATE_SPEC = RequestSpec("POST", "/api/v1/keys/rotate")


class Keys:
    """``client.keys``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def rotate(self) -> RotatedSecretKey:
        """Rotate the calling app's secret key and receive the new one — **once**.

        **There is no grace window.** The key you authenticated this very call with
        stopped working the instant the response was produced, and the response is
        the only copy of the replacement. Write ``result.secret_key`` to your secret
        store *before* you do anything else; a caller that drops it has locked
        itself out of the API and must rotate again from the dashboard.

        ``result.public_key`` comes back unchanged — it identifies your app in the
        widget and is not rotated here — which is what lets a CI job assert it just
        rewrote the right app's secret.

        The client you called this on still holds the **old** key in memory. Build a
        new client from ``result.secret_key`` for subsequent calls; this SDK does
        not silently re-key a live client, because a rotation you did not notice is
        worse than one that fails loudly.

        Raises:
            PermissionError_: With
                :attr:`~dodomain.errors.PermissionError_.secret_key_required` set,
                when called with an OAuth access token rather than a ``dd_sk_`` key.
        """
        return RotatedSecretKey._from_api(self._client.request(_ROTATE_SPEC))


class AsyncKeys:
    """``client.keys`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def rotate(self) -> RotatedSecretKey:
        """Rotate the calling app's secret key. See :meth:`Keys.rotate`."""
        return RotatedSecretKey._from_api(await self._client.request(_ROTATE_SPEC))
