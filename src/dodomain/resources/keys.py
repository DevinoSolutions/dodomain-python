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
from dodomain._validation import validate_overlap_hours
from dodomain.models import RotatedSecretKey, RotationOverlapHours

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncKeys", "Keys"]

_ROTATE_PATH = "/api/v1/keys/rotate"


def _rotate_spec(overlap_hours: RotationOverlapHours) -> RequestSpec:
    """Build the rotate call, sending a body only when a window was asked for.

    The default cutover goes on the wire as **no body at all** — byte for byte
    the request every server version has ever accepted, including the ones that
    predate ``overlapHours``. Only a requested window sends the newer body, so
    the common call cannot be broken by a server that has not shipped the field.
    """
    hours = validate_overlap_hours(overlap_hours)
    body = None if hours == 0 else {"overlapHours": hours}
    return RequestSpec("POST", _ROTATE_PATH, json_body=body)


class Keys:
    """``client.keys``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def rotate(self, *, overlap_hours: RotationOverlapHours = 0) -> RotatedSecretKey:
        """Rotate the calling app's secret key and receive the new one — **once**.

        The response is the only copy of the replacement whichever window you
        choose. Write ``result.secret_key`` to your secret store *before* you do
        anything else; a caller that drops it has locked itself out of the API and
        must rotate again from the dashboard.

        **The default is an immediate cutover.** With ``overlap_hours=0`` the key
        you authenticated this very call with stops working the instant the
        response is produced. That is also the kill switch: a zero-overlap
        rotation **terminates an overlap window still running** from an earlier
        rotation, so it is how you revoke a previous key early.

        **An overlap window is opt-in.** ``overlap_hours=1`` or ``24`` keeps the
        old key authenticating alongside the new one until
        ``result.previous_key_expires_at``, which is how you deploy a new key with
        no downtime: rotate, ship the new key everywhere, and let the old one
        lapse. **Exactly one previous key is ever kept** — rotating again
        overwrites that slot and key n-1 dies immediately, whatever was left of
        its window. So the safe rhythm is rotate, deploy, *then* rotate again, not
        two rotations in a row.

        ``result.public_key`` comes back unchanged — it identifies your app in the
        widget and is not rotated here — which is what lets a CI job assert it just
        rewrote the right app's secret.

        The client you called this on still holds the **old** key in memory. Build a
        new client from ``result.secret_key`` for subsequent calls; this SDK does
        not silently re-key a live client, because a rotation you did not notice is
        worse than one that fails loudly. Within an overlap window that client
        keeps working until the window closes; without one its next call is a 401.

        Args:
            overlap_hours: ``0`` (default), ``1`` or ``24``. Anything else is
                refused locally, before the request that would mint a key.

        Raises:
            InvalidRequestError: With ``status_code == 0``, when ``overlap_hours``
                is not a window the API offers.
            PermissionError_: With
                :attr:`~dodomain.errors.PermissionError_.secret_key_required` set,
                when called with an OAuth access token rather than a ``dd_sk_`` key.
        """
        return RotatedSecretKey._from_api(self._client.request(_rotate_spec(overlap_hours)))


class AsyncKeys:
    """``client.keys`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def rotate(self, *, overlap_hours: RotationOverlapHours = 0) -> RotatedSecretKey:
        """Rotate the calling app's secret key. See :meth:`Keys.rotate`."""
        return RotatedSecretKey._from_api(await self._client.request(_rotate_spec(overlap_hours)))
