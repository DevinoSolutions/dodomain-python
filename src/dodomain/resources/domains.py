"""Stateless domain pre-flight.

``domains.check`` answers "which provider hosts this domain, which tier will it
get, and what are the manual steps if it comes to that" *without* creating a
session or persisting anything. Available on every plan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dodomain._transport import RequestSpec
from dodomain.errors import InvalidRequestError
from dodomain.models import CheckDomainResult

if TYPE_CHECKING:  # pragma: no cover
    from dodomain._client import AsyncDoDomain, DoDomain

__all__ = ["AsyncDomains", "Domains"]

MAX_DOMAIN_LENGTH = 253


def _spec_check(domain: str, idempotency_key: str | None) -> RequestSpec:
    if not isinstance(domain, str):
        raise InvalidRequestError(
            "invalid_request", status_code=0, message="domain must be a string."
        )
    value = domain.strip()
    # `zCheckDomainInput` is looser than `zCreateSessionInput` on purpose (a
    # 1-253 char trimmed string, no hostname regex) — a pre-flight check should
    # answer for anything worth checking. Only the bounds are enforced here.
    if not value or len(value) > MAX_DOMAIN_LENGTH:
        raise InvalidRequestError(
            "invalid_request",
            status_code=0,
            message="domain must be between 1 and 253 characters.",
        )
    return RequestSpec(
        "POST",
        "/api/v1/domains/check",
        json_body={"domain": value},
        idempotency_key=idempotency_key,
    )


class Domains:
    """``client.domains``"""

    def __init__(self, client: DoDomain) -> None:
        self._client = client

    def check(self, *, domain: str, idempotency_key: str | None = None) -> CheckDomainResult:
        """Find out how a domain would connect, before creating a session.

        Args:
            domain: The hostname to inspect. Detection runs against its
                registrable apex (``customer.com`` for ``app.customer.com``).
            idempotency_key: Forwarded as ``Idempotency-Key``; not honoured by the
                API today. This call is read-only anyway.

        Returns:
            A :class:`~dodomain.models.CheckDomainResult`.
        """
        return CheckDomainResult._from_api(
            self._client.request(_spec_check(domain, idempotency_key))
        )


class AsyncDomains:
    """``client.domains`` on :class:`~dodomain.AsyncDoDomain`."""

    def __init__(self, client: AsyncDoDomain) -> None:
        self._client = client

    async def check(self, *, domain: str, idempotency_key: str | None = None) -> CheckDomainResult:
        """Find out how a domain would connect. See :meth:`Domains.check`."""
        return CheckDomainResult._from_api(
            await self._client.request(_spec_check(domain, idempotency_key))
        )
