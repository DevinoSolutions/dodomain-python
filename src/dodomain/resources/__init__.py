"""Resource namespaces hung off the client (``client.sessions``, ``client.apps``…).

Each module holds module-level ``_spec_*`` helpers that build a
:class:`~dodomain._transport.RequestSpec` and ``_parse_*`` helpers that turn a
payload into a model. The sync and async classes both call those helpers, so the
two surfaces can only ever differ in *how* the request is awaited — never in what
is sent or how the answer is read.
"""

from __future__ import annotations
