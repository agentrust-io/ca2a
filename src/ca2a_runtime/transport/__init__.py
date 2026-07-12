"""Transport-side adapters that parse wire formats into PeerRequest.

The cA2A profile does not define a transport. Adapters in this package live
outside the profile core: they map A2A (or other) wire shapes into
``PeerRequest`` for ``handle_peer_request``.
"""

from ca2a_runtime.transport.a2a_adapter import (
    attach_ca2a_metadata,
    collect_metadata,
    has_ca2a_metadata,
    parse_peer_request,
)
from ca2a_runtime.transport.constants import (
    CA2A_METADATA_KEYS,
    EXTENSION_URI,
    KEY_DELEGATION_CHAIN,
    KEY_PARENT_RECORD_HASH,
    KEY_RECORD_ID,
    KEY_REQUESTED_CAPABILITY,
    KEY_SEALED_PAYLOAD,
)

__all__ = [
    "CA2A_METADATA_KEYS",
    "EXTENSION_URI",
    "KEY_DELEGATION_CHAIN",
    "KEY_PARENT_RECORD_HASH",
    "KEY_RECORD_ID",
    "KEY_REQUESTED_CAPABILITY",
    "KEY_SEALED_PAYLOAD",
    "attach_ca2a_metadata",
    "collect_metadata",
    "has_ca2a_metadata",
    "parse_peer_request",
]
