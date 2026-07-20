"""Stable A2A extension namespace for the cA2A profile overlay.

These URIs identify the cA2A v0.1 profile extension on A2A v1.x. Clients opt in
via the ``A2A-Extensions`` HTTP header (or equivalent binding metadata) using
:data:`EXTENSION_URI`. Profile data rides in A2A ``metadata`` maps under the
namespaced keys below. See ``docs/spec/transport.md``.
"""

from __future__ import annotations

EXTENSION_URI = "https://agentrust.io/extensions/ca2a/v0.1"

KEY_DELEGATION_CHAIN = f"{EXTENSION_URI}/delegation_chain"
KEY_REQUESTED_CAPABILITY = f"{EXTENSION_URI}/requested_capability"
KEY_RECORD_ID = f"{EXTENSION_URI}/record_id"
KEY_PARENT_RECORD_HASH = f"{EXTENSION_URI}/parent_record_hash"
KEY_SEALED_PAYLOAD = f"{EXTENSION_URI}/sealed_payload"

CA2A_METADATA_KEYS = frozenset(
    {
        KEY_DELEGATION_CHAIN,
        KEY_REQUESTED_CAPABILITY,
        KEY_RECORD_ID,
        KEY_PARENT_RECORD_HASH,
        KEY_SEALED_PAYLOAD,
    }
)
