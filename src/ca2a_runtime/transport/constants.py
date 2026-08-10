"""Stable A2A extension namespace for the cA2A profile overlay.

These URIs identify the cA2A v0.1 profile extension on A2A v1.x. Clients opt in
via the ``A2A-Extensions`` HTTP header (or equivalent binding metadata) using
:data:`EXTENSION_URI`. Profile data rides in A2A ``metadata`` maps under the
namespaced keys below. See ``docs/spec/transport.md``.
"""

from __future__ import annotations

EXTENSION_URI = "https://agentrust-io.com/extensions/ca2a/v0.1"

KEY_DELEGATION_CHAIN = f"{EXTENSION_URI}/delegation_chain"
KEY_REQUESTED_CAPABILITY = f"{EXTENSION_URI}/requested_capability"
KEY_RECORD_ID = f"{EXTENSION_URI}/record_id"
KEY_PARENT_RECORD_HASH = f"{EXTENSION_URI}/parent_record_hash"
KEY_SEALED_PAYLOAD = f"{EXTENSION_URI}/sealed_payload"

#: The caller's own attested channel key, bound to a challenge the callee issued.
#: Optional, unlike ``parent_record_hash``: a caller that cannot attest omits the
#: key entirely rather than sending null, and is still served by default. Making it
#: required would break every caller that exists today.
KEY_CALLER_OFFER = f"{EXTENSION_URI}/caller_offer"

CA2A_METADATA_KEYS = frozenset(
    {
        KEY_DELEGATION_CHAIN,
        KEY_REQUESTED_CAPABILITY,
        KEY_RECORD_ID,
        KEY_PARENT_RECORD_HASH,
        KEY_SEALED_PAYLOAD,
        KEY_CALLER_OFFER,
    }
)
