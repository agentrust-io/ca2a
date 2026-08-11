"""Attenuated delegation: signed credentials whose scope narrows at each hop.

The semantics here mirror the signed A2A delegation chain implemented and
tested in agent-manifest (https://github.com/agentrust-io/agent-manifest);
this package is the runtime-side model and verifier the cA2A peer path calls.
"""

from ca2a_runtime.delegation.credential import (
    DelegationCredential,
    canonical_bytes,
    new_keypair,
    verify_chain,
)
from ca2a_runtime.delegation.holder import (
    HolderProof,
    build_holder_proof,
    verify_holder_proof,
)

__all__ = [
    "DelegationCredential",
    "HolderProof",
    "build_holder_proof",
    "canonical_bytes",
    "new_keypair",
    "verify_chain",
    "verify_holder_proof",
]
