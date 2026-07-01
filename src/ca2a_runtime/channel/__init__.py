"""Sealed peer channel: seal a task payload to a peer's attested measurement.

Not yet implemented (Tier 2, see ROADMAP.md). The interface is defined so the
runtime peer path can be written against it while the enclave-sealing backend
is built on the cmcp TEE primitives.
"""

from ca2a_runtime.channel.sealed import SealedChannel

__all__ = ["SealedChannel"]
