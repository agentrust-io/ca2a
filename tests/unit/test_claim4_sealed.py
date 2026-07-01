"""Claim 4: sealed-payload confidentiality.

The confidentiality property (payload decrypts only inside the attested peer
measurement) is GATED on Tier 2 and is not implemented in this release. What we
can and do test now is the fail-closed contract of the placeholder: seal() and
open() raise SealedChannelError instead of silently emitting plaintext. The
confidentiality property itself is a skipped placeholder pending Tier 2.
"""

from __future__ import annotations

import pytest

from ca2a_runtime.channel import SealedChannel
from ca2a_runtime.errors import SealedChannelError

PEER_MEASUREMENT = "sha256:" + "ab" * 32


def test_seal_fails_closed() -> None:
    channel = SealedChannel(peer_measurement=PEER_MEASUREMENT)
    with pytest.raises(SealedChannelError):
        channel.seal(b"confidential task payload")


def test_open_fails_closed() -> None:
    channel = SealedChannel(peer_measurement=PEER_MEASUREMENT)
    with pytest.raises(SealedChannelError):
        channel.open(b"sealed blob")


def test_seal_error_carries_tier2_signal() -> None:
    channel = SealedChannel(peer_measurement=PEER_MEASUREMENT)
    with pytest.raises(SealedChannelError) as excinfo:
        channel.seal(b"confidential task payload")
    exc = excinfo.value
    assert exc.code == "SEALED_CHANNEL_ERROR"
    assert exc.detail is not None
    assert "Tier 2" in exc.detail


@pytest.mark.skip(
    reason="Confidentiality property gated on Tier 2: the enclave-sealing "
    "backend (payload decrypts only under the attested peer measurement) is "
    "not implemented in this release. See ROADMAP.md."
)
def test_payload_decrypts_only_under_attested_peer_measurement() -> None:
    channel = SealedChannel(peer_measurement=PEER_MEASUREMENT)
    payload = b"confidential task payload"
    sealed = channel.seal(payload)
    assert sealed != payload
    assert channel.open(sealed) == payload
    wrong_peer = SealedChannel(peer_measurement="sha256:" + "cd" * 32)
    with pytest.raises(SealedChannelError):
        wrong_peer.open(sealed)
