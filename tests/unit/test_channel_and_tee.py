"""Tests for the fail-closed placeholders: sealed channel and TEE base."""

from __future__ import annotations

import pytest

from ca2a_runtime.channel import SealedChannel
from ca2a_runtime.errors import SealedChannelError
from ca2a_runtime.tee import AttestationReport, BaseProvider


def test_sealed_channel_fails_closed() -> None:
    ch = SealedChannel(peer_measurement="sha256:abc")
    assert ch.peer_measurement == "sha256:abc"
    with pytest.raises(SealedChannelError):
        ch.seal(b"secret task")
    with pytest.raises(SealedChannelError):
        ch.open(b"sealed blob")


def test_attestation_report_is_frozen() -> None:
    report = AttestationReport("software-only", "m0", "deadbeef", "nonce")
    assert report.platform == "software-only"
    with pytest.raises(AttributeError):
        report.platform = "tdx"  # type: ignore[misc]


def test_base_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseProvider()  # type: ignore[abstract]
