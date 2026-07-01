"""Tests for the TEE base types."""

from __future__ import annotations

import pytest

from ca2a_runtime.tee import AttestationReport, BaseProvider


def test_attestation_report_is_frozen() -> None:
    report = AttestationReport("software-only", "m0", "deadbeef", "nonce")
    assert report.platform == "software-only"
    with pytest.raises(AttributeError):
        report.platform = "tdx"  # type: ignore[misc]


def test_base_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseProvider()  # type: ignore[abstract]
