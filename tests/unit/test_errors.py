"""Tests for the error registry."""

from __future__ import annotations

from ca2a_runtime.errors import CA2AError, ScopeEscalation


def test_error_carries_code_and_detail() -> None:
    err = ScopeEscalation("nope", detail="added cap:x")
    assert err.code == "SCOPE_ESCALATION"
    assert err.http_status == 403
    assert err.detail == "added cap:x"
    assert isinstance(err, CA2AError)


def test_base_error_defaults() -> None:
    err = CA2AError("boom")
    assert err.code == "CA2A_ERROR"
    assert err.detail is None
