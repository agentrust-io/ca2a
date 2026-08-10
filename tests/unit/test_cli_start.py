"""Tests for ``ca2a start``: what it binds, and what it refuses to start with."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ca2a_runtime import cli
from ca2a_runtime.node import PeerNode
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import server


class _FakeServer:
    """Stands in for a bound HTTP server so no test actually listens."""

    def __init__(self, node: PeerNode) -> None:
        self.node = node
        self.closed = False

    def serve_forever(self) -> None:
        raise KeyboardInterrupt

    def server_close(self) -> None:
        self.closed = True


def _config(tmp_path: Path, body: str) -> str:
    path = tmp_path / "ca2a-config.yaml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_start_serves_the_configured_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound: dict[str, Any] = {}

    def fake_serve(node: PeerNode, host: str = "127.0.0.1", port: int = 8443) -> _FakeServer:
        bound.update(node=node, host=host, port=port)
        return _FakeServer(node)

    monkeypatch.setattr(server, "serve", fake_serve)
    config = _config(
        tmp_path,
        "attestation:\n  provider: software-only\nlocal_policy:\n  - read\n"
        "listen_addr: 127.0.0.1:9443\n",
    )

    assert cli.main(["start", "--config", config]) == 0
    assert (bound["host"], bound["port"]) == ("127.0.0.1", 9443)
    assert isinstance(bound["node"].provider, SoftwareProvider)
    assert bound["node"].policy.allow == frozenset({"read"})


def test_start_refuses_a_config_with_no_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config(tmp_path, "attestation:\n  provider: software-only\n")
    assert cli.main(["start", "--config", config]) == 1
    assert "local_policy or policy_bundle_path" in capsys.readouterr().err


def test_start_refuses_auto_provider_off_hardware(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config(tmp_path, "attestation:\n  provider: auto\nlocal_policy:\n  - read\n")
    assert cli.main(["start", "--config", config]) == 1
    assert "no hardware attestation provider" in capsys.readouterr().err


def test_start_reports_a_bind_failure_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(node: PeerNode, host: str, port: int) -> _FakeServer:
        raise OSError("Address already in use")

    monkeypatch.setattr(server, "serve", refuse)
    config = _config(
        tmp_path,
        "attestation:\n  provider: software-only\nlocal_policy:\n  - read\n"
        "listen_addr: 127.0.0.1:9443\n",
    )
    assert cli.main(["start", "--config", config]) == 1
    err = capsys.readouterr().err
    assert "cannot bind 127.0.0.1:9443" in err
    assert "ca2a listening" not in err


def test_start_warns_that_software_mode_has_no_guarantee(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server, "serve", lambda node, host, port: _FakeServer(node))
    config = _config(tmp_path, "attestation:\n  provider: software-only\nlocal_policy:\n  - read\n")
    assert cli.main(["start", "--config", config]) == 0
    assert 'assurance="none"' in capsys.readouterr().err
