"""Harness controls with injected test doubles; these are not hardware results."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime import hardware_acceptance as harness
from ca2a_runtime.errors import AttestationUnsupported


def test_no_software_fallback(monkeypatch):
    monkeypatch.setattr(harness.SevSnpProvider, "detect", lambda: False)
    with pytest.raises(AttestationUnsupported, match="real non-paravisor"):
        harness.real_provider()


def test_call_requires_hardware_and_labels_response_untrusted(tmp_path, monkeypatch):
    provider = object()
    verifier = object()
    monkeypatch.setattr(harness, "real_provider", lambda: provider)
    monkeypatch.setattr(harness, "build_verifier", lambda *args: verifier)
    (tmp_path / "chain.json").write_text("[]")
    (tmp_path / "key").write_text(Ed25519PrivateKey.generate().private_bytes_raw().hex())
    (tmp_path / "payload").write_bytes(b"private-input")
    log = harness.ReceiptLog(tmp_path / "receipt.jsonl", "test-double-only")

    def send(*args, **kwargs):
        assert kwargs["require_hardware"] is True
        assert kwargs["caller_provider"] is provider
        assert kwargs["verifier"] is verifier
        return {"accepted": True, "caller_attestation": "hardware"}

    monkeypatch.setattr(harness.client, "send_task", send)
    harness.run(
        {
            "peer": {},
            "chain": "chain.json",
            "holder_key": "key",
            "payload": "payload",
            "peer_url": "http://peer",
            "capability": "read",
            "record_id": "r1",
        },
        tmp_path,
        "call",
        log,
    )
    entry = json.loads(log.path.read_text())
    assert entry["response_authenticated"] is False
    assert entry["peer_reported_caller_attestation"] == "hardware"
    assert "private-input" not in log.path.read_text()
    assert "assurance" not in entry


def test_receiver_demands_hardware_and_holder_proof(tmp_path, monkeypatch):
    provider, verifier = object(), object()
    monkeypatch.setattr(harness, "real_provider", lambda: provider)
    monkeypatch.setattr(harness, "build_verifier", lambda *args: verifier)
    observed = []

    class Service:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def serve_forever(self):
            pass

    def serve(node, **kwargs):
        observed.append(node)
        return Service()

    monkeypatch.setattr(harness.server, "serve", serve)
    harness.run(
        {
            "peer": {},
            "trusted_root_issuers": ["authority"],
            "capabilities": ["read"],
            "host": "127.0.0.1",
            "port": 8443,
        },
        tmp_path,
        "serve",
        harness.ReceiptLog(tmp_path / "r.jsonl", "unit"),
    )
    assert observed[0].require_caller_attestation == "hardware"
    assert observed[0].caller_verifier is verifier
    assert observed[0].require_holder_proof is True


def test_cli_records_failed_preflight_without_hardware_claim(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.SevSnpProvider, "detect", lambda: False)
    config = tmp_path / "config.json"
    config.write_text("{}")
    receipt = tmp_path / "receipt.jsonl"
    monkeypatch.setattr(
        "sys.argv",
        [
            "hardware_acceptance",
            "call",
            str(config),
            "--receipt",
            str(receipt),
            "--run-id",
            "local-negative-control",
        ],
    )
    assert harness.main() == 1
    entry = json.loads(receipt.read_text())
    assert entry["event"] == "run_failed"
    assert entry["error_type"] == "AttestationUnsupported"
    assert "hardware" not in entry
