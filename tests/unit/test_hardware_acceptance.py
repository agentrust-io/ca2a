"""Harness controls with injected test doubles; these are not hardware results."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime import hardware_acceptance as harness
from ca2a_runtime.errors import AttestationUnsupported
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.tee.software import SoftwareProvider


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
        assert kwargs["caller_provider"].inner is provider
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
    entry = json.loads(log.path.read_text().splitlines()[-1])
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


def test_real_http_quote_timeout_is_incomplete_work_not_security_rejection(tmp_path, monkeypatch):
    """A stalled test provider demonstrates diagnostics, not the live SNP cause."""
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    class BlockingSoftwareProvider(SoftwareProvider):
        def attest(self, public_key, nonce):
            entered.set()
            assert release.wait(10), "test must release the blocked provider"
            return super().attest(public_key, nonce)

    class FinishingNode(harness.ObservedNode):
        def offer(self, nonce):
            try:
                return super().offer(nonce)
            finally:
                finished.set()

    receiver_log = harness.ReceiptLog(tmp_path / "receiver.jsonl", "software-timeout-test")
    node = FinishingNode(
        LocalPolicy.of({"read"}),
        log=receiver_log,
        provider=harness.ObservedSnpProvider(BlockingSoftwareProvider(), receiver_log),
    )
    service = harness.server.serve(node, port=0)
    # Sending a response after the test client disconnects can raise BrokenPipe.
    service.handle_error = lambda *args: None
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(harness.client, "_TIMEOUT", 1.0)
    monkeypatch.setattr(harness, "real_provider", SoftwareProvider)
    monkeypatch.setattr(harness, "build_verifier", lambda *args: None)
    (tmp_path / "chain.json").write_text("[]")
    (tmp_path / "key").write_text(Ed25519PrivateKey.generate().private_bytes_raw().hex())
    (tmp_path / "payload").write_bytes(b"test-secret-not-for-logs")
    sender_log = harness.ReceiptLog(tmp_path / "sender.jsonl", "software-timeout-test")
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        pending = executor.submit(
            harness.run,
            {
                "peer": {},
                "chain": "chain.json",
                "holder_key": "key",
                "payload": "payload",
                "peer_url": f"http://127.0.0.1:{service.server_port}",
                "capability": "read",
                "record_id": "timeout",
            },
            tmp_path,
            "call",
            sender_log,
        )
        assert entered.wait(5), "receiver must reach quote collection before inspecting the timeout"
        with pytest.raises(TimeoutError):
            pending.result(timeout=5)
        assert pending.done(), "the HTTP call must time out, not the executor wait"
        sender = [json.loads(line) for line in sender_log.path.read_text().splitlines()]
        failure = next(item for item in sender if item["event"] == "operation_failed")
        assert failure["stage"] == "sender_call"
        assert failure["error_type"] == "TimeoutError"
        assert failure["elapsed_seconds"] >= 0
        assert sender[-1]["receiver_outcome"] == "unknown"
        assert sender[-1]["retried"] is False
        receiver = [json.loads(line) for line in receiver_log.path.read_text().splitlines()]
        assert [item["stage"] for item in receiver] == ["receiver_offer", "local_quote_collection"]
        assert all(item["event"] == "operation_started" for item in receiver)
        assert "test-secret" not in sender_log.path.read_text()
        assert not any(item.get("accepted") for item in sender)
    finally:
        release.set()
        executor.shutdown(wait=True)
        assert finished.wait(5)
        service.shutdown()
        service.server_close()
        thread.join(5)
    receiver = [json.loads(line) for line in receiver_log.path.read_text().splitlines()]
    assert receiver[-1]["event"] == "operation_completed"
    assert receiver[-1]["stage"] == "receiver_offer"
