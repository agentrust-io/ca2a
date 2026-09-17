"""Run sequential mutual SNP appraisal on two real hosts; no software fallback.

Receipts are local observations, not signed or remotely authenticated evidence.
Keep and compare the sender and receiver receipts separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256

from ca2a_runtime.attestation import ChannelOffer, Verifier
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported, CA2AError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import PeerResult
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.transport import client, server
from ca2a_verify.sev_snp import sev_snp_verifier


class ReceiptLog:
    """Append a sanitized observation; never log evidence bytes or task plaintext."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self.lock = threading.Lock()

    def write(self, event: str, **values: Any) -> None:
        entry = {
            "schema": "ca2a-mutual-hardware-observation-v1",
            "run_id": self.run_id,
            "time": datetime.now(UTC).isoformat(),
            "event": event,
            "evidence_scope": "local observation; unsigned",
            **values,
        }
        with self.lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")

    @contextmanager
    def span(self, stage: str, **values: Any) -> Iterator[None]:
        """Retain a start even when work stalls; use a monotonic duration."""
        started = time.monotonic()
        values = {**values, "operation_id": secrets.token_hex(8)}
        self.write("operation_started", stage=stage, **values)
        try:
            yield
        except Exception as exc:
            self.write(
                "operation_failed",
                stage=stage,
                elapsed_seconds=time.monotonic() - started,
                error_type=type(exc).__name__,
                **values,
            )
            raise
        else:
            self.write(
                "operation_completed",
                stage=stage,
                elapsed_seconds=time.monotonic() - started,
                **values,
            )


class ObservedSnpProvider(SevSnpProvider):
    """Time collection on the already selected SNP provider; do not retry it."""

    def __init__(self, inner: BaseProvider, log: ReceiptLog) -> None:
        self.inner = inner
        self.log = log

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        with self.log.span("local_quote_collection", nonce_sha256=_nonce_hash(nonce)):
            return self.inner.attest(public_key, nonce)


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


def real_provider() -> SevSnpProvider:
    if not SevSnpProvider.detect():
        raise AttestationUnsupported("acceptance run requires a real non-paravisor SNP guest")
    return SevSnpProvider()


def build_verifier(config: dict[str, Any], base: Path, log: ReceiptLog) -> Verifier:
    """Require operator-provisioned pins; never discover trust from peer evidence."""
    roots = x509.load_pem_x509_certificates((base / config["trusted_roots"]).read_bytes())
    chain = x509.load_pem_x509_certificates((base / config["vcek_chain"]).read_bytes())
    if not roots or not chain:
        raise ValueError("trusted_roots and vcek_chain must contain certificates")
    required = config["require_platform"]
    forbidden = config["forbid_platform"]
    for fields in (required, forbidden):
        if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
            raise ValueError("platform policies must be explicit JSON string arrays")
    reject_unknown = config["reject_unrecognized_platform_bits"]
    if not isinstance(reject_unknown, bool):
        raise ValueError("reject_unrecognized_platform_bits must be a boolean")
    verify = sev_snp_verifier(
        trusted_roots=roots,
        vcek_chain=chain,
        expected_measurement=bytes.fromhex(config["expected_measurement"]),
        min_guest_svn=config["min_guest_svn"],
        require_platform=set(required),
        forbid_platform=set(forbidden),
        reject_unrecognized_platform_bits=reject_unknown,
    )
    log.write(
        "verification_policy",
        expected_measurement=config["expected_measurement"],
        min_guest_svn=config["min_guest_svn"],
        debug_allowed=False,
        required_vmpl=0,
        root_sha256=[root.fingerprint(SHA256()).hex() for root in roots],
        require_platform=required,
        forbid_platform=forbidden,
        reject_unrecognized_platform_bits=reject_unknown,
    )

    def recorded(report: AttestationReport, nonce: str) -> str:
        try:
            with log.span("peer_quote_verification", nonce_sha256=_nonce_hash(nonce)):
                measurement = verify(report, nonce)
        except AttestationFailed:
            log.write("peer_appraisal", accepted=False)
            raise
        log.write(
            "peer_appraisal",
            accepted=True,
            measurement=measurement,
            report_sha256=hashlib.sha256(report.raw_evidence or b"").hexdigest(),
            channel_key_sha256=hashlib.sha256(report.public_key.encode()).hexdigest(),
            nonce_sha256=hashlib.sha256(nonce.encode()).hexdigest(),
        )
        return measurement

    return recorded


class ObservedNode(PeerNode):
    def __init__(self, *args: Any, log: ReceiptLog, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.log = log

    def offer(self, nonce: str) -> ChannelOffer:
        with self.log.span("receiver_offer", nonce_sha256=_nonce_hash(nonce)):
            return super().offer(nonce)

    def handle(self, message: dict[str, Any]) -> PeerResult:
        try:
            with self.log.span("receiver_task_processing"):
                result = super().handle(message)
        except CA2AError as exc:
            self.log.write("receiver_task", accepted=False, error_code=exc.code)
            raise
        self.log.write(
            "receiver_task",
            accepted=True,
            caller_attestation=result.caller_attestation,
            payload_sha256=hashlib.sha256(result.payload or b"").hexdigest(),
            record_hash=result.record.record_hash(),
        )
        return result


def run(config: dict[str, Any], base: Path, mode: str, log: ReceiptLog) -> None:
    provider = ObservedSnpProvider(real_provider(), log)
    verifier = build_verifier(config["peer"], base, log)
    if mode == "serve":
        issuers = config["trusted_root_issuers"]
        if not issuers:
            raise ValueError("trusted_root_issuers must not be empty")
        node = ObservedNode(
            LocalPolicy.of(config["capabilities"]),
            provider=provider,
            require_caller_attestation="hardware",
            caller_verifier=verifier,
            trusted_root_issuers=issuers,
            log=log,
        )
        with server.serve(node, host=config["host"], port=config["port"]) as service:
            log.write("receiver_ready", provider="sev-snp")
            service.serve_forever()
        return
    chain = [
        DelegationCredential.from_dict(item)
        for item in json.loads((base / config["chain"]).read_text(encoding="utf-8"))
    ]
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex((base / config["holder_key"]).read_text(encoding="utf-8").strip())
    )
    payload = (base / config["payload"]).read_bytes()
    try:
        with log.span("sender_call"):
            result = client.send_task(
                config["peer_url"],
                chain,
                config["capability"],
                config["record_id"],
                holder_key=key,
                payload=payload,
                verifier=verifier,
                require_hardware=True,
                caller_provider=provider,
            )
    except OSError:
        # A timeout is neither an attestation rejection nor evidence that the
        # receiver did no work. Preserve the original exception and never retry.
        log.write("sender_transport_failure", receiver_outcome="unknown", retried=False)
        raise
    if result.get("accepted") is not True or result.get("caller_attestation") != "hardware":
        raise AttestationFailed(
            "peer response does not report successful mutual hardware appraisal"
        )
    # HTTP response is not authenticated by the sealed-request protocol. Only
    # the receiver's separately retained log establishes its local observation.
    log.write(
        "sender_task",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        peer_reported_accepted=result.get("accepted"),
        peer_reported_caller_attestation=result.get("caller_attestation"),
        response_authenticated=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "call"))
    parser.add_argument("config", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    log = ReceiptLog(args.receipt, args.run_id)
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        run(config, args.config.resolve().parent, args.mode, log)
    except (CA2AError, ValueError, KeyError, OSError) as exc:
        log.write("run_failed", error_type=type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
