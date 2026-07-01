"""Claim 6: cross-operator attestation.

Two operators in separate trust domains, each with independent keys, mutually
attest before exchanging a task, seal the payload to the counterparty's attested
key, and detect a silently swapped binary via its changed measurement.

Validated in software the way cMCP validates its cross-org claim: the SEV-SNP
report-signature and certificate-chain paths use synthetic vectors (a genuine
report needs SEV-SNP hardware), while the cross-operator protocol itself
(mutual verify, measurement pinning, seal-to-attested-key, binary-swap
detection) is exercised end to end. Real hardware end-to-end remains open.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.errors import AttestationFailed
from ca2a_verify.sev_snp import verify_sev_snp_report
from tests.unit.conftest import make_ec_cert, make_sev_snp_report


@dataclass
class Operator:
    name: str
    measurement: bytes
    channel_priv: X25519PrivateKey
    channel_pub: str
    vcek_key: ec.EllipticCurvePrivateKey
    vcek_cert: x509.Certificate

    def report(self, *, measurement: bytes | None = None) -> bytes:
        # report_data binds this operator's channel public key (32 bytes, padded to 64).
        pub_raw = bytes.fromhex(self.channel_pub)
        report_data = pub_raw + b"\x00" * (64 - len(pub_raw))
        return make_sev_snp_report(
            self.vcek_key, measurement=measurement or self.measurement, report_data=report_data
        )


def _make_operator(name: str, measurement: bytes, root_key: ec.EllipticCurvePrivateKey,
                   root_name: str) -> Operator:
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    vcek_cert = make_ec_cert(f"{name}-VCEK", root_name, vcek_key, root_key)
    priv, pub = generate_channel_keypair()
    return Operator(name, measurement, priv, pub, vcek_key, vcek_cert)


@pytest.fixture
def domains():
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = make_ec_cert("test-root", "test-root", root_key, root_key)
    a = _make_operator("A", b"\xaa" * 48, root_key, "test-root")
    b = _make_operator("B", b"\xbb" * 48, root_key, "test-root")
    return {"root": root, "a": a, "b": b}


def _verify_peer(peer: Operator, root: x509.Certificate, expected_measurement: bytes) -> str:
    report = verify_sev_snp_report(
        peer.report(), [peer.vcek_cert, root],
        trusted_roots=[root], expected_measurement=expected_measurement,
    )
    return report.report_data[:32].hex()  # the peer's attested channel public key


def test_mutual_attestation_and_sealed_delegation(domains) -> None:
    root, a, b = domains["root"], domains["a"], domains["b"]

    # A verifies B's report against B's golden measurement, and vice versa.
    b_attested_key = _verify_peer(b, root, b.measurement)
    a_attested_key = _verify_peer(a, root, a.measurement)
    assert b_attested_key == b.channel_pub
    assert a_attested_key == a.channel_pub

    # A seals a delegated task to B's attested key; only B can open it.
    payload = b"delegated task: reconcile ledger for Q3"
    sealed = SealedChannel(b_attested_key).seal(payload)
    assert open_sealed(sealed, b.channel_priv) == payload


def test_independent_keys_across_domains(domains) -> None:
    a, b = domains["a"], domains["b"]
    assert a.channel_pub != b.channel_pub
    assert a.vcek_cert.fingerprint(a.vcek_cert.signature_hash_algorithm) != \
        b.vcek_cert.fingerprint(b.vcek_cert.signature_hash_algorithm)


def test_binary_swap_detected(domains) -> None:
    root, b = domains["root"], domains["b"]
    # B silently runs a tampered binary: its measurement changes.
    swapped = make_sev_snp_report(
        b.vcek_key, measurement=b"\xee" * 48,
        report_data=bytes.fromhex(b.channel_pub) + b"\x00" * 32,
    )
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(
            swapped, [b.vcek_cert, root],
            trusted_roots=[root], expected_measurement=b.measurement,
        )


def test_untrusted_operator_root_rejected(domains) -> None:
    b = domains["b"]
    stranger_key = ec.generate_private_key(ec.SECP384R1())
    stranger_root = make_ec_cert("stranger", "stranger", stranger_key, stranger_key)
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(
            b.report(), [b.vcek_cert, domains["root"]],
            trusted_roots=[stranger_root], expected_measurement=b.measurement,
        )
