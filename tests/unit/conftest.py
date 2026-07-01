"""Shared fixtures: delegation chains and synthetic SEV-SNP attestation vectors."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.x509.oid import NameOID

from ca2a_runtime.delegation import DelegationCredential, new_keypair
from ca2a_runtime.tee.sev_snp import REPORT_SIZE, SIG_OFFSET


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """Build a correctly signed chain where hop i grants scopes[i].

    Continuity is preserved (each issuer is the previous subject) and depth
    increments from 0. Callers pass narrowing scopes to exercise attenuation.
    """
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


@pytest.fixture
def valid_chain() -> list[DelegationCredential]:
    return build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ]
    )


# --- Synthetic SEV-SNP attestation vectors (test-only; not hardware) ---

def make_ec_cert(
    subject: str,
    issuer: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer_key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    """Build a CA certificate signed by ``issuer_key`` (ECDSA-P384/SHA384)."""
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, SHA384())
    )


def make_sev_snp_report(
    vcek_key: ec.EllipticCurvePrivateKey, *, measurement: bytes, report_data: bytes
) -> bytes:
    """Build a synthetic SEV-SNP report signed by ``vcek_key`` (algo=1)."""
    body = bytearray(SIG_OFFSET)
    struct.pack_into("<IIQ", body, 0, 2, 1, 0)  # version, guest_svn, policy
    struct.pack_into("<I", body, 0x30, 0)       # vmpl
    struct.pack_into("<I", body, 0x34, 1)       # signature_algo = ECDSA-P384/SHA384
    body[0x50 : 0x50 + len(report_data)] = report_data
    body[0x90 : 0x90 + len(measurement)] = measurement
    der = vcek_key.sign(bytes(body), ec.ECDSA(SHA384()))
    r, s = decode_dss_signature(der)
    full = bytearray(REPORT_SIZE)
    full[:SIG_OFFSET] = body
    full[SIG_OFFSET : SIG_OFFSET + 72] = r.to_bytes(72, "little")
    full[SIG_OFFSET + 72 : SIG_OFFSET + 144] = s.to_bytes(72, "little")
    return bytes(full)
