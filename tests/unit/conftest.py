"""Shared fixtures: delegation chains and synthetic SEV-SNP attestation vectors."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.x509.oid import NameOID

from ca2a_runtime.challenge import generate_secret, issue_challenge
from ca2a_runtime.delegation import DelegationCredential, build_holder_proof, new_keypair
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.tee.sev_snp import REPORT_SIZE, SIG_OFFSET

#: A stand-in for a callee's channel key, which is the audience a holder proof
#: commits to. Tests that exercise the handler directly, rather than through a
#: :class:`~ca2a_runtime.node.PeerNode`, pass this and ``TEST_SECRET`` together.
TEST_AUDIENCE = "test-callee-channel-key"
TEST_SECRET = generate_secret()


def build_chain_with_keys(
    scopes: list[frozenset[str]],
) -> tuple[list[DelegationCredential], list[Ed25519PrivateKey]]:
    """Build a signed chain and return it with each hop's subject private key.

    Continuity is preserved (each issuer is the previous subject) and depth
    increments from 0. Callers pass narrowing scopes to exercise attenuation.

    The keys are what a delegate actually holds. The last one is the leaf key a
    holder proof has to be signed with, and keeping it is the difference between
    a fixture that can make a real call and one that only looks like it can.
    """
    chain: list[DelegationCredential] = []
    subject_keys: list[Ed25519PrivateKey] = []
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
        subject_keys.append(next_priv)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain, subject_keys


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """Build a correctly signed chain where hop i grants scopes[i]."""
    return build_chain_with_keys(scopes)[0]


def proved_request(
    chain: list[DelegationCredential],
    leaf_key: Ed25519PrivateKey,
    requested_capability: str,
    record_id: str,
    *,
    sealed_payload: bytes | None = None,
    parent_record_hash: str | None = None,
    caller_offer: object | None = None,
    audience: str = TEST_AUDIENCE,
    secret: bytes | None = None,
    challenge: str | None = None,
) -> PeerRequest:
    """A :class:`PeerRequest` carrying a valid holder proof for the leaf credential."""
    if challenge is None:
        challenge = issue_challenge(TEST_SECRET if secret is None else secret)
    return PeerRequest(
        chain=chain,
        requested_capability=requested_capability,
        record_id=record_id,
        sealed_payload=sealed_payload,
        parent_record_hash=parent_record_hash,
        caller_offer=caller_offer,  # type: ignore[arg-type]
        holder_proof=build_holder_proof(
            leaf_key,
            chain[-1],
            audience=audience,
            challenge=challenge,
            requested_capability=requested_capability,
            record_id=record_id,
            sealed_payload=sealed_payload,
            caller_channel_key=(
                None if caller_offer is None else caller_offer.channel_public_key  # type: ignore[attr-defined]
            ),
        ),
    )


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
    struct.pack_into("<I", body, 0x30, 0)  # vmpl
    struct.pack_into("<I", body, 0x34, 1)  # signature_algo = ECDSA-P384/SHA384
    body[0x50 : 0x50 + len(report_data)] = report_data
    body[0x90 : 0x90 + len(measurement)] = measurement
    der = vcek_key.sign(bytes(body), ec.ECDSA(SHA384()))
    r, s = decode_dss_signature(der)
    full = bytearray(REPORT_SIZE)
    full[:SIG_OFFSET] = body
    full[SIG_OFFSET : SIG_OFFSET + 72] = r.to_bytes(72, "little")
    full[SIG_OFFSET + 72 : SIG_OFFSET + 144] = s.to_bytes(72, "little")
    return bytes(full)
