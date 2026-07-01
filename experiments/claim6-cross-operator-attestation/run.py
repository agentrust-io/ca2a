#!/usr/bin/env python3
"""Claim 6: cross-operator attestation. Two operators in separate trust domains,
each with independent keys, mutually attest before exchanging a task, seal the
payload to the counterparty's attested key, and detect a silently swapped binary
via its changed measurement.

Validated in software (the way cMCP validates its cross-org claim): the SEV-SNP
report-signature and certificate-chain paths use synthetic vectors, since a
genuine report needs SEV-SNP hardware. The cross-operator protocol itself is
exercised end to end. Real hardware end to end remains open (see ROADMAP.md).
"""
# ruff: noqa: T201
from __future__ import annotations

import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.hashes import SHA384  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed  # noqa: E402
from ca2a_runtime.errors import AttestationFailed  # noqa: E402
from ca2a_runtime.tee.sev_snp import REPORT_SIZE, SIG_OFFSET  # noqa: E402
from ca2a_verify.sev_snp import verify_sev_snp_report  # noqa: E402


def make_cert(subject, issuer, subject_key, issuer_key):
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


def make_report(vcek_key, measurement, report_data):
    body = bytearray(SIG_OFFSET)
    struct.pack_into("<IIQ", body, 0, 2, 1, 0)
    struct.pack_into("<I", body, 0x30, 0)
    struct.pack_into("<I", body, 0x34, 1)
    body[0x50 : 0x50 + len(report_data)] = report_data
    body[0x90 : 0x90 + len(measurement)] = measurement
    r, s = decode_dss_signature(vcek_key.sign(bytes(body), ec.ECDSA(SHA384())))
    full = bytearray(REPORT_SIZE)
    full[:SIG_OFFSET] = body
    full[SIG_OFFSET : SIG_OFFSET + 72] = r.to_bytes(72, "little")
    full[SIG_OFFSET + 72 : SIG_OFFSET + 144] = s.to_bytes(72, "little")
    return bytes(full)


def build_operator(name, measurement, root_key):
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    vcek = make_cert(f"{name}-VCEK", "amd-root", vcek_key, root_key)
    priv, pub = generate_channel_keypair()
    report = make_report(vcek_key, measurement, bytes.fromhex(pub) + b"\x00" * 32)
    return {"name": name, "measurement": measurement, "priv": priv, "pub": pub,
            "vcek_key": vcek_key, "vcek": vcek, "report": report}


def main() -> int:
    print("Claim 6: cross-operator attestation (two trust domains)")
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = make_cert("amd-root", "amd-root", root_key, root_key)  # stands in for the AMD ARK
    a = build_operator("A", b"\xaa" * 48, root_key)
    b = build_operator("B", b"\xbb" * 48, root_key)
    checks = passed = 0

    # 1. Independent keys in the two domains.
    checks += 1
    indep = a["pub"] != b["pub"]
    passed += indep
    print(f"  [1] independent keys across domains: {'OK' if indep else 'FAIL'}")

    # 2. Mutual attestation: each verifies the other against its golden measurement.
    checks += 1
    rb = verify_sev_snp_report(b["report"], [b["vcek"], root], trusted_roots=[root],
                               expected_measurement=b["measurement"])
    ra = verify_sev_snp_report(a["report"], [a["vcek"], root], trusted_roots=[root],
                               expected_measurement=a["measurement"])
    b_key = rb.report_data[:32].hex()
    a_key = ra.report_data[:32].hex()
    mutual = b_key == b["pub"] and a_key == a["pub"]
    passed += mutual
    print(f"  [2] mutual attestation binds each channel key: {'OK' if mutual else 'FAIL'}")

    # 3. Confidential cross-operator delegation: A seals a task to B's attested key.
    checks += 1
    payload = b"delegated task across operators: reconcile ledger"
    sealed = SealedChannel(b_key).seal(payload)
    delivered = open_sealed(sealed, b["priv"]) == payload and payload not in sealed
    passed += delivered
    print(f"  [3] payload sealed to attested key, opened only by peer: {'OK' if delivered else 'FAIL'}")

    # 4. Binary-swap detection: B runs a tampered binary. The report is still
    # validly signed by B's VCEK, but the measurement differs from the golden
    # value, so the counterparty rejects it.
    checks += 1
    swapped = make_report(b["vcek_key"], b"\xee" * 48, bytes.fromhex(b["pub"]) + b"\x00" * 32)
    try:
        verify_sev_snp_report(swapped, [b["vcek"], root], trusted_roots=[root],
                              expected_measurement=b["measurement"])
        swap_caught = False
    except AttestationFailed:
        swap_caught = True
    passed += swap_caught
    print(f"  [4] silently swapped binary detected: {'OK' if swap_caught else 'FAIL'}")

    if passed == checks:
        print(f"KEY RESULT: {passed}/{checks} two operators, independent keys, mutual "
              "attestation, sealed cross-operator delegation, binary-swap detected "
              "(synthetic vectors; real hardware end-to-end pending)")
        return 0
    print(f"KEY RESULT: FAIL ({passed}/{checks} passed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
