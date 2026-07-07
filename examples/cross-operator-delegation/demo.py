#!/usr/bin/env python3
"""Cross-operator delegation example (offline, productizes claim 6).

Story: a Parent agent in trust domain A delegates a scoped task to a Child agent
in trust domain B. The two operators hold independent keys. They mutually attest
before exchanging the task, each attestation binds that side's channel key, the
Parent seals the task to the Child's attested key, and the Child enforces the
delegated scope intersected with its local Cedar policy before acting. A silently
swapped binary on the Child changes its measurement and is rejected. Every hop
emits a provenance record, and the records form a hash-linked DAG that an auditor
verifies offline and binds back to the signed delegation chain.

HONEST LABELING (mirrors LIMITATIONS.md and the claim 6 docstring):
  - Attestation here is SOFTWARE-ASSERTED with SYNTHETIC SEV-SNP vectors. There
    is no real quote and no TEE hardware. The report-signature and certificate
    paths use generated keys, exactly as the SEV-SNP verifier's tests do.
  - What IS real and hardware-independent: the attenuated delegation-chain
    verification, the scope ∩ local-policy intersection, and the provenance-DAG
    verification. These run fully offline and are what `ca2a verify-chain` and
    `ca2a verify-dag` re-check on the committed artifacts.
  - The config is software-only / advisory. Nothing is enforced on a live wire;
    cA2A has no transport yet (see issue #43, ROADMAP.md, LIMITATIONS.md).

Run (from repo root, package installed editable):
  python examples/cross-operator-delegation/demo.py
"""
# ruff: noqa: T201
from __future__ import annotations

import json
import struct
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.hashes import SHA384  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed  # noqa: E402
from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402
from ca2a_runtime.errors import AttestationFailed, ScopeNotPermitted  # noqa: E402
from ca2a_runtime.peer import effective_scope, enforce_peer_call  # noqa: E402
from ca2a_runtime.policy import LocalPolicy  # noqa: E402
from ca2a_runtime.provenance import (  # noqa: E402
    DelegationRecord,
    cross_check_chain,
    record_for,
    verify_dag,
)
from ca2a_runtime.tee.sev_snp import REPORT_SIZE, SIG_OFFSET  # noqa: E402
from ca2a_verify.sev_snp import verify_sev_snp_report  # noqa: E402

HERE = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# Synthetic SEV-SNP attestation helpers (software-asserted; no real hardware).
# Lifted from experiments/claim6-cross-operator-attestation/run.py.
# --------------------------------------------------------------------------
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


def step(n: int, text: str, ok: bool) -> bool:
    print(f"  [{n}] {text}: {'OK' if ok else 'FAIL'}")
    return ok


def main() -> int:
    print("Cross-operator delegation example (offline; synthetic SEV-SNP vectors)")
    print("  Parent in domain A delegates a scoped task to Child in domain B.\n")
    checks: list[bool] = []

    # ------------------------------------------------------------------
    # Attestation setup: two operators, independent keys, one trusted root.
    # (Software-asserted: synthetic SEV-SNP vectors, no TEE hardware.)
    # ------------------------------------------------------------------
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = make_cert("amd-root", "amd-root", root_key, root_key)  # stands in for the AMD ARK
    parent_op = build_operator("A-parent", b"\xaa" * 48, root_key)
    child_op = build_operator("B-child", b"\xbb" * 48, root_key)

    # 1. Independent keys across the two trust domains.
    checks.append(step(1, "independent channel keys across domains",
                       parent_op["pub"] != child_op["pub"]))

    # 2. Mutual attestation binds each side's channel key (SOFTWARE-ASSERTED).
    r_child = verify_sev_snp_report(child_op["report"], [child_op["vcek"], root],
                                    trusted_roots=[root],
                                    expected_measurement=child_op["measurement"])
    r_parent = verify_sev_snp_report(parent_op["report"], [parent_op["vcek"], root],
                                     trusted_roots=[root],
                                     expected_measurement=parent_op["measurement"])
    child_key = r_child.report_data[:32].hex()
    parent_key = r_parent.report_data[:32].hex()
    mutual = child_key == child_op["pub"] and parent_key == parent_op["pub"]
    checks.append(step(2, "mutual attestation binds each channel key (software-asserted)",
                       mutual))

    # ------------------------------------------------------------------
    # Attenuated delegation chain: Parent -> intermediate -> Child.
    # Scope narrows at each hop. This part is REAL and hardware-independent.
    # ------------------------------------------------------------------
    scopes = [
        frozenset({"task:read", "task:write", "task:admin"}),  # root grant
        frozenset({"task:read", "task:write"}),                # narrowed to the child
    ]
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

    checks.append(step(3, "attenuated delegation chain verifies (leaf scope narrows)",
                       sorted(chain[-1].scope) == ["task:read", "task:write"]))

    # ------------------------------------------------------------------
    # Scope ∩ local policy at the Child. The child was delegated
    # {task:read, task:write}; its local policy permits {task:read, task:audit}.
    # Effective scope is the intersection: {task:read}.
    #
    # We enforce with the LocalPolicy allow-set (the same model claim 3 uses),
    # so the demo has no dependency on a specific Cedar engine version. The
    # committed policy.cedar states the SAME rule as a Cedar policy for the real
    # engine (ca2a_runtime.cedar.CedarPolicy); binding that engine in the peer
    # path is tracked separately (see policy.py and issue #10).
    # ------------------------------------------------------------------
    policy = LocalPolicy.of(["task:read", "task:audit"])
    eff = effective_scope(chain, policy)
    print(f"      leaf delegated scope : {sorted(chain[-1].scope)}")
    print(f"      child local policy   : {sorted(policy.allow)}")
    print(f"      effective scope      : {sorted(eff)}")
    checks.append(step(4, "effective scope = delegated ∩ policy = {task:read}",
                       sorted(eff) == ["task:read"]))

    # task:read is delegated AND permitted -> ALLOW (emits a provenance record).
    try:
        decision = enforce_peer_call(chain, "task:read", policy=policy, record_id="rec-1")
        read_allowed = True
    except ScopeNotPermitted:
        read_allowed = False
    checks.append(step(5, "child ALLOWS task:read (delegated and locally permitted)",
                       read_allowed))

    # task:write is delegated but NOT locally permitted -> DENY (fail-closed).
    try:
        enforce_peer_call(chain, "task:write", policy=policy, record_id="rec-x")
        write_denied = False
    except ScopeNotPermitted:
        write_denied = True
    checks.append(step(6, "child DENIES task:write (delegated but not locally permitted)",
                       write_denied))

    # ------------------------------------------------------------------
    # Confidential cross-operator delegation: Parent seals the task to the
    # Child's ATTESTED channel key; only the Child's private key opens it.
    # ------------------------------------------------------------------
    payload = b"delegated task across operators: reconcile ledger (read-only)"
    sealed = SealedChannel(child_key).seal(payload)
    delivered = open_sealed(sealed, child_op["priv"]) == payload and payload not in sealed
    checks.append(step(7, "task sealed to child's attested key, opened only by child",
                       delivered))

    # ------------------------------------------------------------------
    # Binary-swap detection: the Child silently runs a tampered binary. Its
    # report is still validly signed by its VCEK, but the measurement differs
    # from the golden value, so the Parent rejects it. (Software-asserted.)
    # ------------------------------------------------------------------
    swapped = make_report(child_op["vcek_key"], b"\xee" * 48,
                          bytes.fromhex(child_op["pub"]) + b"\x00" * 32)
    try:
        verify_sev_snp_report(swapped, [child_op["vcek"], root], trusted_roots=[root],
                              expected_measurement=child_op["measurement"])
        swap_caught = False
    except AttestationFailed:
        swap_caught = True
    checks.append(step(8, "silently swapped binary detected (measurement mismatch)",
                       swap_caught))

    # ------------------------------------------------------------------
    # Provenance DAG: one hash-linked record per hop; verify offline and bind
    # it back to the signed chain. This part is REAL and hardware-independent.
    # ------------------------------------------------------------------
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"rec-{i}", parent_record_hash=parent_hash)
        records.append(rec)
        parent_hash = rec.record_hash()
    dag_ok = verify_dag(records) == records
    cross_check_chain(records, chain)  # raises on any mismatch
    checks.append(step(9, "per-hop provenance DAG verifies and binds to the chain",
                       dag_ok))
    # Sanity: the accepted read hop's record lines up with the leaf credential.
    checks.append(step(10, "accepted-call record matches the leaf credential",
                       decision.record.credential_id == chain[-1].credential_id))

    # ------------------------------------------------------------------
    # Write the offline artifacts and re-verify them through the CLI, exactly
    # as an auditor would, without trusting this process.
    # ------------------------------------------------------------------
    chain_doc = {"chain": [c.body() | {"signature": c.signature} for c in chain]}
    dag_doc = {"records": [r.body() for r in records]}
    chain_path = HERE / "chain.json"
    dag_path = HERE / "dag.json"
    chain_path.write_text(json.dumps(chain_doc, indent=2), encoding="utf-8")
    dag_path.write_text(json.dumps(dag_doc, indent=2), encoding="utf-8")
    print(f"\n  wrote {chain_path.name} and {dag_path.name}; re-verifying via the CLI:")

    def run_cli(args: list[str]) -> bool:
        proc = subprocess.run(
            [sys.executable, "-m", "ca2a_runtime.cli", *args],
            capture_output=True, text=True,
        )
        print(f"      $ ca2a {' '.join(args)}")
        print(f"        {proc.stdout.strip()}")
        if proc.returncode != 0 and proc.stderr.strip():
            print(f"        {proc.stderr.strip()}")
        return proc.returncode == 0

    checks.append(step(11, "ca2a verify-chain accepts chain.json",
                       run_cli(["verify-chain", "--chain", str(chain_path)])))
    checks.append(step(12, "ca2a verify-dag accepts dag.json and cross-checks the chain",
                       run_cli(["verify-dag", "--dag", str(dag_path),
                                "--chain", str(chain_path)])))

    passed = sum(checks)
    total = len(checks)
    print()
    if passed == total:
        print(f"KEY RESULT: {passed}/{total} cross-operator delegation demonstrated offline: "
              "independent keys, mutual attestation (synthetic vectors), attenuated "
              "delegation, scope ∩ policy, sealed task, binary-swap rejected, and an "
              "offline-verifiable provenance DAG. Delegation-chain and provenance-DAG "
              "verification are hardware-independent and fully real; attestation is "
              "software-asserted (real hardware end-to-end pending, see issue #43).")
        return 0
    print(f"KEY RESULT: FAIL ({passed}/{total} checks passed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
