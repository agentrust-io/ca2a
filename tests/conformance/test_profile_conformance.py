"""Runnable cA2A conformance checks. Each test maps to a MUST-level ID in
README.md and exercises the reference implementation. A third-party
implementation is expected to satisfy the same behaviors.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain
from ca2a_runtime.errors import (
    AttestationFailed,
    AttestationUnsupported,
    BrokenDelegationLink,
    CA2AError,
    CredentialReplay,
    DelegationDepthExceeded,
    InvalidCredential,
    ProvenanceLinkBroken,
    ScopeEscalation,
    ScopeNotPermitted,
    SealedChannelError,
)
from ca2a_runtime.peer import PeerRequest, effective_scope, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import DelegationRecord, cross_check_chain, record_for, verify_dag
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.tdx import TdxProvider
from ca2a_verify import verify_delegation_chain
from ca2a_verify.sev_snp import verify_sev_snp_report
from ca2a_verify.tdx import verify_tdx_quote
from tests.unit.conftest import build_chain, make_ec_cert, make_sev_snp_report
from tests.unit.test_tdx import build_quote


@dataclass(frozen=True)
class _ActionEvidence:
    trace_record_hash: str
    credential_id: str
    requested_capability: str
    controller_decision: str = "accepted"


@dataclass(frozen=True)
class _ActionEvidenceResult:
    classification: str
    code: str


def _narrowing():
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def _deep3():
    return build_chain([frozenset({"a", "b", "c"}), frozenset({"a", "b"}), frozenset({"a"})])


def _records(chain):
    recs, ph = [], None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"r{i}", parent_record_hash=ph)
        recs.append(rec)
        ph = rec.record_hash()
    return recs


def _action_chain() -> list[DelegationCredential]:
    return build_chain([
        frozenset({"robot.move", "robot.inspect", "robot.stop"}),
        frozenset({"robot.move", "robot.inspect"}),
    ])


def _action_evidence(
    records: list[DelegationRecord],
    *,
    requested_capability: str = "robot.move",
    controller_decision: str = "accepted",
    credential_id: str | None = None,
    trace_record_hash: str | None = None,
) -> _ActionEvidence:
    leaf = records[-1]
    return _ActionEvidence(
        trace_record_hash=trace_record_hash or leaf.record_hash(),
        credential_id=credential_id or leaf.credential_id,
        requested_capability=requested_capability,
        controller_decision=controller_decision,
    )


def _verify_action_evidence(
    chain: list[DelegationCredential],
    records: list[DelegationRecord],
    evidence: _ActionEvidence,
    policy: LocalPolicy,
) -> _ActionEvidenceResult:
    try:
        verify_delegation_chain(chain)
        verify_dag(records)
        cross_check_chain(records, chain)
    except CA2AError as exc:
        return _ActionEvidenceResult("provenance_invalid", exc.code)

    leaf = records[-1]
    if evidence.trace_record_hash != leaf.record_hash():
        return _ActionEvidenceResult("provenance_invalid", ProvenanceLinkBroken.code)
    if evidence.credential_id != leaf.credential_id:
        return _ActionEvidenceResult("provenance_invalid", ProvenanceLinkBroken.code)

    try:
        handle_peer_request(
            PeerRequest(
                chain=chain,
                requested_capability=evidence.requested_capability,
                record_id="action-attempt",
                parent_record_hash=leaf.record_hash(),
            ),
            policy=policy,
        )
    except ScopeNotPermitted as exc:
        return _ActionEvidenceResult("authorization_invalid", exc.code)

    if evidence.controller_decision == "rejected":
        return _ActionEvidenceResult("valid_negative_outcome", "CONTROLLER_REJECTED")
    return _ActionEvidenceResult("verified", "ACCEPTED")


# --- Group 1: Delegation ---

def test_deleg_001_signature() -> None:
    _, pub = new_keypair()
    _, sub = new_keypair()
    with pytest.raises(InvalidCredential):
        DelegationCredential("c0", pub, sub, frozenset({"a"}), 0).verify_signature()


def test_deleg_002_attenuation() -> None:
    with pytest.raises(ScopeEscalation):
        verify_chain(build_chain([frozenset({"a"}), frozenset({"a", "b"})]))


def test_deleg_003_continuity() -> None:
    rp, rpub = new_keypair()
    mp, mpub = new_keypair()
    _, leaf = new_keypair()
    root = DelegationCredential("c0", rpub, mpub, frozenset({"a"}), 0).sign(rp)
    child = DelegationCredential("c1", mpub, leaf, frozenset({"a"}), 1, parent_id="wrong").sign(mp)
    with pytest.raises(BrokenDelegationLink):
        verify_chain([root, child])


def test_deleg_004_depth() -> None:
    with pytest.raises(DelegationDepthExceeded):
        verify_chain(_deep3(), max_depth=1)  # leaf is depth 2 > 1


def test_deleg_005_replay() -> None:
    chain = build_chain([frozenset({"a"}), frozenset({"a"})])
    dup = DelegationCredential(chain[0].credential_id, chain[0].issuer, chain[0].subject,
                               chain[0].scope, chain[0].depth, chain[0].parent_id, chain[0].signature)
    with pytest.raises(CredentialReplay):
        verify_chain([chain[0], dup])


def test_deleg_006_valid_chain_accepted() -> None:
    verify_chain(_narrowing())


# --- Group 2: Scope-policy intersection ---

def test_policy_001_intersection() -> None:
    assert effective_scope(_narrowing(), LocalPolicy.of(["read", "audit"])) == frozenset({"read"})


def test_policy_002_delegated_not_allowed_denied() -> None:
    req = PeerRequest(chain=_narrowing(), requested_capability="write", record_id="r0")
    with pytest.raises(ScopeNotPermitted):
        handle_peer_request(req, policy=LocalPolicy.of(["read"]))


def test_policy_003_allowed_not_delegated_denied() -> None:
    req = PeerRequest(chain=_narrowing(), requested_capability="audit", record_id="r0")
    with pytest.raises(ScopeNotPermitted):
        handle_peer_request(req, policy=LocalPolicy.of(["read", "audit"]))


# --- Group 3: Attestation ---

def test_attest_001_providers_fail_closed() -> None:
    assert SevSnpProvider.detect() is False
    assert TdxProvider.detect() is False
    with pytest.raises(AttestationUnsupported):
        SevSnpProvider().attest("deadbeef", "n")
    with pytest.raises(AttestationUnsupported):
        TdxProvider().attest("deadbeef", "n")


def _sev_setup():
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = make_ec_cert("root", "root", root_key, root_key)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    vcek = make_ec_cert("vcek", "root", vcek_key, root_key)
    report = make_sev_snp_report(vcek_key, measurement=b"\x11" * 48, report_data=b"\x22" * 64)
    return report, [vcek, root], root


def test_attest_002_wrong_measurement() -> None:
    report, chain, root = _sev_setup()
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, chain, trusted_roots=[root], expected_measurement=b"\x99" * 48)


def test_attest_003_untrusted_root() -> None:
    report, chain, _ = _sev_setup()
    stranger = make_ec_cert("s", "s", ec.generate_private_key(ec.SECP384R1()),
                            ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, chain, trusted_roots=[stranger])


def test_attest_004_tampered_report() -> None:
    report, chain, root = _sev_setup()
    bad = bytearray(report)
    bad[0x90] ^= 0xFF
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(bytes(bad), chain, trusted_roots=[root])


def test_attest_005_tdx_wrong_mrtd() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    quote, root = build_quote(b"\x11" * 48, b"\x22" * 64, root_key=root_key)
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(quote, trusted_roots=[root], expected_mrtd=b"\x99" * 48)


# --- Group 4: Sealed channel ---

def test_seal_001_only_peer_key_opens() -> None:
    priv, pub = generate_channel_keypair()
    sealed = SealedChannel(pub).seal(b"secret")
    assert open_sealed(sealed, priv) == b"secret"
    with pytest.raises(SealedChannelError):
        open_sealed(sealed, X25519PrivateKey.generate())


def test_seal_002_no_plaintext_in_blob() -> None:
    _, pub = generate_channel_keypair()
    assert b"secret" not in SealedChannel(pub).seal(b"secret")


def test_seal_003_tamper_fails_closed() -> None:
    priv, pub = generate_channel_keypair()
    sealed = bytearray(SealedChannel(pub).seal(b"secret"))
    sealed[-1] ^= 0xFF
    with pytest.raises(SealedChannelError):
        open_sealed(bytes(sealed), priv)


# --- Group 5: Provenance ---

def test_prov_001_dag_verifies() -> None:
    recs = _records(_deep3())
    assert verify_dag(recs) == recs


def test_prov_002_tamper_detected() -> None:
    chain = _deep3()
    recs = _records(chain)
    from ca2a_runtime.provenance import DelegationRecord
    # Tamper the middle record: the leaf's parent link no longer matches.
    recs[1] = DelegationRecord(recs[1].record_id, recs[1].credential_id, recs[1].subject,
                               frozenset({"a", "injected"}), recs[1].parent_record_hash)
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag(recs)


def test_prov_003_bound_to_authority() -> None:
    chain = _deep3()
    recs = _records(chain)
    cross_check_chain(recs, chain)  # aligned: passes
    from ca2a_runtime.provenance import DelegationRecord
    recs[0] = DelegationRecord(recs[0].record_id, "WRONG", recs[0].subject, recs[0].scope, None)
    with pytest.raises(ProvenanceLinkBroken):
        cross_check_chain(recs, chain)


# --- Group 6: Inbound pipeline ---

def test_pipe_001_grants_and_records() -> None:
    req = PeerRequest(chain=_narrowing(), requested_capability="read", record_id="r0")
    result = handle_peer_request(req, policy=LocalPolicy.of(["read", "audit"]))
    assert result.granted_capability == "read"
    assert verify_dag([result.record]) == [result.record]


def test_pipe_002_sealed_without_key_fails_closed() -> None:
    _, pub = generate_channel_keypair()
    req = PeerRequest(chain=_narrowing(), requested_capability="read", record_id="r0",
                      sealed_payload=SealedChannel(pub).seal(b"x"))
    with pytest.raises(SealedChannelError):
        handle_peer_request(req, policy=LocalPolicy.of(["read"]))


def test_pipe_003_invalid_chain_rejected_first() -> None:
    bad = build_chain([frozenset({"read"}), frozenset({"read", "write"})])
    req = PeerRequest(chain=bad, requested_capability="read", record_id="r0")
    with pytest.raises(ScopeEscalation):
        handle_peer_request(req, policy=LocalPolicy.of(["read", "write"]))


# --- Group 7: Delegation-linked action evidence ---

def test_action_001_valid_delegated_action_evidence() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move", "robot.inspect"]),
    )
    assert result == _ActionEvidenceResult("verified", "ACCEPTED")


def test_action_002_parent_trace_hash_mismatch_is_provenance_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    records[1] = DelegationRecord(
        records[1].record_id,
        records[1].credential_id,
        records[1].subject,
        records[1].scope,
        parent_record_hash="sha256:wrong-parent",
    )
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "PROVENANCE_LINK_BROKEN")


def test_action_003_missing_parent_trace_record_is_provenance_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        [records[1]],
        _action_evidence(records),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "PROVENANCE_LINK_BROKEN")


def test_action_004_unknown_delegation_credential_id_is_provenance_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records, credential_id="unknown-credential"),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "PROVENANCE_LINK_BROKEN")


def test_action_005_action_outside_delegated_scope_is_authorization_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records, requested_capability="robot.stop"),
        LocalPolicy.of(["robot.move", "robot.stop"]),
    )
    assert result == _ActionEvidenceResult("authorization_invalid", "SCOPE_NOT_PERMITTED")


def test_action_006_local_policy_denial_is_authorization_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records, requested_capability="robot.inspect"),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("authorization_invalid", "SCOPE_NOT_PERMITTED")


def test_action_007_controller_rejection_is_valid_negative_outcome() -> None:
    chain = _action_chain()
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records, controller_decision="rejected"),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("valid_negative_outcome", "CONTROLLER_REJECTED")
