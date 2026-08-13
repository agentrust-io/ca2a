"""Runnable cA2A conformance checks. Each test maps to a MUST-level ID in
README.md and exercises the reference implementation. A third-party
implementation is expected to satisfy the same behaviors.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.attestation import ChannelOffer
from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.challenge import generate_secret, issue_challenge
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain
from ca2a_runtime.delegation.holder import HolderProof, proof_body
from ca2a_runtime.errors import (
    AttestationFailed,
    AttestationUnsupported,
    BrokenDelegationLink,
    CA2AError,
    CredentialExpired,
    CredentialNotYetValid,
    CredentialReplay,
    DelegationDepthExceeded,
    HolderProofInvalid,
    InvalidCredential,
    ProvenanceLinkBroken,
    ScopeEscalation,
    ScopeNotPermitted,
    SealedChannelError,
)
from ca2a_runtime.peer import REQUIRE_ANY, PeerRequest
from ca2a_runtime.peer import effective_scope as _effective_scope
from ca2a_runtime.peer import handle_peer_request as _handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import DelegationRecord, cross_check_chain, record_for, verify_dag
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.tee.tdx import TdxProvider
from ca2a_verify import verify_delegation_chain
from ca2a_verify.sev_snp import verify_sev_snp_report
from ca2a_verify.tdx import verify_tdx_quote
from tests.unit.conftest import (
    TEST_AUDIENCE,
    TEST_SECRET,
    build_chain,
    build_chain_with_keys,
    make_ec_cert,
    make_sev_snp_report,
    proved_request,
)
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


def _narrowing_with_keys():
    return build_chain_with_keys(
        [frozenset({"read", "write", "admin"}), frozenset({"read", "write"})]
    )


def _handle_proved(chain, leaf_key, capability, record_id, policy, **kw):
    """Run the inbound pipeline with a valid holder proof: the shipping path."""
    return handle_peer_request(
        proved_request(chain, leaf_key, capability, record_id, **kw),
        policy=policy,
        audience=TEST_AUDIENCE,
        challenge_secret=TEST_SECRET,
    )


def _narrowing():
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def effective_scope(chain, policy):
    return _effective_scope(chain, policy, trusted_root_issuers={chain[0].issuer})


def handle_peer_request(request, **kwargs):
    return _handle_peer_request(request, trusted_root_issuers={request.chain[0].issuer}, **kwargs)


def _deep3():
    return build_chain([frozenset({"a", "b", "c"}), frozenset({"a", "b"}), frozenset({"a"})])


def _records(chain):
    recs, ph = [], None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"r{i}", parent_record_hash=ph)
        recs.append(rec)
        ph = rec.record_hash()
    return recs


def _action_chain(
    *, not_before: int | None = None, not_after: int | None = None
) -> list[DelegationCredential]:
    return build_chain(
        [
            frozenset({"robot.move", "robot.inspect", "robot.stop"}),
            frozenset({"robot.move", "robot.inspect"}),
        ],
        not_before=not_before,
        not_after=not_after,
    )


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
        # Offline replay of recorded evidence: the auditor is re-deciding an
        # action that already happened, so there is no live caller to answer a
        # challenge. Holder binding is what the callee checked at the time; it is
        # not recoverable from the record, and asserting it here would be
        # asserting something the evidence never carried.
        handle_peer_request(
            PeerRequest(
                chain=chain,
                requested_capability=evidence.requested_capability,
                record_id="action-attempt",
                parent_record_hash=leaf.record_hash(),
            ),
            policy=policy,
            require_holder_proof=False,
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
    dup = DelegationCredential(
        chain[0].credential_id,
        chain[0].issuer,
        chain[0].subject,
        chain[0].scope,
        chain[0].depth,
        chain[0].parent_id,
        chain[0].signature,
    )
    with pytest.raises(CredentialReplay):
        verify_chain([chain[0], dup])


def test_deleg_006_valid_chain_accepted() -> None:
    verify_chain(_narrowing())


def test_deleg_007_expired_credential_rejected() -> None:
    chain = build_chain([frozenset({"a"})], not_before=1_000, not_after=2_000)
    with pytest.raises(CredentialExpired):
        verify_chain(chain, at_time=3_000)


def test_deleg_008_not_yet_valid_credential_rejected() -> None:
    chain = build_chain([frozenset({"a"})], not_before=1_000, not_after=2_000)
    with pytest.raises(CredentialNotYetValid):
        verify_chain(chain, at_time=500)


def test_deleg_009_chain_within_validity_window_accepted() -> None:
    verify_chain(build_chain([frozenset({"a"})], not_before=1_000, not_after=2_000), at_time=1_500)


# --- Group 2: Scope-policy intersection ---


def test_policy_001_intersection() -> None:
    assert effective_scope(_narrowing(), LocalPolicy.of(["read", "audit"])) == frozenset({"read"})


def test_policy_002_delegated_not_allowed_denied() -> None:
    chain, keys = _narrowing_with_keys()
    with pytest.raises(ScopeNotPermitted):
        _handle_proved(chain, keys[-1], "write", "r0", LocalPolicy.of(["read"]))


def test_policy_003_allowed_not_delegated_denied() -> None:
    chain, keys = _narrowing_with_keys()
    with pytest.raises(ScopeNotPermitted):
        _handle_proved(chain, keys[-1], "audit", "r0", LocalPolicy.of(["read", "audit"]))


# --- Group 3: Attestation ---


def test_attest_001_providers_fail_closed() -> None:
    """Both providers can collect on the right guest; this host is not one.

    The pair must agree. A provider that reported True here and then raised
    would be selected and then fail, and the error must name what is missing
    rather than asserting the platform is absent.
    """
    assert SevSnpProvider.detect() is False
    assert TdxProvider.detect() is False
    for provider in (SevSnpProvider(), TdxProvider()):
        with pytest.raises(AttestationUnsupported) as excinfo:
            provider.attest("deadbeef", "n")
        assert excinfo.value.detail


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
        verify_sev_snp_report(
            report, chain, trusted_roots=[root], expected_measurement=b"\x99" * 48
        )


def test_attest_003_untrusted_root() -> None:
    report, chain, _ = _sev_setup()
    stranger = make_ec_cert(
        "s", "s", ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    )
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
    recs[1] = DelegationRecord(
        recs[1].record_id,
        recs[1].credential_id,
        recs[1].subject,
        frozenset({"a", "injected"}),
        recs[1].parent_record_hash,
    )
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
    chain, keys = _narrowing_with_keys()
    result = _handle_proved(chain, keys[-1], "read", "r0", LocalPolicy.of(["read", "audit"]))
    assert result.granted_capability == "read"
    assert verify_dag([result.record]) == [result.record]


def test_pipe_002_sealed_without_key_fails_closed() -> None:
    chain, keys = _narrowing_with_keys()
    _, pub = generate_channel_keypair()
    with pytest.raises(SealedChannelError):
        _handle_proved(
            chain,
            keys[-1],
            "read",
            "r0",
            LocalPolicy.of(["read"]),
            sealed_payload=SealedChannel(pub).seal(b"x"),
        )


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


def test_action_008_invalid_delegation_signature_is_provenance_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    leaf = chain[-1]
    tampered_signature = f"{int(leaf.signature[:2], 16) ^ 1:02x}{leaf.signature[2:]}"
    bad_chain = [*chain[:-1], replace(leaf, signature=tampered_signature)]
    evidence = _action_evidence(
        records,
        requested_capability="robot.inspect",
        controller_decision="rejected",
    )
    restrictive_policy = LocalPolicy.of(["robot.move"])
    permissive_policy = LocalPolicy.of(["robot.move", "robot.inspect"])

    # The controls establish both downstream classifications that invalid provenance must preempt.
    assert _verify_action_evidence(chain, records, evidence, restrictive_policy) == (
        _ActionEvidenceResult("authorization_invalid", "SCOPE_NOT_PERMITTED")
    )
    assert _verify_action_evidence(chain, records, evidence, permissive_policy) == (
        _ActionEvidenceResult("valid_negative_outcome", "CONTROLLER_REJECTED")
    )

    # ACTION-008 verifies provenance validation precedes authorization and controller outcome classification.
    assert _verify_action_evidence(bad_chain, records, evidence, restrictive_policy) == (
        _ActionEvidenceResult("provenance_invalid", "INVALID_CREDENTIAL")
    )
    assert _verify_action_evidence(bad_chain, records, evidence, permissive_policy) == (
        _ActionEvidenceResult("provenance_invalid", "INVALID_CREDENTIAL")
    )


def test_action_009_multi_hop_attenuation_verifies() -> None:
    chain = build_chain(
        [
            frozenset({"robot.move", "robot.inspect", "robot.stop"}),
            frozenset({"robot.move", "robot.inspect"}),
            frozenset({"robot.move"}),
        ]
    )
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move", "robot.inspect"]),
    )
    assert result == _ActionEvidenceResult("verified", "ACCEPTED")


def test_action_010_intermediate_scope_widening_is_provenance_invalid() -> None:
    chain = build_chain(
        [
            frozenset({"robot.move"}),
            frozenset({"robot.move", "robot.inspect"}),
            frozenset({"robot.move"}),
        ]
    )
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move", "robot.inspect"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "SCOPE_ESCALATION")


def test_action_011_delegatee_mismatch_is_provenance_invalid() -> None:
    chain = _action_chain()
    records = _records(chain)
    leaf = records[-1]
    records[-1] = DelegationRecord(
        leaf.record_id,
        leaf.credential_id,
        subject="different-delegatee",
        scope=leaf.scope,
        parent_record_hash=leaf.parent_record_hash,
    )
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "PROVENANCE_LINK_BROKEN")


# 2001-09-09 and 2100-01-01. The action-evidence helper replays through the
# offline verifier at the current time, so bounds this far out keep the
# expired / not-yet-valid classification unambiguous on any sane clock.
_PAST_EPOCH = 1_000_000_000
_FUTURE_EPOCH = 4_102_444_800


def test_action_012_expired_delegation_credential_is_provenance_invalid() -> None:
    chain = _action_chain(not_after=_PAST_EPOCH)
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move", "robot.inspect"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "CREDENTIAL_EXPIRED")


def test_action_013_not_yet_valid_delegation_credential_is_provenance_invalid() -> None:
    chain = _action_chain(not_before=_FUTURE_EPOCH)
    records = _records(chain)
    result = _verify_action_evidence(
        chain,
        records,
        _action_evidence(records),
        LocalPolicy.of(["robot.move", "robot.inspect"]),
    )
    assert result == _ActionEvidenceResult("provenance_invalid", "CREDENTIAL_NOT_YET_VALID")


# --- Group 8: Holder binding ---


def _holder_offer(challenge: str) -> ChannelOffer:
    key = SoftwareProvider().attest("x", "y").public_key
    return ChannelOffer(
        channel_public_key=key,
        report=AttestationReport(
            platform="software-only", measurement="caller", public_key=key, nonce=challenge
        ),
    )


def test_hold_001_chain_without_a_proof_is_refused() -> None:
    chain, _keys = _narrowing_with_keys()
    with pytest.raises(HolderProofInvalid):
        handle_peer_request(
            PeerRequest(chain=chain, requested_capability="read", record_id="r0"),
            policy=LocalPolicy.of(["read"]),
            audience=TEST_AUDIENCE,
            challenge_secret=TEST_SECRET,
        )


def test_hold_002_proof_by_a_non_holder_is_refused() -> None:
    chain, _keys = _narrowing_with_keys()
    challenge = issue_challenge(TEST_SECRET)
    body = proof_body(
        audience=TEST_AUDIENCE,
        challenge=challenge,
        credential_id=chain[-1].credential_id,
        subject=chain[-1].subject,
        requested_capability="read",
        record_id="r0",
        sealed_payload=None,
        caller_channel_key=None,
        parent_record_hash=None,
    )
    forged = HolderProof(
        challenge=challenge,
        signature=Ed25519PrivateKey.generate().sign(canonicalize(body)).hex(),
    )
    with pytest.raises(HolderProofInvalid):
        handle_peer_request(
            PeerRequest(
                chain=chain,
                requested_capability="read",
                record_id="r0",
                holder_proof=forged,
            ),
            policy=LocalPolicy.of(["read"]),
            audience=TEST_AUDIENCE,
            challenge_secret=TEST_SECRET,
        )


def test_hold_003_proof_answering_an_unissued_challenge_is_refused() -> None:
    chain, keys = _narrowing_with_keys()
    with pytest.raises(HolderProofInvalid):
        _handle_proved(
            chain, keys[-1], "read", "r0", LocalPolicy.of(["read"]), secret=generate_secret()
        )


def test_hold_004_proof_for_another_audience_is_refused() -> None:
    chain, keys = _narrowing_with_keys()
    with pytest.raises(HolderProofInvalid):
        _handle_proved(
            chain, keys[-1], "read", "r0", LocalPolicy.of(["read"]), audience="another-peer"
        )


def test_hold_005_proof_does_not_transfer_across_capabilities() -> None:
    chain, keys = _narrowing_with_keys()
    proof = proved_request(chain, keys[-1], "read", "r0").holder_proof
    with pytest.raises(HolderProofInvalid):
        handle_peer_request(
            PeerRequest(
                chain=chain,
                requested_capability="write",
                record_id="r0",
                holder_proof=proof,
            ),
            policy=LocalPolicy.of(["read", "write"]),
            audience=TEST_AUDIENCE,
            challenge_secret=TEST_SECRET,
        )


def test_hold_006_an_attested_caller_cannot_use_another_partys_chain() -> None:
    """Appraisal is not authentication of authority: both are required."""
    chain, _keys = _narrowing_with_keys()
    with pytest.raises(HolderProofInvalid):
        handle_peer_request(
            PeerRequest(
                chain=chain,
                requested_capability="read",
                record_id="r0",
                caller_offer=_holder_offer(issue_challenge(TEST_SECRET)),
            ),
            policy=LocalPolicy.of(["read"]),
            audience=TEST_AUDIENCE,
            challenge_secret=TEST_SECRET,
            require_caller_attestation=REQUIRE_ANY,
        )
