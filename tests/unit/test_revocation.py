"""Revocation of delegation credentials inside their validity window.

Covers who may revoke (the hop's issuer or an issuer above it, never the delegate
and never a stranger), the cascade to descendants, fail-closed handling of forged
or unsigned statements, the not-checked status of offline verification with no
snapshot, the staleness policy, and that nothing can un-revoke.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime.cli import main as cli_main
from ca2a_runtime.delegation import (
    DelegationCredential,
    RevocationSnapshot,
    RevocationStatement,
    credential_digest,
    new_keypair,
    revoke,
    verify_chain,
)
from ca2a_runtime.delegation.holder import build_holder_proof
from ca2a_runtime.delegation.revocation import REVOCATION_TYPE
from ca2a_runtime.errors import (
    CredentialRevoked,
    InvalidRevocation,
    RevocationStatusUnknown,
)
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import PeerRequest, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import a2a_adapter
from ca2a_verify import load_revocation_snapshot, verify_chain_file, verify_delegation_chain
from tests.unit.conftest import TEST_AUDIENCE, TEST_SECRET, proved_request

NOW = 2_000_000_000


def _chain(hops: int = 3) -> tuple[list[DelegationCredential], list[Ed25519PrivateKey]]:
    """Return a chain and every key on it: keys[i] issues hop i, keys[i + 1] is its subject."""
    keys = [new_keypair() for _ in range(hops + 1)]
    scope = ["cap:a", "cap:b", "cap:c", "cap:d"]
    chain: list[DelegationCredential] = []
    parent_id: str | None = None
    for i in range(hops):
        cred = DelegationCredential(
            credential_id=f"cred-{i}",
            issuer=keys[i][1],
            subject=keys[i + 1][1],
            scope=frozenset(scope[: len(scope) - i]),
            depth=i,
            parent_id=parent_id,
        ).sign(keys[i][0])
        chain.append(cred)
        parent_id = cred.credential_id
    return chain, [k[0] for k in keys]


def _verify(chain, snapshot=None, **kwargs):
    return verify_chain(
        chain,
        trusted_root_issuers={chain[0].issuer},
        revocations=snapshot,
        **kwargs,
    )


def _snapshot(*statements: RevocationStatement, as_of: int = NOW) -> RevocationSnapshot:
    return RevocationSnapshot(as_of=as_of, statements=statements)


# --- offline verification without revocation data ---------------------------


def test_offline_verify_without_snapshot_reports_not_checked() -> None:
    chain, _ = _chain()
    status = _verify(chain)
    assert status.checked is False
    assert status.as_of is None
    assert status.state == "not_checked"


def test_chain_result_says_revocation_was_not_checked() -> None:
    chain, _ = _chain()
    result = verify_delegation_chain(chain, trusted_root_issuers={chain[0].issuer})
    assert result.revocation_checked is False
    assert result.revocation == "not_checked"


def test_empty_snapshot_reports_checked_as_of() -> None:
    chain, _ = _chain()
    status = _verify(chain, _snapshot(as_of=NOW - 5))
    assert status.checked is True
    assert status.as_of == NOW - 5
    assert status.state == "not_revoked"


# --- who may revoke -----------------------------------------------------------


def test_issuer_revokes_leaf() -> None:
    chain, keys = _chain()
    stmt = revoke(chain[2], keys[2], issued_at=NOW)
    with pytest.raises(CredentialRevoked) as exc:
        _verify(chain, _snapshot(stmt))
    assert exc.value.code == "CREDENTIAL_REVOKED"
    assert exc.value.http_status == 403
    assert "hop 2" in str(exc.value)


def test_revoking_middle_link_cascades_to_descendants() -> None:
    chain, keys = _chain(4)
    snapshot = _snapshot(revoke(chain[1], keys[1], issued_at=NOW))
    # Every chain that runs through hop 1 is refused, whatever sits beneath it,
    # and the refusal names hop 1 rather than the leaf.
    for end in (2, 3, 4):
        with pytest.raises(CredentialRevoked, match="hop 1"):
            _verify(chain[:end], snapshot)
    # The grant above the revoked link is untouched.
    assert _verify(chain[:1], snapshot).checked is True


def test_ancestor_revokes_grant_made_below_it() -> None:
    chain, keys = _chain()
    # The root issuer withdraws a grant two levels down that it did not sign.
    with pytest.raises(CredentialRevoked, match="hop 2"):
        _verify(chain, _snapshot(revoke(chain[2], keys[0], issued_at=NOW)))


def test_delegate_cannot_revoke_its_delegator() -> None:
    chain, keys = _chain()
    # keys[2] is the subject of hop 1 and the issuer of hop 2. It may revoke
    # hop 2, but it holds no authority over hop 1 or hop 0 above it.
    upward = _snapshot(
        revoke(chain[1], keys[2], issued_at=NOW),
        revoke(chain[0], keys[2], issued_at=NOW),
        # The leaf delegate trying to withdraw its own grant, or its parent's.
        revoke(chain[2], keys[3], issued_at=NOW),
        revoke(chain[1], keys[3], issued_at=NOW),
    )
    status = _verify(chain, upward)
    assert status.checked is True
    assert status.state == "not_revoked"


def test_unrelated_key_cannot_revoke() -> None:
    chain, _ = _chain()
    stranger, _ = new_keypair()
    snapshot = _snapshot(*(revoke(cred, stranger, issued_at=NOW) for cred in chain))
    assert _verify(chain, snapshot).checked is True


def test_revocation_names_one_credential_not_its_id() -> None:
    chain, keys = _chain()
    # A different grant that happens to reuse the credential_id is a different
    # credential, and its revocation does not touch this one.
    _, other_subject = new_keypair()
    lookalike = replace(chain[2], subject=other_subject, signature="").sign(keys[2])
    assert credential_digest(lookalike) != credential_digest(chain[2])
    assert _verify(chain, _snapshot(revoke(lookalike, keys[2], issued_at=NOW))).checked


# --- integrity: forged or unsigned statements --------------------------------


def test_unsigned_statement_refuses_the_snapshot() -> None:
    chain, keys = _chain()
    unsigned = replace(revoke(chain[2], keys[2], issued_at=NOW), signature="")
    with pytest.raises(InvalidRevocation, match="refused as a whole"):
        _snapshot(unsigned)


def test_forged_statement_refuses_the_snapshot() -> None:
    chain, keys = _chain()
    genuine = revoke(chain[1], keys[1], issued_at=NOW)
    # A genuine statement re-pointed at a different credential: the signature
    # no longer covers the body, so it is not accepted.
    retargeted = replace(genuine, revoked_digest=credential_digest(chain[2]))
    with pytest.raises(InvalidRevocation) as exc:
        _snapshot(retargeted)
    assert exc.value.code == "INVALID_REVOCATION"
    # Claiming a different revoker under the original signature fails the same way.
    with pytest.raises(InvalidRevocation):
        _snapshot(replace(genuine, revoker=chain[0].issuer))


def test_one_bad_statement_refuses_the_valid_ones_with_it() -> None:
    chain, keys = _chain()
    good = revoke(chain[2], keys[2], issued_at=NOW)
    bad = replace(revoke(chain[1], keys[1], issued_at=NOW), issued_at=NOW + 1)
    with pytest.raises(InvalidRevocation):
        _snapshot(good, bad)


def test_signing_key_must_match_revoker() -> None:
    chain, keys = _chain()
    stmt = RevocationStatement(credential_digest(chain[0]), chain[0].issuer, NOW)
    with pytest.raises(InvalidRevocation):
        stmt.sign(keys[1])


def test_credential_signature_is_not_a_revocation_signature() -> None:
    chain, _ = _chain()
    # Same key, same signature bytes, different object: the type tag in the
    # revocation body keeps the two signing domains apart.
    borrowed = RevocationStatement(
        credential_digest(chain[0]), chain[0].issuer, NOW, signature=chain[0].signature
    )
    with pytest.raises(InvalidRevocation):
        _snapshot(borrowed)


# --- monotonic ----------------------------------------------------------------


def test_later_statement_cannot_unrevoke() -> None:
    chain, keys = _chain()
    first = revoke(chain[2], keys[2], issued_at=NOW - 100)
    later = revoke(chain[2], keys[2], issued_at=NOW)
    for order in ((first, later), (later, first)):
        with pytest.raises(CredentialRevoked):
            _verify(chain, _snapshot(*order))


@pytest.mark.parametrize(
    "extra",
    [{"revoked": False}, {"action": "unrevoke"}, {"reinstated_at": NOW}],
)
def test_wire_form_cannot_express_unrevoke(extra: dict[str, object]) -> None:
    chain, keys = _chain()
    wire = {**revoke(chain[2], keys[2], issued_at=NOW).to_dict(), **extra}
    with pytest.raises(InvalidRevocation, match="malformed revocation fields"):
        RevocationStatement.from_dict(wire)


def test_unknown_statement_type_is_rejected() -> None:
    chain, keys = _chain()
    wire = revoke(chain[2], keys[2], issued_at=NOW).to_dict()
    wire["type"] = "ca2a.delegation-reinstatement.v1"
    with pytest.raises(InvalidRevocation, match="unsupported revocation type"):
        RevocationStatement.from_dict(wire)


def test_wire_round_trip() -> None:
    chain, keys = _chain()
    snapshot = _snapshot(revoke(chain[2], keys[2], issued_at=NOW))
    wire = json.loads(json.dumps(snapshot.to_dict()))
    assert wire["revocations"][0]["type"] == REVOCATION_TYPE
    assert RevocationSnapshot.from_dict(wire) == snapshot


# --- staleness policy ---------------------------------------------------------


def test_policy_without_snapshot_fails_closed() -> None:
    chain, _ = _chain()
    with pytest.raises(RevocationStatusUnknown) as exc:
        _verify(chain, None, max_revocation_staleness=300)
    assert exc.value.code == "REVOCATION_STATUS_UNKNOWN"
    assert exc.value.http_status == 503


def test_stale_snapshot_under_policy_fails_closed() -> None:
    chain, _ = _chain()
    with pytest.raises(RevocationStatusUnknown, match="older than"):
        _verify(chain, _snapshot(as_of=NOW - 301), at_time=NOW, max_revocation_staleness=300)


def test_snapshot_at_the_bound_is_accepted() -> None:
    chain, _ = _chain()
    status = _verify(chain, _snapshot(as_of=NOW - 300), at_time=NOW, max_revocation_staleness=300)
    assert status.checked is True


def test_stale_snapshot_still_proves_revocation() -> None:
    chain, keys = _chain()
    # Revocation is monotonic, so an old statement is still true. The refusal is
    # the revocation, not the staleness.
    old = _snapshot(revoke(chain[2], keys[2], issued_at=NOW - 1000), as_of=NOW - 900)
    with pytest.raises(CredentialRevoked):
        _verify(chain, old, at_time=NOW, max_revocation_staleness=300)


def test_stale_snapshot_without_policy_is_used_and_reported() -> None:
    chain, _ = _chain()
    status = _verify(chain, _snapshot(as_of=NOW - 10_000), at_time=NOW)
    assert status.checked is True
    assert status.as_of == NOW - 10_000


@pytest.mark.parametrize("bad", [-1, True, 1.5])
def test_staleness_bound_must_be_a_non_negative_int(bad: object) -> None:
    chain, _ = _chain()
    with pytest.raises(ValueError):
        _verify(chain, _snapshot(), max_revocation_staleness=bad)


# --- audit at a past decision time ---------------------------------------------


def test_audit_ignores_revocation_issued_after_the_decision() -> None:
    chain, keys = _chain()
    snapshot = _snapshot(revoke(chain[2], keys[2], issued_at=NOW))
    assert _verify(chain, snapshot, at_time=NOW - 1).checked is True
    with pytest.raises(CredentialRevoked):
        _verify(chain, snapshot, at_time=NOW)


def test_live_verification_applies_every_held_statement() -> None:
    chain, keys = _chain()
    # A revoker whose clock runs ahead still revokes at once for a live verifier.
    future = _snapshot(revoke(chain[2], keys[2], issued_at=4_000_000_000))
    with pytest.raises(CredentialRevoked):
        _verify(chain, future)


# --- files and CLI ------------------------------------------------------------


def _write(tmp_path, chain, snapshot):
    chain_path = tmp_path / "chain.json"
    chain_path.write_text(
        json.dumps([{**c.body(), "signature": c.signature} for c in chain]), encoding="utf-8"
    )
    rev_path = tmp_path / "revocations.json"
    rev_path.write_text(json.dumps(snapshot.to_dict()), encoding="utf-8")
    return chain_path, rev_path


def test_verify_chain_file_with_snapshot(tmp_path) -> None:
    chain, keys = _chain()
    chain_path, rev_path = _write(tmp_path, chain, _snapshot())
    result = verify_chain_file(
        chain_path,
        trusted_root_issuers={chain[0].issuer},
        revocations=load_revocation_snapshot(rev_path),
    )
    assert result.revocation_checked is True
    assert result.revocation_as_of == NOW

    _, rev_path = _write(tmp_path, chain, _snapshot(revoke(chain[1], keys[0], issued_at=NOW)))
    with pytest.raises(CredentialRevoked):
        verify_chain_file(
            chain_path,
            trusted_root_issuers={chain[0].issuer},
            revocations=load_revocation_snapshot(rev_path),
        )


def test_load_snapshot_with_tampered_statement_fails(tmp_path) -> None:
    chain, keys = _chain()
    _, rev_path = _write(tmp_path, chain, _snapshot(revoke(chain[2], keys[2], issued_at=NOW)))
    data = json.loads(rev_path.read_text(encoding="utf-8"))
    data["revocations"][0]["issued_at"] = NOW + 1
    rev_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(InvalidRevocation):
        load_revocation_snapshot(rev_path)


def test_cli_reports_not_checked_without_snapshot(tmp_path, capsys) -> None:
    chain, _ = _chain()
    chain_path, _ = _write(tmp_path, chain, _snapshot())
    rc = cli_main(
        ["verify-chain", "--chain", str(chain_path), "--trusted-root-issuer", chain[0].issuer]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["revocation"] == "not_checked"
    assert "revocation_as_of" not in out


def test_cli_checks_and_refuses_revoked(tmp_path, capsys) -> None:
    chain, keys = _chain()
    chain_path, rev_path = _write(tmp_path, chain, _snapshot())
    base = ["verify-chain", "--chain", str(chain_path), "--trusted-root-issuer", chain[0].issuer]
    assert cli_main([*base, "--revocations", str(rev_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["revocation"] == "not_revoked"
    assert out["revocation_as_of"] == NOW

    _, rev_path = _write(tmp_path, chain, _snapshot(revoke(chain[2], keys[2], issued_at=NOW)))
    assert cli_main([*base, "--revocations", str(rev_path)]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "CREDENTIAL_REVOKED"

    assert cli_main([*base, "--max-revocation-staleness", "60"]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "REVOCATION_STATUS_UNKNOWN"


def test_cli_verify_dag_rejects_revocation_flags_without_chain(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main(["verify-dag", "--dag", str(tmp_path / "dag.json"), "--revocations", "x.json"])
    assert exc.value.code == 2


# --- live peer path -------------------------------------------------------------


def test_peer_refuses_revoked_chain_before_the_holder_proof() -> None:
    chain, keys = _chain(2)
    request = proved_request(chain, keys[-1], "cap:a", "rec-0")
    kwargs = {
        "policy": LocalPolicy.of(["cap:a"]),
        "audience": TEST_AUDIENCE,
        "challenge_secret": TEST_SECRET,
        "trusted_root_issuers": {chain[0].issuer},
    }
    result = handle_peer_request(request, **kwargs)
    assert result.revocation.checked is False

    result = handle_peer_request(request, revocations=_snapshot(), **kwargs)
    assert result.revocation.checked is True

    with pytest.raises(CredentialRevoked):
        handle_peer_request(
            request, revocations=_snapshot(revoke(chain[1], keys[0], issued_at=NOW)), **kwargs
        )
    # Refused before holder binding: a request with no proof at all gets the
    # revocation error, not HOLDER_PROOF_INVALID.
    with pytest.raises(CredentialRevoked):
        handle_peer_request(
            replace(request, holder_proof=None),
            revocations=_snapshot(revoke(chain[1], keys[0], issued_at=NOW)),
            **kwargs,
        )


def _node_message(node: PeerNode, chain, leaf_key, record_id: str) -> dict[str, object]:
    request = PeerRequest(
        chain=chain,
        requested_capability="cap:a",
        record_id=record_id,
        holder_proof=build_holder_proof(
            leaf_key,
            chain[-1],
            audience=node.channel_public_key,
            challenge=node.issue_challenge(),
            requested_capability="cap:a",
            record_id=record_id,
        ),
    )
    return a2a_adapter.attach_ca2a_metadata({}, request)


def test_peer_node_consults_revocation_source_on_every_call() -> None:
    chain, keys = _chain(2)
    current: list[RevocationSnapshot | None] = [_snapshot(as_of=int(time.time()))]
    node = PeerNode(
        LocalPolicy.of(["cap:a"]),
        trusted_root_issuers={chain[0].issuer},
        revocation_source=lambda: current[0],
        max_revocation_staleness=3600,
    )
    assert node.handle(_node_message(node, chain, keys[-1], "rec-0")).revocation.checked

    current[0] = _snapshot(revoke(chain[1], keys[1]), as_of=int(time.time()))
    with pytest.raises(CredentialRevoked):
        node.handle(_node_message(node, chain, keys[-1], "rec-1"))

    # The source going quiet is not a pass: the node's policy requires data.
    current[0] = None
    with pytest.raises(RevocationStatusUnknown):
        node.handle(_node_message(node, chain, keys[-1], "rec-2"))


def test_peer_node_without_revocation_source_reports_not_checked() -> None:
    chain, keys = _chain(2)
    node = PeerNode(LocalPolicy.of(["cap:a"]), trusted_root_issuers={chain[0].issuer})
    result = node.handle(_node_message(node, chain, keys[-1], "rec-0"))
    assert result.revocation.checked is False
