# Experiment: Cross-Chain Replay Rejection

**Claim:** A delegation credential replayed within a chain (duplicate `credential_id`) or spliced in from a different chain is rejected by `verify_chain` (cA2A Claim 2).

**What this experiment proves:**

1. A chain that repeats a `credential_id` is rejected with `CredentialReplay`. An attacker who copies an earlier hop back into the chain to re-use a grant does not get it accepted.
2. A credential signed for chain A, spliced into chain B, is rejected. The spliced hop cannot satisfy chain B's continuity (its `issuer` is not the previous hop's `subject`) and its `parent_id` does not link to B's previous credential. `verify_chain` raises `BrokenDelegationLink`.
3. The unmodified control chains verify without error, so the rejections above are caused by the attack and not by a broken harness.

**What this means for governance:**

Delegation authority in cA2A is a chain of signed hops. Two of the four chain invariants exist to stop replay: every `credential_id` in a chain must be unique, and each hop must chain to the previous hop by both `parent_id` and issuer/subject continuity. A credential is only valid in the exact position of the exact chain it was minted for. Lifting a signed grant out of one session and dropping it into another does not transfer authority, because the signature covers the issuer and parent link, and continuity is checked against the new neighbors. There is no need to trust the party presenting the chain.

## Running

```bash
# From repo root, package installed editable
python experiments/claim2-cross-chain-replay/run.py
```

## Expected output

```
============================================================
Experiment: Cross-Chain Replay Rejection
Claim 2: replayed or spliced credentials are rejected
============================================================

[1] Control: two independent valid chains verify
    chain A (3 hops): VALID  OK
    chain B (3 hops): VALID  OK

[2] Intra-chain replay: duplicate a credential_id
    duplicated credential_id: cred-1
    verify_chain raised: CredentialReplay  OK

[3] Cross-chain splice: hop from chain A dropped into chain B
    spliced credential_id: cred-1 (from chain A)
    verify_chain raised: BrokenDelegationLink  OK

============================================================
KEY RESULT: 2/2 replay attacks rejected (1 CredentialReplay, 1 BrokenDelegationLink); 2/2 control chains valid
```
