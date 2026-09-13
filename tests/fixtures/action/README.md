# ACTION fixture bundles

Self-contained, offline-verifiable bundles for the delegation-linked action
evidence cases (Group 7, `ACTION-*`) in
[`tests/conformance/README.md`](../../conformance/README.md).

Every other ACTION case is assembled in memory inside
`tests/conformance/test_profile_conformance.py`. These bundles instead serialize
a case to disk so it is re-verified end-to-end with the **shipped offline
verifier**, the same `ca2a verify-dag --chain` an auditor runs, not through live
Python objects. That is the point: cA2A's offline-verifiable provenance claim,
checked from committed files by a third party with no access to the runtime.

Idea proposed by @Ahmedibrahim222 in
[#36](https://github.com/agentrust-io/ca2a/issues/36); scoped and tracked in
[#164](https://github.com/agentrust-io/ca2a/issues/164).

## Layout

One directory per case, each holding:

| File | What it is |
|---|---|
| `chain.json` | The signed delegation chain (`{"chain": [...]}`), as `ca2a verify-chain` consumes it. |
| `dag.json` | The provenance records (`{"records": [...]}`), as `ca2a verify-dag --dag` consumes them. |
| `expected.json` | The documented verdict: the ACTION three-axis outcome (`provenance_status` / `authorization_decision` / `controller_outcome`), the `trusted_root_issuer`, an optional `at_time`, and the reason `code` a failure or denial carries. |

## What these do and do not cover

The offline path covers provenance (chain signatures, attenuation, and validity
windows), the DAG, the chain↔record cross-check, and any recorded denial
outcome. It does **not** exercise the holder-proof *authorization-replay* axis:
that needs live audience / secret / challenge material and is not
offline-replayable evidence. See the ACTION helper and holder-proof note in
[`tests/conformance/README.md`](../../conformance/README.md) rather than a
restatement here.

## Cases

| Bundle | ACTION | Offline verdict |
|---|---|---|
| `action-001-verified` | ACTION-001 | `verify-dag` verifies; provenance verified, authorized, accepted. |
| `action-002-parent-hash-mismatch` | ACTION-002 | Fails closed with `PROVENANCE_LINK_BROKEN`. |
| `action-006-policy-denial` | ACTION-005/006 | Verifies with a recorded authorization denial (`outcome: denied`). |
| `action-010-scope-escalation` | ACTION-010 | Fails closed with `SCOPE_ESCALATION`. |
| `action-012-credential-expired` | ACTION-012 | Fails closed with `CREDENTIAL_EXPIRED` when replayed at `at_time=3000`. |

## Regenerating

The bundles are generated with seeded keys, so their bytes are reproducible:

```bash
python scripts/gen_action_fixtures.py
```

`tests/conformance/test_action_fixture_bundles.py` verifies the **committed**
blobs (read out of git, not the working tree), so a change to the record body or
the chain model that forgets to regenerate these fails there.
