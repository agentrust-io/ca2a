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
| `expected.json` | The scenario's ACTION three-axis **classification** (`verdict`), the `trusted_root_issuer`, an optional `at_time`, and the reason `code` a failure or denial carries. |

### Scenario label vs. observed offline verdict

`verdict` is the scenario's ACTION classification (the label from
`tests/conformance/README.md`), **not** what the offline verifier reports.
`ca2a verify-dag --structural-only --chain` checks credential signatures,
attenuation, validity and native record consistency. A successful diagnostic has
`verified: false`, `structural_verified: true` and
`code: UNAUTHENTICATED_LINEAGE`. It does not authenticate record contents.
The fixture's scenario classification does not change that result.

Recorded denial fields remain unsigned claims. Neither an allowed action nor a
controller outcome is established offline. These bundles exercise structural
checks and credential failures; they are not authenticated-lineage conformance.
The substitution regression for #168 is an expected refusal in
`tests/unit/test_lineage_cli.py`, never an accepted authenticated result.

## Cases

| Bundle | Offline diagnostic |
|---|---|
| `action-001-verified` | Structure matches; lineage unauthenticated. |
| `action-002-parent-hash-mismatch` | `PROVENANCE_LINK_BROKEN`. |
| `action-006-policy-denial` | Structure matches; unsigned denial claim retained. |
| `action-010-scope-escalation` | `SCOPE_ESCALATION`. |
| `action-012-credential-expired` | `CREDENTIAL_EXPIRED` at `at_time=3000`. |

## Regenerating

The bundles are generated with seeded keys, so their bytes are reproducible:

```bash
python scripts/gen_action_fixtures.py           # (re)write the bundles
python scripts/gen_action_fixtures.py --check    # compare only; exits nonzero if any bundle is stale or missing
```

`tests/conformance/test_action_fixture_bundles.py` verifies the **committed**
blobs (read out of git, not the working tree), so a change to the record body or
the chain model that forgets to regenerate these fails there. It reads each
bundle in `REQUIRED_BUNDLES` from `HEAD`: when git is available a missing blob
fails (rather than skipping), and the on-disk bundle set is pinned so dropping a
whole directory cannot silently reduce coverage.
