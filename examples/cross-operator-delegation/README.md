# Cross-operator delegation example

A Parent agent in trust domain **A** delegates a scoped task to a Child agent in
trust domain **B**. The two operators hold independent keys. Before exchanging
the task they mutually attest; each attestation binds that side's channel key.
The Parent seals the task to the Child's attested key, the Child enforces the
delegated scope intersected with its local policy, and a silently swapped binary
on the Child is rejected because its measurement no longer matches. Every hop
emits a provenance record, and the records form a hash-linked DAG that an auditor
verifies offline and binds back to the signed delegation chain.

This example productizes `experiments/claim6-cross-operator-attestation/run.py`
into example shape, adding the attenuated delegation chain, the scope ∩ policy
step, and the provenance DAG. It runs fully offline with no hardware.

## What is real vs software-asserted (read this)

Honesty is the point of this repo (see [LIMITATIONS.md](../../LIMITATIONS.md)),
so the labeling here is deliberate:

- **Real and hardware-independent.** The attenuated **delegation-chain**
  verification (signatures, continuity, scope attenuation, depth, replay), the
  **scope ∩ local-policy** intersection, and the **provenance-DAG** verification
  (hash-linked records, tamper/reparent detection, binding to the chain). These
  are what `ca2a verify-chain` and `ca2a verify-dag` re-check on the committed
  artifacts, and they need no TEE.
- **Software-asserted.** The **attestation** step uses **synthetic SEV-SNP
  vectors** — generated keys standing in for a real report and VCEK chain,
  exactly as the SEV-SNP verifier's own tests do. There is **no real quote and
  no TEE hardware**. It exercises the cross-operator protocol logic; it does not
  prove the reports came from genuine silicon or that private keys stayed in an
  enclave. Real hardware end to end is pending (see
  [ROADMAP.md](../../ROADMAP.md) and issue
  [#43](https://github.com/agentrust-io/ca2a/issues/43)).
- **Config is software-only / advisory.** `ca2a-config.yaml` selects no hardware
  backend and enforces nothing on a live wire — cA2A has no transport yet. It
  exists so the example validates with `ca2a validate-config`.

## Files

- `ca2a-config.yaml`: runtime config (software-only, advisory).
- `policy.cedar`: the Child's local policy stated as a Cedar rule. It permits
  `{task:read, task:audit}`. The demo enforces the same rule with the
  `LocalPolicy` allow-set (the model [claim 3](../../experiments/claim3-scope-policy-intersection/)
  uses), so it has no dependency on a specific Cedar engine version; binding the
  Cedar engine in the peer path is tracked separately.
- `demo.py`: the end-to-end offline flow. Regenerates `chain.json` / `dag.json`
  on each run and re-verifies them through the CLI.
- `chain.json`: a valid two-hop delegation chain, `task:admin` narrowing to
  `{task:read, task:write}`. Verified by `ca2a verify-chain`.
- `dag.json`: the per-hop provenance DAG for that chain. Verified by
  `ca2a verify-dag`.

## Run the demo

```bash
# From repo root, package installed editable (pip install -e ".[dev]")
python examples/cross-operator-delegation/demo.py
```

Expected output:

```
Cross-operator delegation example (offline; synthetic SEV-SNP vectors)
  Parent in domain A delegates a scoped task to Child in domain B.

  [1] independent channel keys across domains: OK
  [2] mutual attestation binds each channel key (software-asserted): OK
  [3] attenuated delegation chain verifies (leaf scope narrows): OK
      leaf delegated scope : ['task:read', 'task:write']
      child local policy   : ['task:audit', 'task:read']
      effective scope      : ['task:read']
  [4] effective scope = delegated ∩ policy = {task:read}: OK
  [5] child ALLOWS task:read (delegated and locally permitted): OK
  [6] child DENIES task:write (delegated but not locally permitted): OK
  [7] task sealed to child's attested key, opened only by child: OK
  [8] silently swapped binary detected (measurement mismatch): OK
  [9] per-hop provenance DAG verifies and binds to the chain: OK
  [10] accepted-call record matches the leaf credential: OK

  wrote chain.json and dag.json; re-verifying via the CLI:
      $ ca2a verify-chain --chain .../chain.json
        {"verified": true, "hops": 2, "leaf_scope": ["task:read", "task:write"]}
  [11] ca2a verify-chain accepts chain.json: OK
      $ ca2a verify-dag --dag .../dag.json --chain .../chain.json
        {"verified": true, "records": 2, "leaf_scope": ["task:read", "task:write"], "cross_checked": true}
  [12] ca2a verify-dag accepts dag.json and cross-checks the chain: OK

KEY RESULT: 12/12 ...
```

## Verify the artifacts offline

The chain and DAG are verifiable on their own, without running the demo and
without trusting the operator that produced them:

```bash
cd examples/cross-operator-delegation

ca2a validate-config --config ca2a-config.yaml
ca2a verify-chain   --chain chain.json
ca2a verify-dag     --dag dag.json                    # DAG links only
ca2a verify-dag     --dag dag.json --chain chain.json # also bind DAG to the chain
```

`ca2a verify-dag` runs `provenance.verify_dag` (the hash-linked record
invariants). With `--chain` it additionally runs `cross_check_chain`, so a DAG
cannot be fabricated independently of the signed authority it claims. All four
commands fail closed with a non-zero exit code on any tampering.

## See also

- [Emit and verify provenance](../../docs/tutorials/emit-and-verify-provenance.md) — the DAG model, tamper and reparent walk-throughs.
- [Claim 6 experiment](../../experiments/claim6-cross-operator-attestation/) — the cross-operator attestation flow this example builds on.
- [LIMITATIONS.md](../../LIMITATIONS.md) — what is built, stubbed, and out of scope.
