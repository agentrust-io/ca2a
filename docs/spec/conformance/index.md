# Conformance

An implementation may claim cA2A-compatible for a given version when it passes all MUST-level tests in the cA2A conformance suite for that version. This ties directly to the trademark language in [CHARTER.md](https://ca2a.agentrust-io.com/CHARTER/index.md): the mark asserts that a deployment satisfies the attestation, attenuation, sealing, and provenance requirements defined here.

## The normative suite

The suite is defined in [`tests/conformance/README.md`](https://github.com/agentrust-io/ca2a/blob/main/tests/conformance/README.md). It is a spec document expressed as stable, numbered test IDs grouped by area, each referencing the section it validates. The runnable checks in `tests/conformance/test_profile_conformance.py` exercise every MUST-level requirement against the reference implementation; a third-party implementation is expected to satisfy the same behaviors.

```
pip install -e ".[dev]"
pytest tests/conformance/ -v
```

## Requirement groups

| Group                       | Covers                                                  | Spec                                                                                     |
| --------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Delegation (`DELEG-*`)      | Signature, attenuation, continuity, depth, anti-replay  | [delegation-chain.md](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/index.md) |
| Scope-policy (`POLICY-*`)   | Effective scope = delegated ∩ local policy              | [cedar-policy.md](https://ca2a.agentrust-io.com/docs/spec/cedar-policy/index.md)         |
| Attestation (`ATTEST-*`)    | Fail-closed providers, measurement, chain, tamper, MRTD | [attestation.md](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md)           |
| Sealed channel (`SEAL-*`)   | Seal to attested key, no plaintext, tamper fails closed | [sealed-channel.md](https://ca2a.agentrust-io.com/docs/spec/sealed-channel/index.md)     |
| Provenance (`PROV-*`)       | DAG integrity, tamper detection, bound to authority     | [provenance-dag.md](https://ca2a.agentrust-io.com/docs/spec/provenance-dag/index.md)     |
| Inbound pipeline (`PIPE-*`) | The handler grants, records, and fails closed correctly | [call-graph.md](https://ca2a.agentrust-io.com/docs/spec/call-graph/index.md)             |

## Levels

- MUST: required for a cA2A-compatible claim. Partial conformance (MUST only) is sufficient.
- SHOULD: recommended; indicates a higher-quality implementation.

Test IDs are stable: once assigned, an ID is never reused even if the test is removed. This lets a conformance report for one version be compared against another.

## Scope note

The attestation requirements are validated against synthetic report and quote vectors plus the genuine AMD and Intel roots, since producing a real report requires confidential-computing hardware. A production conformance run on hardware, and end-to-end validation against a real quote, are the remaining step before a hardware-attested cA2A-compatible claim; see [LIMITATIONS.md](https://ca2a.agentrust-io.com/LIMITATIONS/index.md).
