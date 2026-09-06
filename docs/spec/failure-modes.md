# Failure Modes

The full peer handler raises a `CA2AError` subtype when a required check fails and returns no payload. The configured caller-attestation requirement determines whether an absent offer is acceptable. The default permits absence and records `not_offered`; it never accepts a present but invalid offer.

## Inbound failures

| Failure | Error code | Result |
|---|---|---|
| Root issuer outside local trust set | `UNTRUSTED_DELEGATION_ROOT` | Stop before holder proof and policy |
| Invalid credential signature or validity | See [error codes](error-codes.md) | Stop before holder proof and policy |
| Scope widens, link breaks, depth exceeds limit, or credential ID repeats | `SCOPE_ESCALATION`, `BROKEN_DELEGATION_LINK`, `DELEGATION_DEPTH_EXCEEDED`, `CREDENTIAL_REPLAY` | Reject the chain |
| Missing or invalid required holder proof | `HOLDER_PROOF_INVALID` | Stop before policy; emit no decision record |
| Caller offer fails appraisal or required assurance is absent | `ATTESTATION_FAILED` | Stop before payload opening; refusal can carry a denial record |
| Requested capability outside effective scope | `SCOPE_NOT_PERMITTED` | Stop before payload opening; carry a denial record |
| No channel key, wrong key, malformed or altered ciphertext | `SEALED_CHANNEL_ERROR` | Return no plaintext |

See [inbound peer-call decision](call-graph.md) for ordering. The lower-level `enforce_peer_call` helper does not perform holder proof or caller appraisal.

## Attestation requirements

`require_caller_attestation="none"` permits an absent offer. `"any"` requires an appraisable offer, including software assurance. `"hardware"` requires hardware assurance. A present but unappraisable offer is refused at every setting. An Agent Card or valid credential does not replace runtime appraisal.

Hardware provider selection and evidence collection can fail with `ATTESTATION_UNSUPPORTED`; evidence appraisal can fail with `ATTESTATION_FAILED`. A detected device does not guarantee a later collection operation succeeds. TPM, SEV-SNP, and TDX have collectors and verifiers, but their deployment evidence and remaining gaps differ. See [hardware validation](../hardware-validation.md).

The `auto` provider setting does not silently fall back to software when hardware is unavailable. Software mode must be selected explicitly. The `advisory` and `silent` enforcement-mode names do not currently disable peer-path denial.

## Offline evidence failures

Unsigned `verify_dag` checks path consistency: root shape, parent hashes, and record-ID uniqueness. `cross_check_chain` checks credential IDs and subjects against an independently verified chain. These checks do not authenticate an unsigned record producer or detect every possible rewrite; see [provenance DAG](provenance-dag.md).

Signed `verify_trace_dag` additionally checks trusted signing keys and signatures. Invalid records raise `TRACE_RECORD_INVALID`; broken links raise `PROVENANCE_LINK_BROKEN`. A link naming an unsupported digest raises `TRACE_DIGEST_UNSUPPORTED`, meaning the verifier could not establish the link rather than that it established tampering.

## Replay and completion boundaries

Duplicate credential IDs within a chain and cross-chain splices are rejected. The offline verifier has no global used-credential database, so those checks do not establish single-use credentials across requests.

A successful authorization record does not establish that payload opening or application execution succeeded. Applications need evidence of their own completion behavior. See [limitations](../../LIMITATIONS.md) and the [threat model](threat-model.md).
