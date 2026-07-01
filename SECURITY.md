# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/agentrust-io/ca2a/security/advisories/new). You will receive a confirmation within 2 business days and a triage decision within 5 business days.

## Response SLAs

| Severity | Definition | Fix Target |
|----------|------------|------------|
| Critical | Delegation forgery, scope escalation past a parent grant, sealed-channel plaintext exposure, attestation bypass, signing key extraction, provenance chain forgery | 30 days from confirmed report |
| High / Medium / Low | All other confirmed vulnerabilities | 90 days from confirmed report |

Timeline starts when the issue is confirmed as a valid vulnerability, not on initial receipt. We will communicate progress at least every 14 days during active remediation.

## Scope

The following components are in scope:

- **Delegation chain**: scope attenuation correctness (a child grant must be a provable subset of its parent), signature verification, depth limits, and cross-chain replay protection
- **Sealed peer channel**: any path by which a task payload could be read outside the peer's attested measurement
- **TEE attestation path**: peer measurement verification for TPM 2.0, AMD SEV-SNP, Intel TDX, and OPAQUE Managed Runtime providers, and binding of the channel key to that measurement
- **Signing key handling**: hardware-sealed key generation, storage, and use
- **Provenance record**: integrity of the delegation DAG; any path by which a valid TRACE record could be forged, reparented, or suppressed

## Out of Scope

- Bugs in TEE firmware or hardware microcode (AMD, Intel, or cloud provider trust anchor issues): report those directly to the relevant vendor
- Vulnerabilities in the A2A transport itself that are not specific to the cA2A profile: report those to the A2A project
- Vulnerabilities in the upstream Cedar policy engine that are not specific to cA2A's integration: report those to the [Cedar project](https://github.com/cedar-policy/cedar)
- Theoretical weaknesses in TEE threat models that are already acknowledged in public literature

If you are unsure whether an issue is in scope, report it anyway and we will triage.

## Credit

Reporters of confirmed, in-scope vulnerabilities will be acknowledged by name (or handle, if preferred) in the release notes of the fix. We will not publish details of the report without your consent. If you prefer to remain anonymous, say so in your advisory submission and we will honor that.
