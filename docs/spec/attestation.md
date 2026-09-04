# Peer Attestation

Before a peer is trusted with a delegated task, it proves it is running attested, measured code. cA2A reuses the pluggable TEE provider abstraction from [cmcp](https://github.com/agentrust-io/cmcp).

## Provider interface

A provider implements `BaseProvider`:

- `detect()` returns whether the provider is available on the current host. Available means `attest` can actually produce evidence here, not merely that the hardware exists: a provider that returns True and then raises would be selected and then fail.
- `attest(public_key, nonce)` returns an `AttestationReport` binding `public_key` to the host's hardware measurement under `nonce`.

### The signed key-and-nonce binding

Every provider signs over a caller-chosen field: `extraData` on a TPM quote, `REPORT_DATA` on a SEV-SNP report, `REPORTDATA` on a TDX quote. cA2A commits **both** the offered channel public key and the nonce there:

```
binding = sha256(prefix || len32(public_key) || public_key || len32(nonce) || nonce)
```

| Platform | Prefix | Field | Value written |
|---|---|---|---|
| TPM 2.0 | `ca2a-tpm-v1\|` | `extraData` (32 bytes) | the binding |
| AMD SEV-SNP | `ca2a-snp-v1\|` | `REPORT_DATA` (64 bytes) | the binding, zero-padded on the right |
| Intel TDX | `ca2a-tdx-v1\|` | `REPORTDATA` (64 bytes) | the binding, zero-padded on the right |

Committing the nonce alone would sign for freshness only, leaving `public_key` an unsigned assertion, so sealing a payload "to a key from a verified report" would not actually be rooted in hardware. A verifier re-derives this value from the report's own fields and requires equality, which is what promotes `public_key` and `nonce` from claim to signed fact. A report whose key was substituted after collection is rejected.

Three encoding details are load-bearing, and each prefix is versioned because this is wire format: a peer and its verifier MUST derive identical bytes.

- **Hashed, not raw.** `TPM2B_DATA` is capped below 64 bytes on some platforms (Azure returns `TPM_RC_SIZE`), and 32 bytes always fits. SEV-SNP and TDX reserve 64, so the digest is left-aligned and zero-padded, which is the convention the kernel's own callers and `agent-manifest` use; a report collected by either runtime is then byte-comparable.
- **Length-prefixed, not delimiter-joined.** With a delimiter a value containing it shifts the split without changing the digest, so `("a|b", "c")` and `("a", "b|c")` would commit identical bytes and a peer could bind a key other than the one it appears to offer. `nonce` is an arbitrary caller-supplied string, so that is reachable rather than theoretical.
- **Domain-separated per platform.** The three prefixes differ so a report collected on one platform cannot be replayed as another's evidence.

`ca2a_runtime.tee.binding` holds the single derivation the three providers share.

## The report

An `AttestationReport` carries `platform`, `measurement`, the bound `public_key`, and the `nonce`. Those four fields are what a report *claims*; on their own they are an assertion, since any peer can populate them with any values. Four further fields carry the evidence that makes them checkable, and they are named to match cmcp's report model so evidence is portable between the two runtimes:

| Field | Contents |
|---|---|
| `raw_evidence` | the raw blob the hardware signed (for TPM, the bare `TPMS_ATTEST`) |
| `quote_signature` | the signature over `raw_evidence` (for TPM, a marshalled `TPMT_SIGNATURE`) |
| `attestation_key_pem` | the key that produced that signature |
| `attestation_key_chain_pem` | the leaf-first certificate chain for that key |

All four are absent on `software-only`, which has no evidence by construction. A report claiming a hardware platform with no evidence cannot be verified, so it fails closed rather than being trusted.

## Providers

| Provider | Platform | Status |
|---|---|---|
| `software-only` | none | Available; for development and CI. Reports `platform: software-only`, never a hardware platform string. |
| `sev-snp` | AMD SEV-SNP | Verifier and collector both implemented (see below). `attest` produces a real report on a non-paravisor SNP guest through configfs-TSM. |
| `tdx` | Intel TDX | Verifier and collector both implemented (see below). `attest` produces a real DCAP quote on a TDX guest through configfs-TSM. |
| `tpm` | TPM 2.0 / vTPM | Verifier and collector both implemented (see below). `attest` produces a real quote on a Linux host with a TPM and tpm2-pytss. |
| `opaque` | OPAQUE Confidential Runtime | Tier 3, explicit opt-in, not auto-selected |

## SEV-SNP verification

`ca2a_verify.sev_snp.verify_sev_snp_report` appraises an AMD SEV-SNP attestation report offline, in three fail-closed steps:

1. Certificate chain: the VCEK is verified up to a trusted AMD root (ARK) through `ARK -> ASK -> VCEK`. Each certificate must be validly issued by the next, and the root must match a trusted anchor by fingerprint.
2. Report signature: the ECDSA-P384 signature (stored as little-endian `r` and `s`) is verified against the VCEK public key over the report body (`report[:0x2A0]`).
3. Binding: the launch `measurement` and the `report_data` (which carries the runtime key and nonce) are checked against expected values.

What is validated. The chain-verification path is exercised against the genuine AMD Milan ARK/ASK root chain fetched from AMD KDS (`tests/fixtures/sev_snp/`). The report-signature path is exercised end to end with a synthetic VCEK and report, because a genuine report plus VCEK pair requires real SEV-SNP hardware.

### SEV-SNP collection

`SevSnpProvider.attest` requests a report through the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`, Linux 6.7+), writing the `ca2a-snp-v1` binding as `REPORT_DATA` and reading the signed report back. It confirms the kernel's reported provider is `sev_guest` and that the returned report commits the binding it asked for, then ships the report as `raw_evidence` with the embedded signature as `quote_signature`.

No certificate chain travels with an SNP report yet, so `attestation_key_chain_pem` is absent and a verifier fetches the VCEK from the AMD KDS. The kernel does return a certificate table in `auxblob`, but as GUID-tagged DER rather than PEM; parsing a binary layout this collector has never seen from real hardware would be a guess, and shipping it in a PEM-named field would be a wrong one. Parsing it is what would make SNP appraisal fully offline, and is left until there is hardware to check it against.

**Azure confidential VMs are a different collector, not this one.** Azure runs SNP behind a Hyper-V paravisor, so the guest sees no `/dev/sev-guest`, registers no TSM provider, and cannot set `REPORT_DATA` at all: the paravisor binds the vTPM attestation key there instead. `detect()` therefore returns False on Azure and `attest` says why, rather than reporting that no SEV-SNP guest is present on a machine that is one. Rooting a channel key on Azure goes through the vTPM, which is the `tpm` provider's shape.

The collector has **not** been run on real SEV-SNP silicon. It is exercised against a simulated configfs tree and synthetic reports in `tests/unit/test_snp_tdx_attest.py`; see [hardware-validation.md](../hardware-validation.md) for what has.

Cross-operator use. Two operators in separate trust domains each bind their sealed-channel public key into a report and verify the counterparty's report against a pinned golden measurement. This composes into mutual attestation, confidential cross-operator delegation (seal to the attested key), and binary-swap detection (a changed measurement is rejected), validated in software as claim C6. See the [call graph](call-graph.md) and the `claim6-cross-operator-attestation` experiment.

## TDX verification

`ca2a_verify.tdx.verify_tdx_quote` appraises an Intel TDX quote (DCAP, ECDSA-256) offline in four fail-closed steps: the PCK certificate chain is verified up to a trusted Intel root; the Quoting Enclave report is verified against the PCK; the attestation key is confirmed to be the one the QE report data commits to (SHA-256 of the key and the QE auth data); and the attestation key's signature over the quote body is verified, along with the launch measurement (MRTD) and report data.

What is validated. The chain-verification path accepts the genuine self-signed Intel SGX Root CA fetched from Intel (`tests/fixtures/tdx/`) and rejects an untrusted root. The multi-level signature path (PCK to QE report to attestation key to quote) is exercised end to end with a synthetic self-consistent quote, because a genuine quote requires a TDX guest. Byte offsets follow the Intel DCAP Quote v4 layout; end-to-end validation against a real hardware quote requires a TDX guest and remains open.

### TDX collection

`TdxProvider.attest` uses the same configfs-TSM path as SEV-SNP, with the provider name `tdx_guest` and the `ca2a-tdx-v1` binding as `REPORTDATA`. Non-paravisor TDX is guest-controlled, so unlike Azure's SNP the guest sets that field itself, which is what the cross-operator run on GCP C3 relied on. The collector rejects a quote whose TEE type is not TDX or whose `REPORTDATA` does not match the binding it requested. A DCAP quote carries its own signature and PCK chain, so the evidence shipped is the quote verbatim and the chain travels inside it.

The collector has **not** been run on real TDX silicon. It is exercised against a simulated configfs tree and synthetic quotes in `tests/unit/test_snp_tdx_attest.py`.

## TPM verification

`ca2a_verify.tpm.verify_tpm_report` appraises a peer's TPM report offline: the AK certificate chain is verified to a trusted root, the AK signature over the `TPMS_ATTEST` blob is verified using the signature scheme and digest declared by the marshalled `TPMT_SIGNATURE`, the structure is confirmed to be a TPM-generated quote (magic and type), and the key-and-nonce binding below is checked. The released shared verifier supports ECDSA, RSASSA, and RSAPSS with SHA-256, SHA-384, or SHA-512. `verify_tpm_quote` is the lower-level compatibility form taking an attest blob plus either parsed signature metadata or a legacy bare signature. At this cA2A boundary a `bytes` value means only the legacy form: cA2A explicitly tags it as ECDSA/SHA-256 or RSASSA/SHA-256 according to the AK public-key type before delegation. This avoids guessing whether arbitrary signature-prefix bytes are a `TPMT_SIGNATURE` header. Callers holding a marshalled `TPMT_SIGNATURE` must use `parse_tpmt_signature()` first.

The cryptography is not implemented in cA2A. Steps 1, 2 and 4 delegate to `agent_manifest.verify_tpm_quote`, the canonical hardware-validated implementation cA2A already depends on; three divergent copies of one TPM verifier is the problem being retired (cmcp#447). cA2A delegates parsing of the `TPMT_SIGNATURE` emitted by `tpm2_quote -s` and `tpm2-pytss`'s `signature.marshal()` to Agent Manifest too, then passes the complete parsed result to quote verification. The scheme and digest declarations are outside the signed `TPMS_ATTEST` bytes, but they select the verification operation: relabelling either one without producing a matching signature fails. This establishes algorithm consistency, not a deployment policy about which supported algorithms are sufficiently strong.

### What the quote measures

The binding a TPM quote commits in `extraData` is the shared one defined above, under the `ca2a-tpm-v1|` prefix.

The measurement is `sha256:` followed by the quote's own `pcrDigest`, over PCRs 0-7 in the SHA-256 bank. The collector separately reads those PCRs and requires its digest to equal the quoted one, which catches a PCR selection mismatch before evidence ships. The verifier returns the measurement read out of the signed quote rather than the report's `measurement` field, and rejects a report where the two disagree.

### Trust anchors

TPM attestation keys chain to per-vendor roots, not to one published root the way SEV-SNP and TDX do. cA2A does not decide which vendors a deployment trusts: the verifier takes caller-supplied roots and consults nothing implicitly. `ca2a_verify.tpm_roots.AZURE_VTPM_ROOT_2023_PEM` is a root observed on Azure Trusted Launch, available so a deployment on that platform need not re-derive it, but trusting it stays an explicit import. Supplying no root at all is refused, because a chain validated against no anchor would accept any self-consistent chain.

**Pinning a root is not enough on Azure.** Hardware measurement on 2026-08-01 found the AK certificate presentation varies across the fleet. One host (`Standard_D2s_v5`, eastus) presented a 1596-byte certificate under `Azure Cloud Virtual TPM CA - 11` with a walkable AIA chain reaching the pinned root. Another (`Standard_D2s_v7`, eastus2) presented a 994-byte certificate issued by `Global Virtual TPM CA - 03` with **no AIA extension**, so no intermediates could be fetched, none were stored in NV, and chained verification was impossible. A deployment must obtain and pin the root for the hierarchy its own hosts present. See [LIMITATIONS.md](../../LIMITATIONS.md).

### Two deliberate differences from cmcp's collector

cmcp falls back to the SHA-1 PCR bank and downgrades the report to `software-only`; cA2A requires the SHA-256 bank and raises instead, because a report labelled `sha256:` that measured SHA-1 banks is a mislabel waiting to happen. cmcp can also emit a report whose only evidence is an unsigned PCR read, marked software-only; in cA2A, failing to produce a signed quote raises, because the platform string on a cA2A report is the provider's identity and a `tpm` report that can never verify is worse than an honest error.

What is validated. The collector's checks, the TPM interaction shapes, and report verification end to end are exercised against synthetic self-consistent vectors in `tests/unit/test_tpm_attest.py`. Those vectors cover a valid RSAPSS/SHA-384 report and reject RSASSA/SHA-256 signatures falsely declared as either RSAPSS or SHA-384, both directly and through the reference wire and offer-verification path. On a real Azure Trusted Launch vTPM (2026-08-01) the collector produced a genuine platform-AK quote, `parse_tpmt_signature` parsed the real `TPMT_SIGNATURE` (RSASSA/SHA-256), the signature verified against the shipped key, a tampered attest blob was rejected, and the quote's `extraData` equalled the derived key-and-nonce binding. Collector and verifier ran in one process, which retires the earlier tooling caveat. The new non-default algorithm cases are synthetic; they do not claim a live hardware RSAPSS/SHA-384 run.

Chained verification did **not** pass on that host, because its AK certificate carries no AIA extension and so no chain can be assembled. That is a property of the host, not a defect in the verifier, and it is recorded in [LIMITATIONS.md](../../LIMITATIONS.md).

## Fail closed

A provider `detect()`s to True only where `attest` works on that host, and verification fails closed when evidence is absent or invalid. All three hardware providers now implement `attest`, so each `detect` probes what its own collector needs: a TPM device plus tpm2-pytss, or configfs-TSM plus the platform's guest device node. Where a host cannot collect, `attest` raises `AttestationUnsupported` naming the missing piece rather than asserting the platform is absent. `software-only` returns False from `detect` so a no-guarantee posture is always an explicit choice. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Why this is the critical path

Real hardware attestation verification (SEV-SNP VCEK chain from AMD KDS, Intel TDX quote via QVL/PCS, TPM AK cert plus checkquote) is a dependency for any cross-operator trust claim, single-agent or multi-agent. It is shared with cmcp and sequenced first on the roadmap so the demo matches the claim.
