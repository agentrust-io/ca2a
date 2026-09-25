# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the input cA2A reads before it has decided to trust the
party that sent it. Mirrors the setup in agentrust-io/agent-manifest and
agentrust-io/cmcp.

## What is fuzzed

| Target | Surface |
| --- | --- |
| `fuzz_wire_documents.py` | JSON from outside: the A2A request `PeerNode.handle` serves (delegation chain, holder proof, caller offer, sealed payload), the authenticated-response envelope, a revocation snapshot, and the chain and TRACE DAG documents the offline verifier loads. |
| `fuzz_attestation_parsers.py` | TDX quote, SEV-SNP report, TPM quote and TPMT_SIGNATURE parsing, plus `verify_challenge` over caller-supplied challenge text. |
| `fuzz_canonical_json.py` | The RFC 8785 bytes every credential, holder proof, revocation statement and response MAC is computed over. |

## The properties

The wire and parser targets assert that each surface fails closed: it returns,
or raises the error family it documents (`CA2AError`, and `AttestationFailed`
for evidence). A `TypeError`, `struct.error`, `AttributeError` or
`RecursionError` escaping means a caller written against the documented
exception will not catch it, and on the reference server the connection drops
with no response.

`fuzz_canonical_json.py` asserts a round trip: parsing the canonical output must
reproduce the input exactly, and integers outside +/-(2**53 - 1) must be
refused. cA2A's data model has no floats, so the comparison is exact.

## Standing when added

A local plain-Python run of each `TestOneInput` (Atheris does not install on the
Windows machine it was written on) found three escapes that are fixed in the
same change, with regression tests: `TdxQuote.parse` raising `struct.error` on a
quote whose signature section is shorter than its declared contents,
`verify_challenge` raising `TypeError` on a non-ASCII MAC, and
`DelegationCredential.from_dict` raising `TypeError` on a hop that is not an
object.

## Bundling gotcha

`compile_python_fuzzer` bundles each target with PyInstaller, which follows
static imports only and bundles code, not package data. `build.sh` passes
`--collect-submodules=email` for the lazy `email.mime` import in the
cryptography and pydantic stacks, and `--collect-data` for `agentrust_trace`,
whose TRACE schema `ca2a_verify.dag` loads at import time.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_wire_documents
```

## In CI

`cflite_pr.yml` fuzzes code the pull request touched, for five minutes.
`cflite_batch.yml` runs every target for thirty minutes, nightly. Both are
read-only and time out at 45 minutes; the oss-fuzz base image build dominates.
