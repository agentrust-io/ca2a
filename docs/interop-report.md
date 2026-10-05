# cA2A interoperability run, October 5, 2026

Adding optional cA2A discovery and message parsing produced identical outcomes in the selected official A2A TCK tests: **183 passed, 5 failed, 47 skipped**, with 30 tests deselected. This is **not a conformance pass**. All five failures were also present in the baseline without cA2A.

The official ITK traversal engine passed six Python↔TypeScript scenarios without cA2A and the same six with cA2A attached to the Python peer. A separate protected-request probe carried Python-issued, signed two-hop credentials through the official TypeScript client into the Python SDK server. The credential bodies and signatures survived; malformed credentials, invalid signatures, missing opt-in and local policy denial were rejected.

**Assurance was `none`. No hardware attestation was exercised. Reusing a valid proof within its challenge lifetime invoked the protected read handler again.**

## Scope and versions

| Component | Revision or version |
| --- | --- |
| cA2A source | [`9f74318f03c8c92699a2c68e9484fbcb2de2f984`](https://github.com/agentrust-io/ca2a/tree/9f74318f03c8c92699a2c68e9484fbcb2de2f984) |
| Official TCK | [`263b9cfaf16a554bdfb166a7ba5b67716e946349`](https://github.com/a2aproject/a2a-tck/tree/263b9cfaf16a554bdfb166a7ba5b67716e946349) |
| Official ITK | [`b57c5332aa883b27c1e5c915fe61cac76d2a1de9`](https://github.com/a2aproject/a2a-itk/tree/b57c5332aa883b27c1e5c915fe61cac76d2a1de9) |
| Python SDK for TCK, bridge tests and protected requests | Released `a2a-sdk==1.1.5`, matching cA2A's dev dependency |
| Python SDK and peer for ITK | [`5653daf8315ab58c8dacc53be720c4ed632ee7ce`](https://github.com/a2aproject/a2a-python/tree/5653daf8315ab58c8dacc53be720c4ed632ee7ce) |
| TypeScript SDK and peer | [`af1b5a804daabb331a4d4437ac7cef61105bf3ad`](https://github.com/a2aproject/a2a-js/tree/af1b5a804daabb331a4d4437ac7cef61105bf3ad), package `1.3.0` |
| Host | Windows, Python 3.12.10, Node 24.18.1 ARM64 |

The [environment record](../experiments/a2a-interop/results/environment.json) contains installed package versions for the two separate Python environments and the Node dependencies. SDK/runtime source was not modified. The wrappers, probes and this report are additions on the report branch.

## Official TCK: same five failures

The SUT was the TCK's generated official Python SDK agent. The extension variant merged the optional cA2A declaration into its card and parsed incoming message metadata before delegating ordinary traffic to the original executor. It rejected protected operations; this SUT was not a cA2A application service.

Both runs selected MUST tests across JSON-RPC, gRPC and HTTP+JSON. Comparison of every selected JUnit case found identical pass/fail/skip outcomes, not merely matching totals. Both pytest commands exited 1.

| Failing test | Transport | Expected | Observed in both runs |
| --- | --- | --- | --- |
| Cancel terminal task | HTTP+JSON | HTTP 409 | HTTP 400 |
| Subscribe to terminal task | gRPC | `UNIMPLEMENTED` | `INVALID_ARGUMENT` |
| Subscribe to terminal task | JSON-RPC | `-32004` | `-32602` |
| Push notifications unsupported | gRPC | `UNIMPLEMENTED` | `FAILED_PRECONDITION` |
| Unsupported A2A version | gRPC | Reject with `UNIMPLEMENTED` | Request processed normally |

These are failures of this pinned baseline SDK/SUT combination against this pinned TCK. This experiment does not isolate whether each correction belongs in the SDK, generated SUT or TCK. SHOULD/MAY tests were not run because the MUST suite did not pass.

The TCK's requirement-level JSON reports 76 PASS, 3 FAIL, 14 SKIPPED and 36 NOT TESTED entries in each run. These are requirement counts, not pytest case counts. The console's failed column also includes NOT TESTED requirements. Retain that distinction when reading its compatibility percentages.

Evidence: [baseline log](../experiments/a2a-interop/results/baseline/pytest.log), [extension log](../experiments/a2a-interop/results/ca2a/pytest.log), [baseline JUnit](../experiments/a2a-interop/results/baseline/junit.xml), [extension JUnit](../experiments/a2a-interop/results/ca2a/junit.xml), and [comparison](../experiments/a2a-interop/results/summary.json). Each run directory also contains the command, served card, server log and upstream JSON/HTML report.

## Official ITK: bounded two-language traversal

Each scenario traversed Python → TypeScript → Python. The entry request used JSON-RPC; the protocol below selected the cross-agent hops.

| Hop transport | Baseline, non-streaming | Baseline, streaming | cA2A attached, non-streaming | cA2A attached, streaming |
| --- | --- | --- | --- | --- |
| JSON-RPC | Pass | Pass | Pass | Pass |
| gRPC | Pass | Pass | Pass | Pass |
| HTTP+JSON | Pass | Pass | Pass | Pass |

The controller called the upstream `testlib.execute_itk_test` with `send_message`, edges `0->1` and `1->0`, and the specified streaming/transport options. It retained the upstream instruction generator and traversal verifier. The Python extension variant added cA2A discovery and ordinary-message parsing; the TypeScript peer was unchanged.

This was **not the standard ITK cluster launcher or the full multi-SDK matrix**. The launcher requires Linux facilities unavailable on this host. The local controller owned and stopped its peer processes. On Windows, the Python peer wrapper omitted POSIX signal-handler registration. The controller loaded the real launcher configuration module without executing the package initializer, which otherwise imports `fcntl`. No `fcntl` stub or substitute test verdict was used.

These traversal messages do not carry cA2A credentials. Their success establishes ordinary traversal with the extension attached, not credential preservation. See the separate probe below for that narrower measurement.

Evidence: [baseline results](../experiments/a2a-interop/results/itk/baseline-results.json), [extension results](../experiments/a2a-interop/results/itk/ca2a-results.json), [engine log](../experiments/a2a-interop/results/itk-run.log), [controller](../experiments/a2a-interop/run_itk.py) and [Python wrapper](../experiments/a2a-interop/itk_sut.py). Peer cards and logs are in the same results directory.

## Protected TypeScript → Python request

This supplemental probe used the actual TypeScript SDK client, agent-card discovery, SDK JSON conversion and JSON-RPC transport against the existing Python inventory example. Python cA2A issued the credentials, holder proof and sealed payload. TypeScript transported them; it did not independently issue or verify credentials.

| Case | Observation |
| --- | --- |
| Ordinary request | Public response, no protected handler invocation |
| Signed two-hop read | Accepted; credential canonical bytes and signatures preserved; integer fields restored exactly |
| Same A2A message repeated | Accepted; protected read handler invoked again |
| Same proof with new A2A message ID | Accepted; protected read handler invoked again |
| Write capability outside local policy | `SCOPE_NOT_PERMITTED`; no additional handler invocation |
| Missing extension HTTP header | `CA2A_OPT_IN_REQUIRED`; no additional handler invocation |
| Fractional credential depth (`0.5`) | `TRANSPORT_ERROR`; no additional handler invocation |
| Changed signature byte, valid hex encoding | `INVALID_CREDENTIAL`; no additional handler invocation |

The read handler ran three times: the original request and the two reuses. cA2A's stateless challenge permits reuse before expiry. This run demonstrates neither deduplication nor at-most-once execution. Deployments that need those properties must add and test appropriate state. The [holder-proof source](https://github.com/agentrust-io/ca2a/blob/9f74318f03c8c92699a2c68e9484fbcb2de2f984/src/ca2a_runtime/delegation/holder.py) documents that proofs remain usable during this window; its phrase “at-most-once-per-window” should not be interpreted as an execution guarantee.

The current SDK bridge restores only integral numeric values for credential `depth`, `not_before` and `not_after`; it does not blindly truncate fractional values. The older expectation that a cross-language round trip necessarily exposes an integer-coercion bug was not supported by this run.

Evidence: [probe results](../experiments/a2a-interop/results/protected-ts.json), [Python driver](../experiments/a2a-interop/protected_ts.py) and [TypeScript client](../experiments/a2a-interop/ts_client.mts). Separately, all **55 existing bridge and HTTP loopback tests passed** against Python SDK 1.1.5: [JUnit](../experiments/a2a-interop/results/sdk-tests.xml).

## Limits and next checks

- No full conformance pass: five MUST failures remain, and the TCK registers untested requirements.
- No Go, Java, Rust or .NET peer was exercised. No mixed-version v0.3 traversal, push notifications, cancellation or resubscription ITK scenario was run.
- Protected cA2A traffic was tested only from the TypeScript client to the Python server over JSON-RPC. gRPC/REST protected traffic, reverse-direction enforcement and independently issued TypeScript credentials remain untested.
- The ITK and TCK used different Python SDK revisions, deliberately recorded above. Do not combine their results into a claim about one SDK version.
- No enclave, TPM, hardware attestation, production deployment or hostile network was involved. The local peers were software-only; caller attestation was `not_offered`.
- Initial native `cbor2` loading was blocked by Windows Application Control. The measured runs used a fresh environment with the supported pure-Python `cbor2==5.7.1` build. Security controls were not changed.

The next useful work is to isolate the five baseline TCK failures, run the unmodified ITK launcher on Linux across the remaining SDKs, and extend protected metadata probes to gRPC and HTTP+JSON. None of those results is claimed here.

## Reproduction

See [the experiment README](../experiments/a2a-interop/README.md) for setup and commands. Raw artifacts are retained alongside runnable probes. No production keys or long-lived credentials are needed.
