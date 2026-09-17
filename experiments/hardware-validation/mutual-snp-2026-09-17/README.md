# Same-operator mutual SNP diagnostic

On September 17, 2026, two temporary GCP N2D AMD Milan SEV-SNP guests completed
cA2A handoffs in both directions. Separately retrieved receiver logs contained
hardware caller appraisal and matching nonsecret payload digests. Both VMs and
boot disks were deleted after collection.

`a-to-b.json` and `b-to-a.json` are sanitized, unsigned observations from the
paced control run: one positive and ten expected rejections per direction.
`controls.py` retains the exact test runner. It uses real SNP verification with
test-only offer/policy mutations and counters around sealing and task POST.
Seven callee-side rejections per direction occurred before either function ran.
Receiver-side software callers, incorrect signed bindings and excess scope were
also rejected; receiver decryption ordering was not instrumented live.

The runtime was based on `d3b7eb618084c4dc2f1270c2050d443f5bab5a3d` plus the
hardware-floor, pinned-verifier and acceptance-harness changes in this PR.
Uploaded source archive SHA-256:
`c05e0d02c22aba0943f6378bb59bcd9e8c18f9d43b7b27b12274061473cfea93`.
This predates rebasing the PR onto newer upstream changes. The retained private
archive and file manifest identify the tested source; the hardware run was not
repeated on the rebased PR head.

Environment: Ubuntu 24.04, kernel `7.0.0-1011-gcp`, Python 3.12,
agent-manifest 0.12.0, agentrust-trace 0.10.0, cryptography 50.0.1 and
cedarpy 4.8.7. The owner obtained the AMD Milan root independently over HTTPS
and pinned each host's VCEK chain and SSH-bootstrap launch measurement. Private
test delegation keys were generated inside each VM and never exported.

Both signed reports showed PLATFORM_INFO `0x25`, guest SVN 0, VMPL0 and guest
policy `0x30000` (DEBUG disabled). The diagnostic profile required alias checking
and allowed SMT and SVN zero. Policies forbidding SMT, requiring ciphertext
hiding, or requiring guest SVN one rejected the hosts. One visible thread per
core in cloud configuration did not clear the signed report's physical SMT flag.

The first unpaced run in each direction timed out at the final scope case's
handshake and exited 1. Earlier appraisal observations were retained privately;
those attempts are not counted as complete or as security passes. The cause
was not isolated. The runner then saved results incrementally and paced cases
one second apart. Both reruns exited 0 with unchanged runtime/verifier code.
A VCEK nonpositive-serial deprecation warning was observed; current verification
succeeded, but future cryptography compatibility needs attention.

## Limits

This is same-project, same-operator protocol evidence, with unsigned local logs
and an unauthenticated HTTP response. The bootstrap launch measurement does not
measure cA2A application code installed after boot. Certificate revocation was
not checked. Strict confidentiality platform acceptance, cross-operator trust,
complete information-flow enforcement, protected broker provisioning and GPU
inference remain open. Raw reports, certificates, cloud identifiers, test keys
and internal inventory are deliberately absent from this public record.

To repeat, follow [the two-host procedure](../../../docs/mutual-hardware-acceptance.md)
with independently provisioned pins and fresh local keys, then run
`python /opt/ca2a-run/controls.py` on each guest after the initial bidirectional
calls. Collect both receiver logs independently; do not treat a remote success
response as sufficient evidence.
