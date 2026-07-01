# Experiment: Sealed-Payload Confidentiality (Fail-Closed)

**Claim:** A task payload sealed to a peer's attested measurement decrypts only inside that peer's verified enclave (cA2A Claim 4).

**Status:** GATED on Tier 2. `SealedChannel` is a fail-closed placeholder. The enclave-sealing backend that would make the confidentiality property demonstrable is not implemented in this release (see `ROADMAP.md` / `LIMITATIONS.md`). This experiment does **not** claim confidentiality is proven. It proves the honest fallback: absent the backend, the runtime refuses to seal rather than emitting plaintext.

**What this experiment proves today:**

1. `SealedChannel(peer_measurement).seal(payload)` raises `SealedChannelError`. It does not return the payload, an empty blob, or any silent plaintext.
2. `SealedChannel(...).open(sealed)` raises `SealedChannelError` for the same reason.
3. The error carries a `SEALED_CHANNEL_ERROR` code and a detail string that names Tier 2, so a caller can distinguish "not implemented yet" from a runtime encryption fault.

**What this experiment does NOT prove (pending Tier 2):**

- That a sealed payload is confidential against the transport or the host.
- That the payload decrypts only under the attested peer measurement and nowhere else.

Those are the actual confidentiality properties. They require the measurement-bound sealing backend and a real attested peer, and are marked as a skipped placeholder in the CI test.

**Why fail-closed matters for governance:**

The dangerous failure mode for a confidentiality primitive is silent degradation: an unfinished channel that quietly forwards plaintext while callers believe it is sealed. cA2A's placeholder is wired so the confidentiality-dependent path cannot run at all until the backend lands. A caller that forgets to check the Tier gate gets an exception, not a leak.

## Running

```bash
# From repo root, with the package installed editable (pip install -e .)
.venv/Scripts/python.exe experiments/claim4-sealed-payload-confidentiality/run.py
```

## Expected output

```
============================================================
Experiment: Sealed-Payload Confidentiality (Fail-Closed)
Claim 4: payload decrypts only inside the attested peer
Status: GATED on Tier 2 (SealedChannel is a placeholder)
============================================================

[1. seal() fails closed]
    seal(payload) raised: SealedChannelError  OK
    error code: SEALED_CHANNEL_ERROR  OK
    detail names Tier 2: YES  OK
    plaintext emitted: NO  OK

[2. open() fails closed]
    open(sealed) raised: SealedChannelError  OK

============================================================
KEY RESULT: SealedChannel fails closed. seal()/open() raise
SEALED_CHANNEL_ERROR instead of emitting plaintext. This is
the honest current behavior. The confidentiality claim itself
(payload decrypts only under the attested peer measurement) is
PENDING Tier 2 and is not demonstrated here.
```

Exit code is 0: fail-closed behavior confirmed is a success, not a failure.
