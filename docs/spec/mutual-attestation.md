# Mutual Attestation

---
Status: Proposal
Written: 2026-08-09
Stability: Unstable, no code written
---

## What is one-directional, and what is not

The primitives are symmetric. Either peer can bind a channel key into a report
(`attest_channel`) and either can appraise one (`verify_offer`); the
`claim6-cross-operator-attestation` experiment drives both directions and is why
[attestation.md](attestation.md) says the design composes into mutual attestation.

**The reference transport is what is one-directional.** In `ca2a_runtime.transport`:

```
caller                                   callee
  │  GET /channel?nonce=N_caller  ───────▶
  │  ◀─────────── ChannelOffer bound to N_caller
  │  appraise, seal payload to callee key
  │  POST /task  ─────────────────────────▶
  │                                        verify delegation chain, act
```

The callee verifies the caller's **delegation chain**, which is authorization: it
proves the caller holds a credential whose scope covers the request. It says
nothing about what the caller is running. A callee has no way to know whether the
peer sending it a task is an enclave or a laptop.

## The change

A callee-issued challenge, and a caller offer bound to it.

```
caller                                   callee
  │  GET /channel?nonce=N_caller  ───────▶
  │  ◀── ChannelOffer(N_caller) + challenge C
  │  appraise callee, seal payload
  │  attest own channel key under C
  │  POST /task + ChannelOffer(C)  ──────▶
  │                                        appraise caller BEFORE acting
  │  ◀────────────── response sealed to caller key
```

Three properties fall out, and each is a requirement rather than a consequence:

**The challenge must come from the callee.** A caller that picks its own nonce
proves only that it can produce a report, not that it produced one for *this*
exchange. That is the same replay the caller's nonce already prevents in the other
direction.

**The callee must appraise before it acts, not merely before it responds.** The
task payload is sealed to the callee's key, so the callee can read it the moment
it arrives. Appraising afterwards means an unattested caller has already had its
work done. This ordering is the whole value of the change and needs a test that
fails if the calls are swapped.

**The caller's key must be used, or it is ceremony.** An attested key that is
appraised and then discarded adds a round trip and no property. Sealing the
response to it makes it load-bearing: the callee's answer becomes readable only by
the enclave it appraised.

## The state problem

A challenge is worth nothing unless it is single-use and expiring, and the
reference server currently keeps no state at all.

**Option A: a challenge store.** Issue random challenges, remember them, delete on
use, expire on a timer. Straightforward, and it makes the server stateful — which
matters for anyone running more than one instance, because a challenge issued by
one is unknown to the next.

**Option B: a stateless challenge.** `HMAC(server_secret, timestamp || random)`,
verified by recomputation. No storage, works across instances, and single-use is
*not* achievable without state: the same challenge replays until it expires. The
window is a parameter rather than zero.

Neither is free and the difference is real: A gives exactly-once within one
process, B gives at-most-once-per-window across many.

## Posture when the caller will not attest

Most callers, today, cannot: cA2A is alpha and the ecosystem is two peers we run.
A callee that refuses unattested callers by default is a callee nobody can talk
to; one that accepts them silently has added a field nobody reads.

The shape used everywhere else in this stack applies here: record the outcome,
make the requirement configurable, and never let absence look like success. A
callee should be able to say "hardware or nothing" and should not say it by
default.

## What this still does not give you

**It is not simultaneous.** The caller appraises the callee, then the callee
appraises the caller. There is an instant where the caller has committed a sealed
payload to a peer it has verified, and the callee has not yet verified it. A truly
simultaneous exchange needs a commitment step neither side can back out of, which
is a larger protocol than this.

**It does not make either peer trustworthy.** It establishes what each side is
running. A correctly attested enclave can still be running a program that behaves
badly, and the delegation chain remains the thing that says what it is allowed to
ask for.

**It is not validated on hardware in both directions.** The cross-operator run
recorded in [hardware-validation.md](../hardware-validation.md) had the caller
appraise a real TDX quote and the callee appraise nothing. Making the protocol
mutual does not make that run mutual; it makes a mutual run possible, and both
peers in it were driven by one operator's harness.
