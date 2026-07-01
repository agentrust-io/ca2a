"""
Experiment: Sealed-Payload Confidentiality (Fail-Closed)
Claim 4: a task payload sealed to a peer's attested measurement decrypts only
inside that peer's verified enclave.

Status: GATED on Tier 2. SealedChannel is a fail-closed placeholder. The
enclave-sealing backend that would let us demonstrate confidentiality is not
implemented in this release. This script demonstrates the CURRENT honest
behavior: seal()/open() raise SealedChannelError rather than silently emitting
plaintext. The confidentiality property itself is pending Tier 2.

Run from repo root (package installed editable):
  .venv/Scripts/python.exe experiments/claim4-sealed-payload-confidentiality/run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root without install.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ca2a_runtime.channel import SealedChannel
from ca2a_runtime.errors import SealedChannelError

PEER_MEASUREMENT = "sha256:" + "ab" * 32
SECRET = b"confidential task payload: transfer $5000 to account 12345"


def result(label: str, value: str, ok: bool | None = None) -> None:
    if ok is None:
        print(f"    {label}: {value}")
    elif ok:
        print(f"    {label}: {value}  OK")
    else:
        print(f"    {label}: {value}  FAIL")


def main() -> int:
    print("=" * 60)
    print("Experiment: Sealed-Payload Confidentiality (Fail-Closed)")
    print("Claim 4: payload decrypts only inside the attested peer")
    print("Status: GATED on Tier 2 (SealedChannel is a placeholder)")
    print("=" * 60)

    failures = 0
    channel = SealedChannel(peer_measurement=PEER_MEASUREMENT)

    # ------------------------------------------------------------------
    # Property 1: seal() fails closed. No silent plaintext.
    # ------------------------------------------------------------------
    print("\n[1. seal() fails closed]")
    seal_output: bytes | None = None
    try:
        seal_output = channel.seal(SECRET)
    except SealedChannelError as exc:
        result("seal(payload) raised", "SealedChannelError", True)
        result("error code", exc.code, exc.code == "SEALED_CHANNEL_ERROR")
        if exc.code != "SEALED_CHANNEL_ERROR":
            failures += 1
        detail = exc.detail or ""
        names_tier2 = "Tier 2" in detail
        result("detail names Tier 2", "YES" if names_tier2 else "NO", names_tier2)
        if not names_tier2:
            failures += 1
        # The exception path is exactly what "no silent plaintext" means:
        # control never reached a return, so seal_output is still None.
        no_plaintext = seal_output is None
        result("plaintext emitted", "NO" if no_plaintext else "YES", no_plaintext)
        if not no_plaintext:
            failures += 1
    else:
        # A returned value here would be the dangerous silent-degradation case.
        result("seal(payload) raised", "nothing: returned a value", False)
        leaked = seal_output == SECRET
        result("plaintext emitted", "YES" if leaked else "unknown blob", False)
        failures += 1

    # ------------------------------------------------------------------
    # Property 2: open() fails closed too.
    # ------------------------------------------------------------------
    print("\n[2. open() fails closed]")
    try:
        channel.open(b"sealed blob that we never actually produced")
    except SealedChannelError:
        result("open(sealed) raised", "SealedChannelError", True)
    else:
        result("open(sealed) raised", "nothing: returned a value", False)
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures == 0:
        print("KEY RESULT: SealedChannel fails closed. seal()/open() raise")
        print("SEALED_CHANNEL_ERROR instead of emitting plaintext. This is")
        print("the honest current behavior. The confidentiality claim itself")
        print("(payload decrypts only under the attested peer measurement) is")
        print("PENDING Tier 2 and is not demonstrated here.")
        return 0
    print(f"KEY RESULT: {failures} check(s) FAILED. Fail-closed behavior not")
    print("confirmed: see output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
