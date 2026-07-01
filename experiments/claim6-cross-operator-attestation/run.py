"""
Cross-operator attestation experiment (Claim 6).

Two peer agents in separate trust domains, each with independent Ed25519 keys,
mutually attest before exchanging a task. Each peer produces an AttestationReport
binding its public key to its enclave measurement under the counterparty's fresh
nonce. The counterparty verifies that report independently: the quote chains to
genuine TEE silicon, the nonce matches its challenge, and the measurement equals
the golden value it agreed to talk to. A silently swapped binary changes that
side's measurement, so the counterparty (in a different trust domain, with no
shared CA) catches the swap.

This experiment is SKIPPED. It verifies nothing yet: real hardware attestation
backends (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert +
checkquote) are Tier 3 and not implemented in this release. Every BaseProvider
detect() returns False, so no provider can produce a quote and no counterparty
can verify one. See ROADMAP.md.

It is safe to run anywhere: it probes for a hardware provider, finds none, prints
the protocol shape and a software-only illustration of the report structure
clearly labeled as NOT hardware-attested, then prints SKIP and exits 0.

Running:
  pip install -e .
  python experiments/claim6-cross-operator-attestation/run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root without install.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ca2a_runtime.delegation import new_keypair
from ca2a_runtime.tee import AttestationReport, BaseProvider

# A stand-in measurement. It is NOT a hardware value and carries no assurance;
# a real report's measurement is produced by TEE silicon and appraised by a
# verifier against a golden value.
_SW_ONLY_MEASUREMENT = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"


def _detect_hardware_provider() -> BaseProvider | None:
    """Return the first available hardware TEE provider, or None.

    Real hardware providers are Tier 3 and not shipped in this release, so there
    are no BaseProvider subclasses to probe and this returns None. The loop shape
    mirrors the future gateway probe: each candidate's detect() is consulted and
    the software path is never used to fake a hardware result.
    """
    candidates: list[BaseProvider] = []  # no hardware backends implemented yet
    for provider in candidates:
        try:
            if provider.detect():
                return provider
        except Exception:
            continue
    return None


def _short(value: str, width: int = 16) -> str:
    return value[:width] + ("..." if len(value) > width else "")


def main() -> int:
    print("=" * 60)
    print("Experiment: Cross-operator attestation (Claim 6)")
    print("Two peers, different trust domains, independent keys, mutual attestation")
    print("=" * 60)

    # --- 1: independent keys in two trust domains ---
    a_priv, a_pub = new_keypair()
    b_priv, b_pub = new_keypair()
    del a_priv, b_priv  # each stays in its own operator's domain; unused here
    print("\n[1] Independent keys in two trust domains")
    print(f"    Operator A public key: {_short(a_pub)}")
    print(f"    Operator B public key: {_short(b_pub)}")
    print(f"    Keys are distinct: {'YES' if a_pub != b_pub else 'NO'}")

    # --- 2: probe for a real hardware backend ---
    print("\n[2] Provider probe (looking for a real hardware backend)")
    provider = _detect_hardware_provider()
    if provider is None:
        print("    No hardware TEE provider detected (all detect() -> False)")
    else:
        print(f"    Detected: {provider.platform}")

    # --- 3: software-only illustration of the report shape ---
    # These reports are constructed by hand, NOT produced by TEE silicon. They
    # illustrate the AttestationReport structure only and carry no assurance.
    n_a = "nonce-from-A-to-B-0000000000000000"
    n_b = "nonce-from-B-to-A-1111111111111111"
    a_to_b = AttestationReport(
        platform="software-only",
        measurement=_SW_ONLY_MEASUREMENT,
        public_key=a_pub,
        nonce=n_b,  # A binds its key under B's fresh challenge
    )
    b_to_a = AttestationReport(
        platform="software-only",
        measurement=_SW_ONLY_MEASUREMENT,
        public_key=b_pub,
        nonce=n_a,  # B binds its key under A's fresh challenge
    )
    print("\n[3] Software-only illustration of the report shape (NOT hardware-attested)")
    print(
        f"    A -> B report: platform={a_to_b.platform} "
        f"measurement={_short(a_to_b.measurement, 12)} "
        f"key={_short(a_to_b.public_key)} nonce={a_to_b.nonce}"
    )
    print(
        f"    B -> A report: platform={b_to_a.platform} "
        f"measurement={_short(b_to_a.measurement, 12)} "
        f"key={_short(b_to_a.public_key)} nonce={b_to_a.nonce}"
    )

    # --- 4: what a verifier would check once Tier 3 lands ---
    print("\n[4] What a verifier would check (once Tier 3 lands)")
    print("    - quote signature chains to genuine TEE silicon")
    print("    - report nonce equals the counterparty's fresh challenge")
    print("    - measurement equals the agreed golden value (swap -> mismatch -> reject)")

    # --- SKIP ---
    print()
    print("KEY RESULT: SKIP: cross-operator attestation is gated on Tier 3 (real")
    print("hardware attestation backend). No provider can produce a verifiable quote")
    print("yet, so mutual attestation and binary-swap detection cannot be demonstrated.")
    print("The reports above are software-only and carry no assurance. See ROADMAP.md.")
    print("Exiting 0 so CI and dev hosts pass.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
