"""The key-and-nonce binding a cA2A attestation report commits to.

Every hardware provider signs over a field the caller chooses: ``extraData`` on a
TPM quote, ``REPORT_DATA`` on a SEV-SNP report, ``REPORTDATA`` on a TDX quote.
What cA2A puts there is a digest over *both* the offered channel public key and
the caller's nonce, so one signature covers freshness and which key is being
offered. Commit the nonce alone and a report's ``public_key`` stays an unsigned
assertion, which would leave sealing to "a key from a verified report" not
actually rooted in hardware.

The derivation is shared so the three platforms cannot drift apart. Only the
domain-separation prefix differs, and each is versioned because this is wire
format: a peer and its verifier must derive the same bytes independently. See
``docs/spec/attestation.md``.

The prefix also separates the two *roles* an offer can be minted for. A callee
offer answers a nonce anybody may send to its public handshake endpoint; a caller
offer answers a challenge the callee issued and is minted only for the node's own
outbound call. Without separate prefixes the two are the same signed bytes, so a
party with no enclave could ask an honest hardware peer's handshake to attest
under a third node's challenge and present the result as its own caller offer.
The callee-role prefixes are unchanged from v1, so the handshake and every
archived capture still verify; the caller-role prefixes are new and carry the
``ca2a-caller-offer-v2`` version. See ``docs/spec/mutual-attestation.md``.
"""

from __future__ import annotations

import hashlib

from ca2a_runtime.errors import AttestationFailed

#: An offer from the handshake endpoint: the key a caller seals to.
ROLE_CALLEE = "callee"
#: An offer a node mints for its own outbound call, answering the callee's challenge.
ROLE_CALLER = "caller"
ROLES = frozenset({ROLE_CALLEE, ROLE_CALLER})

TPM_PREFIX = b"ca2a-tpm-v1|"
SNP_PREFIX = b"ca2a-snp-v1|"
TDX_PREFIX = b"ca2a-tdx-v1|"

TPM_CALLER_PREFIX = b"ca2a-tpm-caller-v2|"
SNP_CALLER_PREFIX = b"ca2a-snp-caller-v2|"
TDX_CALLER_PREFIX = b"ca2a-tdx-caller-v2|"

_PREFIXES = {
    (TPM_PREFIX, ROLE_CALLEE): TPM_PREFIX,
    (TPM_PREFIX, ROLE_CALLER): TPM_CALLER_PREFIX,
    (SNP_PREFIX, ROLE_CALLEE): SNP_PREFIX,
    (SNP_PREFIX, ROLE_CALLER): SNP_CALLER_PREFIX,
    (TDX_PREFIX, ROLE_CALLEE): TDX_PREFIX,
    (TDX_PREFIX, ROLE_CALLER): TDX_CALLER_PREFIX,
}


def role_prefix(platform_prefix: bytes, role: str) -> bytes:
    """Return the binding prefix for ``platform_prefix`` minted in ``role``.

    ``role`` usually comes off the wire (``AttestationReport.role``), so an
    unknown value fails closed rather than falling back to either role.
    """
    try:
        return _PREFIXES[(platform_prefix, role)]
    except KeyError:
        raise AttestationFailed(
            "attestation report names an unknown offer role",
            detail=f"role={role!r}, expected one of {sorted(ROLES)}",
        ) from None


def derive_binding(prefix: bytes, public_key: str, nonce: str) -> bytes:
    """Return the 32-byte digest committing ``public_key`` and ``nonce``.

    Each field is length-prefixed rather than separated by a delimiter. With a
    delimiter, a value containing it moves the split without changing the digest:
    ``("a|b", "c")`` and ``("a", "b|c")`` would commit identical bytes, so a peer
    could bind a key other than the one it appears to offer. ``nonce`` is an
    arbitrary caller-supplied string, so that is reachable rather than theoretical.
    """
    parts = []
    for field in (public_key.encode(), nonce.encode()):
        parts.append(len(field).to_bytes(4, "big"))
        parts.append(field)
    return hashlib.sha256(prefix + b"".join(parts)).digest()


def pad_report_data(digest: bytes, length: int) -> bytes:
    """Left-align ``digest`` in a ``length``-byte field, zero-filling the rest.

    SEV-SNP and TDX both reserve 64 bytes where a TPM allows 32, and neither
    defines a layout for a shorter value. Left-aligned and zero-padded is the
    convention the kernel's own callers and ``agent-manifest`` use, so a report
    collected here is byte-comparable with one collected by the sibling runtime.
    """
    if len(digest) > length:
        raise ValueError(f"binding digest is {len(digest)} bytes, exceeds the {length}-byte field")
    return digest + bytes(length - len(digest))
