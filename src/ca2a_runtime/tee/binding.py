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
"""

from __future__ import annotations

import hashlib

TPM_PREFIX = b"ca2a-tpm-v1|"
SNP_PREFIX = b"ca2a-snp-v1|"
TDX_PREFIX = b"ca2a-tdx-v1|"


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
