"""Delegation credential model, canonicalization, and chain verification.

A delegation credential is a signed statement that ``issuer`` grants ``subject``
a set of capability strings (``scope``), optionally as a child of ``parent_id``.
A chain is a list of credentials ordered from root to leaf. Verification enforces
four invariants:

1. Signature: each credential verifies against its issuer's Ed25519 public key.
2. Continuity: each hop's issuer is the previous hop's subject.
3. Attenuation: each hop's scope is a subset of its parent's scope.
4. Anti-replay: parent_id links to the previous credential_id and every
   credential_id in the chain is unique.

Canonicalization uses a deterministic JSON encoding (sorted keys, compact
separators, UTF-8). This is the stable byte string signed and verified; it is a
practical subset of RFC 8785 sufficient for the ASCII credential fields used
here. Full RFC 8785 alignment with agent-manifest is tracked on the roadmap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.errors import (
    BrokenDelegationLink,
    CredentialReplay,
    DelegationDepthExceeded,
    InvalidCredential,
    ScopeEscalation,
)


def new_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return a fresh Ed25519 private key and its public key as raw hex."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a credential body (signature excluded)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


@dataclass(frozen=True)
class DelegationCredential:
    """A single signed delegation hop."""

    credential_id: str
    issuer: str  # Ed25519 public key, raw hex
    subject: str  # Ed25519 public key, raw hex
    scope: frozenset[str]
    depth: int
    parent_id: str | None = None
    signature: str = ""  # Ed25519 signature over canonical_bytes(body), hex

    def body(self) -> dict[str, Any]:
        """The signed portion of the credential (everything but the signature)."""
        return {
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scope": sorted(self.scope),
            "depth": self.depth,
            "parent_id": self.parent_id,
        }

    def sign(self, private_key: Ed25519PrivateKey) -> DelegationCredential:
        """Return a copy signed by ``private_key`` (must match ``issuer``)."""
        expected = private_key.public_key().public_bytes_raw().hex()
        if expected != self.issuer:
            raise InvalidCredential(
                "signing key does not match credential issuer",
                detail=f"issuer={self.issuer} key={expected}",
            )
        sig = private_key.sign(canonical_bytes(self.body())).hex()
        return DelegationCredential(
            credential_id=self.credential_id,
            issuer=self.issuer,
            subject=self.subject,
            scope=self.scope,
            depth=self.depth,
            parent_id=self.parent_id,
            signature=sig,
        )

    def verify_signature(self) -> None:
        """Raise InvalidCredential if the signature does not verify."""
        if not self.signature:
            raise InvalidCredential("credential is unsigned")
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.issuer))
            pub.verify(bytes.fromhex(self.signature), canonical_bytes(self.body()))
        except (InvalidSignature, ValueError) as exc:
            raise InvalidCredential(
                "credential signature failed to verify", detail=str(exc)
            ) from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationCredential:
        try:
            return cls(
                credential_id=str(data["credential_id"]),
                issuer=str(data["issuer"]),
                subject=str(data["subject"]),
                scope=frozenset(str(s) for s in data["scope"]),
                depth=int(data["depth"]),
                parent_id=(None if data.get("parent_id") is None else str(data["parent_id"])),
                signature=str(data.get("signature", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidCredential("malformed credential", detail=str(exc)) from exc


def verify_chain(
    chain: list[DelegationCredential], *, max_depth: int = 8
) -> None:
    """Verify a root-to-leaf delegation chain, raising on the first violation.

    A well-formed chain of length N delegates from the root issuer down to the
    leaf subject with monotonically narrowing scope. Raises the specific
    CA2AError subtype for the invariant that failed.
    """
    if not chain:
        raise BrokenDelegationLink("empty delegation chain")

    seen_ids: set[str] = set()
    prev: DelegationCredential | None = None

    for i, cred in enumerate(chain):
        cred.verify_signature()

        if cred.credential_id in seen_ids:
            raise CredentialReplay(f"duplicate credential_id at hop {i}: {cred.credential_id}")
        seen_ids.add(cred.credential_id)

        if cred.depth > max_depth:
            raise DelegationDepthExceeded(
                f"hop {i} depth {cred.depth} exceeds max {max_depth}"
            )

        if prev is None:
            if cred.parent_id is not None:
                raise BrokenDelegationLink("root credential must not name a parent")
            if cred.depth != 0:
                raise BrokenDelegationLink("root credential must have depth 0")
        else:
            if cred.parent_id != prev.credential_id:
                raise BrokenDelegationLink(
                    f"hop {i} parent_id does not match previous credential_id"
                )
            if cred.issuer != prev.subject:
                raise BrokenDelegationLink(
                    f"hop {i} issuer is not the previous hop's subject"
                )
            if cred.depth != prev.depth + 1:
                raise BrokenDelegationLink(f"hop {i} depth is not previous + 1")
            if not cred.scope.issubset(prev.scope):
                escalated = sorted(cred.scope - prev.scope)
                raise ScopeEscalation(
                    f"hop {i} scope exceeds parent grant", detail=f"added: {escalated}"
                )

        prev = cred
