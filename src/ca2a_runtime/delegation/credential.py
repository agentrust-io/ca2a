"""Delegation credential model, canonicalization, and chain verification.

A delegation credential is a signed statement that ``issuer`` grants ``subject``
a set of capability strings (``scope``), optionally as a child of ``parent_id``.
A chain is a list of credentials ordered from root to leaf. Verification enforces
five invariants:

1. Signature: each credential verifies against its issuer's Ed25519 public key.
2. Continuity: each hop's issuer is the previous hop's subject.
3. Attenuation: each hop's scope is a subset of its parent's scope.
4. Anti-replay: parent_id links to the previous credential_id and every
   credential_id in the chain is unique.
5. Validity: each hop's validity window, when present, contains the
   evaluation time.

Canonicalization uses RFC 8785 (JSON Canonicalization Scheme), so the signed
byte string is identical across conforming implementations and cA2A signatures
are cross-verifiable with agent-manifest. See ca2a_runtime.canonical.
"""

from __future__ import annotations

import re
import time
from collections.abc import Collection
from dataclasses import dataclass, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.errors import (
    BrokenDelegationLink,
    CredentialExpired,
    CredentialNotYetValid,
    CredentialReplay,
    DelegationDepthExceeded,
    InvalidCredential,
    ScopeEscalation,
    UntrustedDelegationRoot,
)

_HEX_32_RE = re.compile(r"[0-9a-f]{64}")
_HEX_64_RE = re.compile(r"[0-9a-f]{128}")
_REQUIRED_CREDENTIAL_FIELDS = frozenset(
    {"credential_id", "issuer", "subject", "scope", "depth", "parent_id", "signature"}
)
# Validity bounds are optional on the wire: absent means unbounded on that side,
# and a credential issued before these fields existed keeps its exact signed bytes.
_OPTIONAL_CREDENTIAL_FIELDS = frozenset({"not_before", "not_after"})


def new_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return a fresh Ed25519 private key and its public key as raw hex."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonical byte encoding of a credential body.

    This is the stable byte string signed and verified; using JCS makes cA2A
    signatures cross-verifiable with agent-manifest and any other conforming
    implementation. See ca2a_runtime.canonical.
    """
    return canonicalize(payload)


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
    not_before: int | None = None  # Unix epoch seconds, inclusive
    not_after: int | None = None  # Unix epoch seconds, inclusive

    def __post_init__(self) -> None:
        # Enforced at construction, not only in from_dict: this is also a public
        # constructor, and sign() would otherwise put a bound outside the
        # documented wire format into a signed body that this implementation's
        # own parser rejects. replace() re-runs this, so no path around it.
        for name, bound in (("not_before", self.not_before), ("not_after", self.not_after)):
            if bound is not None and (
                isinstance(bound, bool) or not isinstance(bound, int) or bound < 0
            ):
                raise InvalidCredential(f"{name} must be a non-negative integer when present")
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_before > self.not_after
        ):
            raise InvalidCredential(
                "validity window is inverted",
                detail=f"not_before={self.not_before} > not_after={self.not_after}",
            )

    def body(self) -> dict[str, Any]:
        """The signed portion of the credential (everything but the signature).

        An absent validity bound is omitted rather than encoded as null:
        emitting nulls would change the canonical bytes of every credential
        signed before the fields existed. A bound that is present is signed,
        so it cannot be stripped without invalidating the signature.
        """
        payload: dict[str, Any] = {
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scope": sorted(self.scope),
            "depth": self.depth,
            "parent_id": self.parent_id,
        }
        if self.not_before is not None:
            payload["not_before"] = self.not_before
        if self.not_after is not None:
            payload["not_after"] = self.not_after
        return payload

    def sign(self, private_key: Ed25519PrivateKey) -> DelegationCredential:
        """Return a copy signed by ``private_key`` (must match ``issuer``)."""
        expected = private_key.public_key().public_bytes_raw().hex()
        if expected != self.issuer:
            raise InvalidCredential(
                "signing key does not match credential issuer",
                detail=f"issuer={self.issuer} key={expected}",
            )
        # dataclasses.replace rather than field-by-field reconstruction: a field
        # added to the model but forgotten here would be silently dropped from
        # every credential this ever signs.
        sig = private_key.sign(canonical_bytes(self.body())).hex()
        return replace(self, signature=sig)

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
        unknown = set(data) - _REQUIRED_CREDENTIAL_FIELDS - _OPTIONAL_CREDENTIAL_FIELDS
        missing = _REQUIRED_CREDENTIAL_FIELDS - set(data)
        if unknown or missing:
            raise InvalidCredential(
                "malformed credential fields",
                detail=f"missing={sorted(missing)} unknown={sorted(unknown)}",
            )

        credential_id = data["credential_id"]
        issuer = data["issuer"]
        subject = data["subject"]
        scope = data["scope"]
        depth = data["depth"]
        parent_id = data["parent_id"]
        signature = data["signature"]
        not_before = data.get("not_before")
        not_after = data.get("not_after")

        if not isinstance(credential_id, str) or not credential_id:
            raise InvalidCredential("credential_id must be a non-empty string")
        if not isinstance(issuer, str) or not _HEX_32_RE.fullmatch(issuer):
            raise InvalidCredential("issuer must be a lowercase 32-byte Ed25519 key in hex")
        if not isinstance(subject, str) or not _HEX_32_RE.fullmatch(subject):
            raise InvalidCredential("subject must be a lowercase 32-byte Ed25519 key in hex")
        if (
            not isinstance(scope, list)
            or not scope
            or not all(isinstance(item, str) and item for item in scope)
            or len(set(scope)) != len(scope)
        ):
            raise InvalidCredential("scope must be a non-empty array of unique non-empty strings")
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise InvalidCredential("depth must be a non-negative integer")
        if parent_id is not None and (not isinstance(parent_id, str) or not parent_id):
            raise InvalidCredential("parent_id must be a non-empty string or null")
        if not isinstance(signature, str) or not _HEX_64_RE.fullmatch(signature):
            raise InvalidCredential(
                "signature must be a lowercase 64-byte Ed25519 signature in hex"
            )
        # A present bound must be a real integer; an explicit null is rejected
        # because the signed body never carries one (absent bounds are omitted),
        # so null would be a second wire form for the same signed object.
        for name, bound in (("not_before", not_before), ("not_after", not_after)):
            if name in data and (
                isinstance(bound, bool) or not isinstance(bound, int) or bound < 0
            ):
                raise InvalidCredential(f"{name} must be a non-negative integer when present")
        if not_before is not None and not_after is not None and not_before > not_after:
            raise InvalidCredential(
                "validity window is inverted",
                detail=f"not_before={not_before} > not_after={not_after}",
            )

        return cls(
            credential_id=credential_id,
            issuer=issuer,
            subject=subject,
            scope=frozenset(scope),
            depth=depth,
            parent_id=parent_id,
            signature=signature,
            not_before=not_before,
            not_after=not_after,
        )


def verify_chain(
    chain: list[DelegationCredential],
    *,
    max_depth: int = 8,
    trusted_root_issuers: Collection[str] = (),
    at_time: int | None = None,
) -> None:
    """Verify a root-to-leaf delegation chain, raising on the first violation.

    A well-formed chain of length N delegates from the root issuer down to the
    leaf subject with monotonically narrowing scope. Raises the specific
    CA2AError subtype for the invariant that failed.

    ``at_time`` is the Unix time validity windows are evaluated at; ``None``
    means the current time. Live authorization always evaluates now. An auditor
    replaying recorded evidence passes the time the action was decided, since a
    window that has lapsed by audit time says nothing about validity at
    decision time.
    """
    # Bounds on the wire are strict JSON integers; the evaluation time they are
    # compared against holds the same line, or True / 1.5 / -1 from a library
    # caller would silently decide validity. (The CLI is already argparse-typed.)
    if at_time is not None and (
        isinstance(at_time, bool) or not isinstance(at_time, int) or at_time < 0
    ):
        raise ValueError("at_time must be a non-negative integer or None")

    if not chain:
        raise BrokenDelegationLink("empty delegation chain")

    now = int(time.time()) if at_time is None else at_time

    seen_ids: set[str] = set()
    prev: DelegationCredential | None = None

    for i, cred in enumerate(chain):
        cred.verify_signature()

        # Window checks come after the signature so the bounds being judged are
        # the ones the issuer signed, and before the structural checks so an
        # expired hop is named as expired rather than as some downstream break.
        # An inverted window cannot reach here: __post_init__ refuses to
        # construct one.
        if cred.not_before is not None and now < cred.not_before:
            raise CredentialNotYetValid(
                f"hop {i} credential is not yet valid",
                detail=f"not_before={cred.not_before} at_time={now}",
            )
        if cred.not_after is not None and now > cred.not_after:
            raise CredentialExpired(
                f"hop {i} credential has expired",
                detail=f"not_after={cred.not_after} at_time={now}",
            )

        if cred.credential_id in seen_ids:
            raise CredentialReplay(f"duplicate credential_id at hop {i}: {cred.credential_id}")
        seen_ids.add(cred.credential_id)

        if cred.depth > max_depth:
            raise DelegationDepthExceeded(f"hop {i} depth {cred.depth} exceeds max {max_depth}")

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
                raise BrokenDelegationLink(f"hop {i} issuer is not the previous hop's subject")
            if cred.depth != prev.depth + 1:
                raise BrokenDelegationLink(f"hop {i} depth is not previous + 1")
            if not cred.scope.issubset(prev.scope):
                escalated = sorted(cred.scope - prev.scope)
                raise ScopeEscalation(
                    f"hop {i} scope exceeds parent grant", detail=f"added: {escalated}"
                )

        prev = cred

    # Root authorization is a required part of `verify_chain`, including for
    # library callers. An omitted/empty set fails closed; signature consistency
    # alone does not authorize an attacker-minted root. It runs after the
    # cryptographic and structural checks so malformed evidence still reports
    # its precise invariant failure.
    if chain[0].issuer not in trusted_root_issuers:
        raise UntrustedDelegationRoot(
            "delegation root issuer is not trusted by this peer",
            detail=f"root_issuer={chain[0].issuer}",
        )
