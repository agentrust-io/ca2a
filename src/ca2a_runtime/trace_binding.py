"""Bind a delegation hop to a signed TRACE Trust Record.

cA2A's native provenance record (:class:`ca2a_runtime.provenance.DelegationRecord`)
records *that* a hop happened and links it to its parent. The TRACE binding lifts
each hop into a TRACE Trust Record (the agentrust-io interchange format) carrying
the A2A profile's ``delegation`` block, so a chain of records is verifiable with
the standard TRACE tooling (``agentrust-trace``, ``trace-tests``, the ``/trace``
report) rather than only cA2A's own verifier.

The record is produced, signed, and hashed with the ``agentrust-trace`` reference
implementation (Ed25519 over RFC 8785 JCS canonical bytes), so cA2A does not
reimplement TRACE canonicalization or signing. See the TRACE A2A profile in
``docs/spec/trace-a2a-profile.md``.

The delegation link (``delegation.parent_record_hash``) commits to the parent's
**full signed record**, including its signature: any change to the parent, its
signature included, breaks the child's link. A root hop carries no delegation
block, matching the profile.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import rfc8785
from agentrust_trace import sign_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The frozen TRACE v0.1 profile URI. Every record's eat_profile equals this.
EAT_PROFILE = "tag:agentrust.io,2026:trace-v0.1"

# The platform value for a software-attestation (no hardware TEE) run. Records
# emitted with this platform are honestly Level 0 only: trace-tests fails a
# software-only record at Level 1 by design.
SOFTWARE_PLATFORM = "software-only"


def digest(data: bytes) -> str:
    """Return the ``sha256:``-prefixed lowercase-hex digest TRACE expects.

    cA2A's own provenance hashes are bare hex; TRACE digests carry an algorithm
    prefix (``sha256:...``). This is the one-line conversion between the two.
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class HopContext:
    """The per-hop runtime, model, and policy facts a TRACE record needs.

    A :class:`~ca2a_runtime.provenance.DelegationRecord` carries the delegation
    identity (credential id, subject, scope) but none of the runtime/attestation
    context a full TRACE record requires. The callee supplies that context here;
    :func:`build_trace_record` composes the two into a record.

    Use :meth:`software` for a software-attestation run (no hardware TEE). All
    digest fields must be ``sha256:``/``sha384:`` strings (see :func:`digest`);
    the URI fields must be URIs.
    """

    model_provider: str
    model_id: str
    runtime_measurement: str
    policy_bundle_hash: str
    build_digest: str
    appraisal_verifier: str
    transparency: str
    runtime_platform: str = SOFTWARE_PLATFORM
    enforcement_mode: str = "enforce"
    data_class: str = "confidential"
    slsa_level: int = 0
    appraisal_status: str = "none"
    runtime_nonce: str | None = None
    model_version: str | None = None
    policy_version: str | None = None

    @classmethod
    def software(
        cls,
        *,
        model_provider: str,
        model_id: str,
        image_label: str,
        policy_bundle_hash: str,
        data_class: str = "confidential",
        enforcement_mode: str = "enforce",
        runtime_nonce: str | None = None,
    ) -> HopContext:
        """A software-mode context with clearly non-production placeholders.

        The runtime measurement is the digest of ``image_label`` (a real digest
        of the software identity, not a hardware measurement). The appraisal and
        transparency URIs use the reserved ``.invalid`` TLD so a reader can never
        mistake a software-mode record for a hardware-attested one. Records built
        from this context are Level 0.
        """
        return cls(
            model_provider=model_provider,
            model_id=model_id,
            runtime_platform=SOFTWARE_PLATFORM,
            runtime_measurement=digest(image_label.encode("utf-8")),
            policy_bundle_hash=policy_bundle_hash,
            build_digest=digest(f"software-build:{image_label}".encode()),
            appraisal_status="none",
            appraisal_verifier="https://appraisal.invalid/software-mode",
            transparency="https://transparency.invalid/software-mode",
            data_class=data_class,
            enforcement_mode=enforcement_mode,
            slsa_level=0,
            runtime_nonce=runtime_nonce,
        )


def build_trace_record(
    *,
    subject: str,
    iat: int,
    context: HopContext,
    credential_id: str | None = None,
    parent_record_hash: str | None = None,
) -> dict[str, Any]:
    """Compose an unsigned TRACE record for one delegation hop.

    ``subject`` is the hop's TRACE identity (``spiffe://`` or ``did:``); note this
    is a distinct identifier from the raw-hex public key a
    :class:`DelegationCredential` uses as its subject.

    A non-root hop supplies both ``credential_id`` and ``parent_record_hash`` and
    gets a ``delegation`` block; a root hop supplies neither. Supplying exactly
    one is a programming error and raises ``ValueError``.

    The returned dict has no ``cnf`` or ``signature`` yet; pass it to
    :func:`sign_trace_record` to get a schema-valid, signed record.
    """
    if (parent_record_hash is None) != (credential_id is None):
        raise ValueError(
            "the delegation block needs both parent_record_hash and credential_id; "
            "a root hop supplies neither"
        )

    runtime: dict[str, Any] = {
        "platform": context.runtime_platform,
        "measurement": context.runtime_measurement,
    }
    if context.runtime_nonce is not None:
        runtime["nonce"] = context.runtime_nonce

    model: dict[str, Any] = {
        "provider": context.model_provider,
        "model_id": context.model_id,
    }
    if context.model_version is not None:
        model["version"] = context.model_version

    policy: dict[str, Any] = {
        "bundle_hash": context.policy_bundle_hash,
        "enforcement_mode": context.enforcement_mode,
    }
    if context.policy_version is not None:
        policy["version"] = context.policy_version

    record: dict[str, Any] = {
        "eat_profile": EAT_PROFILE,
        "iat": int(iat),
        "subject": subject,
        "model": model,
        "runtime": runtime,
        "policy": policy,
        "data_class": context.data_class,
        "build_provenance": {
            "slsa_level": context.slsa_level,
            "digest": context.build_digest,
        },
        "appraisal": {
            "status": context.appraisal_status,
            "verifier": context.appraisal_verifier,
        },
        "transparency": context.transparency,
    }
    if parent_record_hash is not None:
        record["delegation"] = {
            "parent_record_hash": parent_record_hash,
            "credential_id": credential_id,
        }
    return record


def sign_trace_record(record: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Sign a TRACE record with ``key`` (Ed25519 over RFC 8785 JCS).

    Thin pass-through to ``agentrust_trace.sign_record``: it sets ``cnf.jwk`` to
    the public key and adds the embedded ``signature``. Returned dict is
    schema-valid and ready to hash, store, or verify.
    """
    return sign_record(record, key)


def trace_record_hash(signed_record: dict[str, Any]) -> str:
    """The ``sha256:`` digest a child hop puts in ``delegation.parent_record_hash``.

    Hashes the **full signed record**, signature included, over its RFC 8785 JCS
    canonical bytes, so the link commits to the exact signed parent. Compute this
    only on a signed record.
    """
    return "sha256:" + hashlib.sha256(rfc8785.dumps(signed_record)).hexdigest()


@dataclass(frozen=True)
class HopSpec:
    """One hop's inputs for assembling a linked TRACE DAG.

    ``credential_id`` is the delegation credential this hop acted under; it is
    recorded in the ``delegation`` block of every non-root hop and ignored for
    the root (whose credential is the chain root and needs no back-link).
    """

    subject: str
    signing_key: Ed25519PrivateKey
    context: HopContext
    iat: int
    credential_id: str = ""


def emit_dag(hops: list[HopSpec]) -> list[dict[str, Any]]:
    """Build and sign an ordered root-to-leaf TRACE DAG, linking each hop.

    Each hop's record links to the previous hop's signed record by hash. The
    first hop is the root (no delegation block); every later hop carries a
    ``delegation`` block referencing its parent's ``trace_record_hash`` and its
    own ``credential_id``. Returns the signed records in root-to-leaf order.
    """
    records: list[dict[str, Any]] = []
    parent_hash: str | None = None
    for i, hop in enumerate(hops):
        credential_id = None if i == 0 else hop.credential_id
        record = build_trace_record(
            subject=hop.subject,
            iat=hop.iat,
            context=hop.context,
            credential_id=credential_id,
            parent_record_hash=parent_hash,
        )
        signed = sign_trace_record(record, hop.signing_key)
        records.append(signed)
        parent_hash = trace_record_hash(signed)
    return records
