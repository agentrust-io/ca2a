"""Central error code registry - mirrors docs/spec/error-codes semantics."""

from __future__ import annotations


class CA2AError(Exception):
    """Base class for all ca2a-runtime errors."""

    code: str = "CA2A_ERROR"
    http_status: int = 500

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail


class ConfigError(CA2AError):
    code = "CONFIG_ERROR"
    http_status = 500


class InvalidCredential(CA2AError):
    """A delegation credential is malformed or its signature does not verify."""

    code = "INVALID_CREDENTIAL"
    http_status = 400


class UntrustedDelegationRoot(CA2AError):
    """The chain is validly signed but its root issuer is not trusted locally."""

    code = "UNTRUSTED_DELEGATION_ROOT"
    http_status = 403


class ScopeEscalation(CA2AError):
    """A child grant claims authority its parent did not hold."""

    code = "SCOPE_ESCALATION"
    http_status = 403


class BrokenDelegationLink(CA2AError):
    """A hop does not chain to its stated parent, or continuity is broken."""

    code = "BROKEN_DELEGATION_LINK"
    http_status = 409


class DelegationDepthExceeded(CA2AError):
    code = "DELEGATION_DEPTH_EXCEEDED"
    http_status = 403


class CredentialReplay(CA2AError):
    """A credential id appears more than once in a chain."""

    code = "CREDENTIAL_REPLAY"
    http_status = 409


class CredentialNotYetValid(CA2AError):
    """A credential's ``not_before`` bound is after the evaluation time.

    403 like the other validity failures: the chain is well formed and validly
    signed, but the grant is not in force at the time being evaluated.
    """

    code = "CREDENTIAL_NOT_YET_VALID"
    http_status = 403


class CredentialExpired(CA2AError):
    """A credential's ``not_after`` bound is before the evaluation time."""

    code = "CREDENTIAL_EXPIRED"
    http_status = 403


class HolderProofInvalid(CA2AError):
    """The presenter of a delegation chain did not prove it holds the leaf key.

    Raised when a holder proof is absent, malformed, answers a challenge this
    callee did not issue or which has expired, or does not verify under
    ``chain[-1].subject``. 401 rather than 403: the chain may well carry the
    authority requested, but the caller has not shown it is the party that
    authority was delegated to.

    Distinct from :class:`AttestationFailed`, which is about what the caller is
    *running*. A caller can appraise perfectly and still fail this, because an
    attested runtime is not a claim to anybody's delegated authority.
    """

    code = "HOLDER_PROOF_INVALID"
    http_status = 401


class AttestationUnsupported(CA2AError):
    code = "ATTESTATION_UNSUPPORTED"
    http_status = 500


class AttestationFailed(CA2AError):
    """An attestation report, challenge, or channel offer did not appraise.

    Carries the provenance record for the refusal on ``record`` when it was
    raised somewhere with enough context to build one (the callee refusing an
    unattested or badly attested caller). Elsewhere ``record`` is None: the
    challenge and offer primitives have no delegation chain to attribute a
    refusal to. As with :class:`ScopeNotPermitted`, the call still fails closed
    and the record is evidence of the refusal, not a way to continue.
    """

    code = "ATTESTATION_FAILED"
    http_status = 412

    def __init__(
        self, message: str, *, detail: str | None = None, record: object | None = None
    ) -> None:
        super().__init__(message, detail=detail)
        self.record = record


class SealedChannelError(CA2AError):
    code = "SEALED_CHANNEL_ERROR"
    http_status = 500


class ProvenanceLinkBroken(CA2AError):
    """A delegation record does not chain to its stated parent record, or a
    record has been tampered with so its hash no longer matches a child's link."""

    code = "PROVENANCE_LINK_BROKEN"
    http_status = 409


class ScopeNotPermitted(CA2AError):
    """A requested capability is not in the effective scope (the delegated
    scope intersected with the callee's local policy).

    Carries the signed-in-place provenance record for the refusal on ``record``
    when the caller supplied enough context to build one. The call still fails
    closed; the record is evidence of the refusal, not a way to continue.
    """

    code = "SCOPE_NOT_PERMITTED"
    http_status = 403

    def __init__(
        self, message: str, *, detail: str | None = None, record: object | None = None
    ) -> None:
        super().__init__(message, detail=detail)
        self.record = record


class TransportError(CA2AError):
    """cA2A A2A-extension metadata was present but malformed or incomplete.

    Raised by the transport adapter when a cA2A-aware peer sees namespaced
    metadata that cannot be parsed into a ``PeerRequest``. Absence of all
    cA2A keys is not an error: that message is ordinary A2A input.
    """

    code = "TRANSPORT_ERROR"
    http_status = 400


class TraceRecordInvalid(CA2AError):
    """A TRACE record is structurally invalid or its signature does not verify.

    Raised by the TRACE DAG verifier when a hop's record fails schema validation,
    is signed by a key that is not trusted, or its embedded key does not match the
    one supplied. Distinct from ProvenanceLinkBroken, which covers the parent-link
    chaining between otherwise valid records."""

    code = "TRACE_RECORD_INVALID"
    http_status = 422
