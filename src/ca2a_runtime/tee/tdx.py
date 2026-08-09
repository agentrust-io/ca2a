"""Intel TDX quote (DCAP, ECDSA-256) parsing and the TDX provider.

Parses a TDX v4 quote: the header, the TD report body (from which the launch
measurement MRTD and the report data are read), and the ECDSA signature section
(the quote signature, the attestation key, the Quoting Enclave report and its
PCK signature, and the PCK certificate chain). Verification lives in
:mod:`ca2a_verify.tdx`.

:meth:`TdxProvider.attest` produces a real quote through the kernel configfs-TSM
interface (see :mod:`ca2a_runtime.tee.tsm`). Non-paravisor TDX is
guest-controlled, so unlike Azure's SEV-SNP the guest sets ``REPORTDATA``
directly: it commits :func:`tdx_report_data`, a digest over *both* the channel
public key and the caller's nonce, so a caller sealing to the key in a verified
quote is sealing to a key the TDX module signed for.

Byte offsets follow the Intel DCAP Quote v4 layout, including the nested type-6
QE certification data that wraps the QE report and the PCK chain. The verifier is
exercised against synthetic self-consistent vectors plus the real Intel SGX Root
CA in the test suite, and against a genuine GCP C3 quote when ``CA2A_TDX_QUOTE``
points at one; see ``docs/hardware-validation.md``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.binding import TDX_PREFIX, derive_binding, pad_report_data
from ca2a_runtime.tee.tsm import (
    PROVIDER_TDX_GUEST,
    collect_report,
    require_tsm,
    tsm_available,
)
from ca2a_runtime.tee.tsm import (
    REPORT_DATA_LEN as TSM_REPORT_DATA_LEN,
)

HEADER_LEN = 48
TD_REPORT_LEN = 584
SIGNED_LEN = HEADER_LEN + TD_REPORT_LEN  # quote signature covers header + TD report
MRTD_OFFSET = HEADER_LEN + 136
MRTD_LEN = 48
REPORT_DATA_OFFSET = HEADER_LEN + 520
REPORT_DATA_LEN = 64

# Signature section (relative to SIGNED_LEN + 4-byte sig_data_len).
QUOTE_SIG_LEN = 64
ATT_KEY_LEN = 64
QE_REPORT_LEN = 384
QE_REPORT_DATA_OFFSET = 320  # within the QE SGX report

TEE_TYPE_TDX = 0x81
# Intel DCAP certification-data types, each preceded by a uint16 type + uint32 size.
CERT_TYPE_PCK_CHAIN = 5
CERT_TYPE_QE_REPORT = 6
CERT_DATA_HEADER_LEN = 6
TDX_GUEST_DEVICE = "/dev/tdx_guest"

# MRTD is a 48-byte launch digest; the label says what produced it.
MEASUREMENT_DIGEST_LABEL = "sha384"


def tdx_report_data(public_key: str, nonce: str) -> bytes:
    """Return the 64 bytes a cA2A TDX quote commits in ``REPORTDATA``.

    The 32-byte binding digest, zero-padded to the field width. See
    :mod:`ca2a_runtime.tee.binding` and ``docs/spec/attestation.md``.
    """
    return pad_report_data(
        derive_binding(TDX_PREFIX, public_key, nonce), TSM_REPORT_DATA_LEN
    )


@dataclass(frozen=True)
class TdxQuote:
    """The parsed subset of a TDX quote cA2A appraises."""

    version: int
    tee_type: int
    measurement: bytes  # MRTD
    report_data: bytes
    signed_body: bytes  # header + TD report body
    quote_signature: bytes  # 64 bytes, r||s big-endian
    attestation_key: bytes  # 64 bytes, raw P-256 x||y
    qe_report: bytes  # 384-byte SGX report
    qe_report_signature: bytes  # 64 bytes, r||s big-endian
    qe_auth_data: bytes
    pck_chain: list[x509.Certificate]  # leaf (PCK) first, root last

    @classmethod
    def parse(cls, blob: bytes) -> TdxQuote:
        if len(blob) < SIGNED_LEN + 4:
            raise AttestationFailed(
                "TDX quote too short",
                detail=f"got {len(blob)} bytes, need at least {SIGNED_LEN + 4}",
            )
        version, _att_key_type, tee_type = struct.unpack_from("<HHI", blob, 0)
        measurement = blob[MRTD_OFFSET : MRTD_OFFSET + MRTD_LEN]
        report_data = blob[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_LEN]

        (sig_len,) = struct.unpack_from("<I", blob, SIGNED_LEN)
        pos = SIGNED_LEN + 4
        end = pos + sig_len
        if end > len(blob):
            raise AttestationFailed("TDX quote signature section is truncated")

        quote_sig = blob[pos : pos + QUOTE_SIG_LEN]
        pos += QUOTE_SIG_LEN
        att_key = blob[pos : pos + ATT_KEY_LEN]
        pos += ATT_KEY_LEN

        # The QE material is nested, not flat: what follows the attestation key is a
        # certification-data header of type 6 wrapping the QE report, its PCK
        # signature, the auth data and the type-5 PCK chain. Reading the QE report
        # here directly lands six bytes early and rejects every genuine quote.
        outer_type, outer_len = struct.unpack_from("<HI", blob, pos)
        pos += CERT_DATA_HEADER_LEN
        if outer_type != CERT_TYPE_QE_REPORT:
            raise AttestationFailed(
                "unsupported certification data type",
                detail=f"type={outer_type}, expected {CERT_TYPE_QE_REPORT} (QE report)",
            )
        cert_data = blob[pos : pos + outer_len]
        if len(cert_data) < QE_REPORT_LEN + QUOTE_SIG_LEN + 2 + CERT_DATA_HEADER_LEN:
            raise AttestationFailed("QE certification data is truncated")

        inner = 0
        qe_report = cert_data[inner : inner + QE_REPORT_LEN]
        inner += QE_REPORT_LEN
        qe_report_sig = cert_data[inner : inner + QUOTE_SIG_LEN]
        inner += QUOTE_SIG_LEN
        (qe_auth_len,) = struct.unpack_from("<H", cert_data, inner)
        inner += 2
        qe_auth = cert_data[inner : inner + qe_auth_len]
        inner += qe_auth_len
        cert_type, cert_len = struct.unpack_from("<HI", cert_data, inner)
        inner += CERT_DATA_HEADER_LEN
        cert_bytes = cert_data[inner : inner + cert_len]
        if cert_type != CERT_TYPE_PCK_CHAIN:
            raise AttestationFailed(
                "unsupported QE certification data type",
                detail=f"type={cert_type}, expected {CERT_TYPE_PCK_CHAIN} (PCK chain)",
            )
        try:
            chain = x509.load_pem_x509_certificates(cert_bytes)
        except ValueError as exc:
            raise AttestationFailed("could not parse PCK certificate chain", detail=str(exc)) from exc

        return cls(
            version=version,
            tee_type=tee_type,
            measurement=measurement,
            report_data=report_data,
            signed_body=blob[:SIGNED_LEN],
            quote_signature=quote_sig,
            attestation_key=att_key,
            qe_report=qe_report,
            qe_report_signature=qe_report_sig,
            qe_auth_data=qe_auth,
            pck_chain=list(chain),
        )


class TdxProvider(BaseProvider):
    """Intel TDX provider. Produces a real DCAP quote via configfs-TSM.

    ``detect`` reports True only where ``attest`` can actually run: Linux, the
    configfs-TSM interface, and the ``tdx_guest`` device node whose driver
    registers the TSM provider. Both signals are required because the provider
    name is only readable from inside an entry, which needs root, so the device
    node stands in for "this is a TDX guest" at detection time and ``attest``
    confirms it against the kernel before returning any bytes.
    """

    platform = "tdx"

    @classmethod
    def detect(cls) -> bool:
        if not tsm_available():
            return False
        return Path(TDX_GUEST_DEVICE).exists()

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        """Request a TDX quote committing ``public_key`` and ``nonce``.

        Raises :class:`AttestationUnsupported` when this host cannot produce a
        quote at all, and :class:`AttestationFailed` when it can but the attempt
        did not yield verifiable evidence.
        """
        self._require_host()

        expected = tdx_report_data(public_key, nonce)
        outblob, _auxblob = collect_report(expected, expect_provider=PROVIDER_TDX_GUEST)
        quote = TdxQuote.parse(outblob)

        if quote.tee_type != TEE_TYPE_TDX:
            raise AttestationFailed(
                "the quote is not a TDX quote",
                detail=f"tee_type={quote.tee_type:#x}, expected {TEE_TYPE_TDX:#x}",
            )
        if quote.report_data != expected:
            raise AttestationFailed(
                "the quote does not commit the requested key and nonce binding",
                detail="REPORTDATA does not match the derived binding",
            )

        # The PCK chain arrives inside the quote, so the evidence is already
        # self-contained; auxblob would only repeat it.
        chain_pem = b"".join(cert.public_bytes(Encoding.PEM) for cert in quote.pck_chain)

        return AttestationReport(
            platform=self.platform,
            measurement=f"{MEASUREMENT_DIGEST_LABEL}:{quote.measurement.hex()}",
            public_key=public_key,
            nonce=nonce,
            # A TDX quote carries its own signature and PCK chain, so the
            # evidence a peer ships is the quote verbatim.
            raw_evidence=outblob,
            quote_signature=quote.quote_signature,
            attestation_key_chain_pem=chain_pem or None,
        )

    @classmethod
    def _require_host(cls) -> None:
        """Fail with the actual reason, never a generic "no TDX guest"."""
        require_tsm("TDX")
        if not Path(TDX_GUEST_DEVICE).exists():
            raise AttestationUnsupported(
                "TDX quote generation requires a non-paravisor TDX guest",
                detail=(
                    f"configfs-TSM is present but {TDX_GUEST_DEVICE} is not, so the "
                    "tdx_guest driver has not registered a TSM provider on this host"
                ),
            )
