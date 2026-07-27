"""Intel TDX quote (DCAP, ECDSA-256) parsing and the TDX provider.

Parses a TDX v4 quote: the header, the TD report body (from which the launch
measurement MRTD and the report data are read), and the ECDSA signature section
(the quote signature, the attestation key, the Quoting Enclave report and its
PCK signature, and the PCK certificate chain). Verification lives in
:mod:`ca2a_verify.tdx`.

Producing a quote requires a real TDX guest, so :meth:`TdxProvider.attest` fails
closed off hardware. Byte offsets follow the Intel DCAP Quote v4 layout, including
the nested type-6 QE certification data that wraps the QE report and the PCK
chain. The verifier is exercised against synthetic self-consistent vectors plus
the real Intel SGX Root CA in the test suite, and against a genuine GCP C3 quote
when ``CA2A_TDX_QUOTE`` points at one; see ``docs/hardware-validation.md``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography import x509

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport, BaseProvider

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
    """Intel TDX provider. Quote generation requires a real TDX guest."""

    platform = "tdx"

    @classmethod
    def detect(cls) -> bool:
        import os

        return os.path.exists(TDX_GUEST_DEVICE)

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        raise AttestationUnsupported(
            "TDX quote generation requires a real TDX guest",
            detail=f"{TDX_GUEST_DEVICE} not present; run on an Intel TDX confidential VM",
        )
