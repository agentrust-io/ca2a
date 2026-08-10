"""Tests for the SEV-SNP and TDX collectors and the binding they commit.

Three halves, loosely:

- the key-and-nonce binding, including that the three platforms derive different
  bytes from the same inputs and that a field boundary cannot be shifted;
- the configfs-TSM collection path, driven against a simulated configfs tree so
  it runs without a confidential guest. Creating an entry materialises its
  attributes and writing ``inblob`` is what makes ``outblob`` readable, which is
  the kernel's actual sequence;
- each provider's ``detect``/``attest`` pair, including that they agree.

Synthetic vectors, not hardware. Neither collector has been run on real SEV-SNP
or TDX silicon; docs/hardware-validation.md records what has.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee import tsm
from ca2a_runtime.tee.binding import (
    SNP_PREFIX,
    TDX_PREFIX,
    TPM_PREFIX,
    derive_binding,
    pad_report_data,
)
from ca2a_runtime.tee.sev_snp import SevSnpProvider, snp_report_data
from ca2a_runtime.tee.tdx import TdxProvider, tdx_report_data
from tests.unit.conftest import make_sev_snp_report
from tests.unit.test_tdx import build_quote

PUBLIC_KEY = "aa" * 32
NONCE = "deadbeef"


# ── the signed binding ────────────────────────────────────────────────────────


def test_binding_is_32_bytes() -> None:
    assert len(derive_binding(SNP_PREFIX, PUBLIC_KEY, NONCE)) == 32


def test_each_platform_commits_different_bytes() -> None:
    """Domain separation: one report must not be replayable as another platform's."""
    digests = {
        derive_binding(prefix, PUBLIC_KEY, NONCE) for prefix in (TPM_PREFIX, SNP_PREFIX, TDX_PREFIX)
    }
    assert len(digests) == 3


def test_a_field_boundary_cannot_be_shifted() -> None:
    """The reason fields are length-prefixed rather than delimiter-joined.

    With a delimiter, these two would commit identical bytes and a peer could
    bind a key other than the one it appears to offer.
    """
    assert derive_binding(SNP_PREFIX, "a|b", "c") != derive_binding(SNP_PREFIX, "a", "b|c")


@pytest.mark.parametrize("report_data", [snp_report_data, tdx_report_data])
def test_report_data_is_the_padded_binding(report_data) -> None:
    value = report_data(PUBLIC_KEY, NONCE)
    assert len(value) == 64
    assert value[32:] == bytes(32)
    assert value[:32] != bytes(32)


def test_padding_refuses_a_digest_wider_than_the_field() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        pad_report_data(b"\x01" * 65, 64)


# ── configfs-TSM ──────────────────────────────────────────────────────────────


def install_fake_tsm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    provider: str,
    make_outblob,
    auxblob: bytes | None = None,
) -> list[Path]:
    """Simulate the kernel's configfs-TSM report interface under ``tmp_path``.

    Returns the list of entry directories created, so a test can assert on how
    the interface was driven rather than only on what came back.
    """
    root = tmp_path / "tsm-report"
    root.mkdir()
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(root))
    monkeypatch.setattr("ca2a_runtime.tee.tsm.sys.platform", "linux")

    entries: list[Path] = []
    real_mkdir = Path.mkdir
    real_write_bytes = Path.write_bytes

    def mkdir(self: Path, *args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        result = real_mkdir(self, *args, **kwargs)
        if self.parent == root:
            entries.append(self)
        return result

    def write_bytes(self: Path, data: bytes) -> int:
        written = real_write_bytes(self, data)
        if self.name == "inblob":
            entry = self.parent
            real_write_bytes(entry / "outblob", make_outblob(data))
            (entry / "provider").write_text(provider + "\n")
            if auxblob is not None:
                real_write_bytes(entry / "auxblob", auxblob)
        return written

    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    return entries


def test_collect_report_returns_the_report_and_its_certificates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda data: b"report:" + data[:4],
        auxblob=b"certs",
    )
    outblob, auxblob = tsm.collect_report(b"\x01" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)
    assert outblob == b"report:" + b"\x01" * 4
    assert auxblob == b"certs"


def test_collect_report_reports_no_certificates_when_none_are_supplied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_TDX_GUEST,
        make_outblob=lambda _data: b"quote",
    )
    _outblob, auxblob = tsm.collect_report(b"\x00" * 64, expect_provider=tsm.PROVIDER_TDX_GUEST)
    assert auxblob is None


def test_collect_report_refuses_the_wrong_platform(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A TDX guest answering an SNP collector is a misconfiguration, not evidence."""
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_TDX_GUEST,
        make_outblob=lambda _data: b"quote",
    )
    with pytest.raises(AttestationFailed, match="not the expected platform"):
        tsm.collect_report(b"\x00" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)


def test_collect_report_refuses_an_empty_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda _data: b"",
    )
    with pytest.raises(AttestationFailed, match="empty report"):
        tsm.collect_report(b"\x00" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)


def test_collect_report_refuses_oversized_report_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda _data: b"report",
    )
    with pytest.raises(AttestationFailed, match="larger than the field"):
        tsm.collect_report(b"\x00" * 65, expect_provider=tsm.PROVIDER_SEV_GUEST)


def test_each_collection_uses_its_own_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A shared entry is a race: a concurrent write would change the report.

    Two processes collecting into one fixed entry means the second ``inblob``
    write moves the report the first is about to read, so a peer could ship a
    report committing someone else's key.
    """
    entries = install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda data: b"report:" + data[:2],
    )
    tsm.collect_report(b"\x01" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)
    tsm.collect_report(b"\x02" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)
    assert len({entry.name for entry in entries}) == 2


def test_collect_report_when_the_kernel_refuses_an_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Creating an entry needs root and a registered provider; say which is missing."""
    root = tmp_path / "tsm-report"
    root.mkdir()
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(root))

    def refuse(self: Path, *args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(Path, "mkdir", refuse)
    with pytest.raises(AttestationUnsupported, match="refused a configfs-TSM report entry"):
        tsm.collect_report(b"\x00" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)


def test_collect_report_when_the_provider_returns_nothing_readable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An entry that exists but produces no outblob is a failure, not empty evidence."""
    root = tmp_path / "tsm-report"
    root.mkdir()
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(root))
    with pytest.raises(AttestationFailed, match="did not return a report"):
        tsm.collect_report(b"\x00" * 64, expect_provider=tsm.PROVIDER_SEV_GUEST)


def test_require_tsm_names_the_missing_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(tmp_path / "absent"))
    monkeypatch.setattr("ca2a_runtime.tee.tsm.sys.platform", "linux")
    with pytest.raises(AttestationUnsupported, match="configfs-TSM"):
        tsm.require_tsm("SEV-SNP")


def test_require_tsm_says_so_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ca2a_runtime.tee.tsm.sys.platform", "darwin")
    with pytest.raises(AttestationUnsupported, match="only implemented on Linux"):
        tsm.require_tsm("TDX")


# ── SEV-SNP ───────────────────────────────────────────────────────────────────


def _snp_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, measurement: bytes = b"\x11" * 48
) -> None:
    """A host that looks like a non-paravisor SNP guest, answering with a report."""
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda data: make_sev_snp_report(
            vcek_key, measurement=measurement, report_data=data
        ),
    )
    device = tmp_path / "sev-guest"
    device.touch()
    monkeypatch.setattr("ca2a_runtime.tee.sev_snp.SEV_GUEST_DEVICE", str(device))


def test_snp_detect_is_false_without_the_tsm_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(tmp_path / "absent"))
    assert SevSnpProvider.detect() is False


def test_snp_detect_is_false_on_the_azure_paravisor_shape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Azure SNP has no sev-guest node, so this collector cannot run there."""
    install_fake_tsm(
        monkeypatch, tmp_path, provider=tsm.PROVIDER_SEV_GUEST, make_outblob=lambda _d: b"x"
    )
    monkeypatch.setattr("ca2a_runtime.tee.sev_snp.SEV_GUEST_DEVICE", str(tmp_path / "absent"))
    assert SevSnpProvider.detect() is False


def test_snp_detect_is_true_when_attest_can_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _snp_host(monkeypatch, tmp_path)
    assert SevSnpProvider.detect() is True


def test_snp_attest_commits_the_offered_key_and_nonce(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _snp_host(monkeypatch, tmp_path, measurement=b"\x33" * 48)
    report = SevSnpProvider().attest(PUBLIC_KEY, NONCE)

    assert report.platform == "sev-snp"
    assert report.measurement == "sha384:" + (b"\x33" * 48).hex()
    assert report.public_key == PUBLIC_KEY
    assert report.nonce == NONCE
    assert report.raw_evidence is not None
    # The signature is a slice of the report body, not a separate blob.
    assert report.quote_signature is not None
    assert report.quote_signature in report.raw_evidence


def test_snp_attest_refuses_a_report_committing_something_else(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """What a concurrent writer into a shared entry would look like from here."""
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    install_fake_tsm(
        monkeypatch,
        tmp_path,
        provider=tsm.PROVIDER_SEV_GUEST,
        make_outblob=lambda _data: make_sev_snp_report(
            vcek_key, measurement=b"\x11" * 48, report_data=b"\x99" * 64
        ),
    )
    device = tmp_path / "sev-guest"
    device.touch()
    monkeypatch.setattr("ca2a_runtime.tee.sev_snp.SEV_GUEST_DEVICE", str(device))

    with pytest.raises(AttestationFailed, match="key and nonce binding"):
        SevSnpProvider().attest(PUBLIC_KEY, NONCE)


def test_snp_attest_explains_the_azure_paravisor_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Not "no SEV-SNP guest" on a machine that is one: name the real reason."""
    install_fake_tsm(
        monkeypatch, tmp_path, provider=tsm.PROVIDER_SEV_GUEST, make_outblob=lambda _d: b"x"
    )
    monkeypatch.setattr("ca2a_runtime.tee.sev_snp.SEV_GUEST_DEVICE", str(tmp_path / "absent"))

    with pytest.raises(AttestationUnsupported) as excinfo:
        SevSnpProvider().attest(PUBLIC_KEY, NONCE)
    assert "paravisor" in str(excinfo.value.detail)


# ── TDX ───────────────────────────────────────────────────────────────────────


def _tdx_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mrtd: bytes = b"\x11" * 48,
    report_data: bytes | None = None,
) -> None:
    """A host that looks like a non-paravisor TDX guest, answering with a quote."""
    root_key = ec.generate_private_key(ec.SECP256R1())

    def make_outblob(data: bytes) -> bytes:
        quote, _root = build_quote(mrtd, report_data or data, root_key=root_key)
        return quote

    install_fake_tsm(
        monkeypatch, tmp_path, provider=tsm.PROVIDER_TDX_GUEST, make_outblob=make_outblob
    )
    device = tmp_path / "tdx_guest"
    device.touch()
    monkeypatch.setattr("ca2a_runtime.tee.tdx.TDX_GUEST_DEVICE", str(device))


def test_tdx_detect_is_false_without_the_tsm_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tsm, "TSM_REPORT_DIR", str(tmp_path / "absent"))
    assert TdxProvider.detect() is False


def test_tdx_detect_is_true_when_attest_can_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _tdx_host(monkeypatch, tmp_path)
    assert TdxProvider.detect() is True


def test_tdx_attest_commits_the_offered_key_and_nonce(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _tdx_host(monkeypatch, tmp_path, mrtd=b"\x44" * 48)
    report = TdxProvider().attest(PUBLIC_KEY, NONCE)

    assert report.platform == "tdx"
    assert report.measurement == "sha384:" + (b"\x44" * 48).hex()
    assert report.public_key == PUBLIC_KEY
    assert report.nonce == NONCE
    # A TDX quote is self-contained, so the evidence is the quote verbatim and
    # the PCK chain travels with it.
    assert report.raw_evidence is not None
    assert report.attestation_key_chain_pem is not None
    assert b"BEGIN CERTIFICATE" in report.attestation_key_chain_pem


def test_tdx_attest_refuses_a_quote_committing_something_else(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _tdx_host(monkeypatch, tmp_path, report_data=b"\x99" * 64)
    with pytest.raises(AttestationFailed, match="key and nonce binding"):
        TdxProvider().attest(PUBLIC_KEY, NONCE)


def test_tdx_attest_refuses_a_quote_that_is_not_tdx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The tdx_guest provider answering with another TEE type is not TDX evidence."""
    root_key = ec.generate_private_key(ec.SECP256R1())

    def make_outblob(data: bytes) -> bytes:
        quote, _root = build_quote(b"\x11" * 48, data, root_key=root_key)
        # tee_type sits in the header at offset 4.
        tampered = bytearray(quote)
        tampered[4:8] = (0x00).to_bytes(4, "little")
        return bytes(tampered)

    install_fake_tsm(
        monkeypatch, tmp_path, provider=tsm.PROVIDER_TDX_GUEST, make_outblob=make_outblob
    )
    device = tmp_path / "tdx_guest"
    device.touch()
    monkeypatch.setattr("ca2a_runtime.tee.tdx.TDX_GUEST_DEVICE", str(device))

    with pytest.raises(AttestationFailed, match="not a TDX quote"):
        TdxProvider().attest(PUBLIC_KEY, NONCE)


def test_tdx_attest_names_the_missing_device(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_tsm(
        monkeypatch, tmp_path, provider=tsm.PROVIDER_TDX_GUEST, make_outblob=lambda _d: b"x"
    )
    monkeypatch.setattr("ca2a_runtime.tee.tdx.TDX_GUEST_DEVICE", str(tmp_path / "absent"))
    with pytest.raises(AttestationUnsupported, match="non-paravisor TDX guest"):
        TdxProvider().attest(PUBLIC_KEY, NONCE)


# ── the contract detect and attest share ──────────────────────────────────────


@pytest.mark.parametrize(
    ("provider_cls", "install_host"),
    [(SevSnpProvider, _snp_host), (TdxProvider, _tdx_host)],
)
def test_detect_and_attest_agree(
    provider_cls, install_host, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The invariant in BaseProvider, and the defect #74 fixed for TPM.

    Returning True from detect and then raising ATTESTATION_UNSUPPORTED means the
    provider is selected and then fails, with an error claiming the platform is
    absent on a machine that has it.
    """
    install_host(monkeypatch, tmp_path)
    assert provider_cls.detect() is True
    provider_cls().attest(PUBLIC_KEY, NONCE)
