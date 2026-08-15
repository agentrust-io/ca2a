#!/usr/bin/env python3
"""cA2A live attested peer on a real Azure SEV-SNP confidential VM.

Drives the `verifier` seam in ca2a_runtime.attestation off a genuine SEV-SNP
report read from this CVM's vTPM, so the sealed channel binds to a key that a
hardware-verified measurement vouches for, instead of the software-mode
assurance="none" path.

Azure SEV-SNP is paravisor-mediated: there is no /dev/sev-guest and the guest
cannot write REPORT_DATA (the paravisor sets it to sha256(runtime_data), binding
the vTPM AK). So the chain is one hop longer than bare-metal SNP:

    channel key + nonce  ->  AK-signed TPM quote (extraData)
    vTPM AK              ->  SNP REPORT_DATA == sha256(runtime_data)
    SNP report           ->  VCEK -> ASK -> ARK (AMD)

Prints a JSON transcript. Run on the CVM with the repo src on the path.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/home/azureuser/src")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

from agent_manifest import parse_hcl_report, parse_snp_report  # noqa: E402
from agent_manifest._snp_verify import (  # noqa: E402
    verify_runtime_data_binding,
    verify_snp_signature,
    verify_vcek_chain,
)
from ca2a_runtime.attestation import (  # noqa: E402
    ChannelOffer,
    generate_channel_keypair,
    seal_to_peer,
    verify_offer,
)
from ca2a_runtime.channel import open_sealed  # noqa: E402
from ca2a_runtime.errors import AttestationFailed  # noqa: E402
from ca2a_runtime.tee.base import AttestationReport  # noqa: E402

HCL_NV_INDEX = "0x01400001"
PLATFORM = "azure-cvm-sev-snp"
out: dict[str, object] = {}


def run(*argv: str) -> bytes:
    r = subprocess.run(argv, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"{argv[:3]} failed: {r.stderr.decode()[:300]}")
    return r.stdout


def read_hcl_report() -> bytes:
    """Read the paravisor's HCL report (SNP report + runtime data) from vTPM NV."""
    path = "/home/azureuser/hcl_report.bin"
    Path(path).unlink(missing_ok=True)
    run("sudo", "tpm2_nvread", "-C", "o", HCL_NV_INDEX, "-o", path)
    run("sudo", "chmod", "a+r", path)
    return Path(path).read_bytes()


def tpm_quote(nonce_hex: str) -> dict[str, bytes]:
    """AK-signed TPM quote whose extraData commits to the caller's nonce."""
    d = Path(tempfile.mkdtemp())
    run("sudo", "tpm2_createek", "-c", str(d / "ek.ctx"), "-G", "rsa", "-u", str(d / "ek.pub"))
    run("sudo", "tpm2_createak", "-C", str(d / "ek.ctx"), "-c", str(d / "ak.ctx"),
        "-G", "rsa", "-g", "sha256", "-s", "rsassa",
        "-u", str(d / "ak.pub"), "-f", "pem", "-n", str(d / "ak.name"))
    run("sudo", "tpm2_quote", "-c", str(d / "ak.ctx"), "-l", "sha256:0,1,2,3,4,5,6,7",
        "-q", nonce_hex, "-m", str(d / "q.msg"), "-s", str(d / "q.sig"),
        "-o", str(d / "pcrs.bin"), "-g", "sha256", "-f", "plain")
    run("sudo", "chmod", "-R", "a+r", str(d))
    return {
        "attest": (d / "q.msg").read_bytes(),
        "sig": (d / "q.sig").read_bytes(),
        "ak_pub": (d / "ak.pub").read_bytes(),
    }


def fetch_vcek_chain(rep) -> tuple[x509.Certificate, bytes]:
    """Fetch this CPU's VCEK and the AMD ASK/ARK chain from AMD KDS."""
    import urllib.request

    tcb = rep.tcb_spls
    url = (
        f"https://kdsintf.amd.com/vcek/v1/Milan/{rep.chip_id.hex()}"
        f"?blSPL={tcb['bl']:02d}&teeSPL={tcb['tee']:02d}"
        f"&snpSPL={tcb['snp']:02d}&ucodeSPL={tcb['ucode']:02d}"
    )
    vcek = x509.load_der_x509_certificate(urllib.request.urlopen(url, timeout=30).read())
    chain = urllib.request.urlopen(
        "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain", timeout=30
    ).read()
    return vcek, chain


def build_verifier(evidence: dict):
    """The `verifier` seam: appraise the real report, return the measurement.

    Fail-closed at every step. Returns the SNP launch measurement only when the
    whole chain holds: nonce in the AK-signed quote, AK bound into the SNP
    report's REPORT_DATA by the paravisor, report signed by a VCEK that chains
    to the AMD root.
    """

    def verifier(report: AttestationReport, expected_nonce: str) -> str:
        if report.platform != PLATFORM:
            raise AttestationFailed(f"unexpected platform {report.platform!r}")

        snp_raw, runtime = parse_hcl_report(evidence["hcl"])
        rep = parse_snp_report(snp_raw)

        # 1. the paravisor bound the vTPM AK into REPORT_DATA
        if not verify_runtime_data_binding(rep, runtime):
            raise AttestationFailed("SNP REPORT_DATA does not bind the runtime data")

        # 2. the AK-signed quote commits to our nonce and to the channel key
        ak_pub = serialization.load_pem_public_key(evidence["ak_pub"])
        ak_pub.verify(evidence["sig"], evidence["attest"], padding.PKCS1v15(), hashes.SHA256())
        if expected_nonce.encode() not in evidence["attest"].hex().encode() and \
                bytes.fromhex(expected_nonce) not in evidence["attest"]:
            raise AttestationFailed("TPM quote extraData does not carry the expected nonce")

        # 3. the SNP report is signed by a VCEK that chains to the AMD root
        vcek, chain_pem = evidence["vcek"], evidence["chain"]
        if not verify_vcek_chain(vcek.public_bytes(serialization.Encoding.DER), chain_pem):
            raise AttestationFailed("VCEK chain to the AMD root failed")
        if not verify_snp_signature(rep, vcek.public_bytes(serialization.Encoding.DER)):
            raise AttestationFailed("SNP report signature failed")

        measurement = rep.measurement.hex()
        if report.measurement != measurement:
            raise AttestationFailed("offered measurement does not match the verified report")
        return measurement

    return verifier


def main() -> int:
    # The caller's fresh nonce, committed into the TPM quote's extraData.
    nonce_hex = hashlib.sha256(b"ca2a-live-attested-peer").hexdigest()

    hcl = read_hcl_report()
    snp_raw, runtime = parse_hcl_report(hcl)
    rep = parse_snp_report(snp_raw)
    out["snp_report_bytes"] = len(snp_raw)
    out["measurement"] = rep.measurement.hex()
    out["tcb"] = rep.tcb_spls
    out["report_data_binds_runtime_data"] = verify_runtime_data_binding(rep, runtime)

    quote = tpm_quote(nonce_hex)
    vcek, chain_pem = fetch_vcek_chain(rep)
    out["vcek_subject"] = vcek.subject.rfc4514_string()
    evidence = {"hcl": hcl, "vcek": vcek, "chain": chain_pem, **quote}

    # The callee (this enclave) offers its channel key, bound into the report.
    callee_priv, callee_pub = generate_channel_keypair()
    channel_pub = callee_pub
    offer = ChannelOffer(
        channel_public_key=channel_pub,
        report=AttestationReport(
            platform=PLATFORM,
            measurement=rep.measurement.hex(),
            public_key=channel_pub,
            nonce=nonce_hex,
        ),
    )

    # The caller appraises it through the real verifier seam.
    verifier = build_verifier(evidence)
    peer = verify_offer(offer, expected_nonce=nonce_hex, verifier=verifier)
    out["assurance"] = peer.assurance
    out["verified_measurement"] = peer.measurement

    # Seal a task payload to the attested key and open it in the enclave.
    payload = b'{"task":"summarise","doc":"confidential"}'
    sealed = seal_to_peer(peer, payload)
    opened = open_sealed(sealed, callee_priv)
    out["sealed_bytes"] = len(sealed)
    out["roundtrip_ok"] = opened == payload

    # Negative: a swapped binary changes the measurement, so the offer is refused.
    swapped = ChannelOffer(
        channel_public_key=channel_pub,
        report=AttestationReport(
            platform=PLATFORM,
            measurement="00" * 48,
            public_key=channel_pub,
            nonce=nonce_hex,
        ),
    )
    try:
        verify_offer(swapped, expected_nonce=nonce_hex, verifier=verifier)
        out["binary_swap_rejected"] = False
    except AttestationFailed as exc:
        out["binary_swap_rejected"] = True
        out["binary_swap_reason"] = str(exc)

    # Negative: a stale nonce is refused before any hardware work.
    try:
        verify_offer(offer, expected_nonce="00" * 32, verifier=verifier)
        out["stale_nonce_rejected"] = False
    except AttestationFailed:
        out["stale_nonce_rejected"] = True

    print(json.dumps(out, indent=2, default=str))
    ok = (
        out["assurance"] == "hardware"
        and out["roundtrip_ok"]
        and out["binary_swap_rejected"]
        and out["stale_nonce_rejected"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
