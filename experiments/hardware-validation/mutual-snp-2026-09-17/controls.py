"""Live negative probes. Real SNP verifier retained; test-only transport instrumentation."""
import copy, json, secrets, time
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ca2a_runtime import hardware_acceptance as h
from ca2a_runtime.attestation import ChannelOffer
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import client,wire

p=Path('/opt/ca2a-run')
c=json.loads((p/'sender.json').read_text())
chain=[DelegationCredential.from_dict(x) for x in json.loads((p/'chain.json').read_text())]
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex((p/'holder-key.hex').read_text()))
log=h.ReceiptLog(p/'controls-appraisal.jsonl','live-negative-controls')
original_get, original_post, original_seal=client._get_json,client._post_json,client.seal_to_peer
results=[]
for case in ['positive','wrong_measurement','stale_nonce','substituted_channel_key',
             'software_callee','strict_no_smt','require_ciphertext_hiding','minimum_guest_svn_1',
             'software_caller','caller_binding_mismatch','scope_escalation']:
    time.sleep(1)
    counts={'seal':0,'task_post':0}
    policy=copy.deepcopy(c['peer'])
    if case=='wrong_measurement': policy['expected_measurement']='00'*48
    if case=='strict_no_smt': policy['forbid_platform']=['smt_enabled']
    if case=='require_ciphertext_hiding': policy['require_platform'].append('ciphertext_hiding_dram_enabled')
    if case=='minimum_guest_svn_1': policy['min_guest_svn']=1
    verifier=h.build_verifier(policy,p,log)
    def get(url):
        requested=parse_qs(urlsplit(url).query)['nonce'][0]
        fetch_url=url.replace(requested,'00'*16) if case=='stale_nonce' else url
        body=original_get(fetch_url)
        offer=wire.parse_channel_offer(body)
        if case=='stale_nonce':
            # Rewrite the claim to the fresh request, retaining the old signed binding.
            offer=replace(offer,report=replace(offer.report,nonce=requested))
        if case=='substituted_channel_key':
            offered='22'*32
            offer=ChannelOffer(offered,replace(offer.report,public_key=offered))
        if case=='software_callee':
            offer=replace(offer,report=replace(offer.report,platform='software-only',raw_evidence=None,quote_signature=None))
        return wire.serialize_channel_offer(offer,challenge=wire.parse_challenge(body))
    def seal(*args,**kwargs):
        counts['seal']+=1
        return original_seal(*args,**kwargs)
    def post(*args,**kwargs):
        counts['task_post']+=1
        return original_post(*args,**kwargs)
    class BadBindingProvider(SevSnpProvider):
        def attest(self,public_key,nonce):
            signed=super().attest(public_key,'00'*16)
            return replace(signed,nonce=nonce)
    provider=SoftwareProvider() if case=='software_caller' else (
        BadBindingProvider() if case=='caller_binding_mismatch' else SevSnpProvider())
    client._get_json,client._post_json,client.seal_to_peer=get,post,seal
    accepted=False
    error=None
    transport_error=None
    try:
        result=client.send_task(c['peer_url'],chain,'write' if case=='scope_escalation' else 'read',
            'control-'+case+'-'+secrets.token_hex(4),holder_key=key,payload=(p/'probe.bin').read_bytes(),
            verifier=verifier,require_hardware=True,caller_provider=provider)
        accepted=result.get('accepted') is True
    except CA2AError as exc:
        error={'code':exc.code,'message':str(exc)}
    except OSError as exc:
        transport_error=type(exc).__name__
    finally:
        client._get_json,client._post_json,client.seal_to_peer=original_get,original_post,original_seal
    before_send=case not in ['positive','software_caller','caller_binding_mismatch','scope_escalation']
    passed=accepted if case=='positive' else (not accepted and error is not None)
    if before_send: passed=passed and counts=={'seal':0,'task_post':0}
    results.append(dict(case=case,passed=passed,accepted=accepted,error=error,transport_error=transport_error,
        counts=counts,rejection_before_seal_and_task_post=before_send and passed))
    (p/'controls.json').write_text(json.dumps({'partial':True,'results':results},indent=2))
    print(json.dumps(results[-1]),flush=True)
out={'scope':'same-project live SNP diagnostic; local instrumentation; unsigned',
     'all_passed':all(r['passed'] for r in results),'results':results}
(p/'controls.json').write_text(json.dumps(out,indent=2))
print(json.dumps(out))
raise SystemExit(0 if out['all_passed'] else 1)
