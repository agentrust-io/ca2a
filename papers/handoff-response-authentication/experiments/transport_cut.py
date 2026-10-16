"""Multi-process transport cut, caller restart and no resubmission.

Hypothesis: with the pinned cA2A client in strict response-authentication mode,
when the connection is cut after the peer has executed (or before dispatch, or
mid-response), the caller reports an unknown outcome, the client makes exactly
one submission, and a restarted caller cannot turn the peer's captured response
into an accepted result. The caller never learns which of the cut cases
happened, which is why the unknown outcome must be preserved.

Topology: peer process (real cA2A HTTP server on an ephemeral port, with an
fsync'd execution journal), relay process (TCP relay that cuts the connection
at a chosen point and captures what the peer returned), and caller processes
(send_task, with an application journal written before sending). Control: a
client mutated to resend once on transport failure must violate the criterion.

Usage: transport_cut.py run SCRATCH. Subcommands peer/relay/caller/recover.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve()
# Child processes never open a console window on Windows (0 elsewhere).
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _append(path, obj):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _lines(path):
    p = Path(path)
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


# --------------------------------------------------------------------- peer
def peer(root_issuer: str, journal: str, port_file: str) -> None:
    from ca2a_runtime.node import PeerNode
    from ca2a_runtime.policy import LocalPolicy
    from ca2a_runtime.transport import server
    from ca2a_runtime.transport.a2a_adapter import parse_peer_request
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={root_issuer})
    original = node.handle

    def handle(message):
        result = original(message)
        _append(journal, {"executed": parse_peer_request(message).record_id, "t": time.time()})
        return result
    node.handle = handle
    http = server.serve(node, port=0)  # never the default port
    Path(port_file).write_text(str(http.server_port), encoding="utf-8")
    http.serve_forever()


# -------------------------------------------------------------------- relay
def _read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v.strip())
    while len(rest) < length:
        rest += conn.recv(65536)
    return head + b"\r\n\r\n" + rest


def relay(peer_port: str, mode: str, port_file: str, log: str, capture: str) -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    Path(port_file).write_text(str(srv.getsockname()[1]), encoding="utf-8")

    def serve(conn):
        with conn:
            request = _read_request(conn)
            is_post = request.startswith(b"POST")
            if is_post:
                _append(log, {"post": True, "t": time.time()})
            if is_post and mode == "cut_before_dispatch":
                return
            up = socket.create_connection(("127.0.0.1", int(peer_port)))
            with up:
                up.sendall(request)
                response = b""
                while chunk := up.recv(65536):
                    response += chunk
            if is_post:
                with open(capture, "ab") as fh:
                    fh.write(len(response).to_bytes(4, "big") + response)
            if is_post and mode == "cut_after_dispatch":
                return
            if is_post and mode == "hold":
                time.sleep(120)
                return
            if is_post and mode == "truncate":
                head, _, body = response.partition(b"\r\n\r\n")
                conn.sendall(head + b"\r\n\r\n" + body[: len(body) // 2])
                return
            conn.sendall(response)

    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


# ------------------------------------------------------------------- caller
def _material(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ca2a_runtime.delegation.credential import DelegationCredential
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    chain = [DelegationCredential.from_dict(c) for c in m["chain"]]
    return chain, Ed25519PrivateKey.from_private_bytes(bytes.fromhex(m["holder"]))


def caller(material: str, url: str, record_id: str, journal: str) -> None:
    from ca2a_runtime.response import AuthenticatedPeerError, ResponseAuthenticationFailed
    from ca2a_runtime.transport import client
    chain, holder = _material(material)
    _append(journal, {"record_id": record_id, "state": "submitted"})
    try:
        result = client.send_task(url, chain, "read", record_id, holder_key=holder,
                                  payload=b"synthetic-task", require_authenticated_response=True)
        outcome = "accepted" if result.get("accepted") else "unexpected"
    except ResponseAuthenticationFailed:
        outcome = "unknown"
    except AuthenticatedPeerError:
        outcome = "authenticated-denial"
    _append(journal, {"record_id": record_id, "state": outcome})
    print(json.dumps({"outcome": outcome}))


def recover(journal: str, capture: str, url: str) -> None:
    """Restarted caller: keep unresolved operations unknown; try the captured reply."""
    from ca2a_runtime.response import PendingResponse, ResponseAuthenticationFailed
    from ca2a_runtime.transport import client
    states = {}
    for e in _lines(journal):
        states[e["record_id"]] = e["state"]
    unresolved = {k: ("unknown" if v in ("submitted", "unknown") else v) for k, v in states.items()}
    replay = "no-capture"
    data = Path(capture).read_bytes() if Path(capture).exists() else b""
    if data:
        size = int.from_bytes(data[:4], "big")
        head, _, body = data[4:4 + size].partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        # New process: re-appraise the same peer; new pending state, new occurrence.
        pending = PendingResponse(client.fetch_verified_peer(url), {"record_id": "restart"})
        try:
            pending.verify(status, body)
            replay = "accepted"
        except ResponseAuthenticationFailed:
            replay = "refused"
    print(json.dumps({"after_restart": unresolved, "captured_response_replay": replay}))


# ------------------------------------------------------------------- parent
def run(scratch: Path) -> dict:
    from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
    scratch.mkdir(parents=True, exist_ok=True)
    root_priv, root_pub = new_keypair()
    holder, holder_pub = new_keypair()
    cred = DelegationCredential(credential_id="c0", issuer=root_pub, subject=holder_pub,
                                scope=frozenset({"read"}), depth=0).sign(root_priv)
    body = {**cred.body(), "signature": cred.signature}
    material = scratch / "material.json"
    from cryptography.hazmat.primitives import serialization
    raw = holder.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    material.write_text(json.dumps({"chain": [body], "holder": raw.hex()}), encoding="utf-8")
    procs = []

    def start(args, port_file):
        p = subprocess.Popen([sys.executable, "-B", str(HERE), *args], creationflags=NO_WINDOW)
        procs.append(p)
        deadline = time.time() + 30
        while not (Path(port_file).exists() and Path(port_file).read_text()):
            if time.time() > deadline or p.poll() is not None:
                raise RuntimeError("child did not start: " + args[0])
            time.sleep(0.05)
        return Path(port_file).read_text()

    def run_caller(url, rid, journal, kill_when=None):
        p = subprocess.Popen([sys.executable, "-B", str(HERE), "caller", str(material), url, rid, str(journal)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             creationflags=NO_WINDOW)
        procs.append(p)
        if kill_when:
            deadline = time.time() + 60
            while not kill_when() and time.time() < deadline:
                time.sleep(0.02)
            p.kill()
        out, err = p.communicate(timeout=120)
        return json.loads(out)["outcome"] if out.strip() else "caller-killed"

    def run_recover(journal, capture, url):
        out = subprocess.run([sys.executable, "-B", str(HERE), "recover", str(journal), str(capture), url],
                             capture_output=True, text=True, timeout=120,
                             creationflags=NO_WINDOW).stdout
        return json.loads(out)

    cases = []
    expectations = {
        "pass": ("accepted", 1),
        "cut_before_dispatch": ("unknown", 0),
        "cut_after_dispatch": ("unknown", 1),
        "truncate": ("unknown", 1),
        "hold": ("caller-killed", 1),
    }
    try:
        for mode, (want_outcome, want_exec) in expectations.items():
            d = scratch / mode
            d.mkdir()
            peer_journal, relay_log, capture, app = d / "peer.jsonl", d / "relay.jsonl", d / "capture.bin", d / "app.jsonl"
            peer_port = start(["peer", root_pub, str(peer_journal), str(d / "peer.port")], d / "peer.port")
            relay_port = start(["relay", peer_port, mode, str(d / "relay.port"), str(relay_log), str(capture)],
                               d / "relay.port")
            rid = f"business-op-{mode}"
            kill_when = (lambda: len(_lines(peer_journal)) >= 1 and capture.exists()) if mode == "hold" else None
            outcome = run_caller(f"http://127.0.0.1:{relay_port}", rid, app, kill_when)
            time.sleep(0.3)
            recovered = run_recover(app, capture, f"http://127.0.0.1:{relay_port}")
            executions = sum(1 for e in _lines(peer_journal) if e["executed"] == rid)
            posts = len(_lines(relay_log))
            case = {"mode": mode, "caller_outcome": outcome, "peer_executions": executions,
                    "submissions_seen_by_relay": posts, **recovered}
            want_replay = "no-capture" if mode == "cut_before_dispatch" else "refused"
            case["ok"] = (outcome == want_outcome and executions == want_exec and posts == 1
                          and recovered["captured_response_replay"] == want_replay
                          and (mode == "pass" or recovered["after_restart"].get(rid) == "unknown"))
            cases.append(case)
            for p in procs:
                if p.poll() is None:
                    p.kill()
                    p.wait(10)
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait(10)
    passed = sum(c["ok"] for c in cases)
    return {"experiment": "transport-cut", "cases": cases, "cases_passed": passed,
            "cases_total": len(cases), "criterion_met": passed == len(cases)}


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "peer":
        peer(*sys.argv[2:])
    elif cmd == "relay":
        relay(*sys.argv[2:])
    elif cmd == "caller":
        caller(*sys.argv[2:])
    elif cmd == "recover":
        recover(*sys.argv[2:])
    else:
        result = run(Path(sys.argv[2]))
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["criterion_met"] else 1)
