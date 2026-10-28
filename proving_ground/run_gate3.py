"""
GROUND gate 3 — THE UNBLINDING. Run ONYX over REAL HTTP against the proving ground.

This is the first point detection logic may be used. It starts proving_server in-process
on loopback, drives the engine through the REAL HTTPTarget (the same adapter used against
any external host — not a mock), enables BOTH nerves, probes the full principal×object
matrix (the standard scan behaviour: try each principal against each object, including the
strange vectors), and writes run.json via the export path.

GT3 lock: NO detection file is edited after seeing the result to improve the number.
"""
import json
import os
import sys
import threading
import time
import hashlib
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import proving_server as ps
from authpath.transport import HTTPTarget, make_exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, Principal
from authpath.diag_export import build_export, to_json_bytes

SEED = 1337
PORT = 8920
BASE = f"http://127.0.0.1:{PORT}"


def start_server():
    g = ps.Ground(SEED)
    oracle = g.oracle()
    oracle["_seed"] = SEED
    oracle["_base_url"] = BASE
    blob = json.dumps(oracle, indent=2, sort_keys=True).encode()
    open(os.path.join(HERE, "oracle.json"), "wb").write(blob)
    open(os.path.join(HERE, "oracle.json.sha256"), "w").write(
        hashlib.sha256(blob).hexdigest() + "\n")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), ps.make_handler(g))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    return oracle


def run_onyx(armed=False):
    scope = ScopeConfig(allowed_hosts=["127.0.0.1"], dry_run=not armed,
                        allow_destructive=armed, automation_permitted=True)
    target = HTTPTarget(BASE, verify_tls=False, scope=scope)

    principals = {
        "alice": Principal("alice", "Alice", {"Authorization": "Bearer tok-alice"}),
        "bob":   Principal("bob",   "Bob",   {"Authorization": "Bearer tok-bob"}),
        "admin": Principal("admin", "Admin", {"Authorization": "Bearer tok-admin"}),
        "anon":  Principal("anon",  "Anon",  {}, is_anonymous=True),
    }
    engine = AuthPathEngine(target, principals, scope)
    engine.nerve = True
    engine.bva = True
    engine.capture = []

    # the probe matrix: every principal attests, then probes every object id and the
    # strange vectors. Probing is standard scan behaviour; DECIDING what is a violation
    # is the tool's job (Δstate, abstain on decoys).
    docs = ["1", "2", "3", "4"]
    accts = ["1", "2", "3", "4"]
    orders_inv = ["INV-AAA", "INV-BBB", "INV-CCC", "INV-DDD"]

    def probe(pid, method, path):
        req = HTTPRequest(method, path, host="127.0.0.1")
        engine.observe(make_exchange(target, req, principals[pid]))

    for pid in principals:
        probe(pid, "GET", "/api/me")
        probe(pid, "GET", "/api/public/info")                      # public decoy (precision)
        for d in docs:
            probe(pid, "GET", f"/api/docs/{d}")
        for a in accts:
            probe(pid, "GET", f"/api/accounts/{a}")
            probe(pid, "GET", f"/api/accounts/{a}?expand=full")    # strange vector
        probe(pid, "GET", "/api/orders")
        for inv in orders_inv:
            probe(pid, "GET", f"/api/orders?invoice={inv}")        # strange vector

    nerve = engine.nerve_findings()
    bva = engine.bva_findings()
    export = build_export(engine, engine.capture, scope=scope,
                          meta={"tool": "ONYX/AuthPath", "run": "GROUND-gate3",
                                "base_url": BASE})
    export["ground_nerve_findings"] = [
        {"resource": getattr(f, "resource", None), "kind": getattr(f, "kind", None),
         "accessor": getattr(f, "accessor", getattr(f, "principal", None))}
        for f in nerve]
    export["ground_bva_findings"] = [
        {"resource": f.resource, "field": f.field, "accessor": f.accessor,
         "owner": f.owner, "kind": f.kind} for f in bva]
    open(os.path.join(HERE, "run.json"), "wb").write(to_json_bytes(export))
    return export, nerve, bva


if __name__ == "__main__":
    oracle = start_server()
    export, nerve, bva = run_onyx()
    print(f"planted: {len(oracle['planted'])} | decoys: {len(oracle['decoys'])}")
    print(f"nerve findings: {len(nerve)} | bva findings: {len(bva)}")
    print(f"raw exchanges captured: {export['run']['exchange_count']}")
    print("run.json written.")
