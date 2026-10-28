#!/usr/bin/env python3
"""adversary_sequences.py — adversarial self-critique of Phase 4 (multi-step flows).
Three traps; each must yield 0 confirmed.

  A) LEGITIMATE TRANSITION: the order IS paid first, THEN fulfilled. The predecessor predicate
     (paid==true) is satisfied on the read-back — reaching 'fulfilled' is correct, not a bug.
  B) TRANSIENT / NON-PERSISTENT: PATCH echoes status='fulfilled' in its response, but the object
     does NOT actually persist it (read-back still shows pending). No Δstate breach → nothing.
  C) GATE ENFORCED WITH ROLLBACK: PATCH accepts the field but the server auto-resets it and
     keeps paid==false consistent; read-back shows the gate held. → nothing.
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import sequences as SEQ

def _make(mode):
    STATE = {}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def _b(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: return json.loads(self.rfile.read(n) or b"{}")
            except Exception: return {}
        def do_POST(self):
            p = self.path.split("?")[0]
            if p == "/api/orders":
                STATE["1001"] = {"id": "1001", "owner": "A", "paid": (mode == "legit"),
                                 "status": "pending"}
                return self._j(200, STATE["1001"])
            if p.endswith("/pay"):
                if "1001" in STATE: STATE["1001"]["paid"] = True
                return self._j(200, STATE.get("1001", {}))
            self._j(404, {})
        def do_PATCH(self):
            p = self.path.split("?")[0]; b = self._b(); oid = p.rsplit("/", 1)[-1]
            if oid not in STATE: return self._j(404, {})
            want = b.get("status")
            if mode == "legit":
                STATE[oid]["status"] = want                      # paid already true → fine
                return self._j(200, STATE[oid])
            if mode == "transient":
                echo = dict(STATE[oid]); echo["status"] = want   # echo only; do NOT persist
                return self._j(200, echo)
            if mode == "rollback":
                # accept then immediately reset (gate holds); read-back shows pending
                return self._j(200, {**STATE[oid], "status": want, "note": "will reset"})
            return self._j(200, STATE[oid])
        def do_GET(self):
            p = self.path.split("?")[0]; oid = p.rsplit("/", 1)[-1]
            return self._j(200, STATE[oid]) if oid in STATE else self._j(404, {})
    return H

def _run(mode, setup):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    flows = [{"name": mode, "setup": setup,
              "critical": {"method": "PATCH", "path": "/api/orders/{id}", "effect": "STATE_GATE",
                           "body": {"status": "fulfilled"}, "ids": {"A": ["1001"]}}}]
    res = SEQ.run(base, {"A": "tokA"}, flows, scope=["127.0.0.1"], researcher="adv-seq")
    srv.shutdown()
    return len(res["confirmed"])

def main():
    ok = True
    # A) legitimate: pay first, then fulfil
    a = _run("legit", [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {}},
                       {"principal": "A", "method": "POST", "path": "/api/orders/1001/pay", "body": {}}])
    print(f"A) legitimate transition : confirmed={a} -> {'PASS' if a == 0 else 'FAIL'} (predecessor satisfied)")
    ok &= a == 0
    # B) transient echo, not persisted
    b = _run("transient", [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {}}])
    print(f"B) transient (not persisted): confirmed={b} -> {'PASS' if b == 0 else 'FAIL'} (read-back shows pending)")
    ok &= b == 0
    # C) rollback / gate holds
    c = _run("rollback", [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {}}])
    print(f"C) rollback (gate holds)  : confirmed={c} -> {'PASS' if c == 0 else 'FAIL'}")
    ok &= c == 0
    print("\nADVERSARY-SEQUENCES:", "PASS — a sequence confirms only a PERSISTED, predecessor-unsatisfied "
          "bypass; legitimate, transient, and rolled-back transitions confirm nothing. 0 FP." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
