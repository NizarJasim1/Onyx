"""
GROUND gate 2 — the proving-ground: a REAL HTTP server with planted authorization
vulnerabilities and legitimate decoys, plus a SEALED oracle of the exact ground truth.

Independence safeguards (so this measures, not flatters):
  * vulnerabilities are placed at SEEDED-RANDOM locations (a seed I do not hand-tune),
    so I do not choose which object is vulnerable;
  * every planted bug is drawn from catalog.json (OWASP), including STRANGE forms the
    tool was not built on (generalization test);
  * legitimate decoys are planted in equal measure (precision test);
  * the oracle is written and hashed BEFORE any detector is run, and never edited after.

Run:  python proving_server.py --seed 1337 --port 8910 --emit-oracle oracle.json
It prints the base_url and writes the oracle. The server then serves until killed.

NO ONYX detection file is imported or read here. This file knows only HTTP + the catalog.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---- fixed world: users, tokens, and their owned objects -------------------------
USERS = {
    "tok-alice": {"id": "u-alice", "role": "member", "email": "alice@pg.local"},
    "tok-bob":   {"id": "u-bob",   "role": "member", "email": "bob@pg.local"},
    "tok-admin": {"id": "u-admin", "role": "admin",  "email": "admin@pg.local"},
}

# mutable per-user profile state. is_admin is ROLE-TIED (true only for the admin in observed
# bodies) → the privileged field. display_name is freely member-settable → a decoy: writing
# it sticks but it is NOT privilege-bound, so it must NOT be flagged.
PROFILES = {
    "u-alice": {"is_admin": False, "display_name": "Alice"},
    "u-bob":   {"is_admin": False, "display_name": "Bob"},
    "u-admin": {"is_admin": True,  "display_name": "Admin"},
}
# objects: each doc/account/order owned by someone, with a sensitive field.
# A WIDE pool: only a seeded-random SUBSET is made vulnerable; the rest stay CLEAN so
# precision (false positives) is measurable.
OBJECTS = {
    "doc:1": {"owner": "u-alice", "title": "Alice plan", "salary": 50000},
    "doc:2": {"owner": "u-bob",   "title": "Bob plan",   "salary": 60000},
    "doc:3": {"owner": "u-alice", "title": "Alice notes", "salary": 51000},
    "doc:4": {"owner": "u-bob",   "title": "Bob notes",   "salary": 61000},
    "acct:1": {"owner": "u-alice", "balance": 1200, "iban": "IBANALICE"},
    "acct:2": {"owner": "u-bob",   "balance": 3400, "iban": "IBANBOB"},
    "acct:3": {"owner": "u-alice", "balance": 800,  "iban": "IBANALICE3"},
    "acct:4": {"owner": "u-bob",   "balance": 9000, "iban": "IBANBOB4"},
    "order:1": {"owner": "u-alice", "invoice": "INV-AAA", "total": 99},
    "order:2": {"owner": "u-bob",   "invoice": "INV-BBB", "total": 77},
    "order:3": {"owner": "u-alice", "invoice": "INV-CCC", "total": 55},
    "order:4": {"owner": "u-bob",   "invoice": "INV-DDD", "total": 33},
}


def _token(headers):
    auth = headers.get("Authorization", "")
    return auth.split("Bearer ", 1)[-1].strip() if "Bearer " in auth else None


def _principal(headers):
    return USERS.get(_token(headers))


class Ground:
    """Decides, from a seed, WHICH objects are vulnerable to WHICH planted class. The
    oracle records this exactly. Placement is random(seed) — not hand-picked."""

    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.plan = self._plant()

    def _plant(self) -> dict:
        docs = ["doc:1", "doc:2", "doc:3", "doc:4"]
        accts = ["acct:1", "acct:2", "acct:3", "acct:4"]
        orders = ["order:1", "order:2", "order:3", "order:4"]
        self.r.shuffle(docs); self.r.shuffle(accts); self.r.shuffle(orders)
        # only a few objects per pool are made vulnerable; the rest stay CLEAN so
        # precision (false positives) is measurable. distinct docs per class.
        return {
            # BOLA familiar: one doc readable cross-owner by id
            "bola_idswap": {"resource": docs[0], "class": "BOLA", "form": "familiar"},
            # BOLA strange: one order readable via ?invoice= secondary key
            "bola_secondary_key": {"resource": orders[0], "class": "BOLA", "form": "strange"},
            # BOPLA familiar: a DIFFERENT doc leaks salary to a non-owner member
            "bopla_field_leak": {"resource": docs[1], "class": "BOPLA", "form": "familiar"},
            # BOPLA strange: one account leaks iban only via ?expand=full to a non-owner
            "bopla_inconsistent_projection": {"resource": accts[0], "class": "BOPLA", "form": "strange"},
            # BFLA familiar: a THIRD doc deletable by a non-owner member
            "bfla_method_escalation": {"resource": docs[2], "class": "BFLA", "form": "familiar"},
            # BFLA strange (verb-tunnel): a FOURTH doc deletable ONLY via X-HTTP-Method-
            # Override (plain DELETE is correctly gated 403; the tunnel bypasses it).
            "tunnel_bfla": {"resource": docs[3], "class": "BFLA", "form": "strange"},
            # AUTHN gap: one account readable anonymously
            "authn_anon_read": {"resource": accts[1], "class": "AUTHN_GAP", "form": "familiar"},
            # --- DECOYS (must NOT be flagged) ---
            # feature flag on a same-role order list (handled in do_GET)
            "decoy_feature_flag": {"resource": orders[1], "class": "DECOY", "form": "feature_flag_same_role"},
            # a clean doc whose non-owner denial (403) is CORRECT — must never be flagged
            "decoy_correct_denial": {"resource": docs[3], "class": "DECOY", "form": "correct_owner_denial"},
            # a clean account with a legit plan-tier field difference (not authz)
            "decoy_plan_tier": {"resource": accts[2], "class": "DECOY", "form": "plan_tier_legit"},
        }

    def oracle(self) -> dict:
        return {"planted": {k: v for k, v in self.plan.items() if v["class"] != "DECOY"},
                "decoys": {k: v for k, v in self.plan.items() if v["class"] == "DECOY"}}


def make_handler(g: Ground):
    plan = g.plan

    def _rid(kind, n):  # path id -> ResourceIdentity string
        return f"{kind}:{n}"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # --- the only place authorization decisions are (mis)made ---
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            parts = [p for p in u.path.split("/") if p]
            p = _principal(self.headers)

            # /api/public/info — a genuinely PUBLIC endpoint (decoy): anon may read it and
            # it declares NO owner. Must NEVER be flagged as an AUTHN-gap (precision).
            if u.path == "/api/public/info":
                return self._send(200, {"id": "info", "announcement": "service status: ok"})

            # /api/me — attestation endpoint (who am I)
            if u.path == "/api/me":
                if not p:
                    return self._send(401, {"error": "auth required"})
                prof = PROFILES.get(p["id"], {})
                return self._send(200, {"id": p["id"], "role": p["role"],
                                        "email": p["email"],
                                        "is_admin": prof.get("is_admin", False),
                                        "display_name": prof.get("display_name", "")})

            # /api/docs/{n}
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "docs":
                rid = _rid("doc", parts[2])
                obj = OBJECTS.get(rid)
                if not obj:
                    return self._send(404, {"error": "not found"})
                if not p:
                    return self._send(401, {"error": "auth required"})
                is_owner = obj["owner"] == p["id"] or p["role"] == "admin"
                # BOLA familiar: planted doc is served cross-owner
                bola = plan["bola_idswap"]["resource"] == rid
                base = {"id": parts[2], "title": obj["title"], "owner_id": obj["owner"]}
                is_owner_view = obj["owner"] == p["id"]
                base["_links"] = ({"self": {}, "delete": {}, "edit": {}}
                                  if (is_owner_view or p["role"] == "admin")
                                  else {"self": {}})
                if not is_owner and not bola:
                    # BOPLA familiar: planted doc leaks salary to non-owner instead of 403
                    if plan["bopla_field_leak"]["resource"] == rid:
                        return self._send(200, dict(base, salary=obj["salary"]))  # LEAK
                    return self._send(403, {"error": "requires role owner"})
                if is_owner:
                    base["salary"] = obj["salary"]
                return self._send(200, base)

            # /api/accounts/{n}  (+ ?expand=full)
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "accounts":
                rid = _rid("acct", parts[2])
                obj = OBJECTS.get(rid)
                if not obj:
                    return self._send(404, {"error": "not found"})
                # AUTHN gap: planted account readable anonymously
                anon_ok = plan["authn_anon_read"]["resource"] == rid
                if not p and not anon_ok:
                    return self._send(401, {"error": "auth required"})
                viewer = p["id"] if p else None
                is_owner = obj["owner"] == viewer or (p and p["role"] == "admin")
                expand = q.get("expand", [""])[0] == "full"
                bopla = plan["bopla_inconsistent_projection"]["resource"] == rid
                # clean accounts enforce ownership: a non-owner (non-admin) is denied,
                # UNLESS this is the planted BOPLA-strange account (non-owner may read the
                # balance, and iban leaks only via ?expand=full) or the AUTHN-gap account.
                if p and not is_owner and not bopla and not anon_ok:
                    return self._send(403, {"error": "requires role owner"})
                body = {"id": parts[2], "balance": obj["balance"], "owner_id": obj["owner"]}
                # BOPLA strange: iban leaks to non-owner ONLY via ?expand=full
                if is_owner:
                    body["iban"] = obj["iban"]
                elif expand and bopla:
                    body["iban"] = obj["iban"]  # LEAK only in expanded representation
                return self._send(200, body)

            # /api/orders  (+ ?invoice=)
            if u.path == "/api/orders":
                if not p:
                    return self._send(401, {"error": "auth required"})
                inv = q.get("invoice", [None])[0]
                if inv:
                    # BOLA strange: secondary-key ownership — returns victim's order by invoice
                    for rid, obj in OBJECTS.items():
                        if rid.startswith("order:") and obj["invoice"] == inv:
                            planted = plan["bola_secondary_key"]["resource"] == rid
                            owns = obj["owner"] == p["id"]
                            if owns or planted:
                                return self._send(200, {"id": rid.split(":")[1],
                                                        "invoice": inv, "total": obj["total"],
                                                        "owner_id": obj["owner"]})
                            return self._send(403, {"error": "not your order"})
                    return self._send(404, {"error": "no such invoice"})
                # list own orders + a decoy beta field for same-role A/B (NOT a vuln)
                mine = [{"id": r.split(":")[1], "total": o["total"]}
                        for r, o in OBJECTS.items()
                        if r.startswith("order:") and o["owner"] == p["id"]]
                resp = {"orders": mine}
                if plan["decoy_feature_flag"]["resource"].startswith("order") and p["id"] == "u-bob":
                    resp["beta_recommendations"] = True  # feature flag, same role — a decoy
                return self._send(200, resp)

            return self._send(404, {"error": "no route"})

        def do_PATCH(self):
            from urllib.parse import urlparse
            if urlparse(self.path).path != "/api/me":
                return self._send(404, {"error": "no route"})
            p = _principal(self.headers)
            if not p:
                return self._send(401, {"error": "auth required"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                body = {}
            prof = PROFILES.setdefault(p["id"], {})
            # MASS-ASSIGNMENT BUG: is_admin (a privilege-bound field) is blindly bound from
            # the request body → a member can set it true and it STICKS.
            if "is_admin" in body:
                prof["is_admin"] = bool(body["is_admin"])
            # legitimate: display_name is the user's own to set (member-settable; a decoy).
            if "display_name" in body:
                prof["display_name"] = str(body["display_name"])
            # control: 'role' is NOT bound from the body (server ignores it) → never sticks.
            return self._send(200, {"id": p["id"], "role": p["role"],
                                    "is_admin": prof.get("is_admin", False),
                                    "display_name": prof.get("display_name", "")})

        def do_POST(self):
            # verb-tunneling: a POST carrying X-HTTP-Method-Override is treated as that
            # method. The function gate here checks the HTTP method but NOT the override
            # header — so the tunneled DELETE bypasses the ownership gate that plain DELETE
            # enforces. (GT3 strange BFLA form.)
            override = self.headers.get("X-HTTP-Method-Override", "").upper()
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            p = _principal(self.headers)
            if override == "DELETE" and len(parts) == 3 and parts[1] == "docs":
                rid = _rid("doc", parts[2])
                obj = OBJECTS.get(rid)
                if not obj:
                    return self._send(404, {"error": "not found"})
                if not p:
                    return self._send(401, {"error": "auth required"})
                is_owner = obj["owner"] == p["id"] or p["role"] == "admin"
                # the tunnel BFLA is planted on ONE doc: there the override path forgets to
                # re-check ownership (gate bypass). Every OTHER doc's tunnel correctly
                # enforces ownership (403 to non-owners) — so a tool must flag ONLY the
                # planted doc (precision).
                tunnel_bypass = plan["tunnel_bfla"]["resource"] == rid
                if not is_owner and not tunnel_bypass:
                    return self._send(403, {"error": "requires role owner"})
                return self._send(200, {"deleted": parts[2], "via": "override"})
            return self._send(404, {"error": "no route"})

        def do_DELETE(self):
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            p = _principal(self.headers)
            if len(parts) == 3 and parts[1] == "docs":
                rid = _rid("doc", parts[2])
                obj = OBJECTS.get(rid)
                if not obj:
                    return self._send(404, {"error": "not found"})
                if not p:
                    return self._send(401, {"error": "auth required"})
                is_owner = obj["owner"] == p["id"] or p["role"] == "admin"
                # BFLA familiar: planted doc deletable by non-owner member
                bfla = plan["bfla_method_escalation"]["resource"] == rid
                if not is_owner and not bfla:
                    return self._send(403, {"error": "requires role owner"})
                return self._send(200, {"deleted": parts[2]})
            return self._send(404, {"error": "no route"})

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--port", type=int, default=8910)
    ap.add_argument("--emit-oracle", default="oracle.json")
    a = ap.parse_args()

    g = Ground(a.seed)
    oracle = g.oracle()
    oracle["_seed"] = a.seed
    oracle["_base_url"] = f"http://127.0.0.1:{a.port}"
    blob = json.dumps(oracle, indent=2, sort_keys=True).encode()
    digest = hashlib.sha256(blob).hexdigest()
    with open(a.emit_oracle, "wb") as fh:
        fh.write(blob)
    with open(a.emit_oracle + ".sha256", "w") as fh:
        fh.write(digest + "\n")
    print(f"oracle sealed → {a.emit_oracle}  sha256={digest[:16]}…")
    print(f"base_url = http://127.0.0.1:{a.port}")
    print(f"planted vulns: {len(oracle['planted'])} | decoys: {len(oracle['decoys'])}")

    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(g))
    print("serving (Ctrl+C to stop)…")
    srv.serve_forever()


if __name__ == "__main__":
    main()
