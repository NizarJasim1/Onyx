"""
PROVING WORLD — an isolated, LIVE, genuinely-vulnerable application.
=================================================================================
This is NOT a capture and NOT a set of canned responses. It is a real application
with real in-memory state and real (deliberately broken) authorization logic. It is
built from a RANDOMLY-SEEDED ownership graph, and for each object-serving endpoint a
seeded coin decides whether that endpoint ENFORCES ownership (safe) or OMITS the
check (vulnerable). Neither the graph nor the vulnerability map is visible to the
attacker; both are the sealed ORACLE.

ANTI-CIRCULARITY (the whole point — enforced, not promised):
  * This module imports ONLY the standard library. It never imports `authpath`.
    It is written the way an ordinary web developer writes a REST backend: an
    ownership check is `if requester != resource.owner: 403`, and the BUG is simply
    omitting that line. Nothing here references ONYX's laws, confirmer, or EIL.
  * WHICH endpoints are vulnerable is chosen at random per seed — not hand-picked to
    match any detector. The attacker must discover exactly the vulnerable subset from
    Δstate alone.
  * The oracle (graph + vuln map) is hashable and is sealed BEFORE any attack; the
    attacker receives only HTTP request/response.

If ONYX, attacking purely over HTTP with no sight of the oracle, reconstructs which
endpoints are vulnerable and to whom each object belongs, that is independent
detection — the target's broken behaviour is real, not authored to be caught.
"""
from __future__ import annotations

import hashlib
import json
import random
import uuid as _uuid


# --------------------------------------------------------------------------- #
# Domain model — plain data, no security framework, no ONYX concepts.          #
# --------------------------------------------------------------------------- #

class World:
    """A live app instance: users own vehicles / reports / orders / videos, and a
    random subset of endpoints fail to enforce ownership."""

    # object-serving endpoints whose ownership enforcement is decided per seed
    GUARDED_ENDPOINTS = [
        "vehicle_location",   # GET  /world/vehicle/{uuid}/location   (BOLA)
        "mechanic_report",    # GET  /world/report?report_id={n}      (BOLA, sequential id)
        "order_read",         # GET  /world/order/{n}                 (BOLA)
        "order_status",       # PUT  /world/order/{n}                 (mass-assign / BFLA-write)
        "video_read",         # GET  /world/video/{n}                 (BOLA, establishes owner)
        "admin_delete_video", # DEL  /world/admin/videos/{n}          (BFLA -> cross-principal destroy)
        "community_feed",     # GET  /world/feed                      (EDE of author PII)
        "users_directory",    # GET  /world/management/users          (EDE bulk PII)
    ]

    def __init__(self, seed: int, n_users: int = 3):
        self.seed = seed
        self.rng = random.Random(seed)
        self.n_users = n_users
        self.users = {}          # pid -> profile dict (private fields)
        self.vehicles = {}       # uuid -> {owner, lat, lon, vin}
        self.reports = {}        # report_id(int) -> {owner, vin, details}
        self.orders = {}         # order_id(int) -> {owner, status, total, credit_after}
        self.videos = {}         # video_id(int) -> {owner, name, internal_token}
        # vuln map: endpoint -> True(vulnerable / no ownership check) or False(safe)
        self.vuln = {e: bool(self.rng.getrandbits(1)) for e in self.GUARDED_ENDPOINTS}
        self._build()

    # ---- world construction (randomised) ---------------------------------- #
    def _build(self):
        pids = [f"U{i}" for i in range(self.n_users)]
        rid = 1
        oid = 1
        vid = 1
        for pid in pids:
            self.users[pid] = {
                "id": 100 + int(pid[1:]),
                "email": f"{pid.lower()}-{self.rng.randrange(10**6):06d}@world.test",
                "name": pid,
                "phone": f"415{self.rng.randrange(10**7):07d}",
                "ssn": f"***-**-{self.rng.randrange(10000):04d}",
                "role": "ROLE_USER",
                "credit": 100.0,
            }
            # each user owns exactly one vehicle, report, order, video
            vu = str(_uuid.UUID(int=self.rng.getrandbits(128)))
            self.vehicles[vu] = {"owner": pid, "vin": f"VIN{self.rng.randrange(10**10):010d}",
                                 "lat": round(self.rng.uniform(-90, 90), 6),
                                 "lon": round(self.rng.uniform(-180, 180), 6)}
            self.reports[rid] = {"owner": pid, "vin": self.vehicles[vu]["vin"],
                                 "details": f"issue-{self.rng.randrange(1000)}"}
            self.orders[oid] = {"owner": pid, "status": "delivered", "total": 250.0}
            self.videos[vid] = {"owner": pid, "name": f"vid-{pid}",
                                "internal_token": _uuid.UUID(int=self.rng.getrandbits(128)).hex}
            self.users[pid]["vehicle_uuid"] = vu
            self.users[pid]["report_id"] = rid
            self.users[pid]["order_id"] = oid
            self.users[pid]["video_id"] = vid
            rid += 1; oid += 1; vid += 1

    # ---- the ORACLE (ground truth), sealed before any attack -------------- #
    def oracle(self) -> dict:
        return {
            "seed": self.seed,
            "vuln": dict(self.vuln),
            "ownership": {
                "vehicles": {u: self.vehicles[u]["owner"] for u in self.vehicles},
                "reports": {str(r): self.reports[r]["owner"] for r in self.reports},
                "orders": {str(o): self.orders[o]["owner"] for o in self.orders},
                "videos": {str(v): self.videos[v]["owner"] for v in self.videos},
            },
        }

    def oracle_seal(self) -> str:
        return hashlib.sha256(json.dumps(self.oracle(), sort_keys=True).encode()).hexdigest()

    # ---- HTTP-ish handler: (method, path, principal, query, body) -> (status, body)
    # Written like a normal backend. The vulnerability is the MISSING owner check.
    def handle(self, method: str, path: str, principal: str, query: dict, body):
        u = self.users.get(principal)
        if u is None:
            return 401, {"error": "unauthenticated"}

        # GET /world/user/dashboard  -> caller's own private profile (always safe)
        if method == "GET" and path == "/world/user/dashboard":
            return 200, {k: u[k] for k in ("id", "email", "name", "phone", "ssn",
                                           "role", "credit", "vehicle_uuid")}

        # GET /world/vehicle/{uuid}/location
        if method == "GET" and path.startswith("/world/vehicle/") and path.endswith("/location"):
            vu = path.split("/")[3]
            veh = self.vehicles.get(vu)
            if veh is None:
                return 404, {"error": "no vehicle"}
            if not self.vuln["vehicle_location"] and veh["owner"] != principal:
                return 403, {"error": "forbidden"}
            owner = self.users[veh["owner"]]
            return 200, {"carId": vu, "fullName": owner["name"], "ownerEmail": owner["email"],
                         "vehicleLocation": {"lat": veh["lat"], "lon": veh["lon"]}}

        # GET /world/report?report_id=n
        if method == "GET" and path == "/world/report":
            rid = int(query.get("report_id", -1))
            rep = self.reports.get(rid)
            if rep is None:
                return 404, {"error": "no report"}
            if not self.vuln["mechanic_report"] and rep["owner"] != principal:
                return 403, {"error": "forbidden"}
            owner = self.users[rep["owner"]]
            return 200, {"id": rid, "problem_details": rep["details"],
                         "vehicle": {"vin": rep["vin"],
                                     "owner": {"email": owner["email"], "phone": owner["phone"]}},
                         "status": "pending"}

        # GET /world/order/{n}
        if method == "GET" and path.startswith("/world/order/"):
            oid = int(path.split("/")[3])
            o = self.orders.get(oid)
            if o is None:
                return 404, {"error": "no order"}
            if not self.vuln["order_read"] and o["owner"] != principal:
                return 403, {"error": "forbidden"}
            owner = self.users[o["owner"]]
            return 200, {"id": oid, "status": o["status"], "total": o["total"],
                         "user": {"email": owner["email"]}}

        # PUT /world/order/{n}  (mass-assign status -> refund credit)
        if method == "PUT" and path.startswith("/world/order/"):
            oid = int(path.split("/")[3])
            o = self.orders.get(oid)
            if o is None:
                return 404, {"error": "no order"}
            if not self.vuln["order_status"] and o["owner"] != principal:
                return 403, {"error": "forbidden"}
            new = (body or {}).get("status")
            if new in ("delivered", "return pending", "returned"):
                prev = o["status"]
                o["status"] = new
                # returning a delivered order refunds credit to the ORDER OWNER
                if new == "returned" and prev != "returned":
                    self.users[o["owner"]]["credit"] += o["total"]
            return 200, {"id": oid, "status": o["status"]}

        # GET /world/video/{n}  (owner establishes ownership here; BOLA if unguarded)
        if method == "GET" and path.startswith("/world/video/"):
            vid = int(path.split("/")[3])
            v = self.videos.get(vid)
            if v is None:
                return 404, {"error": "no video"}
            if not self.vuln["video_read"] and v["owner"] != principal:
                return 403, {"error": "forbidden"}
            owner = self.users[v["owner"]]
            return 200, {"id": vid, "name": v["name"],
                         "owner": {"email": owner["email"]}}

        # DELETE /world/admin/videos/{n}  (admin function; BFLA if no role check)
        if method == "DELETE" and path.startswith("/world/admin/videos/"):
            vid = int(path.split("/")[4])
            v = self.videos.get(vid)
            if v is None:
                return 404, {"error": "no video"}
            # admin function: a correct app requires ROLE_ADMIN; the bug is skipping it
            if not self.vuln["admin_delete_video"] and u["role"] != "ROLE_ADMIN":
                return 403, {"error": "forbidden"}
            self.videos.pop(vid, None)
            return 200, {"message": "deleted", "video_id": vid}

        # GET /world/feed  (community feed; EDE if it exposes author PII)
        if method == "GET" and path == "/world/feed":
            posts = []
            for pid, up in self.users.items():
                author = {"nickname": up["name"]}
                if self.vuln["community_feed"]:           # over-exposes private fields
                    author["email"] = up["email"]
                    author["vehicleid"] = up["vehicle_uuid"]
                posts.append({"id": self.rng.randrange(10**6), "title": f"post by {pid}",
                              "author": author})
            return 200, {"posts": posts}

        # GET /world/management/users  (bulk directory; EDE if it exposes PII)
        if method == "GET" and path == "/world/management/users":
            out = []
            for pid, up in self.users.items():
                rec = {"name": up["name"]}
                if self.vuln["users_directory"]:
                    rec["email"] = up["email"]; rec["phone"] = up["phone"]
                out.append(rec)
            return 200, {"users": out}

        return 404, {"error": "no route"}


def _assert_isolation():
    """Fail loudly if this module ever actually IMPORTS authpath (circularity
    guard). Checks real import statements, not string literals in comments/docs."""
    import ast
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [node.module or ""]
        assert not any(m.split(".")[0] == "authpath" for m in mods), \
            "ISOLATION BREACH: proving world must not import ONYX internals"


_assert_isolation()
