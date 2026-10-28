"""
① Transport Adapter — §4 / M0 / M7.

The engine is transport-agnostic. A `Target` is anything the engine can send a
request to as a given principal and get a response back. The SAME engine runs
against:
  * MockTarget  — an in-process app used for the offline harness/demo, so
                  confirm-by-Δstate is GENUINE (real read-backs), not faked.
  * HTTPTarget  — a real authorised target via proxy (requests/httpx).
  * (M7) an MCP shim — v2 revived as one adapter of the same engine.

Because the confirmer can *re-send* a request as the owner and read state back,
Δstate confirmation is real regardless of adapter.  Scope-Guard sits in front of
every send (RL5).
"""

from __future__ import annotations

import copy
from typing import Protocol

from .models import Exchange, HTTPRequest, HTTPResponse, Principal


class Target(Protocol):
    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse: ...


# --------------------------------------------------------------------------- #
# MockTarget — a deliberately-vulnerable in-memory app for the offline harness #
# --------------------------------------------------------------------------- #

class MockTarget:
    """
    A tiny e-commerce/banking-shaped app with PLANTED bugs (labeled, §9), plus
    benign flows that MUST NOT fire (the confirm-by-Δstate test). State is real,
    so reading it back actually proves Δstate.

    Planted bugs:
      * IDOR/BOLA           GET /api/orders/{id}        — no owner check
      * Mass-assignment     PATCH /api/users/{id}       — accepts client `role`
      * BFLA                GET /api/admin/users        — no function-level authz
      * Payment tampering   POST /api/checkout          — trusts client amount_paid
      * Price tampering     POST /api/cart/price        — trusts client total
      * State-gate skip     POST /api/orders/{id}/fulfil— fulfils unpaid order
      * Coupon reuse        POST /api/coupon/redeem     — no single-use enforcement
    Benign (must stay silent):
      * GET /api/orders/{id} as the true owner
      * PATCH /api/users/{id} of own non-privileged field
      * authorised-but-empty read (200 with no leaked data)
    """

    # APQ (#2-a): persisted-query hash -> the query text the server resolves it to.
    # Simulates a real server's server-side APQ store so a HASH-ONLY request routes
    # identically to its full-text form.
    _APQ_HASHES = {
        "wallet_sha256_demo": "query GetWallet($id: ID!){ wallet(id:$id){ id private_key } }",
    }

    def __init__(self) -> None:
        self.host = "demo.local"
        # RL16 temporal demo state: per-path read counter (simulates a deploy that
        # regresses a field filter on a later read) and per-principal promotion.
        self._authreg_reads: dict = {}
        self._promoted: dict = {}
        self._transferred: set = set()       # RL18: folders whose ownership moved to B
        # owners: order_id -> owner principal id
        self.orders = {
            "101": {"id": "101", "owner_id": "A", "total": 250.0, "amount_due": 250.0,
                    "status": "created", "paid": False, "items": [{"sku": "x", "price": 250.0, "qty": 1}]},
            "202": {"id": "202", "owner_id": "B", "total": 90.0, "amount_due": 90.0,
                    "status": "created", "paid": False, "items": [{"sku": "y", "price": 90.0, "qty": 1}]},
            "303": {"id": "303", "owner_id": "B", "total": 40.0, "amount_due": 40.0,
                    "status": "created", "paid": False, "items": [{"sku": "z", "price": 40.0, "qty": 1}]},
        }
        self.users = {
            "A": {"id": "A", "name": "Alice", "role": "user", "email": "a@demo.local"},
            "B": {"id": "B", "name": "Bob", "role": "user", "email": "b@demo.local"},
        }
        # A correctly-protected resource: soft-denies with HTTP 200 + an error body
        # (NO data leak). This is the D3 trap — a naive status/length scanner reports
        # it; confirm-by-Δstate must stay silent.
        self.profiles = {
            "A": {"id": "A", "ssn": "***-**-1111", "address": "1 Alice St"},
            "B": {"id": "B", "ssn": "***-**-2222", "address": "2 Bob Rd"},
        }
        self.coupon_redemptions: dict[str, int] = {}
        # Principals provisioned for the orders subsystem. A non-provisioned
        # principal (e.g. the widget-only control 'C') gets 404 on orders, so it
        # never pollutes the IDOR/BFLA control read-back for the original probes.
        self._order_users = {"A", "B"}
        # ---- SAIE demo surface (structural-divergence) -------------------- #
        # widgets: id -> owner + tier. priv-tier widgets carry an internal/audit
        # sub-structure; std-tier widgets are lean. The PLANTED SAIE bug: a
        # non-owner reading a PRIV widget gets the privileged SHAPE with sensitive
        # values nulled — the privileged serialization path executed, output
        # filtering was the only barrier.
        self.widgets = {
            "50": {"owner": "A", "tier": "priv"},   # privileged, owned by A (victim)
            "60": {"owner": "C", "tier": "std"},    # standard,  owned by C (control)
            "70": {"owner": "B", "tier": "std"},    # standard,  owned by B (attacker)
        }
        # reports: 80 is a "featured" public-rich report — EVERY reader is run
        # through the rich serialization path (values populated only for the
        # report admin A). This is by-design object-driven richness: a genuine
        # lower-priv control ALSO receives the rich shape, so SAIE Gate 2 must
        # SUPPRESS it (no clean control) — it is not an authorization flaw.
        self.reports = {"80": {"featured": True}, "90": {"owner": "B"}}
        self.cases = {"300": True}      # a record whose field projection differs by principal
        self._config_reads = 0
        self._feed_reads = 0
        self._session_reads = 0

    # -- SAIE demo body builders ------------------------------------------ #
    @staticmethod
    def _widget_priv(wid: str, populated: bool) -> dict:
        return {
            "id": wid,
            "status": "active",
            "total": (91.0 if populated else None),
            "buyer": {"id": wid, "tier": ("gold" if populated else None)},
            "internal": {"margin": (22.4 if populated else None),
                         "risk_score": (0.1 if populated else None),
                         "fraud_flags": []},
            "audit": {"by": ("system" if populated else None),
                      "at": ("2026-01-02T00:00:00Z" if populated else None)},
        }

    @staticmethod
    def _widget_lean(wid: str) -> dict:
        return {"id": wid, "status": "active", "total": 12.0,
                "buyer": {"id": wid, "tier": "silver"}}

    @staticmethod
    def _report_rich(rid: str, populated: bool) -> dict:
        return {
            "id": rid,
            "title": ("Quarterly" if populated else None),
            "body": ("report text" if populated else None),
            "internal": {"margin": (5.0 if populated else None),
                         "notes": ("confidential" if populated else None)},
            "audit": {"by": ("admin" if populated else None)},
        }

    @staticmethod
    def _report_lean(rid: str) -> dict:
        return {"id": rid, "title": "Quarterly", "body": "report text"}

    # -- the single entrypoint -------------------------------------------- #
    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse:
        m, p = req.method.upper(), req.path
        actor = principal.pid

        # GET /api/orders/{id}  (IDOR: returns the order regardless of owner)
        if m == "GET" and p.startswith("/api/orders/") and p.count("/") == 3:
            oid = p.rsplit("/", 1)[-1]
            order = self.orders.get(oid)
            if not order:
                return HTTPResponse(404, {"error": "not found"})
            if actor not in self._order_users:        # not provisioned for orders
                return HTTPResponse(404, {"error": "not found"})
            return HTTPResponse(200, copy.deepcopy(order))  # ← missing owner check

        # GET /api/profiles/{id}  (CORRECTLY protected — soft-deny with 200)
        if m == "GET" and p.startswith("/api/profiles/"):
            pid = p.rsplit("/", 1)[-1]
            if pid == actor:                       # owner only
                return HTTPResponse(200, copy.deepcopy(self.profiles.get(pid, {})))
            # soft-deny: 200 OK but no data (the trap)
            return HTTPResponse(200, {"error": "forbidden", "id": pid})

        # GET /api/admin/users  (BFLA: no function-level authz)
        if m == "GET" and p == "/api/admin/users":
            return HTTPResponse(200, {"users": list(self.users.values())})  # ← no authz

        # PATCH /api/users/{id}  (mass-assignment: accepts client role)
        if m == "PATCH" and p.startswith("/api/users/"):
            uid = p.rsplit("/", 1)[-1]
            user = self.users.get(uid)
            if not user:
                return HTTPResponse(404, {"error": "not found"})
            body = req.body or {}
            # ← server trusts client-supplied privileged field
            for k in ("role", "is_admin", "verified", "balance"):
                if k in body:
                    user[k] = body[k]
            if "name" in body:
                user["name"] = body["name"]
            return HTTPResponse(200, copy.deepcopy(user))

        # POST /api/checkout  (payment tampering: trusts client amount_paid)
        if m == "POST" and p == "/api/checkout":
            body = req.body or {}
            oid = str(body.get("order_id", ""))
            order = self.orders.get(oid)
            if not order:
                return HTTPResponse(404, {"error": "order not found"})
            paid = float(body.get("amount_paid", 0))
            order["paid"] = True            # ← marks paid regardless of amount
            order["amount_paid"] = paid
            order["status"] = "paid"
            return HTTPResponse(200, {"order_id": oid, "amount_due": order["amount_due"],
                                      "amount_paid": paid, "status": "paid"})

        # POST /api/cart/price  (price tampering: trusts client total)
        if m == "POST" and p == "/api/cart/price":
            body = req.body or {}
            return HTTPResponse(200, {"total": body.get("total"),
                                      "items": body.get("items", [])})  # ← echoes client total

        # POST /api/orders/{id}/fulfil  (state-gate skip)
        if m == "POST" and p.startswith("/api/orders/") and p.endswith("/fulfil"):
            oid = p.split("/")[3]
            order = self.orders.get(oid)
            if not order:
                return HTTPResponse(404, {"error": "not found"})
            order["status"] = "fulfilled"   # ← fulfils even if not paid
            return HTTPResponse(200, {"id": oid, "status": "fulfilled", "paid": order["paid"]})

        # POST /api/coupon/redeem  (coupon reuse)
        if m == "POST" and p == "/api/coupon/redeem":
            body = req.body or {}
            token = str(body.get("coupon", ""))
            self.coupon_redemptions[token] = self.coupon_redemptions.get(token, 0) + 1
            return HTTPResponse(200, {"coupon": token, "applied": True,
                                      "discount": 20.0, "limit": 1})  # ← no enforcement

        # GET /api/me  (session endpoint — returns the caller's own private data)
        # Planted temporal-drift bug: the server NEVER invalidates a token after a
        # password change, so a stale credential keeps returning private data.
        if m == "GET" and p == "/api/me":
            prof = self.profiles.get(actor) or self.users.get(actor) or {}
            return HTTPResponse(200, copy.deepcopy(prof))

        # POST /api/account/password  (password change = a revocation event;
        # the bug is that it does NOT revoke existing sessions/tokens)
        if m == "POST" and p == "/api/account/password":
            return HTTPResponse(200, {"status": "password_updated", "id": actor})

        # ---- SAIE demo routes --------------------------------------------- #
        # GET /api/widgets/{id}  (PLANTED SAIE bug on priv-tier widgets)
        if m == "GET" and p.startswith("/api/widgets/") and p.count("/") == 3:
            wid = p.rsplit("/", 1)[-1]
            w = self.widgets.get(wid)
            if not w:
                return HTTPResponse(404, {"error": "not found"})
            is_owner = (actor == w["owner"])
            if w["tier"] == "std":
                if is_owner:
                    return HTTPResponse(200, self._widget_lean(wid))
                return HTTPResponse(404, {"error": "not found"})   # std: properly scoped
            # priv-tier: owner sees populated; NON-owner gets the privileged SHAPE
            # with sensitive values nulled (the structural-divergence bug).
            return HTTPResponse(200, self._widget_priv(wid, populated=is_owner))

        # GET /api/reports/{id}  (object-driven richness — SAIE Gate-2 negative)
        if m == "GET" and p.startswith("/api/reports/") and p.count("/") == 3:
            rid = p.rsplit("/", 1)[-1]
            r = self.reports.get(rid)
            if not r:
                return HTTPResponse(404, {"error": "not found"})
            if r.get("owner"):                          # a principal's own lean report
                if actor == r["owner"]:
                    return HTTPResponse(200, self._report_lean(rid))
                return HTTPResponse(404, {"error": "not found"})
            # featured public-rich: rich SHAPE for everyone, values for admin 'A'
            return HTTPResponse(200, self._report_rich(rid, populated=(actor == "A")))

        # GET /api/config  (map-like: key order varies across reads — SAIE negative)
        if m == "GET" and p == "/api/config":
            self._config_reads += 1
            if self._config_reads % 2 == 0:             # reorder on alternate reads
                return HTTPResponse(200, {"lang": "en", "flags": {"beta": True}, "theme": "dark"})
            return HTTPResponse(200, {"theme": "dark", "lang": "en", "flags": {"beta": True}})

        # GET /api/feed  (volatile topology — excluded by Layer 0 — SAIE negative)
        if m == "GET" and p == "/api/feed":
            self._feed_reads += 1
            if self._feed_reads % 2 == 1:
                return HTTPResponse(200, {"items": [{"id": 1}], "ts": "t"})
            return HTTPResponse(200, {"items": [{"id": 1}, {"id": 2}], "ts": "t",
                                      "extra": {"k": 1}})

        # GET /api/directory/{id}  (canonical detail view — correctly FILTERS the
        # privileged fields for a non-owner; the LIST view above leaks them, so the
        # list-vs-detail differential confirms an inconsistent-projection finding)
        if m == "GET" and p.startswith("/api/directory/") and p.count("/") == 3:
            mid = p.rsplit("/", 1)[-1]
            base = {"u1": ("Dana", "Engineer"), "u2": ("Evan", "Engineer"),
                    "u3": ("Faye", "Designer"), "u4": ("Gita", "Manager")}.get(mid)
            if not base:
                return HTTPResponse(404, {"error": "not found"})
            row = {"id": mid, "name": base[0], "title": base[1]}
            if actor == mid:                       # only the member sees their own overlay
                row["salary"] = 142000
                row["internal"] = {"cost_center": "R&D-7"}
            return HTTPResponse(200, row)           # non-owner: filtered (no salary/internal)

        # GET /api/directory  (clean to the finding-pipeline, but one member's row
        # leaked a privileged overlay the others lack — reference-free SIBLING
        # ASYMMETRY that intrinsic interrogation catches in a single response)
        if m == "GET" and p == "/api/directory":
            return HTTPResponse(200, {"members": [
                {"id": "u1", "name": "Dana", "title": "Engineer"},
                {"id": "u2", "name": "Evan", "title": "Engineer",
                 "salary": 142000, "internal": {"cost_center": "R&D-7"}},  # ← leaked overlay
                {"id": "u3", "name": "Faye", "title": "Designer"},
                {"id": "u4", "name": "Gita", "title": "Manager"},
            ]})

        # GET /api/dossier  (privileged branch 'internal' present but NULLED — no
        # substantive value leaks, so the value-based TEMPORAL_DRIFT law abstains;
        # the temporal STRUCTURAL drift lead still fires on the retained branch)
        if m == "POST" and p == "/api/role/downgrade":
            return HTTPResponse(200, {"ok": True})
        if m == "GET" and p == "/api/dossier":
            row = {"summary": "case digest"}
            if actor == "C":                          # C retains a privileged branch post-downgrade
                row["internal"] = {"clearance": None, "audit": None}
            return HTTPResponse(200, row)

        # GET /api/handoff  (A receives a sensitive transfer token) + POST /api/claim
        # (B consumes that very token in its request — cross-step value migration)
        if m == "GET" and p == "/api/handoff":
            return HTTPResponse(200, {"transfer_token": "tok_AB12cd34ef56gh", "note": "ok"})
        if m == "POST" and p == "/api/claim":
            return HTTPResponse(200, {"claimed": True})

        # POST /graphql  (a single GraphQL endpoint — the family is the OPERATION,
        # the object lives in variables; the privileged field 'internal' is served
        # to A but DENIED to B with a FORBIDDEN error on the SAME order → field-BOLA)
        if m == "POST" and (p == "/graphql" or p.endswith("/graphql")):
            gbody = req.body if isinstance(req.body, dict) else {}
            variables = gbody.get("variables") or {}
            query = str(gbody.get("query") or "")
            # APQ (#2-a): a real server resolves the persisted hash to its query
            # text server-side. The mock simulates that so a HASH-ONLY request
            # behaves exactly like the full-text one.
            ext = gbody.get("extensions") or {}
            pq = ext.get("persistedQuery") or {}
            phash = str(pq.get("sha256Hash") or "")
            effective = query or self._APQ_HASHES.get(phash, "")
            oid = str(variables.get("id") or variables.get("orderId") or "")
            # ---- RL15 Residue-A (#2-a): a GraphQL APQ-ONLY `wallet` resource whose
            # `private_key` is FORBIDDEN to B; the query may arrive as a bare
            # persisted HASH (no text). The intent-declared canonical still binds. ----
            if "wallet" in effective:
                wid = str(variables.get("id") or "")
                return HTTPResponse(200, {
                    "data": {"wallet": {"id": wid}},
                    "errors": [{"message": "Not authorized to access Wallet.private_key",
                                "path": ["wallet", "private_key"],
                                "extensions": {"code": "FORBIDDEN"}}]})
            # ---- RL15 Residue-A: a GraphQL-ONLY `vault` resource. The server
            # EXPLICITLY forbids `vault.secret` for B at the field level (intent-
            # declared canonical). There is NO REST detail door for vaults, so the
            # ONLY authoritative reference is this FORBIDDEN — and a REST list later
            # over-exposes the very same field. RL15's exposed-reference path alone
            # cannot see this; the intent-declared path can. ----
            if "vault" in effective:
                vid = str(variables.get("id") or "")
                vault = {"id": vid}
                return HTTPResponse(200, {
                    "data": {"vault": vault},
                    "errors": [{"message": "Not authorized to access Vault.secret",
                                "path": ["vault", "secret"],
                                "extensions": {"code": "FORBIDDEN"}}]})
            order = {"id": oid, "status": "shipped"}
            if actor == "C":                         # allowed the privileged field
                order["internal"] = {"margin": 22.4}
                return HTTPResponse(200, {"data": {"order": order}})
            order["internal"] = None                 # denied at the field level
            return HTTPResponse(200, {
                "data": {"order": order},
                "errors": [{"message": "Not authorized to access Order.internal",
                            "path": ["order", "internal"],
                            "extensions": {"code": "FORBIDDEN"}}]})

        # GET /api/cases/{id}  (same record, but the privileged 'internal' branch is
        # served to the JUNIOR principal C and ABSENT for the senior A — a field-level
        # ACL inconsistency with no PRESENT_NULL residue; the 'missing shadow' map
        # surfaces it across principals on the SAME object)
        if m == "GET" and p.startswith("/api/cases/") and p.count("/") == 3:
            cid = p.rsplit("/", 1)[-1]
            if cid not in self.cases:
                return HTTPResponse(404, {"error": "not found"})
            row = {"id": cid, "title": f"Case {cid}", "status": "open"}
            if actor == "C":                         # junior over-exposed (the planted bug)
                row["internal"] = {"notes": "sealed case notes"}
            return HTTPResponse(200, row)

        # GET /api/session  (IDENTICAL request, but the sensitive 'internal_token'
        # field flickers in/out across repeats — authorization-conditional emission
        # that the structural-normalisation layer surfaces as an INTERMITTENT lead)
        if m == "GET" and p == "/api/session":
            self._session_reads += 1
            body = {"user": actor, "expires": 3600}
            if self._session_reads % 2 == 1:        # present on odd reads only
                body["internal_token"] = "sk_live_9f2c8a14bd77"
            return HTTPResponse(200, body)

        # GET /api/vault/{id}  (same priv/std semantics as widgets, but read ONCE
        # each in the demo — so the stability gate stays UNPROVEN and the relational
        # finding path is silent; the provisional lead path covers it instead)
        if m == "GET" and p.startswith("/api/vault/") and p.count("/") == 3:
            vid = p.rsplit("/", 1)[-1]
            v = {"200": {"owner": "A", "tier": "priv"},
                 "210": {"owner": "B", "tier": "std"}}.get(vid)
            if not v:
                return HTTPResponse(404, {"error": "not found"})
            if v["tier"] == "std":
                if actor == v["owner"]:
                    return HTTPResponse(200, self._widget_lean(vid))
                return HTTPResponse(404, {"error": "not found"})
            return HTTPResponse(200, self._widget_priv(vid, populated=(actor == v["owner"])))

        # GET /api/admin/billing  (correctly DENIES non-admins with 403, but the
        # denial body discloses the exact gate — an AUTHZ_ORACLE recon lead)
        if m == "GET" and p == "/api/admin/billing":
            if actor == "A":                       # suppose A is an admin
                return HTTPResponse(200, {"invoices": [{"id": "inv1", "amount": 1200}]})
            return HTTPResponse(403, {"error": "forbidden", "required_role": "admin",
                                      "your_role": "user",
                                      "missing_scopes": ["billing:read"]})

        # ================= RL15 CROSS-SURFACE SURFACE ===================== #
        # PLANTED cross-surface bug on the `accounts` resource:
        #   * canonical detail GET /api/accounts/{id}  CORRECTLY filters `iban`
        #     (PCI: the full IBAN is never returned by the detail serializer, even
        #     to the owner) — this is the server's AUTHORITATIVE answer.
        #   * list view   GET /api/accounts            ACCIDENTALLY includes a
        #     populated `iban` in each row (the list serializer, written by another
        #     team, forgot the field-level filter). Same principal, same resource,
        #     a sensitive field one door withholds and another leaks.
        # `tx_count` is a NON-sensitive divergence (present in list, absent in
        # detail) — it MUST be ignored (sensitive-only guard).
        if m == "GET" and p == "/api/accounts" and p.count("/") == 2:
            # B's own account 900 — list row over-projects `iban`
            return HTTPResponse(200, {"accounts": [
                {"id": "900", "balance_label": "Gold", "country": "IQ",
                 "iban": "IQ98NBIQ1234567890", "tx_count": 12},
            ]})
        if m == "GET" and p.startswith("/api/accounts/") and p.count("/") == 3:
            aid = p.rsplit("/", 1)[-1]
            if aid != "900":
                return HTTPResponse(404, {"error": "not found"})
            # canonical detail — `iban` correctly filtered (authoritative view)
            return HTTPResponse(200, {"id": "900", "balance_label": "Gold",
                                      "country": "IQ"})

        # ================= RL17 COMBINATORIAL ORCHESTRATION ================= #
        # A `payouts` LIST over-projects `iban` for FOUR siblings (600..603). The
        # canonical detail filters `iban` for 600/601/602 (vulnerable) but the
        # payout 603 is a PUBLIC payout whose detail legitimately exposes `iban`
        # (so the rule, applied to 603, must be REFUTED per-cell → no false positive).
        # Only 600 is read canonically in the baseline; the engine must orchestrate
        # the discovery of 601 & 602 from that single proof, and clear 603.
        if m == "GET" and p == "/api/payouts" and p.count("/") == 2:
            return HTTPResponse(200, {"payouts": [
                {"id": "600", "status": "paid", "iban": "IQ11AAA600"},
                {"id": "601", "status": "paid", "iban": "IQ11AAA601"},
                {"id": "602", "status": "paid", "iban": "IQ11AAA602"},
                {"id": "603", "status": "paid", "iban": "IQ11AAA603"},  # public payout
            ]})
        if m == "GET" and p.startswith("/api/payouts/") and p.count("/") == 3:
            pid_obj = p.rsplit("/", 1)[-1]
            if pid_obj == "603":
                # PUBLIC payout — detail legitimately exposes `iban` ⇒ rule refuted here
                return HTTPResponse(200, {"id": "603", "status": "paid",
                                          "iban": "IQ11AAA603"})
            if pid_obj in ("600", "601", "602"):
                return HTTPResponse(200, {"id": pid_obj, "status": "paid"})  # iban filtered
            return HTTPResponse(404, {"error": "not found"})

        # ================= RL18 GLOBAL INVARIANT (emergent break) ================= #
        # A folder/doc hierarchy. Folder F1 starts owned by A; after a TRANSFER it
        # belongs to B, so A loses access to F1 — but the doc D1 inside it never
        # followed the parent and stays readable by A. No single operation broke a
        # rule; the SEQUENCE (own → transfer → still-read-child) broke the global
        # invariant "a child's authority follows its parent's".
        if m == "POST" and p.startswith("/api/folders/") and p.endswith("/transfer"):
            fid = p.split("/")[3].lower()
            self._transferred.add(fid)               # ownership moves to B
            return HTTPResponse(200, {"id": fid, "owner": "B"})
        if m == "GET" and p.startswith("/api/folders/") and p.count("/") == 3:
            fid = p.rsplit("/", 1)[-1].lower()
            if fid in self._transferred and actor != "B":
                return HTTPResponse(403, {"error": "forbidden", "owner": "B"})
            return HTTPResponse(200, {"id": fid, "owner": actor})
        if m == "GET" and p.startswith("/api/docs/") and p.count("/") == 3:
            did = p.rsplit("/", 1)[-1].lower()
            if did == "d1":                          # child of f1, NO independent grant → break
                return HTTPResponse(200, {"id": "d1", "parent": "f1", "title": "Q3 plan"})
            if did == "d2":                          # child of f2 (never transferred) → no break
                return HTTPResponse(200, {"id": "d2", "parent": "f2", "title": "notes"})
            if did == "d3":                          # child of f1 but INDEPENDENTLY shared with D
                return HTTPResponse(200, {"id": "d3", "parent": "f1", "title": "shared",
                                          "shared_with": ["D"]})
            return HTTPResponse(404, {"error": "not found"})

        # BENIGN DECOY — directional: the DETAIL view is richer than the LIST view
        # (summary vs full), which is by-design and MUST NOT fire. `cards` list
        # exposes only {id,last4}; the canonical detail additionally exposes the
        # sensitive `full_pan`. Since the NON-canonical door exposes nothing the
        # canonical door hides, the cross-surface law stays silent.
        if m == "GET" and p == "/api/cards" and p.count("/") == 2:
            return HTTPResponse(200, {"cards": [{"id": "c1", "last4": "4242"}]})
        if m == "GET" and p.startswith("/api/cards/") and p.count("/") == 3:
            cid = p.rsplit("/", 1)[-1]
            return HTTPResponse(200, {"id": cid, "last4": "4242",
                                      "full_pan": "4242424242424242"})

        # RL15 Residue-A POSITIVE: the `vaults` LIST over-projects `secret` for B's
        # own vault 500 — the exact field the GraphQL layer declares FORBIDDEN to B.
        # There is deliberately NO `GET /api/vaults/{id}` detail door, so only the
        # intent-declared (GraphQL FORBIDDEN) reference can catch this leak.
        if m == "GET" and p == "/api/vaults" and p.count("/") == 2:
            return HTTPResponse(200, {"vaults": [
                {"id": "500", "label": "primary", "secret": "sk_live_abc123xyz789"},
            ]})

        # RL15 Residue-A (#2-a) POSITIVE: the `wallets` LIST over-projects
        # `private_key` for wallet 700 — the field GraphQL forbids to B, where the
        # denial was learned from a HASH-ONLY (persisted) request.
        if m == "GET" and p == "/api/wallets" and p.count("/") == 2:
            return HTTPResponse(200, {"wallets": [
                {"id": "700", "label": "cold", "private_key": "0xDEADBEEFcafe1234"},
            ]})

        # ================= RL16 TEMPORAL AUTHORIZATION DRIFT ================= #
        # POSITIVE: a profile whose detail view correctly NULLS `ssn` at first, but
        # a later read (simulating a deploy that regressed the field filter) serves
        # it POPULATED — to the SAME principal, with no role change. `nickname` also
        # goes null→populated but is NON-sensitive and MUST be ignored.
        if m == "GET" and p.startswith("/api/profile2/") and p.count("/") == 3:
            self._authreg_reads[p] = self._authreg_reads.get(p, 0) + 1
            leaked = self._authreg_reads[p] >= 2          # deploy regression after T1
            return HTTPResponse(200, {
                "id": p.rsplit("/", 1)[-1], "holder": "self",
                "ssn": ("123-45-6789" if leaked else None),
                "nickname": ("bobby" if leaked else None)})

        # NEGATIVE (role-change decoy): `clearance.secret` becomes populated ONLY
        # after a LEGITIMATE promotion. Because a declared role-change event fires,
        # the principal's epoch advances and the temporal law must NOT compare across
        # it — a promotion is not a regression.
        if m == "POST" and p == "/api/promote":
            self._promoted[actor] = True
            return HTTPResponse(200, {"promoted": actor})
        if m == "GET" and p.startswith("/api/clearance/") and p.count("/") == 3:
            promoted = self._promoted.get(actor, False)
            return HTTPResponse(200, {
                "id": p.rsplit("/", 1)[-1], "level": "L2",
                "secret": ("topsecret-xyz" if promoted else None)})

        return HTTPResponse(404, {"error": "no route"})


# --------------------------------------------------------------------------- #
# HTTPTarget — real engagement adapter (kept minimal & dependency-light)       #
# --------------------------------------------------------------------------- #

_CHALLENGE_MARKERS = (
    "just a moment", "checking your browser", "cf-challenge", "cf_chl_",
    "_cf_chl_opt", "attention required", "cloudflare", "access denied",
    "pardon our interruption", "incapsula", "_incapsula_", "imperva",
    "request unsuccessful", "distil", "px-captcha", "perimeterx", "hcaptcha",
    "recaptcha", "are you a robot", "verify you are human", "akamai", "reference #",
)
_CHALLENGE_HEADERS = ("cf-mitigated", "cf-chl-bypass", "x-iinfo", "x-cdn",
                      "x-datadome", "x-px", "server-timing")

def detect_auth_expiry(status: int, body) -> bool:
    """True when a response signals EXPIRED/INVALID credentials (not a normal deny).
    Used only on read-backs of a principal that SHOULD succeed (owner/control); a
    stale short-lived JWT/session there must make the confirmer ABSTAIN with a clear
    note, never be mistaken for 'no vulnerability' (obstacle 4b, RL5)."""
    if status not in (401, 419, 440):           # 419/440 = session expired (some stacks)
        return False
    if status in (419, 440):
        return True                              # these codes mean session expiry outright
    text = ""
    if isinstance(body, str):
        text = body.lower()
    elif isinstance(body, dict):
        text = " ".join(str(v) for v in body.values()).lower()
    # a BARE 401 is ambiguous (could be a normal deny) -> only call it expiry when an
    # explicit expiry marker is present, so the abstain NOTE is never misleading (#6).
    markers = ("expired", "token expired", "jwt expired", "session expired",
               "invalid token", "tokenexpired", "re-authenticate",
               "must re-login", "token is no longer valid")
    return any(m in text for m in markers)


def detect_block(status: int, body, headers: dict | None = None):
    """Return a short reason string if a response looks like a WAF block / bot
    challenge / decoy, else None. CORRECTNESS guard (obstacle 2/6): a challenged
    read-back must NEVER be compared as if it were a real owner view — doing so
    corrupts the Δstate verdict. On a hit the confirmer ABSTAINS (RL5)."""
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    # explicit bot-defense status codes are suspicious when paired with markers
    suspicious_status = status in (401, 403, 405, 406, 409, 429, 503)
    # header signals
    if "cf-mitigated" in h and "challenge" in h.get("cf-mitigated", ""):
        return "cloudflare challenge (cf-mitigated header)"
    # body signals (text bodies; an API returning HTML is itself a red flag)
    text = ""
    if isinstance(body, str):
        text = body.lower()
    elif isinstance(body, dict):
        raw = body.get("_raw")
        if isinstance(raw, str):
            text = raw.lower()
    if text:
        for m in _CHALLENGE_MARKERS:
            if m in text:
                return f"bot-defense challenge marker: {m!r}"
        if suspicious_status and ("<html" in text or "<!doctype" in text):
            return f"HTML body on status {status} (likely WAF interstitial)"
    return None


class _RateGovernor:
    """Serialises live requests to at most one per `min_interval` seconds (plus
    optional jitter). Deterministic, per-target, transport-only — it changes
    *when* a request is sent, never *what* is sent or how it is judged. This
    respects program rate limits and removes the burst signature that reputation
    engines flag, without any evasion."""
    def __init__(self, min_interval: float = 0.0, jitter: float = 0.0, seed: int = 1337):
        import random
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self.jitter = max(0.0, float(jitter or 0.0))
        self._rng = random.Random(seed)      # SEEDED -> jitter is reproducible (determinism)
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0 and self.jitter <= 0:
            return
        import time
        now = time.monotonic()
        gap = now - self._last
        target = self.min_interval + (self._rng.uniform(0, self.jitter) if self.jitter else 0.0)
        if gap < target:
            time.sleep(target - gap)
        self._last = time.monotonic()


# GLOBAL registry: all targets sharing an egress share ONE governor, so the rate
# cap holds across multiple HTTPTarget instances (a per-instance clock would let
# the combined rate exceed the cap — adversarial attack #4).
_GOVERNORS: dict = {}

def _get_governor(egress_key: str, interval: float, jitter: float, seed: int) -> "_RateGovernor":
    g = _GOVERNORS.get(egress_key)
    if g is None or g.min_interval != interval or g.jitter != jitter:
        g = _RateGovernor(interval, jitter, seed)
        _GOVERNORS[egress_key] = g
    return g


_TRANSPORT_MANAGED = {"host", "content-length", "connection", "transfer-encoding",
                      "content-encoding", "accept-encoding", "keep-alive", "te",
                      "upgrade", "proxy-authorization"}

def _coherent_headers(profile: dict, req_headers: dict, auth: dict) -> dict:
    """Merge a real captured browser profile with request + secret headers into
    one self-consistent set, dropping headers the HTTP client must own. This makes
    a replayed request indistinguishable (at the header layer) from the browser
    that produced the capture — instead of a bare token with no coherence. Purely
    additive: with no profile it degrades to the previous {req, auth} behaviour."""
    merged = {}
    for src in (profile or {}, req_headers or {}, auth or {}):
        for k, v in src.items():
            if k and k.lower() not in _TRANSPORT_MANAGED:
                merged[k] = v
    return merged


def _extract_field(body, path: str):
    """Read a value from a JSON-ish body by a simple dotted path (e.g. 'data.csrf')."""
    cur = body
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur if not isinstance(cur, (dict, list)) else None


class SessionRefresher:
    """OBSTACLE-4a: declarative session-token freshness. A recipe declares, for a
    set of (write) requests, how to obtain a FRESH token from a GET source and
    where to inject it. Replay then carries a live token instead of a stale captured
    one. Purely a plumbing fix: the VERDICT depends on the Δstate outcome, never on
    the token bytes, so determinism of the verdict is preserved. Recipes are EXPLICIT
    (never auto-applied); the source is GET-only so a refresh can never recurse."""
    def __init__(self, recipes: list | None = None):
        self.recipes = []
        for r in (recipes or []):
            src = r.get("source", {})
            if (src.get("method", "GET").upper() != "GET"):
                continue            # safety: source MUST be idempotent (no recursion / no writes)
            self.recipes.append(r)

    def recipe_for(self, principal_pid: str, method: str, endpoint_key: str):
        for r in self.recipes:
            if r.get("principal") not in (None, principal_pid):
                continue
            when = r.get("when", "*")
            if when == "*" or when == endpoint_key or when.split()[-1] == endpoint_key.split()[-1]:
                if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                    return r
        return None


_TRANSPORT_MANAGED2 = None  # (placeholder to keep diff anchors stable)



# ===================================================================== #
# OBSTACLE 6 — pluggable transport backends (TLS / HTTP-2 realism)       #
# ===================================================================== #
# The DEFAULT backend is `requests` (unchanged, zero new dependency, the same
# catalogued fingerprint as before — honest). An OPT-IN impersonation backend uses
# curl_cffi to present a real Chrome JA3/JA4 + HTTP/2 fingerprint so requests reach
# the application on TLS-fingerprinting targets (Akamai/Cloudflare/DataDome). Both
# backends normalise every response to the SAME (status, body, headers) triple, so
# the engine's inputs are shape-identical and the verdict stays deterministic.
#
# HONEST BOUNDARY: impersonation fixes the TLS/HTTP-2 fingerprint + header order
# ONLY. It does NOT solve JS challenges (canvas/WebGL/Turnstile), behavioural
# signals, or IP reputation. On those layers the obstacle-2 block detector makes
# the engine ABSTAIN rather than mis-judge — never a faked "success".

def _normalise_body(text: str, json_getter):
    try:
        return json_getter()
    except Exception:
        return {"_raw": (text or "")[:4096]}


class _RequestsBackend:
    """Default backend. Same behaviour ONYX always had. No new dependency."""
    name = "requests"

    def __init__(self):
        try:
            import requests  # noqa: F401
        except ImportError as e:
            raise RuntimeError("HTTPTarget needs `requests` (pip install requests)") from e

    def dispatch(self, method, url, params=None, json_body=None, headers=None,
                 verify=True, timeout=10.0, proxies=None):
        import requests
        resp = requests.request(method, url, params=params, json=json_body,
                                headers=headers, verify=verify, timeout=timeout,
                                proxies=proxies)
        body = _normalise_body(getattr(resp, "text", ""), resp.json)
        return resp.status_code, body, dict(resp.headers)


# curl_cffi profile catalogue (major browser version -> impersonation target).
_IMPERSONATE_PROFILES = (
    "chrome131", "chrome124", "chrome120", "chrome116", "chrome110",
    "edge101", "edge99", "safari17_0", "safari16_5", "firefox133",
)

def impersonate_profile_from_ua(ua: str) -> str:
    """Resolve a curl_cffi impersonation profile from a captured User-Agent so the
    TLS fingerprint AGREES with the UA and headers (no cross-layer drift, RISK 4).
    Falls back to a recent Chrome if the UA is unrecognised."""
    if not ua:
        return "chrome124"
    u = ua.lower()
    import re
    def ver(pat):
        m = re.search(pat, u)
        return int(m.group(1)) if m else 0
    if "edg/" in u or "edge" in u:
        return "edge101"
    if "firefox" in u:
        return "firefox133"
    if "safari" in u and "chrome" not in u and "chromium" not in u:
        return "safari17_0" if ver(r"version/(\d+)") >= 17 else "safari16_5"
    if "chrome" in u or "chromium" in u:
        v = ver(r"chrom(?:e|ium)/(\d+)")
        for prof in ("chrome131", "chrome124", "chrome120", "chrome116", "chrome110"):
            if v >= int(prof.replace("chrome", "")):
                return prof
        return "chrome110"
    return "chrome124"


class _ImpersonateBackend:
    """Opt-in curl_cffi backend: a real browser TLS/HTTP-2 fingerprint. Lazily
    imported; a persistent Session keeps the HTTP-2 fingerprint stable across the
    run (no mid-session drift). If curl_cffi is absent we RAISE — never silently
    fall back to the catalogued `requests` fingerprint (that would be a silent
    failure: the user believes they are impersonating while getting blocked)."""
    def __init__(self, profile: str):
        self.name = f"impersonate:{profile}"
        self.profile = profile
        try:
            from curl_cffi import requests as creq      # lazy, optional
        except ImportError as e:
            raise RuntimeError(
                "tls_impersonate was requested but `curl_cffi` is not installed. "
                "Install it (pip install curl_cffi) or unset tls_impersonate. "
                "Refusing to silently fall back to a catalogued fingerprint that "
                "would be blocked — that would hide real findings.") from e
        self._creq = creq
        self._session = creq.Session()                  # reused -> stable HTTP/2 fp

    def dispatch(self, method, url, params=None, json_body=None, headers=None,
                 verify=True, timeout=10.0, proxies=None):
        kwargs = dict(params=params, headers=headers, timeout=timeout,
                      impersonate=self.profile, verify=verify)
        if json_body is not None:
            kwargs["json"] = json_body
        if proxies:
            kwargs["proxies"] = proxies
        resp = self._session.request(method, url, **kwargs)
        body = _normalise_body(getattr(resp, "text", ""), resp.json)
        return resp.status_code, body, dict(resp.headers)


def _profile_family(p: str) -> str:
    for fam in ("chrome", "edge", "safari", "firefox"):
        if p.startswith(fam):
            return fam
    return p

def make_backend(tls_impersonate: str, ua_hint: str = ""):
    """Select a backend. '' -> requests (default). 'auto' -> impersonate a profile
    derived from the captured UA. An explicit 'chromeNNN' -> that profile.
    Warns (never silently) when an EXPLICIT profile contradicts the captured UA
    family — a Chrome-JA4 with a Firefox-UA is itself a cross-layer tell (RISK 4)."""
    sel = (tls_impersonate or "").strip()
    if not sel:
        return _RequestsBackend()
    if sel == "auto":
        profile = impersonate_profile_from_ua(ua_hint)
    else:
        profile = sel
        if ua_hint:
            ua_fam = _profile_family(impersonate_profile_from_ua(ua_hint))
            if _profile_family(profile) != ua_fam:
                import warnings
                warnings.warn(
                    f"tls_impersonate={profile!r} contradicts the captured "
                    f"User-Agent family ({ua_fam}); a mismatched TLS/UA pair is a "
                    f"cross-layer fingerprint tell. Use 'auto' to stay coherent.",
                    stacklevel=2)
    return _ImpersonateBackend(profile)


class HTTPTarget:
    """Real adapter. Uses `requests` if available; never fabricates credentials —
    the principal's `auth` headers are supplied by the tester (D6)."""

    def __init__(self, base_url: str, verify_tls: bool = True, timeout: float = 10.0,
                 scope=None):
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        # OBSTACLE-2: a SINGLE governor + ONE shared egress for ALL principals
        # (the IP-stability invariant — every identity leaves from the same origin).
        self.scope = scope
        proxy = getattr(scope, "proxy", "") or ""
        # GLOBAL governor keyed by egress (proxy + host) so the rate cap is honoured
        # even across multiple targets to the same origin (attack #4).
        egress_key = f"{proxy}|{self.base_url}"
        self._gov = _get_governor(egress_key,
                                  getattr(scope, "min_request_interval", 0.0),
                                  getattr(scope, "request_jitter", 0.0),
                                  getattr(scope, "governor_seed", 1337))
        self._attribution = self._build_attribution(scope)
        self._ua_suffix = (getattr(scope, "researcher_id", "")
                           if getattr(scope, "attribution_in_ua", False) else "")
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._refresher = SessionRefresher(getattr(scope, "session_refresh", None))
        # OBSTACLE-6: select the transport backend (default = requests; opt-in
        # curl_cffi impersonation). ua_hint lets "auto" cohere TLS with the UA.
        self._backend = make_backend(getattr(scope, "tls_impersonate", ""),
                                     getattr(scope, "tls_ua_hint", ""))

    @staticmethod
    def _build_attribution(scope) -> dict:
        if not scope:
            return {}
        out = dict(getattr(scope, "extra_attribution", {}) or {})
        rid = getattr(scope, "researcher_id", "") or ""
        if rid:
            out[getattr(scope, "attribution_header", "X-Bug-Bounty") or "X-Bug-Bounty"] = rid
        return out

    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse:  # pragma: no cover
        # OBSTACLE-4a: if a declarative recipe matches this WRITE, fetch a fresh
        # token from its GET source and inject it, so the replay is not rejected for
        # a stale CSRF/nonce. The token value is plumbing, never part of the verdict.
        req = self._apply_session_refresh(req, principal)
        # OBSTACLE-1 FIX: assemble a COHERENT browser header set.
        #   profile_headers (real captured UA/Accept/Sec-* ...) form the base,
        #   the per-request headers refine it, and the SECRET auth headers win last.
        # Then strip transport-managed headers so the client sets them correctly
        # (a stale Content-Length / Host / Accept-Encoding would itself be a tell).
        headers = _coherent_headers(getattr(principal, "profile_headers", {}),
                                    req.headers, principal.auth)
        # OBSTACLE-2: declare the researcher (authorised attribution, not evasion).
        for k, v in self._attribution.items():
            headers[k] = v
        if self._ua_suffix:
            base_ua = headers.get("User-Agent", "")
            headers["User-Agent"] = (base_ua + " " if base_ua else "") + f"({self._ua_suffix})"
        url = self.base_url + req.path
        self._gov.wait()                       # respect rate limits; kill the burst tell
        # OBSTACLE-6: dispatch through the selected transport BACKEND. The default
        # backend is `requests` (unchanged); an opt-in impersonation backend gives a
        # real Chrome JA3/JA4 + HTTP/2 fingerprint so requests reach the application
        # on TLS-fingerprinting targets. Both backends normalise to one HTTPResponse.
        status, body, resp_headers = self._backend.dispatch(
            req.method, url, params=req.query, json_body=req.body,
            headers=headers, verify=self.verify_tls, timeout=self.timeout,
            proxies=self._proxies)
        return HTTPResponse(status, body, resp_headers)

    def _apply_session_refresh(self, req, principal):
        try:
            ek = f"{req.method.upper()} {req.path}"
            recipe = self._refresher.recipe_for(getattr(principal, "pid", ""),
                                                req.method, ek)
            if not recipe:
                return req
            src = recipe["source"]
            # source is GET-only (enforced by SessionRefresher) -> cannot recurse.
            sresp = self.send(HTTPRequest("GET", src["path"],
                                          query=src.get("query", {}), host=req.host),
                              principal)
            if sresp is None or not (200 <= sresp.status < 300):
                return req            # could not refresh -> send as-is (will likely fail; honest)
            token = _extract_field(sresp.body, recipe.get("extract", ""))
            if token is None:
                return req
            inj = recipe.get("inject", {})
            new_headers = dict(req.headers or {})
            new_body = req.body
            if "header" in inj:
                new_headers[inj["header"]] = str(token)
            elif "cookie" in inj:
                ck = new_headers.get("Cookie", "")
                new_headers["Cookie"] = (ck + "; " if ck else "") + f"{inj['cookie']}={token}"
            elif "body" in inj and isinstance(new_body, dict):
                new_body = dict(new_body); new_body[inj["body"]] = token
            return HTTPRequest(req.method, req.path, query=req.query,
                               headers=new_headers, body=new_body, host=req.host)
        except Exception:
            return req                # refresh is best-effort; never breaks a send

    def warmup(self, principal: Principal, paths: list) -> int:
        """OBSTACLE-3: send a few of THIS principal's own benign GETs as session
        context before a probe, so the probe is not a cold isolated hit. PURELY
        traffic-shaping — responses are DISCARDED and NOTHING here touches the
        engine, so it can never change a verdict (verdict-neutral by construction).
        Governed by the same rate limiter; aborts on the first WAF challenge."""
        sent = 0
        for p in paths:
            try:
                resp = self.send(HTTPRequest("GET", p, host=getattr(self, "host", "")
                                             or principal.__dict__.get("host", "")), principal)
            except Exception:
                break
            sent += 1
            # if warm-up itself is blocked/challenged, stop — the probe matters more.
            if resp is not None and detect_block(resp.status, resp.body,
                                                 getattr(resp, "headers", {})):
                break
        return sent


def make_exchange(target: Target, req: HTTPRequest, principal: Principal,
                  session_id: str = "s0") -> Exchange:
    """Send a request through a target and wrap as an Exchange."""
    req.host = req.host or getattr(target, "host", "")
    resp = target.send(req, principal)
    return Exchange(request=req, response=resp, principal=principal, session_id=session_id)


class ReplayTarget:
    """A passive, offline target built from CAPTURED traffic (e.g. a HAR export).

    It serves the recorded response for a (principal, method, normalised-path)
    that was actually observed in the capture, and ONLY that. When the confirmer
    asks for a read-back that was never captured, it returns a sentinel non-2xx
    so confirmation fails safe (the candidate stays unconfirmed → a lead, never a
    fabricated finding). No network, no replay of live credentials, fully
    deterministic — the right substrate for analysing a capture with zero live
    access."""

    NOT_CAPTURED = 599

    def __init__(self, exchanges) -> None:
        # FIX #2: key by FULL object identity (pid, method, path, sorted object-ids)
        # so a read-back can never return a DIFFERENT object that merely shares the
        # normalised endpoint. The old (pid,method,endpoint_key) collapsed every
        # /orders/{id} of a principal to one body (last-write-wins) and an
        # any-principal _by_endpoint fallback fabricated cross-object "leaks".
        self._by_key: dict[tuple, HTTPResponse] = {}
        for ex in exchanges:
            self._by_key[self._key(ex.principal.pid, ex.request)] = ex.response

    @staticmethod
    def _key(pid, req):
        try:
            oids = ",".join(sorted(str(o) for o in req.object_ids()))
        except Exception:
            oids = ""
        return (pid, req.method, req.path, oids)

    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse:
        hit = self._by_key.get(self._key(principal.pid, req))
        if hit is not None:
            return hit
        # No captured read-back for THIS exact (principal, object). Fail safe to
        # inaction (RL5): the confirmer will get a non-2xx and abstain -> lead,
        # never a fabricated finding. No any-principal fallback (that was the bug).
        return HTTPResponse(self.NOT_CAPTURED, {"error": "not captured in this trace"})
