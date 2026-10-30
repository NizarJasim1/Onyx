"""
⑥ Multi-Principal Differential Confirmer — §4.5 / §7.1 / RL3 / D3.

This is the precision engine, and precision is the economic engine. A CANDIDATE
becomes a CONFIRMED FINDING ONLY when an authenticated read-back proves the
security-critical property actually CHANGED or LEAKED.

We NEVER promote on a status-code or length difference. "B got a 200" is noise.
"B read A's private object and a read-back as A proves it is the same object", or
"the order is marked paid with amount_paid < amount_due, proven by reading the
order state back" — that is a finding.

Each strategy issues REAL requests through the Target (so the proof is genuine),
behind Scope-Guard's mutation gate (RL5): in dry-run we confirm leaks via reads
and suppress irreversible mutations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import (
    Candidate,
    EffectClass,
    HTTPRequest,
    Principal,
    ScopeVerdict,
    StateProof,
)
from .scope_guard import ScopeGuard
from .transport import Target


class Confirmer:
    def __init__(self, target: Target, principals: dict[str, Principal],
                 scope_guard: ScopeGuard, coherence=None, stability_gate=None,
                 ledger=None):
        self.target = target
        self.principals = principals          # pid -> Principal (A, B, anon, owner…)
        self.scope = scope_guard
        # Strengthening flag (default OFF -> byte-identical). When the engine
        # enables it, the leak audit requires DISCRIMINATING values, killing
        # the shared-default false positive. Real runs turn it on.
        self.strict_leak = False
        # RL24 read-back stability voting (default 1 = single send = byte-identical).
        self.stability_k = 1
        # G13: when stability voting (k>1), optionally project OUT well-known volatile
        # scaffolding fields (timestamps, trace ids, etags…) before computing the
        # quorum key, so noise that carries no security meaning cannot break the vote
        # and cost recall. Default OFF ⇒ byte-identical; security fields are never
        # stripped and the ≥80% quorum threshold is unchanged.
        self.stability_strip_volatile = False
        # SAIE refs (optional): present only when the engine wires structural
        # detection. Used solely by _confirm_structural_divergence (Gates 2+3).
        self.coherence = coherence
        self.stability_gate = stability_gate
        # RL6 (economy): the budget authority every network read draws from. When
        # None, an UNBOUNDED ledger is used → _read behaves byte-identically to the
        # pre-economy code (no acquire ever denies, no reputation effect).
        if ledger is None:
            from .economy import BudgetLedger
            ledger = BudgetLedger.unbounded()
        self.ledger = ledger
        # RL10 (read consistency): re-read window for distributed/eventually-
        # consistent targets. Default 1 ⇒ single-shot ⇒ byte-identical to before.
        self.consistency_reads = 1
        self.consistency_quorum = 2
        self._unstable: list = []

    def confirm(self, cand: Candidate) -> Optional[StateProof]:
        """RL10 read-consistency wrapper. With the default consistency_reads=1 this
        is a single confirmation pass — byte-identical to the pre-RL10 behaviour.
        With consistency_reads=N>1 (set for a distributed/eventually-consistent
        target) it re-runs the confirmation until the VERDICT is STABLE — the last
        `consistency_quorum` passes agree — and acts only on that converged verdict.
        This fixes the self-inflicted AHP-3 regression (a stale replica read could
        REFUTE a real leak) WITHOUT weakening precision (a transient leak that does
        not survive re-reads is never confirmed). Mid-convergence flicker ⇒ abstain
        + an honest instability lead (RL5). Re-reads draw from the RL6 budget, so
        the window is bounded; budget exhaustion simply ends the window early."""
        reads = max(1, int(getattr(self, "consistency_reads", 1)))
        if reads == 1:
            return self._confirm_once(cand)
        quorum = max(2, int(getattr(self, "consistency_quorum", 2)))
        run = 0
        streak = 0
        last_confirmed = None
        last_proof = None
        while run < reads:
            run += 1
            proof = self._confirm_once(cand)
            confirmed = bool(proof and proof.confirmed)
            if confirmed == last_confirmed:
                streak += 1
            else:
                streak = 1
                last_confirmed = confirmed
            last_proof = proof
            if streak >= quorum:
                # converged: act on the stable verdict
                return last_proof if confirmed else None
        # never converged within the window → unstable → fail safe (abstain) and
        # surface the instability so it is investigated, never silently dropped.
        self._unstable.append({
            "endpoint": cand.exchange.request.endpoint_key(),
            "principal": cand.exchange.principal.pid,
            "effect": getattr(cand.verdict, "effect", None) and cand.verdict.effect.value,
            "reason": "read-back did not stabilise within the consistency window",
        })
        return None

    def _confirm_once(self, cand: Candidate) -> Optional[StateProof]:
        """Dispatch to the per-effect Δstate strategy. Returns a proof or None.
        Routing uses the LAW's effect (verdict.effect), which is more precise than
        the request's classification — e.g. a cross-cutting TEMPORAL_DRIFT verdict
        rides on a request whose classification might be OBJECT_ACCESS."""
        effect = getattr(cand.verdict, "effect", None) or cand.classification.effect
        # RL19: a conservation read-leak is confirmed by a cross-principal VALUE-
        # PRESENCE differential (works for feeds/search/aggregations, where the
        # whole-body owner audit does not), so it is routed before the per-effect map.
        if (cand.verdict.evidence or {}).get("conservation_axis"):
            return self._confirm_conservation(cand)
        strategy = {
            EffectClass.OBJECT_ACCESS: self._confirm_object_access,
            EffectClass.OWNERSHIP: self._confirm_ownership,
            EffectClass.AUTHORITY: self._confirm_authority,
            EffectClass.AUTHORITY_GRANT: self._confirm_authority_grant,
            EffectClass.PAYMENT: self._confirm_payment,
            EffectClass.PRICE: self._confirm_price,
            EffectClass.STATE_GATE: self._confirm_state_gate,
            EffectClass.INVENTORY: self._confirm_inventory,
            EffectClass.COUPON: self._confirm_coupon,
            EffectClass.TEMPORAL_DRIFT: self._confirm_temporal_drift,
            EffectClass.STRUCTURAL_DIVERGENCE: self._confirm_structural_divergence,
            EffectClass.FIELD_PROJECTION: self._confirm_field_projection,
            EffectClass.CROSS_SURFACE: self._confirm_cross_surface,
            EffectClass.AUTH_REGRESSION: self._confirm_auth_regression,
            EffectClass.EMERGENT_BREAK: self._confirm_global_invariant,
        }.get(effect)
        if not strategy:
            return None
        return strategy(cand)

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _derive_object_ref(cand) -> str:
        """Best-effort object reference from the request, shape-agnostic (R2 fix):
        any id-bearing path segment, then any id-like body field, else ''."""
        req = cand.exchange.request
        try:
            oids = req.object_ids()
            if oids:
                return str(oids[0])
        except Exception:
            pass
        body = req.body or {}
        if isinstance(body, dict):
            for k, v in body.items():
                kl = str(k).lower()
                if (kl == "id" or kl.endswith("_id") or kl in ("ref", "order_id", "order_ref")) \
                        and isinstance(v, (str, int)):
                    return str(v)
        return ""

    @staticmethod
    def _resource_path(cand, ref: str) -> str:
        """Derive a canonical GET path for the object. If the request path already
        ends in the ref (a REST resource), reuse it; else fall back to the request
        path's parent + ref. Never hard-codes /api/orders (R2 fix)."""
        p = cand.exchange.request.path.rstrip("/")
        if p.endswith("/" + ref):
            return p
        # POST .../checkout  -> read back the same resource collection + ref when sane
        base = p.rsplit("/", 1)[0] if "/" in p else p
        return f"{base}/{ref}" if ref else p

    def _owner_of(self, cand: Candidate) -> Optional[Principal]:
        """The principal a laundered value provably belongs to — we read back as them."""
        origin = cand.causal_origin or cand.verdict.evidence.get("laundered_from")
        if origin is not None:
            return self.principals.get(origin.principal_id)
        return None

    @property
    def _abstain_notes(self):
        if not hasattr(self, "__abstain_notes"):
            self.__abstain_notes = []
        return self.__abstain_notes

    # G13: universally-volatile SCAFFOLDING field names — safe to ignore in the
    # stability vote because they carry no security meaning and change every read.
    # NEVER includes security-relevant names (id/owner/role/amount/email/tenant/…).
    _VOLATILE_FIELDS = frozenset({
        "created_at", "updated_at", "modified_at", "timestamp", "ts", "time",
        "datetime", "last_seen", "last_login", "last_modified", "etag", "_etag",
        "request_id", "requestid", "x_request_id", "trace_id", "traceid",
        "correlation_id", "nonce", "_cb", "server_time", "servertime",
        "refreshed_at", "cache_ts", "iat", "exp", "seq", "sequence",
        "rate_limit_remaining", "x_ratelimit_remaining", "response_time_ms",
        "latency_ms", "generated_at", "fetched_at",
    })

    @staticmethod
    def _strip_volatile(obj):
        """Return a copy of `obj` with only well-known volatile scaffolding fields
        removed (recursively). Conservative: security-relevant fields are never
        touched — the vote still fully covers everything that could be a finding."""
        if isinstance(obj, dict):
            return {k: Confirmer._strip_volatile(v) for k, v in obj.items()
                    if str(k).strip().lower() not in Confirmer._VOLATILE_FIELDS}
        if isinstance(obj, list):
            return [Confirmer._strip_volatile(v) for v in obj]
        return obj

    def _quorum_key(self, r):
        """The (status, body) key a read-back contributes to the stability vote.
        Status is ALWAYS part of the key (a status flip is never masked). Under G13
        (`stability_strip_volatile`), volatile scaffolding is projected out first so
        transport noise cannot break an otherwise-stable security verdict. If
        stripping would empty a non-empty body, fall back to the full body (S-5)."""
        import json
        body = getattr(r, "body", None)
        if getattr(self, "stability_strip_volatile", False):
            stripped = self._strip_volatile(body)
            if body and not stripped:      # S-5: never vote on nothing
                stripped = body
            body = stripped
        try:
            return (r.status, json.dumps(body, sort_keys=True, default=str))
        except Exception:
            return (r.status, str(body))

    def _stable_send(self, req: HTTPRequest, principal: Principal):
        """RL24 (default OFF -> byte-identical). Under production chaos a single
        read-back is unreliable: a stale replica, a shared-cache bleed, or a 202/async
        gap can hand back a body that is not the true current state. A REAL leak
        reproduces across reads; a transient artifact does not. So when stability_k>1
        we sample the read-back k times and return the MAJORITY (status, body); with
        no strict majority we abstain (RL5) rather than trust noise. This is what
        keeps precision at 1.0 when the transport is hostile."""
        k = getattr(self, "stability_k", 1)
        if k <= 1:
            return self.target.send(req, principal)
        import uuid as _uuid
        from collections import Counter
        import math
        stealth = getattr(self, "stealth", None)
        if stealth is not None:
            # Deficiency #6: same majority guarantee, quiet delivery. Sample INCREMENTALLY,
            # cache-bust via a natural header, pace between reads, and STOP as soon as a
            # strong majority is settled (a calm target ends early; only real disagreement
            # escalates to max_k). Zero-FP semantics are unchanged — the winner must still
            # clear the strong-majority threshold below.
            samples = []
            counts = Counter()
            for i in range(stealth.max_k):
                if i > 0:
                    stealth.pace()
                q, h = stealth.bust(req.query, getattr(req, "headers", {}) or {})
                probe = HTTPRequest(req.method, req.path, query=q,
                                    host=getattr(req, "host", ""), headers=h)
                r = self.target.send(probe, principal)
                if r is None:
                    continue
                key = self._quorum_key(r)
                samples.append((key, r))
                counts[key] += 1
                if stealth.decided(counts, len(samples)) is not None:
                    break
            if not samples:
                return None
            counts = Counter(key for key, _ in samples)
            top, n = counts.most_common(1)[0]
            if n < max(2, math.ceil(stealth.majority * len(samples))):
                return None
            for key, r in samples:
                if key == top:
                    return r
            return None
        samples = []
        for _ in range(k):
            # cache-bust each sample so a URL-keyed shared cache cannot feed the vote
            # a stale/foreign body; a real backend answer survives, a cache bleed does not.
            q = dict(req.query or {})
            q["_cb"] = _uuid.uuid4().hex[:8]
            probe = HTTPRequest(req.method, req.path, query=q, host=getattr(req, "host", ""))
            r = self.target.send(probe, principal)
            if r is None:
                continue
            key = self._quorum_key(r)
            samples.append((key, r))
        if not samples:
            return None
        counts = Counter(key for key, _ in samples)
        top, n = counts.most_common(1)[0]
        # STRONG QUORUM (iron discipline): a real target answer is a PERSISTENT
        # property that dominates fresh cache-busted reads; a transient chaos artifact
        # cannot. Require >=80% agreement among valid samples, else abstain (RL5).
        import math
        if n < max(2, math.ceil(0.8 * len(samples))):  # strong quorum or abstain
            return None
        for key, r in samples:
            if key == top:
                return r
        return None

    def _read(self, req: HTTPRequest, principal: Principal):
        d = self.scope.check(req)
        if d.verdict is ScopeVerdict.HALT:
            return None
        # RL6 (economy): draw one request from the global/per-host budget BEFORE
        # spending it. On denial (budget exhausted or host frozen by the reputation
        # governor) we fail safe to abstain — exactly like a failed read-back — so
        # an out-of-budget candidate degrades to an honest unconfirmed lead, never
        # a silent skip and never a status-only confirmation. Unbounded ledger
        # (the default) always grants → byte-identical to the pre-economy path.
        host = getattr(req, "host", "") or ""
        if not self.ledger.acquire(host):
            return None
        resp = self._stable_send(req, principal)
        # CORRECTNESS guard (obstacle 2/6): if the read-back is a WAF block or bot
        # challenge, it is NOT the owner's view. Comparing it would corrupt Δstate,
        # so we abstain (return None) — the confirmer then cannot confirm a leak.
        try:
            from .transport import detect_block, detect_auth_expiry
            if resp is not None:
                expiry = detect_auth_expiry(resp.status, resp.body)
                blocked = detect_block(resp.status, resp.body, getattr(resp, "headers", {}))
                # feed the reputation governor: a block/expiry OR an explicit
                # rate-limit/unavailable status (429/503) is a STRIKE that tightens
                # the host's budget and can freeze it (RL6 closed loop). 429/503 are
                # back-off signals even with a plain JSON body, so they are counted
                # here independently of detect_block (which requires a WAF marker).
                rate_limited = resp.status in (429, 503)
                self.ledger.record(host, struck=bool(expiry or blocked or rate_limited))
                if expiry:
                    # owner/control read-back failed on STALE creds — not "no vuln".
                    self._abstain_notes.append(
                        "credentials likely expired during scan — re-capture and "
                        "re-run; a 401 on a read-back is NOT evidence of safety.")
                    return None
                if blocked:
                    return None
        except Exception:
            # D-READ-EXCEPT fix (AHP-12 pass 6): if block/expiry detection itself
            # raises, we CANNOT vouch that this read-back is the real owner view.
            # Fail safe to inaction (RL5) — abstain — rather than pass a possibly
            # challenged/blocked response through to a Δstate comparison (which
            # would risk treating a WAF interstitial as authoritative data).
            return None
        return resp

    @staticmethod
    def _resp_ok(resp, is_gql: bool) -> bool:
        """Success test for a read-back. GraphQL signals failure via `errors`
        even on HTTP 200 (improvement #2). PROBLEM 3: a REST 200 carrying an error
        ENVELOPE (e.g. {"error": ...}) is NOT a successful object read either — the
        semantics normaliser prevents that 200-with-error-body false positive."""
        if not (200 <= resp.status < 300):
            return False
        if is_gql:
            from .graphql import gql_succeeded
            return gql_succeeded(resp.status, resp.body)
        from .errnorm import classify_outcome, Outcome
        return classify_outcome(resp.status, resp.body,
                                getattr(resp, "headers", {})) is Outcome.AUTHORIZED

    def _confirm_conservation(self, cand: Candidate) -> Optional[StateProof]:
        """RL19 cross-principal VALUE-PRESENCE differential. Proves a read-leak
        without whole-body comparison (so it works for feeds/search/aggregations):
          (1) the leaked value V is present in the actor B's response;
          (2) V is present in the OWNER A's authoritative read-back (proves V is
              really A's private data, readable by A) — else fail-safe drop;
          (3) V is ABSENT for a fresh authenticated CONTROL peer (proves V is not
              broadly shared); if a control peer also sees it, it is a broader
              function-level exposure (BFLA-class) — still a finding, described
              accurately. A status/length diff is never used."""
        ev = cand.verdict.evidence or {}
        V = ev.get("object_id")
        owner = self._owner_of(cand)
        if owner is None or V is None:
            return None
        # strict (default OFF -> byte-identical): a shared DEFAULT/sentinel value
        # (0/1/-1, bool, empty, short enum) is present in every principal's response
        # by construction, so the value-presence differential would confirm it
        # falsely. Require the leaked value to DISCRIMINATE a private object.
        if getattr(self, "strict_leak", False) and not _value_is_discriminating(V):
            return None
        actor = cand.exchange.principal
        is_gql = cand.exchange.request.is_graphql()

        # chaos defence (RL24): DO NOT trust the analyze-time trigger body — a shared
        # cache bleed or a stale replica can place V in B's response on a SAFE
        # endpoint. Re-establish the trigger on a FRESH cache-busted majority read as
        # the actor; a real leak re-serves V, a transient artifact vanishes. Gated on
        # stability_k>1 so the default path stays byte-identical.
        if getattr(self, "stability_k", 1) > 1 and cand.exchange.request.method == "GET":
            fresh = self._read(cand.exchange.request, actor)
            if fresh is None or not _value_present(fresh.body, V):
                return None

        if not _value_present(cand.exchange.response.body, V):
            return None  # the value B supposedly leaked is not even in B's body

        readback = self._readback_request(cand)
        owner_resp = self._read(readback, owner)
        if owner_resp is None or not self._resp_ok(owner_resp, is_gql):
            return None  # cannot vouch for the owner view -> drop (RL5)
        if not _value_present(owner_resp.body, V):
            return None  # owner cannot read V here -> cannot prove it is A's -> drop

        control = next(
            (p for pid, p in self.principals.items()
             if pid != actor.pid and pid != owner.pid and not p.is_anonymous),
            None,
        )
        bfla = False
        if control is not None:
            ctl = self._read(readback, control)
            if ctl is not None and self._resp_ok(ctl, is_gql) and _value_present(ctl.body, V):
                bfla = True

        diagnosis = (
            "endpoint exposes this principal's private value to ANY authenticated "
            "principal — function-level authorization failure (BFLA-class)"
            if bfla else
            f"value owned by '{owner.pid}' is exposed to '{actor.pid}' yet withheld "
            f"from a control peer — cross-principal object-level leak (BOLA)"
        )
        return StateProof(
            confirmed=True,
            method="cross-principal value-presence differential (owner present + control absent)",
            before=f"private to {owner.pid}",
            after=f"exposed to {actor.pid}",
            read_as=owner.pid,
            detail=diagnosis,
        )

    def _readback_request(self, cand: Candidate) -> HTTPRequest:
        """Construct the request used to read the object back as another
        principal. This is invoked ONLY for OBJECT_ACCESS confirmation, where the
        operation is by definition a READ — so replaying the original request
        verbatim (only the principal's auth differs) is safe and correct for both
        GraphQL operations AND POST-body lookups/search endpoints, where the
        object identity lives in the body rather than the path. A bare GET on the
        path would miss those (dev idea #1)."""
        orig = cand.exchange.request
        return HTTPRequest(orig.method, orig.path, host=orig.host,
                           headers=dict(orig.headers or {}),
                           query=dict(orig.query or {}),
                           body=orig.body)

    # -- OBJECT_ACCESS / IDOR --------------------------------------------- #
    def _confirm_object_access(self, cand: Candidate) -> Optional[StateProof]:
        """Three-way differential leak audit (improvements #6/#7/#2):
          (1) attacker_body — what the actor actually got
          (2) owner read-back — the legitimate owner's private view
          (3) control read-back — a third authenticated principal that should NOT
              hold the object, used to distinguish IDOR from BFLA-class.
        For GraphQL the read-back replays the same operation (improvement #2).
        A leak is reported when attacker reproduces substantive owner fields; a
        BFLA-class diagnosis is emitted when control sees the same data."""
        oid = str(cand.verdict.evidence.get("object_id", ""))
        actor = cand.exchange.principal
        attacker_body = cand.exchange.response.body or {}
        is_gql = cand.exchange.request.is_graphql()

        # chaos defence (RL24): re-establish the trigger on a FRESH cache-busted
        # majority read as the actor rather than trusting the analyze-time body,
        # which a cache bleed / stale replica can have polluted with owner data on a
        # SAFE endpoint. Gated on stability_k>1 -> default path byte-identical.
        if getattr(self, "stability_k", 1) > 1 and cand.exchange.request.method == "GET":
            fresh = self._read(cand.exchange.request, actor)
            if fresh is None:
                return None
            attacker_body = fresh.body or {}

        owner = self._owner_of(cand)
        if owner is None:
            owner = next((p for pid, p in self.principals.items()
                          if pid != actor.pid and not p.is_anonymous), None)
        if owner is None:
            return None

        readback = self._readback_request(cand)
        owner_resp = self._read(readback, owner)
        if owner_resp is None or not self._resp_ok(owner_resp, is_gql):
            return None

        # For GraphQL, compare the data subtrees, not the whole envelope, so the
        # {"data": {...}} wrapper does not defeat the field-level leak audit.
        attacker_cmp = _gql_data(attacker_body) if is_gql else attacker_body
        owner_cmp = _gql_data(owner_resp.body) if is_gql else owner_resp.body

        # primary leak audit: did attacker reproduce owner's substantive data?
        primary = audit_leak(attacker_cmp, owner_cmp, strict=self.strict_leak)
        if not primary.has_substantive:
            return None  # soft-deny — no substantive data leaked, drop

        # differential: pick an AUTHENTICATED control principal that is neither
        # actor nor owner. If the control sees the same substantive data, this
        # is a broader function-level authorization failure (BFLA-class), not
        # a pure object-level IDOR.  Either way it is a finding — we just
        # describe it more accurately.
        control = next(
            (p for pid, p in self.principals.items()
             if pid != actor.pid and pid != owner.pid and not p.is_anonymous),
            None,
        )
        bfla_class = False
        if control is not None:
            control_resp = self._read(readback, control)
            if control_resp is not None and self._resp_ok(control_resp, is_gql):
                ctl_cmp = _gql_data(control_resp.body) if is_gql else control_resp.body
                ctl_audit = audit_leak(ctl_cmp, owner_cmp, strict=self.strict_leak)
                if ctl_audit.has_substantive:
                    bfla_class = True

        leaked = primary.leaked_fields
        sens = primary.sensitive_leaked
        sens_note = (f" · SENSITIVE fields leaked: {sens}" if sens else "")
        diagnosis = (
            "endpoint exposes cross-principal object data to any authenticated "
            "principal — function-level authorization failure (BFLA-class)"
            if bfla_class else
            f"actor reproduced {len(leaked)}/{primary.substantive_total} of "
            f"owner's substantive private fields"
        )
        return StateProof(
            confirmed=True,
            method=(
                "three-way differential read-back "
                "(owner authoritative + control denial check) with leak audit"
            ),
            before=(
                f"object {oid} private to '{owner.pid}'"
                + (f" with sensitive fields {sens}" if sens else "")
            ),
            after=(
                f"object {oid} readable by '{actor.pid}'"
                + (" AND by any authenticated principal" if bfla_class else "")
                + f" — leaked fields: {leaked}{sens_note}"
            ),
            read_as=owner.pid,
            detail=diagnosis,
        )

    # -- OWNERSHIP / mass-assignment -------------------------------------- #
    def _confirm_ownership(self, cand: Candidate) -> Optional[StateProof]:
        field = cand.verdict.evidence.get("field")
        value = cand.verdict.evidence.get("value")
        path = cand.exchange.request.path           # /api/users/{id}
        actor = cand.exchange.principal
        # D-CONFIRM-FALLBACK fix (AHP-12 pass 3): if an authenticated read-back is
        # AVAILABLE (2xx real object) it is AUTHORITATIVE — it both confirms (field
        # persisted == client value) AND refutes (server did NOT persist the field,
        # i.e. it only optimistically echoed it in the mutation response). Only when
        # no authoritative read-back exists do we fall back to the mutation
        # response as the server's own post-state assertion (single-sided). This
        # adds refutation without removing the fallback ⇒ FP↓, FN unchanged.
        rb = self._read(HTTPRequest("GET", path, host=cand.exchange.request.host), actor)
        authoritative = rb.body if (rb is not None and 200 <= rb.status < 300
                                    and isinstance(rb.body, dict)) else None
        if authoritative is not None:
            observed = authoritative.get(field)
            single_sided = False
        else:
            observed = (cand.exchange.response.body or {}).get(field)
            single_sided = True
        if observed is not None and str(observed) == str(value):
            return StateProof(
                confirmed=True,
                method=("server post-state assertion in the mutation response "
                        "(no independent read-back available)" if single_sided
                        else "authenticated read-back of the mutated field"),
                before=f"'{field}' was server-authoritative",
                after=f"'{field}' = '{value}' set via client-supplied input",
                read_as=actor.pid,
                detail="privileged field persisted to the server-side object state",
            )
        return None

    # -- AUTHORITY / BFLA -------------------------------------------------- #
    def _confirm_authority_grant(self, cand: Candidate) -> Optional[StateProof]:
        """RL13 Δstate confirmation for IAM escalation. A grant is confirmed ONLY by
        reading the authority graph back and proving the binding the actor created
        PERSISTED — i.e. the member now holds the role on the resource. Status alone
        (the setIamPolicy returned 200) is never enough (the optimistic-echo trap).
        If the read-back does not show the binding (no-op / rejected / unreadable),
        we abstain (fail-safe) — the engine surfaces it as a strong lead."""
        from .iam import extract_bindings, member_matches_principal, RoleModel
        req = cand.exchange.request
        ev = cand.verdict.evidence or {}
        granted_role = ev.get("role")
        members = ev.get("members") or []
        if not granted_role:
            return None
        # Build the read-back path: the canonical getIamPolicy sibling of the grant.
        read_path = self._iam_read_path(req.path)
        if read_path is None:
            return None
        # Read the policy back as the OWNER/control principal (authoritative view),
        # falling back to the actor only if no other principal is available.
        owner = self._owner_principal(cand)
        resp = self._read(HTTPRequest("GET", read_path, host=req.host), owner)
        if resp is None or not (200 <= resp.status < 300):
            return None
        after = extract_bindings(resp.body)
        # the granted (member, role) must now be present in the authority graph
        rm = RoleModel()
        persisted = False
        for b in after:
            if rm.rank(b["role"]) >= rm.rank(granted_role):
                for m in b["members"]:
                    if (not members) or any(member_matches_principal(m, mm.split(":")[-1])
                                            for mm in members):
                        persisted = True
                        break
        if not persisted:
            return None      # grant did not take effect → no Δstate → abstain
        return StateProof(
            confirmed=True,
            method="authority-graph read-back (getIamPolicy) proving the binding persisted",
            before=f"actor '{cand.exchange.principal.pid}' not entitled to grant '{granted_role}'",
            after=f"member(s) {members or '[self]'} now hold '{granted_role}' on the resource",
            read_as=owner.pid,
            detail=("IAM privilege escalation: the actor edited the authority graph to "
                    "confer a role above its own held authority, and a read-back confirms "
                    "the binding persisted."),
        )

    @staticmethod
    def _iam_read_path(grant_path: str) -> Optional[str]:
        """Canonical read sibling of a grant path. GCP uses ':setIamPolicy' ->
        ':getIamPolicy'. Generic ACL writes map to their GET. Returns None when no
        safe read-back path can be derived (fail-safe)."""
        p = grant_path
        for setter, getter in ((":setIamPolicy", ":getIamPolicy"),
                               ("setIamPolicy", "getIamPolicy"),
                               ("setAcl", "getAcl"), ("/setiampolicy", "/getiampolicy")):
            if setter in p:
                return p.replace(setter, getter)
        return None

    def _owner_principal(self, cand: Candidate):
        """Pick an authoritative read-back principal that is NOT the acting one
        (so the read reflects the true server state, not the actor's session)."""
        actor = cand.exchange.principal.pid
        for pid, pr in self.principals.items():
            if pid != actor and not getattr(pr, "is_anonymous", False):
                return pr
        return cand.exchange.principal

    def _confirm_authority(self, cand: Candidate) -> Optional[StateProof]:
        actor = cand.exchange.principal
        body = cand.exchange.response.body or {}
        # Leak proof: the function returned data belonging to principals OTHER than
        # the actor, to an actor that has no envelope authority over the function
        # (the EIL already established that). Works even when the actor is anon —
        # anon holds nothing, so any cross-principal data is a leak. No degenerate
        # "compare against anon" baseline (which breaks when the actor IS anon).
        known = set(self.principals.keys())
        others = _other_principal_ids(body, actor.pid, known)
        if not others:
            return None
        return StateProof(
            confirmed=True,
            method="response-payload inspection + envelope authority check",
            before=f"function exposes data for principals {sorted(others)}",
            after=f"'{actor.pid}' (no authority over this function) obtained that data",
            read_as=actor.pid,
            detail="privileged function returned cross-principal data to a non-authorised actor",
        )

    # -- PAYMENT ----------------------------------------------------------- #
    def _confirm_payment(self, cand: Candidate) -> Optional[StateProof]:
        ev = cand.verdict.evidence
        actor = cand.exchange.principal
        # R2 FIX: the transition response IS the server's authoritative post-state
        # (it shows the settled order). Start from it — never from a guessed
        # /api/orders path. A read-back may ENHANCE the proof but only when it
        # genuinely succeeds (2xx); a 404 from a wrong-shaped guess must never
        # overwrite the real evidence (that silently lost real findings before).
        order = dict(cand.exchange.response.body or {})
        ref = self._derive_object_ref(cand)
        read_back_seen = False
        if ref:
            rb = self._read(HTTPRequest("GET", self._resource_path(cand, ref),
                                        host=cand.exchange.request.host), actor)
            if rb is not None and 200 <= rb.status < 300 and isinstance(rb.body, dict):
                order = rb.body
                read_back_seen = True
        paid_state = str(order.get("status", "")).lower() == "paid" or order.get("paid") is True
        # D-CONFIRM-FALLBACK fix (AHP-12 pass 3): when the read-back is authoritative,
        # RE-MEASURE the amounts from it rather than trusting the law-time evidence.
        # A server that corrected/rejected the underpayment on settlement (paid now
        # ≥ due, or no longer paid) must REFUTE the finding, not be overridden by the
        # stale optimistic checkout response. Falls back to law-time evidence only
        # when no authoritative read-back exists (single-sided) ⇒ FP↓, FN unchanged.
        m_paid = _num_or_none(order.get("amount_paid")) if read_back_seen else None
        m_due = _num_or_none(order.get("amount_due")) if read_back_seen else None
        if m_paid is None:
            m_paid = ev.get("amount_paid", 0)
        if m_due is None:
            m_due = ev.get("amount_due", 0)
        if paid_state and m_paid < m_due:
            return StateProof(
                confirmed=True,
                method=("authenticated read-back of order settlement state"
                        if read_back_seen else
                        "server post-state assertion in the settlement response"),
                before=f"amount_due = {m_due}",
                after=f"order settled (paid) with amount_paid = {m_paid} "
                      f"(shortfall {round(m_due - m_paid, 2)})",
                read_as=actor.pid,
                detail="order reached terminal paid state below the amount due",
            )
        return None

    # -- PRICE ------------------------------------------------------------- #
    def _confirm_price(self, cand: Candidate) -> Optional[StateProof]:
        ev = cand.verdict.evidence
        actor = cand.exchange.principal
        claimed = _num_or_none(ev.get("claimed_total"))
        computed = _num_or_none(ev.get("computed_total"))
        if claimed is None:
            return None
        # D-CONFIRM-FALLBACK fix (AHP-12 pass 3): a fresh read-back of the priced
        # object is AUTHORITATIVE. If it shows the server recomputed the correct
        # line-item total (≈ computed), the client total was NOT treated as
        # authoritative downstream → REFUTE (the immediate response merely echoed
        # the cart for UX — the classic optimistic-echo false positive). Only the
        # claimed (tampered) total persisting confirms. With no read-back we fall
        # back to the echo as the server's own post-state (single-sided).
        ref = self._derive_object_ref(cand)
        if ref:
            rb = self._read(HTTPRequest("GET", self._resource_path(cand, ref),
                                        host=cand.exchange.request.host), actor)
            if rb is not None and 200 <= rb.status < 300 and isinstance(rb.body, dict):
                auth_total = _num_or_none(rb.body.get("total"))
                if auth_total is not None:
                    if abs(auth_total - claimed) <= 0.005:
                        return self._price_proof(actor, claimed, computed,
                                                 "authenticated read-back of stored order total")
                    return None      # server holds a different (corrected) total → refute
        accepted = _num_or_none((cand.exchange.response.body or {}).get("total"))
        if accepted is not None and abs(accepted - claimed) <= 0.005:
            return self._price_proof(actor, claimed, computed,
                                     "server post-state assertion in the pricing response "
                                     "(no independent read-back available)")
        return None

    @staticmethod
    def _price_proof(actor, claimed, computed, method):
        return StateProof(
            confirmed=True, method=method,
            before=f"line-item sum = {computed}",
            after=f"server accepted client total = {claimed}",
            read_as=actor.pid,
            detail="client-supplied amount was treated as authoritative",
        )

    # -- STATE_GATE -------------------------------------------------------- #
    def _confirm_state_gate(self, cand: Candidate) -> Optional[StateProof]:
        ev = cand.verdict.evidence
        actor = cand.exchange.principal
        # R2 FIX: authoritative post-state is the transition response; a read-back
        # only overrides on a real 2xx (never a wrong-path 404).
        order = dict(cand.exchange.response.body or {})
        ref = self._derive_object_ref(cand)
        if ref:
            rb = self._read(HTTPRequest("GET", self._resource_path(cand, ref),
                                        host=cand.exchange.request.host), actor)
            if rb is not None and 200 <= rb.status < 300 and isinstance(rb.body, dict):
                order = rb.body
        reached = str(order.get("status", "")).lower() == ev.get("reached")
        # D-STATEGATE-FP fix (AHP-12 pass 1): re-evaluate the ACTUAL predicate specs
        # against the authoritative post-state using the SAME predicate engine the
        # law used (one source of truth). A finding stands only if the predecessor
        # predicate is STILL unsatisfied on the read-back — so an order that the
        # read-back proves was legitimately settled (gate satisfied) can no longer
        # be mis-confirmed as a workflow-bypass. RL3 (real Δstate eval) + RL5
        # (uncertainty ⇒ abstain) both preserved.
        from .eil import _predicate_holds
        specs = ev.get("unmet_predicate_specs")
        _now = cand.exchange.observed_at
        if specs is not None:
            still_unmet = [p for p in specs if not _predicate_holds(p, order, now=_now)]
            gate_unsatisfied = bool(still_unmet)
            missing_desc = ev.get("missing_gate")
        else:
            # No machine-usable specs (legacy / externally-built candidate): we
            # cannot verify the predecessor against the post-state, so fail safe
            # to inaction (RL5) rather than fall back to the broken comparison.
            still_unmet, gate_unsatisfied, missing_desc = [], False, ev.get("missing_gate")
        if reached and gate_unsatisfied:
            return StateProof(
                confirmed=True,
                method="authenticated read-back of object workflow state "
                       "(predecessor predicate re-evaluated on the post-state)",
                before=f"predecessor gate '{missing_desc}' not satisfied on the read-back",
                after=f"object reached terminal state '{ev.get('reached')}'",
                read_as=actor.pid,
                detail="terminal state persisted without its required predecessor",
            )
        return None

    # -- INVENTORY --------------------------------------------------------- #
    def _confirm_inventory(self, cand: Candidate) -> Optional[StateProof]:
        """D-INVENTORY-NOREADBACK fix (AHP-12 pass 2). The previous version
        returned confirmed=True whenever a quantity was present and the response
        body was non-empty — a pure status/existence stamp, the exact RL3 breach
        the WHY doc forbids ("a 200 is enough"). It is replaced by a real Δstate
        proof: an authenticated read-back of the affected object must show the
        out-of-bounds quantity was actually ACCEPTED INTO SERVER STATE (the bad
        qty is recorded, or stock/available went negative). If the read-back
        proves the qty was clamped/rejected we REFUTE (abstain); if no post-state
        carries positive evidence of persistence we abstain (RL5) — never stamp."""
        ev = cand.verdict.evidence
        actor = cand.exchange.principal
        bad_qty = _num_or_none(ev.get("requested_qty"))
        if bad_qty is None:
            return None
        # Authoritative post-state: prefer a fresh read-back of the object; fall
        # back to the transition response ONLY as the server's own post-state.
        authoritative = dict(cand.exchange.response.body or {})
        ref = self._derive_object_ref(cand)
        read_back_seen = False
        if ref:
            rb = self._read(HTTPRequest("GET", self._resource_path(cand, ref),
                                        host=cand.exchange.request.host), actor)
            if rb is not None and 200 <= rb.status < 300 and isinstance(rb.body, dict):
                authoritative, read_back_seen = rb.body, True

        from .provenance import ValueClass, extract_values
        stored_qtys = [_num_or_none(tv.value) for tv in extract_values(authoritative)
                       if tv.value_class == ValueClass.QTY]
        stored_qtys = [q for q in stored_qtys if q is not None]
        # available/stock recorded in the post-state (negative ⇒ oversold persisted)
        avail = None
        for tv in extract_values(authoritative):
            leaf = tv.field_path.split(".")[-1].split("[")[0].lower()
            if leaf in ("available", "stock", "in_stock", "remaining"):
                avail = _num_or_none(tv.value)
                break

        persisted = (bad_qty in stored_qtys) or (avail is not None and avail < 0)
        if persisted:
            return StateProof(
                confirmed=True,
                method=("authenticated read-back of post-state quantity"
                        if read_back_seen else
                        "server post-state assertion in the transition response"),
                before=f"valid range 0..{ev.get('available', '∞')}",
                after=(f"out-of-bounds quantity {bad_qty} is recorded in the object's "
                       f"server-side state"
                       + (f" and available dropped to {avail}" if avail is not None and avail < 0 else "")),
                read_as=actor.pid,
                detail="quantity-bounds law breached and persisted to server state",
            )
        # read-back succeeded but the bad qty is NOT in state → it was clamped/
        # rejected → refute. Or no qty/stock field to prove persistence → abstain.
        return None

    # -- COUPON ------------------------------------------------------------ #
    def _confirm_coupon(self, cand: Candidate) -> Optional[StateProof]:
        ev = cand.verdict.evidence
        actor = cand.exchange.principal
        # Idempotency proof: replay the redemption; if it yields an additional
        # effect (applied again), single-use enforcement is broken. Guarded by
        # Scope-Guard — only if mutation is permitted; otherwise rely on the
        # measured redemption count already > limit.
        if ev.get("redemptions", 0) > ev.get("limit", 1):
            return StateProof(
                confirmed=True,
                method="measured redemption count across exchanges",
                before=f"declared single-use limit = {ev.get('limit')}",
                after=f"token redeemed {ev.get('redemptions')} times with effect each time",
                read_as=actor.pid,
                detail="single-use token replayed with additional effect",
            )
        return None

    # -- TEMPORAL_DRIFT ---------------------------------------------------- #
    def _confirm_temporal_drift(self, cand: Candidate) -> Optional[StateProof]:
        """Δstate confirmation (RL3): replay the access with the SAME (stale)
        credential. The credential should be dead after its revocation event, so
        if the replay STILL returns substantive (non-echo, non-ephemeral) private
        data, stale authority is proven. A bare 200 with no substantive body is
        NOT confirmed — that would be a status diff."""
        actor = cand.exchange.principal
        ev = cand.verdict.evidence or {}
        is_gql = cand.exchange.request.is_graphql()
        readback = self._readback_request(cand)
        resp = self._read(readback, actor)
        if resp is None or not self._resp_ok(resp, is_gql):
            return None
        body = _gql_data(resp.body) if is_gql else resp.body
        audit = audit_leak(body, body, strict=self.strict_leak)   # self-compare → "is there substantive data?"
        if not audit.has_substantive:
            return None
        sens = f" · SENSITIVE fields exposed: {audit.sensitive_leaked}" if audit.sensitive_leaked else ""
        kind = ev.get("revocation_kind") or "revocation"
        return StateProof(
            confirmed=True,
            method="stale-credential replay after recorded revocation event "
                   "(authenticated read-back, substantive-data required)",
            before=f"credential should be invalid after the {kind} event "
                   f"(seq {ev.get('revocation_seq')}, {ev.get('revocation_endpoint')})"
                   + (" with sensitive fields" if audit.sensitive_leaked else ""),
            after=f"stale credential still returns {len(audit.leaked_fields)} "
                  f"substantive private field(s): {audit.leaked_fields}{sens}",
            read_as=actor.pid,
            detail=f"authorization not enforced after {kind} — credential remained "
                   f"live against private state (basis: {ev.get('basis')})",
        )

    # -- STRUCTURAL_DIVERGENCE / SAIE (Gates 2 + 3) ----------------------- #
    def _confirm_structural_divergence(self, cand: Candidate) -> Optional[StateProof]:
        """Confirm a Gate-1 coherence breach by enforcing the two remaining gates
        under RL3 — no status/length/timing diff is ever a finding here:

          Gate 2 (dimensional control): there must exist a THIRD principal that is
            genuinely lower-privilege (rank < matched) AND whose own grammar LACKS
            the privileged paths. If every available principal that could be a
            control already receives the privileged shape, the richness is
            object-driven / by-design — NOT an authorization flaw — and we abstain.

          Gate 3 (functional anchor): at least one privileged-only path that is
            PRESENT_POPULATED in the matched grammar must be PRESENT (any state) in
            the acting principal's own response — proving the served structure is
            materially the privileged one, not a coincidental superset.

        Optional escalation: a live, scope-guarded owner read-back + top-level leak
        audit. The structural finding stands regardless; a real sensitive-value
        leak only raises severity (it is then ALSO an object-level exposure)."""
        if self.coherence is None or self.stability_gate is None:
            return None
        ev = cand.verdict.evidence or {}
        family = ev.get("family")
        acting = ev.get("acting")
        matched = ev.get("matched")
        matched_rank = ev.get("matched_rank", 0)
        acting_rank = ev.get("acting_rank", 0)
        diverging = set(ev.get("diverging_paths", []))
        fp_present = set(ev.get("fp_present_paths", []))
        if not (family and acting and matched and diverging):
            return None

        coh = self.coherence
        mask = self.stability_gate.trust_mask(family)

        # ---- Gate 2: dimensional control ---------------------------------- #
        control = None
        for pid in sorted(coh.principals_with_grammar(family)):
            if pid in (acting, matched):
                continue
            if coh.privilege_rank(pid, family, mask) >= matched_rank:
                continue                                   # not genuinely lower-priv
            if diverging & coh.grammar_present_paths(pid, family, mask):
                continue                                   # control also gets the shape
            control = pid
            break
        if control is None:
            return None    # no clean control ⇒ object-driven/by-design ⇒ abstain

        # ---- Gate 3: functional anchor ------------------------------------ #
        rep = coh.representative(matched, family, mask)
        matched_pop = set(rep.populated_paths()) if rep is not None else set()
        anchors = sorted((diverging & matched_pop) & fp_present)
        if not anchors:
            return None    # no populated privileged path is materially present

        # ---- optional escalation: did a sensitive VALUE actually cross? --- #
        sensitive_leaked: list[str] = []
        try:
            owner = self.principals.get(matched)
            if owner is not None:
                readback = self._readback_request(cand)
                owner_resp = self._read(readback, owner)
                is_gql = cand.exchange.request.is_graphql()
                if owner_resp is not None and self._resp_ok(owner_resp, is_gql):
                    attacker_body = cand.exchange.response.body or {}
                    owner_body = owner_resp.body or {}
                    la = audit_leak(_gql_data(attacker_body) if is_gql else attacker_body,
                                    _gql_data(owner_body) if is_gql else owner_body,
                                    strict=self.strict_leak)
                    sensitive_leaked = la.sensitive_leaked
        except Exception:
            sensitive_leaked = []

        div = sorted(diverging)
        sens_note = (f" · SENSITIVE values actually leaked: {sorted(sensitive_leaked)}"
                     if sensitive_leaked else "")
        return StateProof(
            confirmed=True,
            method=("passive structural interrogation — three-gate authorization-path "
                    "divergence: (1) Gate-1 coherence breach vs own grammar, "
                    f"(2) genuine lower-privilege control '{control}' does NOT receive "
                    "this shape, (3) functional anchor on a privileged-populated path"),
            before=(f"'{acting}'s own grammar for {family} (structural rank {acting_rank}) "
                    f"never contains the privileged path(s) {div} — they are ABSENT"),
            after=(f"'{acting}' received the privileged shape of '{matched}' "
                   f"(rank {matched_rank}): {len(div)} privileged-only path(s) present, "
                   f"functionally anchored at {anchors}{sens_note}"),
            read_as=matched,
            detail=("the server executed the privileged serialization/authorization code "
                    "path for an under-privileged principal; output filtering was the "
                    "only barrier"
                    + (" — and it failed, leaking sensitive values" if sensitive_leaked
                       else " — sensitive values were filtered out, but the reachable "
                            "privileged path is itself the authorization flaw")),
        )


    # -- FIELD_PROJECTION / ISI elevation (list-vs-detail differential) --- #
    def _confirm_field_projection(self, cand: Candidate) -> Optional[StateProof]:
        """Elevate an intrinsic sibling-asymmetry lead to a finding by a SINGLE
        scope-guarded read-back: fetch the carrier element through its canonical
        detail endpoint AS THE SAME (acting) principal. If the list view exposed a
        populated privileged field that the detail view FILTERS for that very
        principal, the list serializer over-projects — a concrete behavioural
        contradiction, confirmed by Δstate, not a heuristic (RL3). If the detail
        view also exposes it (consistent), or cannot be read, we abstain — the
        lead stays a lead."""
        ev = cand.verdict.evidence or {}
        field = ev.get("field")
        ids = ev.get("populated_ids") or []
        if not field or not ids:
            return None
        actor = cand.exchange.principal
        list_path = cand.exchange.request.path.rstrip("/")
        is_gql = cand.exchange.request.is_graphql()
        for eid in ids:
            detail = HTTPRequest("GET", f"{list_path}/{eid}",
                                 host=cand.exchange.request.host)
            resp = self._read(detail, actor)
            if resp is None or not self._resp_ok(resp, is_gql):
                continue                       # cannot read canonical view -> abstain
            present, _val = _dig(resp.body, field)
            if not present or _val in (None, "", [], {}):
                # the list leaked a populated field the detail view filters for
                # this same principal -> confirmed inconsistent projection.
                sens = name_sensitivity_safe(field)
                return StateProof(
                    confirmed=True,
                    method=("single canonical detail read-back as the acting principal "
                            "(list-vs-detail projection differential)"),
                    before=(f"canonical view GET {list_path}/{eid} as '{actor.pid}' "
                            f"does NOT expose '{field}'"
                            + (" (sensitive field)" if sens else "")),
                    after=(f"the list view GET {list_path} exposed a populated '{field}' "
                           f"for element '{eid}' to '{actor.pid}' — the list serializer "
                           f"over-projects a field the detail serializer filters"),
                    read_as=actor.pid,
                    detail=("inconsistent field projection: the same principal is denied "
                            f"'{field}' on the canonical object yet receives it in the "
                            "collection view — a list-serializer authorization gap"),
                )
        return None

    # -- CROSS_SURFACE / RL15 (canonical-vs-door divergence) -------------- #
    def _confirm_cross_surface(self, cand: Candidate) -> Optional[StateProof]:
        """RL15 Δstate confirmation — INTRA-PRINCIPAL, no multi-principal replay.

        The candidate says: a non-canonical door exposed sensitive field F for
        resource R to principal P, while the canonical view (recorded in baseline)
        withheld F from P. We prove the divergence is REAL and LIVE — not a stale
        baseline artefact — by reading the CANONICAL door back NOW, as the acting
        principal P, and confirming it STILL withholds F while the door's response
        carries a real value for F.

          * canonical read-back still HIDES F  ∧  door exposed a real F  → CONFIRM
          * canonical read-back now EXPOSES F (consistent)               → REFUTE
          * canonical door cannot be read / built                        → ABSTAIN

        Because the read-back is the SAME principal hitting its own canonical view,
        this needs no principal swapping — it sidesteps the biggest operational
        constraint on automated authz testing (RL14 / scope policy).
        """
        ev = cand.verdict.evidence or {}
        field = ev.get("field")
        rid = ev.get("object_id")
        rtype = ev.get("resource_type")
        door_val = ev.get("_door_value")
        if not field or rid is None:
            return None
        actor = cand.exchange.principal
        host = cand.exchange.request.host

        # ---- INTENT-DECLARED branch (GraphQL FORBIDDEN) -------------------- #
        # The server itself said FORBIDDEN for this field+principal. Prove the
        # denial is LIVE by replaying the exact operation as the SAME principal and
        # confirming the field is STILL authz-denied, while another door served it.
        if ev.get("_intent_declared") and ev.get("_denial_request") is not None:
            denial_req = ev["_denial_request"]
            replay = HTTPRequest(denial_req.method, denial_req.path,
                                 host=denial_req.host or host,
                                 headers=dict(denial_req.headers or {}),
                                 query=dict(denial_req.query or {}),
                                 body=denial_req.body)
            resp = self._read(replay, actor)
            if resp is None:
                return None
            from .graphql import authz_denied_paths
            still_denied = ev.get("_denial_path") in set(authz_denied_paths(resp.body))
            if not still_denied:
                return None      # the denial no longer reproduces → refute / abstain
            door_value = ev.get("_door_value")
            from .surface_map import _is_redacted
            if door_value is None or _is_redacted(door_value):
                return None
            return StateProof(
                confirmed=True,
                method=("intent-declared canonical: replay of the server's own "
                        "GraphQL operation as the acting principal, proving the field "
                        "is STILL authorization-denied while another door serves it"),
                before=(f"the server EXPLICITLY refuses '{field}' on authorization grounds "
                        f"for principal '{actor.pid}' at {ev.get('canonical_endpoint')} "
                        f"(GraphQL FORBIDDEN, re-proven live)"),
                after=(f"the non-canonical door {cand.exchange.request.endpoint_key()} served "
                       f"a populated '{field}' for resource {rtype}:{rid} to the SAME "
                       f"principal '{actor.pid}' — a door over-exposes a field the server's "
                       f"own GraphQL layer declares forbidden to this principal"),
                read_as=actor.pid,
                detail=("cross-surface inconsistency against an EXPLICIT denial: the server "
                        f"forbids '{field}' on one surface yet serves it on another for the "
                        "same principal — a field-level authorization gap invisible to "
                        "per-endpoint tools and unreachable on REST-only modelling"),
            )

        # ---- RL15 EXPOSED-reference branch (REST canonical read-back) ------ #
        canon_path = ev.get("_canonical_path") or self._synth_canonical_path(
            cand.exchange.request, rtype, rid)
        if not canon_path:
            return None
        resp = self._read(HTTPRequest("GET", canon_path, host=host), actor)
        if resp is None or not (200 <= resp.status < 300) or not isinstance(resp.body, dict):
            return None

        from .surface_map import exposed_sensitive_fields, _is_redacted
        canon_fields = exposed_sensitive_fields(resp.body)
        present, canon_val = _dig(resp.body, field)
        canonical_exposes = (field in canon_fields) or (present and not _is_redacted(canon_val))
        if canonical_exposes:
            return None      # surfaces agree → refute (stale baseline / by-design)

        door_present, door_value = _dig(cand.exchange.response.body, field)
        if not door_present or _is_redacted(door_value):
            # nested list bodies won't resolve a top-level dig — use the value the
            # law captured at the element it actually leaked from.
            door_value = door_val
        if door_value is None or _is_redacted(door_value):
            return None

        return StateProof(
            confirmed=True,
            method=("canonical authoritative read-back as the acting principal "
                    "(cross-surface field-exposure differential, intra-principal)"),
            before=(f"canonical view GET {canon_path} as '{actor.pid}' WITHHOLDS "
                    f"'{field}' (sensitive field) — the server's authoritative answer "
                    f"is that this principal may not see it here"),
            after=(f"the non-canonical door {cand.exchange.request.endpoint_key()} served "
                   f"a populated '{field}' for resource {rtype}:{rid} to the SAME "
                   f"principal '{actor.pid}' — one of the server's own doors over-projects "
                   f"a field its canonical view filters"),
            read_as=actor.pid,
            detail=("cross-surface inconsistency: the same principal is denied a sensitive "
                    f"field on the canonical object yet receives it through {ev.get('door')} "
                    "— a non-canonical-serializer authorization gap that lives in the "
                    "boundary between the two doors, invisible to per-endpoint tools"),
        )

    @staticmethod
    def _synth_canonical_path(request, rtype: str, rid) -> Optional[str]:
        """Synthesise the conventional REST canonical detail path for a resource by
        reusing the door's own path structure. Returns None when nothing safe can be
        derived (fail-safe — the confirmer then abstains)."""
        try:
            segs = request.segments()
        except Exception:
            return None
        from .surface_map import _singular
        cols = [(i, s) for i, (s, is_id) in enumerate(segs) if not is_id]
        chosen = None
        for i, s in cols:
            if rtype and _singular(s) == rtype:
                chosen = (i, s)
        if chosen is None and cols:
            chosen = cols[-1]
        if chosen is None:
            return None
        idx, _col = chosen
        prefix_parts = [s for s, _ in segs[:idx + 1]]
        return "/" + "/".join(prefix_parts) + "/" + str(rid)

    # -- AUTH_REGRESSION / RL16 (temporal authorization drift) ----------- #
    def _confirm_auth_regression(self, cand: Candidate) -> Optional[StateProof]:
        """RL16 Δstate confirmation — INTRA-PRINCIPAL, no role swapping.

        The candidate says: a sensitive field was withheld from this principal at an
        earlier snapshot but is populated now. We prove the regression is LIVE (not a
        one-off cache blip) by re-reading the same endpoint as the SAME principal and
        confirming the field is STILL populated.

          * read-back still POPULATES the field  → CONFIRM (the regression is live)
          * read-back withholds it again         → REFUTE / abstain (transient)
          * endpoint unreadable                  → ABSTAIN
        """
        ev = cand.verdict.evidence or {}
        path = ev.get("field_path")
        if not path:
            return None
        actor = cand.exchange.principal
        req = cand.exchange.request
        resp = self._read(HTTPRequest(req.method, req.path, host=req.host,
                                      query=dict(req.query or {})), actor)
        if resp is None or not (200 <= resp.status < 300) or not isinstance(resp.body, dict):
            return None
        from .structural import fingerprint, AbsenceState
        now_state = fingerprint(resp.body).absence_map.get(path)
        if now_state != AbsenceState.PRESENT_POPULATED:
            return None      # not populated on read-back → transient → abstain
        return StateProof(
            confirmed=True,
            method=("temporal authorization-shape read-back as the acting principal "
                    "(field withheld at the prior snapshot, populated now and on re-read)"),
            before=(f"at the prior snapshot the field '{path}' was structurally "
                    f"{ev.get('prior_state')} for principal '{actor.pid}' on "
                    f"{req.endpoint_key()} — the server withheld it"),
            after=(f"the field '{path}' is now POPULATED for the SAME principal "
                   f"'{actor.pid}' with no declared role change — an authorization "
                   f"regression confirmed live on read-back"),
            read_as=actor.pid,
            detail=("authorization drift over time: a deploy widened the field-level "
                    "exposure for a principal whose role did not change — a window "
                    "invisible to any point-in-time scan or to a tester without a "
                    "historical snapshot to diff against"),
        )

    # -- EMERGENT_BREAK / RL18 (global invariant, read-only) ------------- #
    def _confirm_global_invariant(self, cand: Candidate) -> Optional[StateProof]:
        """RL18 Δstate confirmation — READ-ONLY (AEGIS execution level 1).

        The candidate says: principal X accesses child C while its declared parent P
        was observed forbidden to X. We prove the break is LIVE by reading BOTH as X,
        now, read-only: child accessible ∧ parent forbidden ∧ no independent grant.
        No write is ever issued — the sequence that produced the break was OBSERVED,
        never generated, so no server state can be damaged (AEGIS gate 3).
        """
        ev = cand.verdict.evidence or {}
        child_id = ev.get("child")
        parent_id = ev.get("parent")
        if not child_id or not parent_id:
            return None
        actor = cand.exchange.principal
        req = cand.exchange.request
        host = req.host

        child_resp = self._read(HTTPRequest(req.method, req.path, host=host,
                                            query=dict(req.query or {})), actor)
        if child_resp is None or not (200 <= child_resp.status < 300):
            return None                      # child not live-accessible → abstain
        if isinstance(child_resp.body, dict) and _declares_grant_to(child_resp.body, actor.pid):
            return None                      # legit independent share → abstain

        parent_path = ev.get("_parent_path") or _path_for_identity(parent_id, req)
        if not parent_path:
            return None
        parent_resp = self._read(HTTPRequest("GET", parent_path, host=host), actor)
        if parent_resp is None or parent_resp.status not in (401, 403):
            return None                      # parent still accessible → not a real break

        return StateProof(
            confirmed=True,
            method=("read-only global-invariant read-back as the acting principal "
                    "(child accessible while declared parent forbidden — no writes issued)"),
            before=(f"the declared parent {parent_id} is FORBIDDEN to principal "
                    f"'{actor.pid}' (GET {parent_path} → {parent_resp.status}) — the "
                    f"authority over the subtree was transferred away"),
            after=(f"yet the child {child_id} remains ACCESSIBLE to '{actor.pid}' "
                   f"({req.method} {req.path} → {child_resp.status}) with no independent "
                   f"grant — the authority transfer did not propagate to the child"),
            read_as=actor.pid,
            detail=("emergent authorization break: a sequence of individually-permitted "
                    "operations left the child in a state that violates 'a child's "
                    "authority follows its parent's' — a global invariant no single "
                    "operation owns or checks, invisible to per-request analysis"),
        )


# --------------------------------------------------------------------------- #
# deterministic comparison helpers                                             #
# --------------------------------------------------------------------------- #

def _declares_grant_to(body: dict, principal_id: str) -> bool:
    """True if a resource body explicitly declares an INDEPENDENT grant to this
    principal (shared_with / acl / collaborators containing the actor). Used by RL18
    to abstain on a child that is legitimately shared, independent of its parent."""
    keys = ("shared_with", "shared", "collaborators", "acl", "grantees",
            "members", "viewers", "editors")
    pid = str(principal_id).lower()
    for k in keys:
        v = body.get(k)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.lower() == pid:
                    return True
                if isinstance(item, dict):
                    for vv in item.values():
                        if isinstance(vv, str) and vv.lower() == pid:
                            return True
        elif isinstance(v, str) and v.lower() == pid:
            return True
    return False


def _path_for_identity(identity: str, sibling_request) -> Optional[str]:
    """Synthesise a concrete path for a parent ResourceIdentity ("type:id") by reusing
    the child request's path structure: replace the child's collection+id with the
    parent's. Best-effort and read-only; returns None when nothing safe derives."""
    try:
        rtype, rid = identity.split(":", 1)
    except ValueError:
        return None
    # try to rebuild from the sibling path's leading segments
    try:
        segs = sibling_request.segments()
    except Exception:
        segs = []
    from .surface_map import _singular
    # find the collection in the path matching the parent type (e.g. "folders")
    prefix = []
    for s, is_id in segs:
        if not is_id and (_singular(s) == rtype):
            prefix.append(s)
            return "/" + "/".join(prefix + [str(rid)])
        prefix.append(s)
    # fallback: /<api-prefix>/<type>s/<id> using the leading non-id segment
    lead = [s for s, is_id in segs if not is_id]
    if lead:
        base = lead[0] if len(lead) > 1 else ""
        coll = rtype + "s"
        parts = ([base] if base else []) + [coll, str(rid)]
        return "/" + "/".join(p for p in parts if p)
    return None


def _num_or_none(value):
    """Best-effort float coercion (None on failure). Used by Δstate quantity
    comparisons so a stored '−5' string and a numeric −5 reconcile."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dig(body, dotted: str):
    """Resolve a dotted/indexed path in a JSON body. Returns (present, value)."""
    if not isinstance(body, (dict, list)):
        return (False, None)
    cur = body
    import re as _re
    for seg in _re.split(r"\.", dotted):
        m = _re.match(r"^(.*?)\[(\d+)\]$", seg)
        key, idx = (m.group(1), int(m.group(2))) if m else (seg, None)
        if key:
            if not isinstance(cur, dict) or key not in cur:
                return (False, None)
            cur = cur[key]
        if idx is not None:
            if not isinstance(cur, list) or idx >= len(cur):
                return (False, None)
            cur = cur[idx]
    return (True, cur)


def name_sensitivity_safe(path: str) -> int:
    try:
        from .intrinsic import name_sensitivity
        return name_sensitivity(path)
    except Exception:
        return 0

def _attacker_obtained_owner_data(attacker, owner) -> bool:
    """[Legacy single-axis check — kept for backward compatibility.]
    Returns True iff attacker reproduces ALL substantive owner fields verbatim.
    Superseded by `audit_leak()` below which adds partial-leak + sensitivity
    + ephemeral-noise tolerance (improvements #6/#7)."""
    if not isinstance(attacker, dict) or not isinstance(owner, dict):
        return False
    substantive = {k: v for k, v in owner.items()
                   if k.lower() not in EPHEMERAL_FIELDS | ECHO_FIELDS}
    if not substantive:
        return False
    return all(attacker.get(k) == v for k, v in substantive.items())


# ----- closed vocabularies (improvements #6/#7) -------------------------- #
# Fields that are echoes of the request or generic envelope plumbing — they
# are NOT evidence of a leak.  Closed list, not learned.
ECHO_FIELDS = {"id", "error", "message", "code", "status", "ok", "success"}

# Fields whose value typically changes between successive reads even for the
# same object — comparing them produces noise.  Exclude from substantive set.
EPHEMERAL_FIELDS = {
    "created_at", "updated_at", "last_seen", "last_seen_at", "timestamp",
    "request_id", "trace_id", "etag", "version", "_rev", "modified_at",
    "fetched_at", "as_of", "now", "server_time",
}

# Field-name fragments that mark a value as sensitive (PII / financial /
# secrets).  Leak of ANY of these escalates severity (improvement #7).
# A closed dictionary, not learned — additions go through this list.
SENSITIVE_FIELDS = {
    # PII (incl. international national-identifier names)
    "ssn", "social_security", "national_id", "passport", "dob", "birthdate",
    "birth_date", "date_of_birth", "phone", "phone_number", "address",
    "home_address", "ip_address", "geolocation", "personnummer", "aadhaar",
    "cpf", "cnpj", "curp", "rfc", "nino", "sin", "pesel", "codice_fiscale",
    "fiscal_code", "steuer_id", "steuerid", "dni", "nric", "my_number",
    "emirates_id", "voter_id", "drivers_license", "license_number", "id_number",
    "tax_id", "taxid", "vat", "national_insurance", "mother_maiden", "maiden_name",
    "place_of_birth", "biometric", "fingerprint_hash",
    # financial
    "balance", "bank_account", "account_number", "account_no", "iban", "routing",
    "sort_code", "swift", "bic", "card_number", "card_no", "credit_card",
    "cc_number", "cvv", "cvc", "pan", "pin", "security_code", "expiry",
    # secrets / access
    "secret", "secret_key", "api_key", "apikey", "private_key", "client_secret",
    "token", "refresh_token", "access_token", "session_token", "auth_token",
    "bearer", "mfa_seed", "totp_seed", "otp", "password", "passwd", "credentials",
    "seed_phrase", "mnemonic",
    # health
    "diagnosis", "medical_record", "health_record", "prescription", "mrn",
    "patient_id", "insurance_number",
}

# Vocabulary entries this short would collide as substrings of innocent words
# ("pan" ⊂ "company", "pin" ⊂ "shipping"), so they match a field name ONLY as a
# whole token — never as a substring. Longer entries are safe to substring-match.
_SHORT_TOKEN_LEN = 4

# SENTINEL S4: an engagement against a real target can declare its OWN sensitive
# field names (e.g. a bespoke `kunde_geheimnis`) so coverage matches the target,
# deterministically (RL1 — declared, never inferred).
_CUSTOM_SENSITIVE: set = set()


def register_sensitive_fields(names) -> None:
    """Operator hook: extend the sensitive-field vocabulary for a specific target.
    Declared, deterministic, additive — it can only WIDEN coverage, never narrow it."""
    for n in names or []:
        if isinstance(n, str) and n.strip():
            _CUSTOM_SENSITIVE.add(n.strip().lower())


def _field_tokens(key: str) -> set:
    """Split a field name into lowercase word tokens across snake_case, kebab-case,
    dotted paths AND camelCase, so `userSSN`, `user_ssn` and `user.ssn` all yield
    the token `ssn`."""
    import re
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def _is_sensitive_key(key: str) -> bool:
    """Token-aware sensitivity test. SHORT vocabulary entries match only as a whole
    token (so `pan`/`pin` no longer flag `company`/`shipping`); longer entries may
    substring-match (safe). Honours the operator-declared custom vocabulary."""
    k = key.lower()
    toks = _field_tokens(key)
    for s in SENSITIVE_FIELDS:
        if len(s) <= _SHORT_TOKEN_LEN:
            if s in toks:
                return True
        elif s in k or any(s in t for t in toks):
            return True
    for s in _CUSTOM_SENSITIVE:
        if (len(s) <= _SHORT_TOKEN_LEN and s in toks) or \
           (len(s) > _SHORT_TOKEN_LEN and s in k):
            return True
    return False


@dataclass
class LeakAudit:
    """Outcome of comparing an attacker response to an owner read-back."""
    leaked_fields: list[str]              # substantive fields attacker reproduced
    sensitive_leaked: list[str]            # subset that are sensitive
    substantive_total: int                 # total substantive fields owner has
    has_substantive: bool                  # any non-trivial leak at all
    has_sensitive: bool                    # at least one sensitive leak


def _value_present(body, value) -> bool:
    """True if `value` appears anywhere in a (possibly nested) response body. Value-
    level presence is what a feed/search/aggregation leak audit needs — a whole-body
    comparison cannot align differing element sets across principals."""
    target = str(value)
    stack = [body]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, (list, tuple)):
            stack.extend(x)
        elif str(x) == target:
            return True
    return False


def _value_is_discriminating(value) -> bool:
    """Structural (RL1-safe, no learning) test of whether a VALUE has enough
    discriminating power to identify a specific private object, versus being a
    shared DEFAULT/sentinel that many objects/principals carry identically.

    A shared default (0, 1, -1, booleans, empty, short single-case enum words like
    'pending'/'active'/'ROLE_USER') matches trivially across principals and is NOT
    private-leak evidence. A discriminating value (specific amounts, uuids, emails,
    addresses, mixed-case names, long tokens) is. Structural only — reads SHAPE,
    never meaning, never a corpus baseline."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (list, dict)):
        return bool(value)                       # a non-empty structure is specific
    if isinstance(value, (int, float)):
        return value not in (0, 1, -1)           # 0/1/-1 are canonical defaults/flags
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return False
        if "@" in s:
            return True                          # email
        if sum(ch.isdigit() for ch in s) >= 2:
            return True                          # ids, phones, ssns, uuids, addresses
        if any(ch.islower() for ch in s) and any(ch.isupper() for ch in s):
            return True                          # mixed-case (real names / camelCase)
        if len(s) >= 16:
            return True                          # long token / hash
        return False                             # short single-case word (enum default)
    return True


def _substantive_leak_value(key: str, value) -> bool:
    """A leaked (key, value) is substantive private-leak evidence only if its value
    DISCRIMINATES a private object. Identity/secret/financial-bearing fields (OWNER/
    TOKEN/AMOUNT) and PII field names always qualify; everything else must clear the
    structural discriminating-power bar. This is the fix for the shared-default false
    positive: matching on `category_id=0` / `status=pending` / `role=ROLE_USER` no
    longer counts as leaking another principal's private data."""
    if value in (None, "", "redacted", "***", "[REDACTED]") or isinstance(value, bool):
        return False
    from .provenance import classify_field, ValueClass
    vc = classify_field(key, value if not isinstance(value, (list, dict)) else "x")
    if vc in (ValueClass.OWNER, ValueClass.TOKEN, ValueClass.AMOUNT):
        return True                              # identity / secret / financial
    if _is_sensitive_key(key):
        return True                              # PII field
    return _value_is_discriminating(value)


def audit_leak(attacker, owner, strict: bool = False) -> LeakAudit:
    """Compare attacker response to the owner's authenticated read-back.

    A field counts as 'substantive' if it is in the owner body AND not:
      * an echo field (id/error/...), or
      * an ephemeral field (timestamps, etags, ...),
      * a None / null-redacted value (servers commonly redact rather than omit).

    A field counts as 'leaked' if the attacker reproduces the same value.
    Partial leaks are valid evidence — `all()` is too strict (improvement #6)."""
    empty = LeakAudit([], [], 0, False, False)
    if not isinstance(attacker, dict) or not isinstance(owner, dict):
        return empty
    substantive = {
        k: v for k, v in owner.items()
        if k.lower() not in EPHEMERAL_FIELDS
        and k.lower() not in ECHO_FIELDS
        and v not in (None, "", "redacted", "***", "[REDACTED]")
        # strict (default OFF -> byte-identical): a field is substantive only if its
        # value DISCRIMINATES a private object, so a shared default/sentinel matching
        # across principals is not counted as a leak (kills the shared-default FP).
        and (not strict or _substantive_leak_value(k, v))
    }
    if not substantive:
        return empty
    leaked = [k for k, v in substantive.items() if attacker.get(k) == v]
    sensitive = [k for k in leaked if _is_sensitive_key(k)]
    return LeakAudit(
        leaked_fields=leaked,
        sensitive_leaked=sensitive,
        substantive_total=len(substantive),
        has_substantive=bool(leaked),
        has_sensitive=bool(sensitive),
    )


def _other_principal_ids(body, actor_pid: str, known: set[str]) -> set[str]:
    """Identifying ids in a response that belong to principals other than the actor.
    A non-empty result on a function outside the actor's authority = a real leak."""
    found: set[str] = set()

    def scan(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("id", "owner_id", "user_id", "account_id", "customer_id"):
                    sv = str(v)
                    if sv != actor_pid and (sv in known or not known):
                        found.add(sv)
                scan(v)
        elif isinstance(node, list):
            for v in node:
                scan(v)

    scan(body)
    return found


def _gql_data(body):
    """Return the substantive data subtree of a GraphQL response for leak audit.
    Unwraps the {"data": {...}} envelope and, when there is a single root field,
    descends into it so the audit compares the object itself, not the wrapper
    (improvement #2). Falls back to the body unchanged when shape is unexpected."""
    if not isinstance(body, dict):
        return body
    data = body.get("data", body)
    if isinstance(data, dict) and len(data) == 1:
        only = next(iter(data.values()))
        if isinstance(only, dict):
            return only
    return data if isinstance(data, dict) else body
