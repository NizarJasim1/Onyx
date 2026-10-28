"""
⑤ Effect-Invariant Library (EIL) — §4.4 / §6 / D2.  THE v3 CORE.

Each entry is a conservation/consistency law that is TRUE BY THE DEFINITION of an
effect-class — never induced from traffic (RL1).  "This transition never appeared
in legitimate traffic" is NOT evidence of anything; only "this transition violates
the effect's conservation law" is.

A law's job is deterministic: from the structured values + Axis-1 provenance +
Axis-2 envelope, decide whether the conservation law is *potentially* broken and,
if so, name the value that laundered the authority.  It emits a CANDIDATE.
It NEVER emits a finding — promotion to a finding requires Δstate proof in the
confirmer (RL3).  The status code may gate whether a request is worth examining,
but it can never confirm; confirmation is always a read-back.

The catalog is the compounding asset: every new bug found anywhere becomes a new
reusable entry here.  Adding a law = subclassing Law and registering it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .envelope import EnvelopeEngine
from .models import (
    EffectClass,
    EffectClassification,
    Exchange,
    ImpactClass,
    LawVerdict,
    ValueOrigin,
    Verdict,
)
from .provenance import ProvenanceStore, ValueClass, classify_field, extract_values


@dataclass
class LawContext:
    """Everything a law needs — all of it measured/declared, none of it induced."""
    exchange: Exchange
    classification: EffectClassification
    provenance: ProvenanceStore
    envelopes: EnvelopeEngine
    # Optional declarative workflow gates supplied by the contract (improvement #4).
    # Keyed by target_state (lowercased) → {"requires_all": [predicate, ...]}.
    state_gates: dict = field(default_factory=dict)
    # Authority lifecycle ledger + this request's sequence number (temporal-drift
    # angle). Optional so existing call-sites and tests keep working untouched.
    lifecycle: Any = None
    seq: int = 0
    # SAIE (structural-divergence) state. Optional and supplied ONLY by the
    # independent structural pass — the main evaluate() chain never reads these,
    # so removing SAIE leaves every existing verdict byte-identical.
    stability_gate: Any = None
    coherence: Any = None
    # RL11: optional sealed cross-session store. When present, cross-session laws
    # (coupon single-use replay) augment their in-session count with prior-session
    # redemptions. None ⇒ in-session only ⇒ byte-identical.
    store: Any = None
    # RL13: declared IAM facts (never induced). actor_roles maps principal id →
    # [role names] it is known to hold; role_ranks overrides the default rank
    # ladder. Both optional ⇒ the AuthorityGrantLaw falls back to the
    # self-escalation-of-privileged-role signal only.
    actor_roles: Any = None
    role_ranks: Any = None
    resource_parents: Any = None
    # RL15: optional cross-surface ledger. When present, the (separately-dispatched)
    # CrossSurfaceConsistencyLaw consults the canonical door's recorded exposures.
    # None ⇒ the law is never reached ⇒ byte-identical to the pre-RL15 engine.
    surface_ledger: Any = None
    # RL16: optional authorization-shape time-series ledger + per-principal declared
    # role epoch. When present, the (separately-dispatched) AuthShapeRegressionLaw
    # compares the live shape to the prior snapshot. None ⇒ inert ⇒ byte-identical.
    auth_shape_ledger: Any = None
    role_epoch: int = 0
    # RL18: optional global-invariant ledger. When present, the (separately-dispatched)
    # GlobalInvariantLaw detects emergent parent/child authority-propagation breaks.
    # None ⇒ inert ⇒ byte-identical.
    invariant_ledger: Any = None

    def acting_envelope(self):
        return self.envelopes.envelope_for(self.exchange.principal.pid)

    def req_values(self):
        return extract_values(self.exchange.request.body)

    def resp_values(self):
        return extract_values(self.exchange.response.body)

    def succeeded(self) -> bool:
        """True iff the operation truly succeeded. For GraphQL, a 200 carrying
        an `errors` array is a SOFT FAILURE and must not count as success
        (improvement #2) — otherwise we would inflate findings on rejected
        operations. REST keeps the plain 2xx test."""
        if self.exchange.request.is_graphql():
            from .graphql import gql_succeeded
            return gql_succeeded(self.exchange.response.status,
                                 self.exchange.response.body)
        return 200 <= self.exchange.response.status < 300


class Law:
    """Base class. A law is a pure predicate over measured/declared facts."""
    effect: EffectClass
    name: str
    impact: ImpactClass

    def evaluate(self, ctx: LawContext) -> LawVerdict:  # pragma: no cover - interface
        raise NotImplementedError

    def _pass(self, reason: str) -> LawVerdict:
        return LawVerdict(Verdict.PASS, self.name, self.effect, reason)

    def _candidate(self, reason: str, evidence: dict[str, Any]) -> LawVerdict:
        return LawVerdict(Verdict.CANDIDATE, self.name, self.effect, reason, self.impact, evidence)


# --------------------------------------------------------------------------- #
# OBJECT_ACCESS — IDOR / BOLA                                                  #
#   law: accessed.object_id ∈ acting_principal.self_envelope                   #
# --------------------------------------------------------------------------- #

class ObjectAccessLaw(Law):
    effect = EffectClass.OBJECT_ACCESS
    name = "OBJECT_ACCESS: object_id ∈ self_envelope"
    impact = ImpactClass.DATA_EXPOSURE

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success response grants no access")
        env = ctx.acting_envelope()
        acting = ctx.exchange.principal.pid

        # The object-ids this action touched: path ids + ids echoed in the request.
        touched = list(ctx.exchange.request.object_ids())
        for tv in ctx.req_values():
            if tv.value_class in (ValueClass.ID, ValueClass.OWNER):
                touched.append(str(tv.value))

        # Bypass-shape recognition (dev idea #1): recognise — never craft — the
        # well-known IDOR bypass shapes already present in the captured request.
        # Every polluted value counts as 'touched' (the JSON/query parser may
        # have kept only one), and the mechanism is recorded for the report.
        from .bypass import detect_bypass_shapes, bypass_values
        shapes = detect_bypass_shapes(ctx.exchange.request)
        bvals = bypass_values(shapes)
        for bv in bvals:
            if bv not in touched:
                touched.append(bv)
        shape_for = {}
        for s in shapes:
            for v in s.values:
                shape_for.setdefault(str(v), s)

        for oid in touched:
            _host = ctx.exchange.request.host
            if env.holds_object_on_host(oid, (_host or "").strip().lower()):
                continue  # legitimately held ON THIS SERVICE — clean (RL9)
            # Not held on this service. Is it laundered from another principal
            # (on ANY service — a value belonging to another principal anywhere is
            # a launder signal)?
            laundered: ValueOrigin | None = ctx.provenance.first_seen_for_other_principal(oid, acting)
            # D-ENVELOPE-OVERBROAD + RL9: HELD (addressed+received) vs merely SEEN,
            # both scoped to THIS service. A hold/sighting on a different service no
            # longer suppresses — cross-service access fires a candidate and the
            # Δstate confirmer decides (so a legitimate cross-service self-access
            # fails to confirm rather than producing a false positive).
            held_self = ctx.provenance.held_object_by_principal(oid, acting, host=_host)
            if held_self:
                continue  # authoritatively held on this service → authorised
            seen_self = ctx.provenance.seen_by_principal(oid, acting, host=_host)
            if seen_self and laundered is None:
                continue  # only incidentally seen here and NOT cross-principal — clean
            reason = (
                f"object_id={oid} accessed by '{acting}' is not in its measured "
                f"self-envelope"
            )
            if laundered:
                reason += (
                    f"; it provably originated in principal '{laundered.principal_id}'"
                    f"'s response ({laundered.endpoint} → {laundered.field_path})"
                )
            evidence = {"object_id": oid, "laundered_from": laundered}
            shape = shape_for.get(oid)
            if shape is not None:
                reason += f"; reached via {shape.kind} bypass shape ({shape.detail})"
                evidence["bypass_kind"] = shape.kind
                evidence["bypass_detail"] = shape.detail
            return self._candidate(reason, evidence)
        return self._pass("all accessed object-ids are within the actor's self-envelope")


# --------------------------------------------------------------------------- #
# OWNERSHIP — Mass assignment / BOPLA                                          #
#   law: privileged server-authoritative field immutable via client value     #
#        by a non-owner principal                                             #
# --------------------------------------------------------------------------- #

class OwnershipLaw(Law):
    effect = EffectClass.OWNERSHIP
    name = "OWNERSHIP: privileged field is server-authoritative"
    impact = ImpactClass.PRIVILEGE_ESCALATION

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success response mutates nothing")
        # A privileged field supplied by the client AND reflected as accepted.
        req_priv = {tv.field_path.split(".")[-1]: tv.value
                    for tv in ctx.req_values() if tv.value_class == ValueClass.ROLE}
        if not req_priv:
            return self._pass("no privileged field supplied by client")
        resp_vals = {tv.field_path.split(".")[-1]: tv.value for tv in ctx.resp_values()}
        env = ctx.acting_envelope()
        for fname, supplied in req_priv.items():
            # R4 FIX: a principal RESUBMITTING a privileged value it already legitimately
            # held is a benign no-op, not mass-assignment. Only a value the actor did
            # NOT already hold can be an elevation. Measured fact (RL1), language-neutral.
            held = env.held_field_values.get(fname, set())
            if str(supplied) in held:
                continue
            reflected = resp_vals.get(fname, None)
            if reflected is not None and str(reflected) == str(supplied):
                return self._candidate(
                    f"client-supplied privileged field '{fname}={supplied}' was "
                    f"accepted and reflected by the server (server-authoritative "
                    f"field mutated via client input)",
                    {"field": fname, "value": supplied},
                )
        # Field supplied but not yet observed in response → still a candidate to confirm
        # (unless it is a value the actor already legitimately held — R4 no-op).
        env2 = ctx.acting_envelope()
        pending = [(fn, sv) for fn, sv in req_priv.items()
                   if str(sv) not in env2.held_field_values.get(fn, set())]
        if not pending:
            return self._pass("client only resubmitted privileged values it already held (no-op)")
        fname, supplied = pending[0]
        return self._candidate(
            f"client supplied privileged field '{fname}={supplied}'; confirm whether "
            f"the server accepted it as authoritative",
            {"field": fname, "value": supplied},
        )


# --------------------------------------------------------------------------- #
# AUTHORITY — BFLA / confused deputy                                           #
#   law: action.effect ⊆ acting_principal.envelope                            #
# --------------------------------------------------------------------------- #

class AuthorityLaw(Law):
    effect = EffectClass.AUTHORITY
    name = "AUTHORITY: action.effect ⊆ principal.envelope"
    impact = ImpactClass.FUNCTION_AUTHZ

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success response exercises no authority")
        env = ctx.acting_envelope()
        ep = ctx.exchange.request.endpoint_key()
        # A privileged function the acting principal did not previously hold this
        # session. (Anonymous principals hold nothing — strongest signal.)
        if ctx.exchange.principal.is_anonymous:
            return self._candidate(
                f"anonymous principal successfully invoked privileged function {ep}",
                {"endpoint": ep, "actor": "anon"},
            )
        if not env.holds_authority(ep):
            return self._candidate(
                f"principal '{ctx.exchange.principal.pid}' invoked privileged "
                f"function {ep} that is not in its measured authority envelope",
                {"endpoint": ep, "actor": ctx.exchange.principal.pid},
            )
        return self._pass("function is within the actor's measured authority envelope")


# --------------------------------------------------------------------------- #
# PAYMENT                                                                      #
#   law: amount_paid ≥ amount_due  ∧  paid-state monotonic & terminal          #
# --------------------------------------------------------------------------- #

class PaymentLaw(Law):
    effect = EffectClass.PAYMENT
    name = "PAYMENT: amount_paid ≥ amount_due ∧ same currency ∧ paid-state terminal"
    impact = ImpactClass.FINANCIAL

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success payment changes nothing")
        amount_due, cur_due = _find_amount_with_currency(
            ctx, ("due", "total", "amount_due", "subtotal", "grand_total"))
        amount_paid, cur_paid = _find_amount_with_currency(
            ctx, ("paid", "amount_paid", "charged", "captured", "amount"))
        if amount_due is None or amount_paid is None:
            return self._pass("payment amounts not both present — no conservation breach provable")

        # Currency-confusion law (improvement #5): two amounts in DIFFERENT
        # currencies are not comparable. If the server accepted such a payment,
        # either (a) it has a correct FX conversion (Δstate confirmation will
        # show parity in stored currency), or (b) it accepted numerically
        # without unit check (catastrophic, e.g. 100 KRW ≥ 90 USD). Either way,
        # a CANDIDATE is the correct fail-safe.
        if cur_due and cur_paid and cur_due.upper() != cur_paid.upper():
            return self._candidate(
                f"payment accepted with currency mismatch: due={amount_due} {cur_due} "
                f"vs paid={amount_paid} {cur_paid} — amounts in different units are "
                f"not directly comparable; confirm whether the server enforces "
                f"unit-aware conservation",
                {"amount_paid": amount_paid, "amount_due": amount_due,
                 "currency_due": cur_due, "currency_paid": cur_paid,
                 "currency_confusion": True},
            )
        if amount_paid < amount_due:
            return self._candidate(
                f"amount_paid={amount_paid} < amount_due={amount_due}"
                + (f" ({cur_due})" if cur_due else "")
                + " on a successful payment — value-conservation law violated",
                {"amount_paid": amount_paid, "amount_due": amount_due,
                 "shortfall": round(amount_due - amount_paid, 2),
                 "currency": cur_due or cur_paid},
            )
        return self._pass(f"amount_paid={amount_paid} ≥ amount_due={amount_due}")


# --------------------------------------------------------------------------- #
# PRICE / AMOUNT                                                               #
#   law: server-side amount == Σ(server-side line items); client amount advisory#
# --------------------------------------------------------------------------- #

class PriceLaw(Law):
    effect = EffectClass.PRICE
    name = "PRICE: total == Σ(line items)"
    impact = ImpactClass.PRICE_TAMPERING

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success response sets no price")
        body = ctx.exchange.request.body or {}
        items = body.get("items") or body.get("line_items") or []
        # R1 FIX: 'price' removed from the TOTAL name set — it collided with the
        # line-item 'price' fields and mis-resolved the claimed total.
        claimed_total = _find_amount(ctx, ("total", "grand_total", "order_total", "amount_total"))
        if not items or claimed_total is None:
            return self._pass("no line-items + total pair to reconcile")
        computed = 0.0
        for it in items:
            if not isinstance(it, dict):
                continue
            # R1 FIX: a unit price may be nested ({"value":5,"currency":..}); dig it.
            raw_unit = it.get("price") or it.get("unit_price") or it.get("amount") or 0
            if isinstance(raw_unit, dict):
                raw_unit = raw_unit.get("value") or raw_unit.get("amount") or 0
            unit = _num(raw_unit)
            qty = _num(it.get("qty") or it.get("quantity") or 1)
            if unit is None or qty is None:
                # cannot reconcile this line deterministically -> do not fabricate a
                # mismatch; abstain on the whole reconciliation (fail-safe, no FP).
                return self._pass("line item not numerically reconcilable — abstaining")
            computed += unit * qty
        # R1 FIX: tolerate IEEE-754 noise with a half-cent epsilon, not exact eq.
        if abs(round(computed, 2) - round(claimed_total, 2)) > 0.005:
            return self._candidate(
                f"client total={claimed_total} ≠ Σ(line items)={round(computed, 2)} — "
                f"client-supplied amount is advisory only and must not be authoritative",
                {"claimed_total": claimed_total, "computed_total": round(computed, 2)},
            )
        return self._pass(f"total {claimed_total} reconciles with line items")


# --------------------------------------------------------------------------- #
# STATE_GATE                                                                   #
#   law: privileged state reachable only via its declared predecessor gate,    #
#        bound to the SAME object (e.g. fulfilment ⇐ settled-payment(order))   #
# --------------------------------------------------------------------------- #

class StateGateLaw(Law):
    effect = EffectClass.STATE_GATE
    name = "STATE_GATE: terminal state requires its predecessor predicate(s)"
    impact = ImpactClass.WORKFLOW_BYPASS

    # Default declarative gates — applied when the contract does not declare
    # custom ones.  Each entry is the simple 1:1 form (target_state →
    # predecessor field).  Workflows beyond this simple shape are expressed by
    # the operator via `state_gates` in the contract (improvement #4).
    DEFAULT_GATES = {
        "fulfilled": {"requires_all": [{"field": "paid", "equals": True}]},
        "shipped":   {"requires_all": [{"field": "paid", "equals": True}]},
        "completed": {"requires_all": [{"field": "paid", "equals": True}]},
        "approved":  {"requires_all": [{"field": "reviewed", "equals": True}]},
        "settled":   {"requires_all": [{"field": "authorized", "equals": True}]},
    }

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success transition changes no state")
        resp = ctx.exchange.response.body or {}
        req = ctx.exchange.request.body or {}
        target_state = self._terminal_state(resp) or self._terminal_state(req)
        if target_state is None:
            return self._pass("no terminal state reached")

        # Resolve gates: custom (from contract) override defaults.
        gates = self._lookup_gates(ctx, target_state)
        if not gates:
            return self._pass(f"no gate registered for terminal state '{target_state}'")

        # Evaluate the predicate set against the SAME object's server state
        # (response is the server's view immediately after the transition).
        unmet_records = self._unmet_predicates(gates, resp, req,
                                               now=ctx.exchange.observed_at)
        if unmet_records:
            unmet_desc = [r["desc"] for r in unmet_records]
            # D-STATEGATE-FP root fix (spec-drift, AHP-12 pass 1): emit the
            # machine-usable predicate SPECS (the dicts), separate from the human
            # descriptions. improvement #4 turned `missing_gate` into a *description
            # string* ("paid equals True") while the confirmer still string-compared
            # it to a raw field name — silently disabling the "predecessor still
            # unsatisfied" half of the Δstate proof (a latent FALSE POSITIVE). The
            # confirmer now re-evaluates these specs against the authoritative
            # read-back via the SAME _predicate_holds engine (one source of truth).
            return self._candidate(
                f"object reached terminal state '{target_state}' with "
                f"{len(unmet_desc)} predecessor predicate(s) unsatisfied: {unmet_desc} — "
                f"workflow-order gate(s) skipped",
                {"reached": target_state, "missing_gate": unmet_desc[0],
                 "unmet_predicates": unmet_desc,
                 "unmet_predicate_specs": [r["spec"] for r in unmet_records],
                 "gates_source": "contract" if self._has_custom(ctx, target_state) else "default"},
            )
        return self._pass(f"'{target_state}' reached with all predecessor predicates satisfied")

    # -- helpers -------------------------------------------------------- #
    def _terminal_state(self, body: dict) -> str | None:
        for tv in extract_values(body):
            if tv.value_class == ValueClass.STATE:
                return str(tv.value).lower()
        return None

    def _lookup_gates(self, ctx: LawContext, target_state: str) -> dict | None:
        custom = self._contract_gates(ctx).get(target_state)
        if custom:
            return custom
        return self.DEFAULT_GATES.get(target_state)

    @staticmethod
    def _contract_gates(ctx: LawContext) -> dict:
        return getattr(ctx, "state_gates", {}) or {}

    def _has_custom(self, ctx: LawContext, target_state: str) -> bool:
        return target_state in self._contract_gates(ctx)

    @staticmethod
    def _unmet_predicates(gate: dict, server_body: dict, client_body: dict,
                          now: float | None = None) -> list[dict]:
        """Evaluate the predicate set against SERVER state by default. Returns one
        record per UNMET predicate: {"desc": human string, "spec": the predicate
        dict, "from": source}. The `spec` lets the confirmer re-evaluate the exact
        same predicate against the authoritative read-back (D-STATEGATE-FP fix).
        `now` is the deterministic reference time for temporal predicates (pass 4).
        A predicate may declare `from: client` to assert source.  Server-sourced
        predicates are the authoritative ones (a client-claimed predicate that
        the server treats as truth is itself a finding — BOPLA on the gate)."""
        preds = gate.get("requires_all", [])
        unmet: list[dict] = []
        for p in preds:
            src = p.get("from", "server")
            source_body = server_body if src == "server" else client_body
            if not _predicate_holds(p, source_body, now=now):
                unmet.append({"desc": _predicate_desc(p), "spec": p, "from": src})
        return unmet


# --------------------------------------------------------------------------- #
# INVENTORY / QTY                                                              #
#   law: 0 ≤ requested_qty ≤ available                                         #
# --------------------------------------------------------------------------- #

class InventoryLaw(Law):
    effect = EffectClass.INVENTORY
    name = "INVENTORY: 0 ≤ qty ≤ available"
    impact = ImpactClass.INVENTORY_ABUSE

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success response moves no stock")
        qty = None
        for tv in ctx.req_values():
            if tv.value_class == ValueClass.QTY:
                qty = _num(tv.value)
                break
        if qty is None:
            return self._pass("no quantity supplied")
        if qty < 0:
            return self._candidate(
                f"requested quantity {qty} is negative — quantity-bounds law violated "
                f"(negative qty can invert a charge or inflate balance)",
                {"requested_qty": qty},
            )
        available = _find_amount(ctx, ("available", "stock", "in_stock", "remaining"))
        if available is not None and qty > available:
            return self._candidate(
                f"requested quantity {qty} exceeds available {available} — "
                f"oversell / inventory-bounds law violated",
                {"requested_qty": qty, "available": available},
            )
        return self._pass(f"quantity {qty} within bounds")


# --------------------------------------------------------------------------- #
# COUPON / SINGLE-USE                                                          #
#   law: redemptions(token) ≤ declared_limit ∧ replay has no extra effect      #
# --------------------------------------------------------------------------- #

class CouponLaw(Law):
    effect = EffectClass.COUPON
    name = "COUPON: redemptions(token) ≤ declared_limit"
    impact = ImpactClass.COUPON_ABUSE

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success redemption has no effect")
        token = None
        for tv in ctx.req_values():
            if tv.value_class == ValueClass.TOKEN:
                token = str(tv.value)
                break
        if token is None:
            return self._pass("no coupon/single-use token in request")
        # The redemption count is a measured fact across the session, surfaced by
        # the engine via provenance: count prior successful redemptions of this token.
        prior = ctx.provenance.origins_of(token)
        # A successful redemption response typically echoes the applied token; if
        # this token already has a redemption origin in another exchange, this is a replay.
        prior_redemptions = [o for o in prior if o.response_id != ctx.exchange.rid]
        # RL11: add redemptions persisted from PRIOR SESSIONS (cross-session replay).
        # Disabled/absent store ⇒ 0 ⇒ byte-identical to the in-session-only count.
        cross_session = 0
        if getattr(ctx, "store", None) is not None:
            cross_session = ctx.store.prior_redemptions(token)
        total = len(prior_redemptions) + cross_session + 1
        declared_limit = _find_amount(ctx, ("limit", "max_uses", "uses_allowed")) or 1
        if total > declared_limit:
            xs = " (incl. prior sessions)" if cross_session else ""
            return self._candidate(
                f"coupon/single-use token '{token}' redeemed "
                f"{total} times{xs}, exceeding declared limit "
                f"{int(declared_limit)} — single-use replay",
                {"token": token, "redemptions": total,
                 "limit": int(declared_limit), "cross_session": cross_session},
            )
        return self._pass(f"token '{token}' within redemption limit")


# --------------------------------------------------------------------------- #
# The catalog                                                                  #
# --------------------------------------------------------------------------- #

class TemporalDriftLaw(Law):
    """Cross-cutting law (stateful angle): a credential that should have been
    invalidated by a prior revocation event is still reaching private state.

    Detection is purely analytical over the ordered ledger: did a SUCCESSFUL
    revocation event affecting THIS credential occur earlier in the capture, and
    is the credential now succeeding at an access that returns substantive data?
    Confirmation (Δstate, RL3) is performed later by the confirmer: the stale
    credential must still reproduce SUBSTANTIVE private fields — a bare 200 is
    never a finding.
    """
    effect = EffectClass.TEMPORAL_DRIFT
    name = "TEMPORAL_DRIFT: credential valid after its revocation event"
    impact = ImpactClass.TEMPORAL_DRIFT

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        if not ctx.succeeded():
            return self._pass("non-success access proves no live authority")
        from .temporal import credential_of
        cred = credential_of(ctx.exchange.request, ctx.exchange.principal)
        hit = ctx.lifecycle.revocation_before(ctx.exchange.principal.pid, cred, ctx.seq)
        if hit is None:
            return self._pass("no prior revocation event invalidates this credential")
        # The access must touch substantive (non-echo) data to be worth confirming.
        # Object-ids touched OR any substantive response body field.
        touched = list(ctx.exchange.request.object_ids())
        has_body = isinstance(ctx.exchange.response.body, dict) and bool(ctx.exchange.response.body)
        if not touched and not has_body:
            return self._pass("revoked credential used, but access returns no state to leak")
        ev = hit.event
        return self._candidate(
            f"credential used by '{ctx.exchange.principal.pid}' was invalidated by a "
            f"prior {ev.revocation_kind or 'revocation'} event "
            f"({ev.method} {ev.path}, seq {ev.seq}) yet still succeeds at "
            f"{ctx.exchange.request.method} {ctx.exchange.request.path} (seq {ctx.seq}) "
            f"— authorization was not enforced after revocation [{hit.basis}]",
            {"object_id": touched[0] if touched else None,
             "revocation_kind": ev.revocation_kind,
             "revocation_endpoint": ev.endpoint,
             "revocation_seq": ev.seq,
             "basis": hit.basis,
             "laundered_from": None},
        )


class StructuralDivergenceLaw(Law):
    """SAIE Gate 1 — coherence breach (Part D / Part F Step 4).

    A purely analytical predicate: does the acting principal's value-blind
    response fingerprint fit a STRICTLY higher-privilege principal's grammar for
    this endpoint family, while NOT fitting the acting principal's own grammar?

    If so, the server ran the acting principal through a privileged code path; the
    only remaining barrier was output filtering. This is a CANDIDATE only — the
    dimensional control (Gate 2) and functional anchor (Gate 3) are enforced by
    the confirmer under RL3. The law never touches values, timing, or status; it
    operates entirely on Layer-0-admissible structural signals (RL1/RL5).

    Deliberately NOT part of EIL.evaluate()'s dispatch chain. It is reached only
    via EIL.evaluate_structural() from the engine's independent additive pass, so
    removing SAIE leaves every existing verdict byte-identical (design requirement #4).
    """
    effect = EffectClass.STRUCTURAL_DIVERGENCE
    name = "STRUCTURAL_DIVERGENCE: response fits a higher-privilege grammar"
    impact = ImpactClass.AUTHZ_PATH_DIVERGENCE

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        gate, coh = ctx.stability_gate, ctx.coherence
        if gate is None or coh is None:
            return self._pass("structural state absent — SAIE inert")
        if not ctx.succeeded():
            return self._pass("non-success response carries no served code path")
        body = ctx.exchange.response.body
        if not isinstance(body, (dict, list)):
            return self._pass("response body is not a structural document")

        from .structural import fingerprint

        family = ctx.exchange.request.endpoint_key()
        mask = gate.trust_mask(family)
        if not mask.stable:
            return self._pass(f"family '{family}' has no stability-proven grammar")

        acting = ctx.exchange.principal.pid
        # Cannot assert incoherence against a grammar we do not have (fail-safe).
        if not coh.has_grammar(acting, family):
            return self._pass(f"no stable own-grammar for '{acting}' on '{family}'")

        fp = fingerprint(body, mask)
        if coh.fits(fp, acting, family, mask):
            return self._pass("response is coherent with the acting principal's own grammar")

        acting_rank = coh.privilege_rank(acting, family, mask)
        matched, matched_rank = None, acting_rank
        for q in coh.principals_with_grammar(family):
            if q == acting:
                continue
            if coh.fits(fp, q, family, mask) and coh.privilege_rank(q, family, mask) > acting_rank:
                r = coh.privilege_rank(q, family, mask)
                if matched is None or r > matched_rank:
                    matched, matched_rank = q, r
        if matched is None:
            return self._pass("no higher-privilege grammar matches this shape")

        diverging = sorted(coh.grammar_present_paths(matched, family, mask)
                           - coh.grammar_present_paths(acting, family, mask))
        oids = list(ctx.exchange.request.object_ids())
        return self._candidate(
            f"principal '{acting}' (structural rank {acting_rank}) received a response on "
            f"'{family}' that fits the higher-privilege grammar of '{matched}' "
            f"(rank {matched_rank}); {len(diverging)} privileged-only path(s) are present "
            f"that never appear in '{acting}'s own grammar "
            f"({', '.join(diverging[:6])}{'…' if len(diverging) > 6 else ''}) "
            f"— the privileged serialization path executed for an under-privileged principal",
            {"object_id": oids[0] if oids else None,
             "laundered_from": None,
             "family": family,
             "acting": acting,
             "matched": matched,
             "acting_rank": acting_rank,
             "matched_rank": matched_rank,
             "diverging_paths": diverging,
             "fp_present_paths": sorted(p for p in fp.present_paths() if p != "$"),
             "fp_populated_paths": sorted(fp.populated_paths())},
        )


# --------------------------------------------------------------------------- #
# AUTHORITY_GRANT — IAM privilege escalation (RL13)                            #
#   law: an actor must not grant authority above what it itself holds, and     #
#        must not raise its own effective authority (self-escalation).         #
# --------------------------------------------------------------------------- #
class AuthorityGrantLaw(Law):
    effect = EffectClass.AUTHORITY_GRANT
    name = "AuthorityGrantConservation"
    impact = ImpactClass.IAM_ESCALATION

    _PRIVILEGED = 75      # owner/admin/iam/billing tier — granting this to self is suspect

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        from .iam import (is_authority_grant, extract_bindings,
                          member_matches_principal, RoleModel)
        req = ctx.exchange.request
        if not is_authority_grant(req.method, req.path, req.body):
            return self._pass("not an authority-graph edit")
        bindings = extract_bindings(req.body)
        if not bindings:
            # a grant operation we cannot parse into bindings — fail safe, do not
            # fabricate a verdict (the confirmer would have nothing to prove).
            return self._pass("authority-grant op with no parseable binding")
        actor = ctx.exchange.principal.pid
        rm = RoleModel(getattr(ctx, "role_ranks", None))
        # RL14: the actor's effective rank is resolved over the RESOURCE ANCESTRY —
        # a binding at an ancestor (org/folder/project) inherits to this node. This
        # both suppresses false positives (an org-admin granting at a descendant is
        # legitimate) and scopes escalation (a grant above where the actor holds
        # authority confers power over the whole subtree).
        from .hierarchy import effective_rank_at, parse_resource_name, subtree_scope
        grant_resource = parse_resource_name(req.path)
        declared = getattr(ctx, "actor_roles", None)
        actor_binding = declared.get(actor) if isinstance(declared, dict) else None
        actor_rank = effective_rank_at(actor_binding, grant_resource, rm,
                                       getattr(ctx, 'resource_parents', None))
        scope = subtree_scope(grant_resource)
        for b in bindings:
            granted = rm.rank(b["role"])
            self_grant = any(member_matches_principal(m, actor) for m in b["members"])
            # (1) measured: actor grants a rank ABOVE what it holds at this node or
            #     any ancestor — it cannot legitimately confer authority it lacks.
            if actor_rank is not None and granted > actor_rank:
                who = "itself" if self_grant else f"member(s) {b['members']}"
                return self._candidate(
                    f"principal '{actor}' (effective rank {actor_rank} here) grants {who} "
                    f"role '{b['role']}' (rank {granted}) over {scope} — conferring "
                    f"authority above its own; IAM privilege escalation",
                    self._ev(actor, b, granted, actor_rank, scope))
            # (2) self-grant of a PRIVILEGED role with the actor's rank unknown —
            #     granting yourself owner/admin/iam is inherently escalation-shaped;
            #     the Δstate confirmer proves whether it actually took effect.
            if self_grant and actor_rank is None and granted >= self._PRIVILEGED:
                return self._candidate(
                    f"principal '{actor}' grants ITSELF privileged role '{b['role']}' "
                    f"(rank {granted}) over {scope} — self-escalation of the authority graph",
                    self._ev(actor, b, granted, None, scope))
        return self._pass("grant within the actor's held authority")

    def _ev(self, actor, binding, granted, actor_rank, scope=None):
        return {"actor": actor, "role": binding["role"], "members": binding["members"],
                "granted_rank": granted, "actor_rank": actor_rank, "subtree_scope": scope,
                "self_grant": True if actor in " ".join(binding["members"]).lower() else None}


class CrossSurfaceConsistencyLaw(Law):
    """RL15 — CROSS-SURFACE CONSISTENCY (the boundary law).

    A resource is a single truth reachable through several DOORS: a canonical
    detail view (`GET /collection/{id}`), a list view, a GraphQL selection, a
    search result, a legacy API version. A careful team writes the canonical
    detail serializer defensively; the other doors — written by other teams, at
    other times — drift. The conservation law that is TRUE BY DEFINITION:

        For one principal P and one resource R, the set of SENSITIVE fields P is
        permitted to see for R is a property of (P, R) — NOT of the door. So no
        non-canonical door may expose a sensitive field for (P, R) that the
        CANONICAL authoritative view withholds from that very same principal.

    This is not induction: it never says "this is unusual". It says "the canonical
    view — the server's own authoritative answer to 'what may P see of R' — is
    being contradicted by another of the server's own doors." The contradiction is
    the server disagreeing with itself; the only barrier left was the list/graphql
    serializer, and it failed.

    Critically DIRECTIONAL (CRUCIBLE kill-test): a detail view exposing MORE than a
    list view is by-design (summary vs full) and never fires. Only a NON-canonical
    door exposing what the CANONICAL door HIDES — for the same principal — fires.

    Deliberately NOT in the effect-routed evaluate() chain. It is reached only via
    EIL.evaluate_cross_surface() from the engine's flag-gated additive pass, so
    removing RL15 leaves every existing verdict byte-identical (the project's
    additive-isolation invariant).
    """
    effect = EffectClass.CROSS_SURFACE
    name = "CROSS_SURFACE: non-canonical door ⊆ canonical door (per principal, sensitive)"
    impact = ImpactClass.CROSS_SURFACE_LEAK

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        ledger = getattr(ctx, "surface_ledger", None)
        if ledger is None:
            return self._pass("cross-surface ledger absent — RL15 inert")
        if not ctx.succeeded():
            return self._pass("non-success door exposes nothing")

        from .surface_map import (
            classify_door, identify, exposed_sensitive_fields,
            DOOR_CANONICAL, _normalise_id,
        )
        req = ctx.exchange.request
        pqreg = getattr(ledger, "pq_registry", None)
        door = classify_door(req)
        if door == DOOR_CANONICAL:
            return self._pass("this IS the canonical door — nothing to test it against")

        actor = ctx.exchange.principal.pid
        body = ctx.exchange.response.body
        if not isinstance(body, (dict, list)):
            return self._pass("door response is not a structural document")

        # A non-canonical door may return ONE object (graphql/search) or MANY (list).
        # We test each resource identity the door exposes against ITS canonical
        # reference for THIS principal. A list row is attributed to its own id, so
        # we never compare across resources (RL1 — no cross-object bleed).
        candidates = self._resource_views(req, body, pqreg)
        for ident, view_body, element_id in candidates:
            ref = ledger.canonical_for(ident, actor)
            denials = ledger.denials_for(ident, actor)
            if ref is None and not denials:
                continue  # no authoritative reference of EITHER kind — abstain
            door_fields = exposed_sensitive_fields(view_body, element_id=element_id)
            if not door_fields:
                continue
            for leaf, val in door_fields.items():
                # INTENT-DECLARED trigger (strongest, works on GraphQL-only surfaces
                # with NO REST detail): the server EXPLICITLY returned this field as
                # authz-FORBIDDEN for this principal, yet another door serves it.
                if leaf in denials:
                    d = denials[leaf]
                    return self._candidate(
                        f"door '{door}' ({req.endpoint_key()}) exposes sensitive field "
                        f"'{leaf}' for resource {ident} to principal '{actor}', but the "
                        f"server EXPLICITLY refused '{leaf}' on authorization grounds for "
                        f"that same principal at {d.get('endpoint')} (GraphQL FORBIDDEN) "
                        f"— the server contradicts its own declared denial across surfaces",
                        {"object_id": ident.rid, "resource_type": ident.rtype,
                         "field": leaf, "door": door, "door_endpoint": req.endpoint_key(),
                         "canonical_endpoint": d.get("endpoint"),
                         "element_id": element_id, "_door_value": val,
                         "_denial_request": d.get("request"),
                         "_denial_path": d.get("path"), "_intent_declared": True,
                         "laundered_from": None},
                    )
                # RL15 trigger: the canonical EXPOSED-reference withholds it.
                if ref is not None and leaf not in ref.sensitive_fields:
                    return self._candidate(
                        f"door '{door}' ({req.endpoint_key()}) exposes sensitive field "
                        f"'{leaf}' for resource {ident} to principal '{actor}', but the "
                        f"CANONICAL authoritative view ({ref.endpoint}) withholds '{leaf}' "
                        f"from that same principal — the server contradicts itself across "
                        f"surfaces; the non-canonical serializer over-projects",
                        {"object_id": ident.rid, "resource_type": ident.rtype,
                         "field": leaf, "door": door, "door_endpoint": req.endpoint_key(),
                         "canonical_endpoint": ref.endpoint, "element_id": element_id,
                         "_door_value": val, "laundered_from": None},
                    )
        return self._pass("every sensitive field this door exposes is also exposed by "
                          "the canonical view (or never declared denied) for this principal "
                          "— surfaces agree")

    @staticmethod
    def _resource_views(req, body, pq_registry=None):
        """Yield (ResourceIdentity, body_to_inspect, element_id) for each resource
        the door addresses. A single-object door yields one (its primary identity,
        whole body, None). A list door yields one per element it carries, each
        attributed to that element's OWN identity so the comparison is never
        cross-resource."""
        from .surface_map import (identify, classify_door, DOOR_LIST,
                                  _normalise_id, _singular, ResourceIdentity)
        out = []
        ident = identify(req, pq_registry)
        if ident is not None:
            out.append((ident, body, None))
            return out
        # No primary id in the path (a list/collection door): attribute each row.
        door = classify_door(req)
        if door in (DOOR_LIST,):
            rtype = _list_resource_type(req)
            for elem, eid in _iter_elements_with_ids(body):
                nid = _normalise_id(eid)
                if rtype and nid:
                    out.append((ResourceIdentity(rtype, nid), body, eid))
        return out


def _list_resource_type(req):
    """Resource type a list door enumerates: the last collection segment."""
    from .surface_map import _singular
    try:
        segs = req.segments()
    except Exception:
        return ""
    cols = [s for s, is_id in segs if not is_id]
    return _singular(cols[-1]) if cols else ""


def _iter_elements_with_ids(body):
    """Yield (element_dict, id_str) for every object carrying an id, any depth."""
    def walk(node):
        if isinstance(node, dict):
            for k in ("id", "_id", "uid", "uuid"):
                if k in node and isinstance(node[k], (str, int)):
                    yield node, str(node[k])
                    break
            for v in node.values():
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)
    yield from walk(body)


class AuthShapeRegressionLaw(Law):
    """RL16 — AUTHORIZATION-SHAPE REGRESSION (the temporal law).

    The authorization a principal has over a resource is invariant in the absence
    of a declared role change. So the conservation law that is TRUE BY DEFINITION:

        For one principal P and one resource R, a sensitive field that the server
        WITHHELD from P at time T1 (absent / null / empty in the value-blind shape)
        must not become POPULATED for P at T2 unless P's declared role changed in
        between. If it does, a deploy regressed the field-level filter — P now sees
        what P was previously denied.

    Not induction: it compares two MEASURED value-blind fingerprints and reports a
    specific path that crossed withheld→populated. The worst false positive — a
    legitimate role promotion widening P's view — is defused by the declared
    role-epoch guard: snapshots taken under different role-epochs are never
    compared (handled inside the ledger).

    Reached only via EIL.evaluate_auth_regression() from the engine's flag-gated
    additive pass, so removing RL16 leaves every existing verdict byte-identical.
    """
    effect = EffectClass.AUTH_REGRESSION
    name = "AUTH_REGRESSION: sensitive field withheld@T1 → populated@T2 (no role change)"
    impact = ImpactClass.AUTH_REGRESSION

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        ledger = getattr(ctx, "auth_shape_ledger", None)
        if ledger is None:
            return self._pass("auth-shape ledger absent — RL16 inert")
        if not ctx.succeeded():
            return self._pass("non-success response exposes nothing")
        req = ctx.exchange.request
        actor = ctx.exchange.principal.pid
        regs = ledger.regressions(req, ctx.exchange.response, actor,
                                  role_epoch=getattr(ctx, "role_epoch", 0))
        if not regs:
            return self._pass("authorization-shape stable since last snapshot "
                              "(or role changed / no prior reference) — no regression")
        r = regs[0]
        return self._candidate(
            f"sensitive field '{r.path}' was structurally WITHHELD ({r.prior_state}) "
            f"for principal '{actor}' on {req.endpoint_key()} at the prior snapshot, "
            f"but is now POPULATED — an authorization regression over time with no "
            f"declared role change (a deploy widened what this principal may see)",
            {"object_id": ctx.exchange.request.primary_object_id(),
             "field": r.path.split(".")[-1].split("[")[0],
             "field_path": r.path,
             "prior_state": r.prior_state,
             "laundered_from": None},
        )


class GlobalInvariantLaw(Law):
    """RL18 — GLOBAL INVARIANT (the emergent / sequence law).

    The conservation law that is TRUE BY DEFINITION but owned by no single
    operation: a child resource's authority follows its parent's. So if a principal
    has been observed FORBIDDEN its parent (the authority transferred away) yet can
    still access the child, the transfer did not propagate — an emergent break the
    composition produced and no step checked.

    Not induction: the parent→child link is DECLARED (resource_parents); the break
    is a structural fact (child accessible ∧ parent forbidden ∧ declared link). The
    refutation — a child legitimately shared with the principal independently of the
    parent — is defused at confirm time by reading the child's own declared grants.

    Reached only via EIL.evaluate_global_invariant() from the engine's flag-gated
    additive pass, so removing RL18 leaves every existing verdict byte-identical.
    """
    effect = EffectClass.EMERGENT_BREAK
    name = "EMERGENT_BREAK: child accessible while declared parent forbidden (no propagation)"
    impact = ImpactClass.EMERGENT_BREAK

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        ledger = getattr(ctx, "invariant_ledger", None)
        if ledger is None:
            return self._pass("invariant ledger absent — RL18 inert")
        brk = ledger.break_for(ctx.exchange.request, ctx.exchange.response,
                               ctx.exchange.principal.pid)
        if brk is None:
            return self._pass("no emergent parent/child break in the observed sequence")
        try:
            oid = ctx.exchange.request.primary_object_id()
        except Exception:
            oid = None
        return self._candidate(
            f"principal '{brk.principal}' can still access child {brk.child} while its "
            f"DECLARED parent {brk.parent} has been observed FORBIDDEN to it — a sequence "
            f"of permitted operations broke the global invariant 'a child's authority "
            f"follows its parent's' (emergent; no single step checked it)",
            {"object_id": oid, "child": brk.child, "parent": brk.parent,
             "laundered_from": None},
        )


class EIL:
    """The reusable law catalog. Routing is by effect-class only."""

    def __init__(self) -> None:
        self._laws: dict[EffectClass, list[Law]] = {}
        for law in (
            ObjectAccessLaw(), OwnershipLaw(), AuthorityLaw(),
            PaymentLaw(), PriceLaw(), StateGateLaw(),
            InventoryLaw(), CouponLaw(), AuthorityGrantLaw(),
        ):
            self.register(law)
        # Cross-cutting law: evaluated on EVERY exchange regardless of effect
        # class, because stale-credential drift can ride on any action.
        self.temporal = TemporalDriftLaw()
        # SAIE structural-divergence law: NOT in the effect-routed map and NOT in
        # the evaluate() chain. Reached only via evaluate_structural() from the
        # engine's independent additive pass (design requirement #4: additive isolation).
        self.structural = StructuralDivergenceLaw()
        # RL15 cross-surface consistency law: like SAIE, NOT in the effect-routed
        # map and NOT in evaluate(). Reached only via evaluate_cross_surface() from
        # the engine's flag-gated additive pass (additive isolation preserved).
        self.cross_surface = CrossSurfaceConsistencyLaw()
        # RL16 authorization-shape regression law: non-routed, reached only via
        # evaluate_auth_regression() from the engine's flag-gated additive pass.
        self.auth_regression = AuthShapeRegressionLaw()
        # RL18 global-invariant law: non-routed, reached only via
        # evaluate_global_invariant() from the engine's flag-gated additive pass.
        self.global_invariant = GlobalInvariantLaw()
        from .conservation import AuthorityConservationLaw
        self.conservation = AuthorityConservationLaw()

    def register(self, law: Law) -> None:
        self._laws.setdefault(law.effect, []).append(law)

    def laws_for(self, effect: EffectClass) -> list[Law]:
        return self._laws.get(effect, [])

    def catalog(self) -> list[dict]:
        out = []
        for effect, laws in self._laws.items():
            for law in laws:
                out.append({"effect": effect.value, "name": law.name,
                            "impact": law.impact.value})
        # cross-cutting law is not in the effect-routed map; list it explicitly
        out.append({"effect": self.temporal.effect.value, "name": self.temporal.name,
                    "impact": self.temporal.impact.value})
        out.append({"effect": self.structural.effect.value, "name": self.structural.name,
                    "impact": self.structural.impact.value})
        out.append({"effect": self.cross_surface.effect.value, "name": self.cross_surface.name,
                    "impact": self.cross_surface.impact.value})
        out.append({"effect": self.auth_regression.effect.value, "name": self.auth_regression.name,
                    "impact": self.auth_regression.impact.value})
        out.append({"effect": self.global_invariant.effect.value, "name": self.global_invariant.name,
                    "impact": self.global_invariant.impact.value})
        out.append({"effect": self.conservation.effect.value, "name": self.conservation.name,
                    "impact": self.conservation.impact.value})
        return out

    def evaluate_global_invariant(self, ctx: LawContext) -> LawVerdict:
        """Independent RL18 entry point. Kept OUT of evaluate() so every existing
        probe's main verdict is untouched; the engine runs this as a flag-gated
        additive pass and routes any CANDIDATE through the global-invariant confirmer
        (RL3, read-only). Inert unless an invariant ledger is present."""
        if getattr(ctx, "invariant_ledger", None) is None:
            return self.global_invariant._pass("invariant ledger absent — RL18 inert")
        return self.global_invariant.evaluate(ctx)

    def evaluate_auth_regression(self, ctx: LawContext) -> LawVerdict:
        """Independent RL16 entry point. Kept OUT of evaluate() so every existing
        probe's main verdict is untouched; the engine runs this as a flag-gated
        additive pass and routes any CANDIDATE through the auth-regression confirmer
        (RL3). Inert unless an auth-shape ledger is present."""
        if getattr(ctx, "auth_shape_ledger", None) is None:
            return self.auth_regression._pass("auth-shape ledger absent — RL16 inert")
        return self.auth_regression.evaluate(ctx)

    def evaluate_cross_surface(self, ctx: LawContext) -> LawVerdict:
        """Independent RL15 entry point. Kept OUT of evaluate() so every existing
        probe's main verdict is untouched; the engine runs this as a flag-gated
        additive pass and routes any CANDIDATE through the cross-surface confirmer
        (RL3). Inert unless a surface ledger is present."""
        if getattr(ctx, "surface_ledger", None) is None:
            return self.cross_surface._pass("cross-surface ledger absent — RL15 inert")
        return self.cross_surface.evaluate(ctx)

    def evaluate_structural(self, ctx: LawContext) -> LawVerdict:
        """Independent SAIE entry point — Gate 1 only. Kept OUT of evaluate() so
        the main verdict for every existing probe is untouched; the engine runs
        this as an additive pass and routes any CANDIDATE through the confirmer's
        Gate 2 + Gate 3. Inert unless structural state is present."""
        if ctx.stability_gate is None or ctx.coherence is None:
            return self.structural._pass("structural state absent — SAIE inert")
        return self.structural.evaluate(ctx)

    def evaluate_conservation(self, ctx: LawContext) -> LawVerdict:
        """Independent RL19 entry point. Kept OUT of evaluate(); the engine runs it
        as a flag-gated additive pass and routes any CANDIDATE through the cross-
        principal differential confirmer (RL3). Fail-safe inert without provenance."""
        if ctx.provenance is None:
            return self.conservation._pass("provenance absent — RL19 inert")
        return self.conservation.evaluate(ctx)

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        # Cross-cutting temporal-drift check FIRST: a stale credential reaching
        # private state is a root-cause finding that overrides whatever the
        # effect-class law would say. Only runs when a lifecycle ledger is present.
        if ctx.lifecycle is not None:
            tv = self.temporal.evaluate(ctx)
            if tv.verdict is Verdict.CANDIDATE:
                return tv
        laws = self.laws_for(ctx.classification.effect)
        if not laws:
            return LawVerdict(Verdict.SKIP, "(no law)", ctx.classification.effect,
                              f"no EIL law applies to effect-class "
                              f"{ctx.classification.effect.value}")
        # Evaluate all applicable laws; the first CANDIDATE wins (fail-safe toward
        # scrutiny). If a classification is high_caution and every law passes, we
        # still PASS — but the inference flag is carried for the operator's view.
        for law in laws:
            v = law.evaluate(ctx)
            if v.verdict is Verdict.CANDIDATE:
                return v
        return LawVerdict(Verdict.PASS, laws[0].name, ctx.classification.effect,
                          "all applicable conservation laws hold")


# --------------------------------------------------------------------------- #
# small deterministic helpers                                                  #
# --------------------------------------------------------------------------- #

def _num(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _find_amount(ctx: LawContext, names: tuple[str, ...]) -> float | None:
    """Find a named amount in request then response. Deterministic field lookup."""
    a, _ = _find_amount_with_currency(ctx, names)
    return a


# Field-name fragments that mark a value as a currency code (ISO 4217 or similar).
_CURRENCY_FIELDS = ("currency", "currency_code", "ccy", "cur")


def _find_amount_with_currency(ctx: LawContext, names: tuple[str, ...]
                               ) -> tuple[float | None, str | None]:
    """Locate (amount, currency) pair (improvement #5).

    Handles three real-world shapes:
      (1) flat: {"amount_due": 100, "currency": "USD"} — sibling currency
      (2) nested: {"amount": {"value": 100, "currency": "USD"}} — Adyen-style
      (3) per-field: {"amount_due": 100, "amount_due_currency": "USD"} — prefixed

    Always returns a tuple; either may be None when the source is missing.
    """
    for source in (ctx.exchange.request.body, ctx.exchange.response.body):
        if not isinstance(source, dict):
            continue
        # try nested envelope first (Adyen pattern):
        # parent's name matches one of our `names`, and its value is a dict
        # containing a numeric "value"/"amount" + a currency field.
        for k, v in _shallow_pairs(source):
            kl = k.lower()
            if any(kl.endswith(n) or kl == n for n in names) and isinstance(v, dict):
                inner_amount = _num(v.get("value")) or _num(v.get("amount"))
                inner_cur = None
                for ck in _CURRENCY_FIELDS:
                    if ck in v:
                        inner_cur = str(v[ck])
                        break
                if inner_amount is not None:
                    return inner_amount, inner_cur
        # flat scan: find the amount and a co-located currency
        amount_found: float | None = None
        amount_field_leaf: str | None = None
        for tv in extract_values(source):
            leaf = tv.field_path.split(".")[-1].split("[")[0].lower()
            if leaf in names or any(leaf.endswith(n) or leaf == n for n in names):
                if classify_field(leaf, tv.value) in (ValueClass.AMOUNT,) or _num(tv.value) is not None:
                    n = _num(tv.value)
                    if n is not None:
                        amount_found = n
                        amount_field_leaf = leaf
                        break
        if amount_found is not None:
            # search for currency: same-source flat scan first
            currency = _scan_currency(source, prefer_field=amount_field_leaf)
            return amount_found, currency
    return None, None


def _scan_currency(source: dict, prefer_field: str | None = None) -> str | None:
    """Pick a currency value from a body. Prefer prefixed match
    (e.g. 'amount_due_currency' when amount field was 'amount_due')."""
    pairs = list(_shallow_pairs(source))
    if prefer_field:
        for k, v in pairs:
            if k.lower() == f"{prefer_field}_currency" and isinstance(v, str):
                return v
    for k, v in pairs:
        if k.lower() in _CURRENCY_FIELDS and isinstance(v, str):
            return v
    # deep scan as a fallback
    for tv in extract_values(source):
        leaf = tv.field_path.split(".")[-1].lower()
        if leaf in _CURRENCY_FIELDS and isinstance(tv.value, str):
            return tv.value
    return None


def _shallow_pairs(d: dict):
    if isinstance(d, dict):
        yield from d.items()


def _state_satisfied(body: dict, predecessor: str) -> bool:
    """True if a predecessor gate flag is satisfied in this body. [Legacy
    1:1 helper retained for backward use sites; new code uses _predicate_holds.]"""
    for tv in extract_values(body):
        leaf = tv.field_path.split(".")[-1].lower()
        val = str(tv.value).lower()
        if predecessor in leaf and val in ("true", "1", "yes", predecessor, "settled", "complete"):
            return True
        if tv.value_class == ValueClass.STATE and val == predecessor:
            return True
        if leaf in (predecessor, f"is_{predecessor}", f"{predecessor}_at", f"{predecessor}_state"):
            if val not in ("false", "0", "none", "null", ""):
                return True
    return False


# --------------------------------------------------------------------------- #
# STATE_GATE predicate engine (improvement #4)                                #
# --------------------------------------------------------------------------- #
# Declarative predicate DSL — purely deterministic, no code injection.
# Supported predicate operators:
#   equals   : value equality
#   gte/lte/gt/lt : numeric comparison
#   in       : membership in a list
#   exists   : field present and not null/empty
#   within_seconds : temporal — timestamp within N seconds of "now"
#
# Each predicate may declare `from: server|client` — server is the default and
# the authoritative source.  A client-sourced predicate that the SERVER then
# treats as authoritative is itself a finding (BOPLA on the gate).
# --------------------------------------------------------------------------- #

import time as _time
from datetime import datetime as _dt


def _resolve_field(body, dotted: str):
    """Read a dotted-path value from a nested body; returns None if absent."""
    if not isinstance(body, dict) or not dotted:
        return None
    cur = body
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _to_number(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_epoch(v):
    """Best-effort: ISO 8601 string or numeric epoch → epoch seconds."""
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            # accept Z suffix
            s = v.rstrip("Z")
            return _dt.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None


def _predicate_holds(p: dict, body: dict, now: float | None = None) -> bool:
    """Evaluate one predicate against a body. Strict, deterministic, fail-safe:
    anything ambiguous returns False (predicate unmet) so the law fires CANDIDATE
    — better to surface for review than silently pass.

    D-DETERMINISM-CLOCK fix (AHP-12 pass 4): `now` is the reference time for the
    `within_seconds` temporal predicate. Call-sites pass the exchange's
    observed_at so the verdict is a pure function of the capture (a re-run of the
    same capture yields the same verdict). It defaults to wall-clock ONLY when no
    reference is supplied, preserving backward compatibility for ad-hoc callers."""
    if not isinstance(p, dict):
        return False
    field = p.get("field")
    if not field:
        return False
    val = _resolve_field(body, field)
    if "equals" in p:
        return val == p["equals"]
    if "in" in p and isinstance(p["in"], (list, tuple)):
        return val in p["in"]
    if "exists" in p:
        present = val is not None and val != "" and val != []
        return present == bool(p["exists"])
    for op, cmp in (("gte", lambda a, b: a >= b), ("lte", lambda a, b: a <= b),
                    ("gt", lambda a, b: a > b),  ("lt",  lambda a, b: a < b)):
        if op in p:
            n = _to_number(val); m = _to_number(p[op])
            if n is None or m is None: return False
            return cmp(n, m)
    if "within_seconds" in p:
        epoch = _to_epoch(val); win = _to_number(p["within_seconds"])
        if epoch is None or win is None: return False
        ref = now if now is not None else _time.time()
        return (ref - epoch) <= win
    return False


def _predicate_desc(p: dict) -> str:
    if not isinstance(p, dict): return "<invalid predicate>"
    f = p.get("field", "?")
    for op in ("equals", "in", "exists", "gte", "lte", "gt", "lt", "within_seconds"):
        if op in p:
            return f"{f} {op} {p[op]}"
    return f"{f} (unspecified)"
