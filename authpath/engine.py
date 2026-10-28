"""
AuthPath v3 — Engine orchestrator (§4 pipeline).

Two phases, matching the build roadmap (M0/M1 then M2+):

  observe(ex)  — record a LEGITIMATE baseline action. Grows Axis-1 provenance and
                 Axis-2 envelopes. This is how measured authority is built — from
                 each principal's OWN authenticated actions (RL1: measured, not induced).

  analyze(ex)  — run the full detection pipeline on a PROBE action (possibly
                 malicious). It NEVER grows an envelope (a probe must not be able to
                 grant itself authority by being observed). Produces a deterministic
                 pipeline trace and, when Δstate-confirmed, a reportable Finding.

The whole hot path is parsing + table lookup + predicate eval + a read-back.
No anomaly model, no learned baseline, no LLM in the value/decision path.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

from .confirmer import Confirmer
from .contract import ContractResolver
from .eil import EIL, LawContext
from .envelope import EnvelopeEngine
from .models import (
    Candidate,
    EffectClass,
    Exchange,
    Finding,
    HTTPRequest,
    ImpactClass,
    LawVerdict,
    Principal,
    ScopeVerdict,
    Verdict,
)
from .poc import PoCEmitter
from .provenance import ProvenanceStore
from .scope_guard import ScopeConfig, ScopeGuard
from .transport import Target


@dataclass
class StageResult:
    stage: str
    status: str            # "ok" | "halt" | "candidate" | "pass" | "confirmed" | "unconfirmed" | "skip"
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class PipelineTrace:
    """A full, replayable record of one analyzed exchange — drives the dashboard."""
    tid: str
    principal: str
    method: str
    path: str
    endpoint: str
    status_code: int
    stages: list[StageResult] = field(default_factory=list)
    outcome: str = "clean"        # clean | candidate-unconfirmed | finding | halted | skipped
    finding_id: Optional[str] = None

    def add(self, stage: str, status: str, detail: str, **data) -> None:
        self.stages.append(StageResult(stage, status, detail, data))


def _host_like(aud: str) -> bool:
    """Is this audience value a hostname/URL (vs an opaque client-id)? Conservative:
    requires a scheme or a dotted domain so identifier-style auds are not compared."""
    a = aud.strip().lower()
    if "://" in a:
        return True
    core = a.split("/")[0]
    return "." in core and " " not in core and len(core) >= 4


def _host_covered(host: str, aud: str) -> bool:
    """Does the request host fall within the token's declared (host-like) audience?
    Lenient (suffix match) so sub-domains and scheme/path noise do not false-flag."""
    a = aud.strip().lower()
    if "://" in a:
        a = a.split("://", 1)[1]
    a = a.split("/")[0].split(":")[0]
    h = host.strip().lower().split(":")[0]
    if not a or not h:
        return True                                # unknown → do not flag
    return h == a or h.endswith("." + a) or a.endswith("." + h)


_BVA_ROLE_FIELDS = ("role", "roles", "tier", "plan", "account_type", "user_type",
                    "type", "membership", "level", "group")
_BVA_SELF_LEAVES = {"me", "self", "whoami", "current", "current_user", "viewer",
                    "profile", "account", "userinfo", "user_info"}


def _bva_role(request, response):
    """Extract a declared role/tier the TARGET emitted for the caller at a self endpoint.
    Used by the Broadcast-vs-Act FP guard so a broadcast difference is only an
    authorization claim when principals differ on a declared signal (not a feature flag)."""
    path = (getattr(request, "path", "") or "").strip("/").split("/")
    leaf = path[-1].lower() if path else ""
    if leaf not in _BVA_SELF_LEAVES:
        return None
    if not (200 <= getattr(response, "status", 0) < 300):
        return None
    from .attestation import _scalar_fields
    fields = _scalar_fields(getattr(response, "body", None))
    for k, v in fields.items():
        if k.split(".")[-1].lower() in _BVA_ROLE_FIELDS and v:
            return str(v)
    return None


class AuthPathEngine:
    def __init__(self, target: Target, principals: dict[str, Principal],
                 scope: ScopeConfig, contract: dict | None = None, ledger=None,
                 schemas=None, consistency_reads: int = 1,
                 store=None, store_path=None):
        self.target = target
        self.principals = principals
        self.scope_guard = ScopeGuard(scope)
        # Improvement #4: the contract may carry workflow gate predicates under
        # a top-level "state_gates" key (declarative DSL). Strip them out before
        # handing the endpoint map to the resolver.
        contract = dict(contract or {})
        # RL13: declared IAM facts (optional). Pulled out so they are not treated as
        # endpoint classifications. actor_roles: {pid: [roles]}; role_ranks: {role: rank}.
        self._actor_roles = contract.pop("actor_roles", None)
        self._role_ranks = contract.pop("role_ranks", None)
        self._resource_parents = contract.pop("resource_parents", None)
        self.state_gates = {
            k.lower(): v for k, v in (contract.pop("state_gates", {}) or {}).items()
        }
        # Temporal-drift revocation events (stateful angle). Declared list is
        # authoritative; heuristic recognition seeds suggestions. Stripped before
        # the endpoint map reaches the resolver.
        revocation_events = contract.pop("revocation_events", []) or []
        # Privilege-NARROWING events (role downgrade, plan change). Unlike a
        # revocation these do NOT invalidate the credential — they only reduce what
        # it should see — so the value-based TemporalDriftLaw never fires for them.
        # That is exactly the gap the temporal STRUCTURAL drift lead covers.
        role_change_events = contract.pop("role_change_events", []) or []
        self._role_change_eps = {d["endpoint"]: (set(d.get("affects_principals", [])),
                                                 d.get("kind", "role_change"))
                                 for d in role_change_events if d.get("endpoint")}
        self._role_narrowed: dict = {}      # pid -> (seq, kind, endpoint)
        self.contract = ContractResolver(contract)
        self.provenance = ProvenanceStore()
        self.envelopes = EnvelopeEngine()
        self.eil = EIL()
        # SAIE structural state (Layer 0 + Layer 2). These are read ONLY by the
        # independent structural pass; the main pipeline never touches them, so
        # they cannot perturb any existing verdict.
        from .structural import CoherenceModel, StabilityGate
        self.stability_gate = StabilityGate()
        self.coherence = CoherenceModel(self.stability_gate)
        # RL6 (economy): optional budget ledger. None ⇒ unbounded ⇒ byte-identical
        # to the pre-economy engine. A BudgetedScanner injects a real ledger.
        if ledger is None:
            from .economy import BudgetLedger
            ledger = BudgetLedger.unbounded()
        self.ledger = ledger
        self.confirmer = Confirmer(target, principals, self.scope_guard,
                                   coherence=self.coherence,
                                   stability_gate=self.stability_gate,
                                   ledger=self.ledger)
        # RL10: optional read-consistency window for distributed targets (default
        # 1 ⇒ single-shot ⇒ byte-identical). Set >1 for eventually-consistent APIs.
        if consistency_reads and int(consistency_reads) > 1:
            self.confirmer.consistency_reads = int(consistency_reads)
        self.emitter = PoCEmitter(getattr(self.scope_guard.config, "target_provenance", "self"))
        # Allocator buffer (Slice 3): populated only when analyze(defer=True) is
        # used by the BudgetedScanner; drained in yield-descending order. Empty
        # and untouched on the default streaming path.
        self._deferred: list = []
        self._defer_counter = 0
        # RL7.2: optional protobuf/wire schema registry (endpoint → field-map).
        # Empty by default ⇒ schema-free decode (shape fallback) ⇒ byte-identical.
        from .codec import SchemaRegistry
        self.schemas = schemas if schemas is not None else SchemaRegistry()
        # RL11: sealed cross-session memory. Disabled (no path) ⇒ no-op ⇒
        # byte-identical to the pre-RL11 engine.
        from .persistence import SealedStore
        self.store = store if store is not None else SealedStore(store_path)

        self.findings: list[Finding] = []
        self._finding_sigs: set = set()
        self.traces: list[PipelineTrace] = []
        # Intrinsic (reference-free) leads — a SEPARATE channel from findings. Never
        # alters a verdict or a trace; pure additive coverage surfaced for triage.
        self.leads: list = []
        # HARD epistemic gate (defect #1/#3): when True (offline HAR mode) the
        # engine may NOT promote an object-access candidate to a FINDING, because
        # a passive capture cannot distinguish ownership from IDOR. Live scan=False.
        self.offline: bool = False
        # Opt-in: emit lead-only relational hints from UNSTABLE (single-observation)
        # grammars. Off by default => byte-identical to the gated engine.
        self.provisional_leads: bool = False
        self._emitted_intermittent: set = set()   # (family, path) dedupe for normalisation leads
        self._emitted_absence: set = set()         # (family, objsig, branch) dedupe for absence-map
        self._gql_field: dict = {}                 # (family,objsig,field) -> {"pop":set,"deny":set}
        self._emitted_gql: set = set()             # dedupe for graphql field leads
        # Opt-in: a disciplined READ-ONLY active probe that reproduces a field-level
        # differential in one controlled cycle to confirm a lead (RL3/RL5). Off by
        # default => byte-identical; strict per-run budget; never mutates.
        self.active_probing: bool = False
        self._active_budget: int = 8
        # G14/G1/G2 opt-in run flag (default OFF ⇒ byte-identical). When enabled, the
        # BvA bridge is built WITH a ledger-tied nonce authority so the attributed /
        # drift / OOB confirmation paths become usable end-to-end.
        self.stateful_attribution: bool = False
        self._nonce_authority = None
        self._nonce_seeker = None
        # G6: follow async/deferred (202/saga/CQRS) commits to their landed state
        # instead of abstaining at the ack. Default OFF => byte-identical. Confirms
        # ONLY a persisted read-back, so an optimistic-ack-then-rejected still abstains.
        self.follow_async_commit: bool = False
        self._async_max_polls: int = 4
        self._probed_bola: set = set()
        # Opt-in: cross-step value provenance — a distinctive value that originated in
        # one principal's private response, later consumed in another principal's
        # request. Leads-only, flag-gated => byte-identical when off.
        self.chain_provenance: bool = False
        self._emitted_chain: set = set()
        # Opt-in: temporal STRUCTURAL drift — a revoked credential whose responses
        # retain a privileged branch structurally (even nulled), where TEMPORAL_DRIFT
        # abstains for lack of a substantive value. Leads-only, flag-gated.
        self.temporal_drift: bool = False
        self._emitted_tdrift: set = set()
        # RL15: cross-surface consistency. Off by default ⇒ ledger never seeded,
        # pass never runs ⇒ byte-identical to the pre-RL15 engine. When on, the
        # engine records canonical-door exposures during observe() and runs an
        # additive cross-surface pass in _finish() that can only ADD a finding.
        self.cross_surface: bool = False
        from .surface_map import SurfaceLedger
        self.surface_ledger = SurfaceLedger()
        self._emitted_xsurface: set = set()
        # RL16: authorization-shape time-series. Off by default ⇒ ledger never
        # seeded, pass never runs ⇒ byte-identical to the pre-RL16 engine.
        self.temporal_shape: bool = False
        from .temporal_shape import AuthShapeLedger
        self.auth_shape_ledger = AuthShapeLedger()
        self._role_epoch: dict = {}          # pid -> declared-role epoch (bumped on role change)
        self._emitted_authreg: set = set()
        # RL17: combinatorial orchestration. Off by default ⇒ no rule learned or
        # applied ⇒ byte-identical to the pre-RL17 engine. When on, a confirmed
        # cross-surface leak generalises into a structural rule that TARGETS sibling
        # matrix cells; each is still convicted by a single per-cell Δstate (C6).
        self.combinatorial: bool = False
        from .hypothesis import HypothesisEngine
        self.hypothesis = HypothesisEngine()
        self._derived_count: int = 0          # findings discovered by RL17 orchestration
        # RL18: global invariant engine (the 4th dimension — sequence/emergent).
        # Off by default ⇒ ledger never seeded, pass never runs ⇒ byte-identical.
        # READ-ONLY by construction (AEGIS gate 3): it observes the sequence in
        # traffic and confirms with read-only read-backs; it never writes state.
        self.global_invariants: bool = False
        from .global_invariants import InvariantLedger
        self.invariant_ledger = InvariantLedger(parent_map=self._resource_parents)
        self._emitted_emergent: set = set()
        # SENTINEL S1: count of additive-pass exceptions on real (messy) responses,
        # surfaced as a coverage-honesty metric — a non-zero value means some
        # exchanges were not fully analysed and is reported, never hidden.
        self._pass_errors: int = 0
        self._cur_seq: int = 0
        # Cross-request access ledger (dev idea #2, safe part): records which
        # (principal) touched which object_id via which (method, endpoint, status).
        # Bounded by #objects × #methods, not #requests of payload (D10 spirit).
        # Used ONLY to enrich already-confirmed findings with cross-method authz
        # inconsistency evidence — never to fire or confirm a finding on its own
        # (that would be a status-diff, violating RL3).
        self.access_ledger: dict[str, list[dict]] = {}
        # Authority lifecycle ledger (temporal-drift angle). Ordered, cross-request.
        from .temporal import LifecycleLedger
        self.lifecycle = LifecycleLedger(revocation_events)
        self._seq = 0

    def _record_access(self, ex: Exchange, legitimate: bool = False) -> None:
        ok = 200 <= ex.response.status < 300
        rec = {"pid": ex.principal.pid, "method": ex.request.method.upper(),
               "endpoint": ex.request.endpoint_key(), "status": ex.response.status,
               "ok": ok, "path": ex.request.path,
               "query": dict(ex.request.query or {}), "host": ex.request.host,
               "legitimate": legitimate}
        try:
            oids = ex.request.object_ids()
        except Exception:
            oids = []
        for oid in oids:
            self.access_ledger.setdefault(str(oid), []).append(rec)

    def _owner_of(self, value):
        """Owner attribution that respects the giant-volume collision-proof gate (protocol
        [21], G3). With `giant_volume` on, a value legitimately originating under >=2 distinct
        principals is treated as shared/colliding -> None (abstain), so a coincidental value
        collision at 10^6 scale can never be misattributed as a cross-principal leak. Off ->
        unchanged behaviour."""
        if getattr(self, "giant_volume", False):
            return self.provenance.unambiguous_owner(value)
        return self.provenance.owner_of_value(value)

    def _emit_finding(self, finding) -> bool:
        """Dedup by (actor, target object, law) — identical triples are the SAME
        issue re-observed (defect #6). Returns True if newly emitted.

        Deficiency #1 gate (flag-gated via `policy_hypothesis`, empty by default so the
        proving world is byte-identical): when the operator has declared an out-of-band
        policy hypothesis, a confirmed cross-principal access is checked against it.
        PERMITTED (a declared, legitimate crossing/sharing) -> SUPPRESS, so a real sharing
        feature is never mistaken for a breach on a sharing-rich target. FORBIDDEN ->
        emit, annotated as a breach RELATIVE TO the declared invariant (never absolute
        truth). UNCOVERED / no hypothesis -> unchanged behaviour. The gate can only
        suppress or annotate, never turn a non-finding into one, so it cannot add a
        false positive (GP5 preserved)."""
        hyp = getattr(self, "policy_hypothesis", None)
        if hyp is not None and hyp.declared():
            from .policy import PERMITTED, FORBIDDEN
            # owner (if resolvable) + concrete resource id -> the resource's established
            # tenant domain is preferred, so classification works even when the owner's
            # identity never appears in any body (server-side binding).
            owner = self.provenance.owner_of_value(finding.target_ref)
            if owner is None and finding.target_ref in self.principals:
                owner = finding.target_ref
            resource = getattr(finding, "resource_ref", "") or ""
            verdict = hyp.classify_access(finding.actor_pid, owner, resource)
            if verdict == PERMITTED:
                return False                               # declared legitimate sharing/grant
            if verdict == FORBIDDEN:
                reason = hyp.breach_reason(finding.actor_pid, owner, resource)
                if reason and getattr(finding, "proof", None) is not None:
                    try:
                        finding.proof.detail = (finding.proof.detail or "") + f" [{reason}]"
                    except Exception:
                        pass
        sig = (finding.actor_pid, finding.target_ref, finding.law_name)
        if sig in self._finding_sigs:
            return False
        self._finding_sigs.add(sig)
        self.findings.append(finding)
        return True

    def evidence_report(self, provenance: Optional[str] = None) -> dict:
        """RL20 — apply ONYX's own 'prove, don't claim' rigor to ONYX's own output.
        Every finding is stamped with the tier it is ENTITLED to, derived from the
        target's provenance (declared once on the scope), never chosen. The same
        confirmed finding is T2 on a self target and T1 on crAPI. Also decomposes the
        false-positive claim, emits the strongest claim defensible right now, and
        audits for over-claims. Purely additive: reads self.findings, mutates
        nothing, so existing output stays byte-identical."""
        from .evidence import (
            EvidenceLedger, TargetProvenance, coerce_provenance, EvidenceTier,
            grade, decompose_fp_claim, evidence_stamp, strongest_honest_claim,
        )
        prov = coerce_provenance(
            provenance if provenance is not None
            else getattr(self.scope_guard.config, "target_provenance", "self"))

        ledger = EvidenceLedger()
        stamps, confirmed_count = [], 0
        for f in self.findings:
            confirmed = bool(getattr(getattr(f, "state_proof", None), "confirmed", True))
            confirmed_count += int(confirmed)
            tier = grade(confirmed, prov)
            ledger.add(f"{f.fid}: {f.impact.value}", tier, detail=f.law_name)
            stamps.append({"fid": f.fid, "tier": tier.name,
                           "stamp": evidence_stamp(confirmed, prov)})

        fp_parts = decompose_fp_claim(demo_n=0, independent_measured=False, provenance=prov)
        for c in fp_parts:
            ledger.add(c.statement, c.tier, c.detail)

        has_independent = prov.ceiling is EvidenceTier.T1_INDEPENDENT and confirmed_count > 0
        claim = strongest_honest_claim(
            has_independent_recall=has_independent, has_baseline_delta=False,
            has_real_cve_or_bounty=(prov is TargetProvenance.LIVE_BOUNTY and confirmed_count > 0))

        ceiling = prov.ceiling
        overclaims = [c.render() for c in ledger.audit(max_allowed=ceiling)]
        return {
            "target_provenance": prov.value,
            "evidence_ceiling": ceiling.name,
            "findings_total": len(self.findings),
            "findings_confirmed": confirmed_count,
            "per_finding": stamps,
            "false_positive_claim": [c.render() for c in fp_parts],
            "strongest_honest_claim": claim,
            "overclaims_detected": overclaims,
            "evidence_map": ledger.render(),
        }

    def _cross_method_note(self, object_id: str, actor_pid: str,
                           success_method: str) -> str | None:
        """If the SAME actor was denied (4xx) on the same object via a DIFFERENT
        method/endpoint than the one that succeeded, authorization is enforced
        inconsistently across methods — strong corroborating evidence. This is a
        report annotation on an ALREADY Δstate-confirmed finding, not a verdict."""
        recs = self.access_ledger.get(str(object_id), [])
        denied = [r for r in recs
                  if r["pid"] == actor_pid and not r["ok"]
                  and 400 <= r["status"] < 500
                  and r["method"] != success_method.upper()]
        if not denied:
            return None
        d = denied[0]
        return (f"the same principal '{actor_pid}' was DENIED ({d['status']}) on the "
                f"same object via {d['endpoint']}, yet succeeded via "
                f"{success_method} — authorization is enforced inconsistently across "
                f"HTTP methods (method-restriction bypass)")

    # -- phase 1: build measured authority from legitimate traffic --------- #
    def observe(self, ex: Exchange) -> None:
        decision = self.scope_guard.check(ex.request)
        if decision.verdict is ScopeVerdict.HALT:
            return
        cls = self.contract.classify(ex)
        self.provenance.observe_response(ex)
        self.envelopes.observe(ex, cls.effect)
        self._record_access(ex, legitimate=True)
        # Deficiency #1: establish this resource's tenant domain from the legitimate
        # provisioning walk (owner-identity-independent). No-op unless a hypothesis is set.
        hyp = getattr(self, "policy_hypothesis", None)
        if hyp is not None and hyp.declared() and 200 <= ex.response.status < 300:
            try:
                for oid in ex.request.object_ids():
                    hyp.observe_owner(ex.principal.pid, str(oid))
            except Exception:
                pass
        # Deficiency #4: capture the capability baseline ONCE (before any attack) so a
        # later denied->allowed flip is a provable escalation Δstate. No-op without oracle.
        oracle = getattr(self, "consequence_oracle", None)
        if (oracle is not None and getattr(oracle, "actions", None)
                and not getattr(self, "_capability_baseline", None)):
            self._capability_baseline = {}
            for pid in self.principals:
                for action in oracle.actions:
                    try:
                        self._capability_baseline[(pid, action)] = bool(oracle.capability_gained(pid, action))
                    except Exception:
                        self._capability_baseline[(pid, action)] = None
        self._seq += 1
        self.lifecycle.record(self._seq, ex.request, ex.response, ex.principal.pid, ex.principal)
        # SAIE seeding (additive, isolated): feed successful structural responses
        # to the stability gate + coherence model. Only 2xx bodies that are JSON
        # documents seed a grammar; everything else is ignored. A family needs >=2
        # identical-request repeats before any grammar is trusted, so endpoints
        # observed once (every existing demo family) never become SAIE-eligible.
        self._saie_seed(ex)
        self._record_credential_lifecycle(ex)
        # RL15: record the canonical-door exposure for this legitimate observation
        # (gated — no-op when cross_surface is off, so observe() stays byte-identical).
        if getattr(self, "cross_surface", False) and 200 <= ex.response.status < 300:
            self.surface_ledger.record(ex.request, ex.response, ex.principal.pid)
            # RL15/Residue-A: record the server's EXPLICIT field-level denials
            # (GraphQL FORBIDDEN) as the intent-declared canonical reference.
            self.surface_ledger.record_denials(ex.request, ex.response, ex.principal.pid)
        # RL16: snapshot the value-blind authorization-shape for this observation so
        # a later read can be diffed against it (gated — observe stays byte-identical).
        if getattr(self, "temporal_shape", False) and 200 <= ex.response.status < 300:
            self.auth_shape_ledger.record(
                ex.request, ex.response, ex.principal.pid,
                role_epoch=self._role_epoch.get(ex.principal.pid, 0))
        # RL18: record this principal's access outcome (2xx OR 403) so the emergent
        # parent/child break can be detected from the observed SEQUENCE (gated).
        if getattr(self, "global_invariants", False):
            self.invariant_ledger.observe(ex.request, ex.response, ex.principal.pid)
        # NERVE (identity⇄ownership reconciliation): feed the SEPARATE-channel bridge.
        # Gated — no-op when `nerve` is off, so observe() stays byte-identical. Even
        # when ON it only fills the bridge's ledgers; it never touches self.findings
        # or any existing output (findings are obtained via the explicit
        # nerve_findings() method, a channel distinct from the pipeline).
        if getattr(self, "nerve", False):
            self._nerve_feed(ex)
        # BROADCAST-vs-ACT nerve: feed the SEPARATE-channel ledgers. Gated — no-op when
        # `bva` is off, so observe() stays byte-identical. Even when ON it only fills the
        # broadcast ledger; findings come from the explicit bva_findings() method, a
        # channel distinct from engine.findings.
        if getattr(self, "bva", False):
            self._bva_feed(ex)
        # DIAGNOSTICS CAPTURE: retain the raw exchange for the export file. Gated —
        # `capture` is None by default, so this is a no-op and observe() stays
        # byte-identical. A real scan sets `engine.capture = []` before the loop.
        _cap = getattr(self, "capture", None)
        if _cap is not None:
            _cap.append(ex)

    def _nerve_bridge(self):
        """Lazily build the NerveBridge over THIS engine's audited confirmer. Built
        only when the `nerve` flag is on; never touched otherwise (byte-identical)."""
        br = getattr(self, "_nerve", None)
        if br is None:
            from .nerve_bridge import NerveBridge
            anon = next((p for p in self.principals.values()
                         if getattr(p, "is_anonymous", False)), None)
            br = NerveBridge(self.confirmer, principals_by_identity={},
                             anon_principal=anon)
            self._nerve = br
        return br

    def _nerve_feed(self, ex: Exchange) -> None:
        """Feed one observed exchange into the nerve's three ledgers. SENTINEL-isolated:
        any failure is contained and can never perturb the live pipeline (the nerve is
        a separate channel)."""
        try:
            br = self._nerve_bridge()
            fp = ex.principal.pid                       # stable per-principal fingerprint
            br.feed_self(fp, ex.request, ex.response, principal=ex.principal)
            br.feed_owned(ex.request, ex.response, fp)
            br.feed_access(ex.request, ex.response, fp)
        except Exception:                               # noqa: BLE001 — never crash the scan
            self._pass_errors = getattr(self, "_pass_errors", 0) + 1

    def nerve_findings(self) -> list:
        """Run the nerve's live Δstate confirmation over everything observed and return
        its findings. A SEPARATE channel: this does NOT write to self.findings and does
        not alter any existing output. Empty unless the `nerve` flag was on during
        observation. Each finding is proven by a live read-back as the declared owner;
        unconfirmed candidates are dropped (RL5)."""
        br = getattr(self, "_nerve", None)
        if br is None:
            return []
        return br.confirmed_findings()

    def nerve_diagnostics(self) -> dict:
        """The nerve's real-target self-diagnosis (coverage + abstention taxonomy +
        findings). Empty when the nerve flag was off during observation. This is the
        payload the dashboard's EXPORT JSON button / CLI export ships so you can see
        where the nerve had reach and where it was blind."""
        br = getattr(self, "_nerve", None)
        if br is None:
            return {"enabled": False, "note": "nerve flag was off; no diagnosis collected"}
        d = br.diagnostics()
        d["enabled"] = True
        return d

    def _bva_channel(self):
        """Lazily build the Broadcast-vs-Act channel (declaration ledger + attestation
        + act bridge over THIS engine's audited confirmer). Built only when `bva` is on;
        never touched otherwise (byte-identical)."""
        ch = getattr(self, "_bva", None)
        if ch is None:
            from .broadcast import BroadcastLedger
            from .attestation import AttestationLedger
            from .act_bridge import ActBridge
            ch = {"broadcast": BroadcastLedger(), "attest": AttestationLedger(),
                  "by_identity": {}, "read_req": {}, "bridge": None}
            if getattr(self, "stateful_attribution", False):
                if self._nonce_authority is None:
                    from .nonce_provenance import NonceAuthority, NonceSeeker
                    self._nonce_authority = NonceAuthority(ledger=self.ledger)
                    self._nonce_seeker = NonceSeeker(self._nonce_authority)
                ch["bridge"] = ActBridge(self.confirmer, ch["by_identity"],
                                         nonce_authority=self._nonce_authority,
                                         seeker=self._nonce_seeker)
            else:
                ch["bridge"] = ActBridge(self.confirmer, ch["by_identity"])
            self._bva = ch
        return ch

    def _bva_feed(self, ex: Exchange) -> None:
        """Feed one exchange into the BvA channel. SENTINEL-isolated; any failure is
        contained and cannot perturb the live pipeline (separate channel)."""
        try:
            from .surface_map import identify
            from .attestation import _scalar_fields
            ch = self._bva_channel()
            fp = ex.principal.pid
            ch["attest"].record_self_response(fp, ex.request, ex.response)
            ident = ch["attest"].identity_of(fp) or fp
            ch["by_identity"].setdefault(ident, ex.principal)
            # declared role from a self response (the FP guard's signal)
            role = _bva_role(ex.request, ex.response)
            if role:
                ch["broadcast"].note_declared_role(ident, role)
            # record the broadcast for this principal+resource
            ri = identify(ex.request)
            if ri is not None:
                ch["broadcast"].record(ident, str(ri), ex.response,
                                       is_anonymous=getattr(ex.principal, "is_anonymous", False))
                # keep a GET request to re-read this resource during confirmation
                if getattr(ex.request, "method", "GET").upper() in ("GET", "HEAD"):
                    ch["read_req"].setdefault(str(ri), ex.request)
        except Exception:                               # noqa: BLE001 — never crash the scan
            self._pass_errors = getattr(self, "_pass_errors", 0) + 1

    def massassign_findings(self, self_path: str = "/api/me") -> list:
        """Write-side BOPLA channel (mass-assignment). Empty unless `bva` was on."""
        return _massassign_findings(self, self_path)

    def bva_findings(self) -> list:
        """Run the Broadcast-vs-Act nerve over everything observed: broadcast-difference
        candidates → field-leak confrontations → live Δstate confirmation. A SEPARATE
        channel — never writes engine.findings. Empty unless `bva` was on during
        observation. Each finding is proven by live reads as the accessor AND the
        privileged viewer; unconfirmed candidates abstain (RL5)."""
        ch = getattr(self, "_bva", None)
        if ch is None:
            return []
        from .act_confront import Confrontation
        out = []
        for cand in ch["broadcast"].broadcast_difference_candidates():
            resource = cand["resource"]
            read_req = ch["read_req"].get(resource)
            if read_req is None:
                continue                                # no GET to re-read with ⇒ skip
            # fields the target showed A but hid from B → B is the leaked-to accessor,
            # A is the privileged viewer whose real value proves the leak.
            for field, accessor, owner in (
                    [(f, cand["accessor_b"], cand["accessor_a"]) for f in cand["fields_only_a"]]
                    + [(f, cand["accessor_a"], cand["accessor_b"]) for f in cand["fields_only_b"]]):
                conf = Confrontation(kind="hidden_field", accessor=accessor,
                                     resource=resource, verb="GET", declared=field,
                                     owner_hint=owner)
                f = ch["bridge"].confirm_field_leak(conf, owner, read_req)
                if f is not None:
                    out.append(f)
            # actions the target offered the OWNER but withheld from the NON-owner → the
            # non-owner attempts the action; if the act executes it (2xx), that is BFLA.
            # The mutation is scope-gated inside confirm_action (default dry_run ⇒ abstain).
            from .act_confront import _verb_for_action
            from .models import HTTPRequest
            owner_a = cand["accessor_a"] if ch["broadcast"]._by_resource.get(resource, {}).get(cand["accessor_a"]) and ch["broadcast"]._by_resource[resource][cand["accessor_a"]].is_owner else None
            owner_b = cand["accessor_b"] if ch["broadcast"]._by_resource.get(resource, {}).get(cand["accessor_b"]) and ch["broadcast"]._by_resource[resource][cand["accessor_b"]].is_owner else None
            for action, accessor, owner in (
                    [(a, cand["accessor_b"], owner_a) for a in cand["actions_only_a"]]
                    + [(a, cand["accessor_a"], owner_b) for a in cand["actions_only_b"]]):
                if owner is None:                       # only the owner-withheld direction
                    continue
                verb = _verb_for_action(action)
                mut = HTTPRequest(verb, getattr(read_req, "path", f"/{resource.replace(':', '/')}"),
                                  host=getattr(read_req, "host", ""))
                conf = Confrontation(kind="hidden_action", accessor=accessor,
                                     resource=resource, verb=verb, declared=action,
                                     owner_hint=owner)
                f = ch["bridge"].confirm_action(conf, mut)
                if f is not None:
                    out.append(f)
                fd = self._bva_drift_probe(ch, conf, verb, mut, owner, read_req)
                if fd is not None:
                    out.append(fd)
        # AUTHN-gap: an ANONYMOUS principal received a 200 body that DECLARES an owner
        # (a private resource served without a token). The owner_ref is a real attested
        # identity, and anon is provably not that owner → candidate. Confirm by Δstate:
        # re-read as the declared owner; the anon body must carry the owner's real private
        # datum (value match), proving owner-scoped private data, not a public field.
        # Abstain when the anon body declares no owner (could legitimately be public) — RL5.
        for resource, per_acc in ch["broadcast"]._by_resource.items():
            read_req = ch["read_req"].get(resource)
            if read_req is None:
                continue
            for pb in per_acc.values():
                if not (pb.is_anonymous and pb.accessible and pb.owner_ref):
                    continue                            # not anon / not 200 / no private decl
                owner = ch["by_identity"].get(pb.owner_ref)
                if owner is None or pb.owner_ref == pb.accessor:
                    ch["bridge"].abstained.append((resource, "authn-gap: owner not provisioned"))
                    continue
                f = ch["bridge"].confirm_authn_gap(resource, pb.accessor, pb.owner_ref,
                                                   owner, read_req)
                if f is not None:
                    out.append(f)
        return out

    def _bva_drift_probe(self, ch, conf, verb, mut, owner, read_req):
        """G2 object-binding-drift probe on an owner-withheld action. Additive and
        flag-gated: no-op unless a nonce authority is wired (stateful_attribution on)
        and an owner is known. Stamps a unique marker into a conditional write and
        delegates to the tested `confirm_action_conditional` (scope-gated; dry_run ⇒
        abstain, zero-harm). Returns a finding or None."""
        bridge = ch["bridge"]
        if getattr(bridge, "nonce_authority", None) is None or owner is None:
            return None
        from .models import HTTPRequest
        marker = bridge.nonce_authority.mint(f"drift {conf.resource}").as_text()
        marked = HTTPRequest(verb, getattr(mut, "path", ""),
                             host=getattr(mut, "host", ""),
                             body={"_onyx_drift_probe": marker})
        return bridge.confirm_action_conditional(
            conf, marked, owner_identity=owner, drift_marker=marker,
            host=getattr(read_req, "host", ""))

    def bva_diagnostics(self) -> dict:
        """The Broadcast-vs-Act nerve's real-target self-diagnosis: where it had reach
        (identities attested, declared roles seen, resources with a role-pair to compare)
        and why confirmations abstained. Empty when bva was off. Separate channel — does
        not touch engine.findings."""
        ch = getattr(self, "_bva", None)
        if ch is None:
            return {"enabled": False, "note": "bva flag was off; no diagnosis collected"}
        cands = ch["broadcast"].broadcast_difference_candidates()
        findings = self.bva_findings()
        by_reason: dict = {}
        for _res, why in ch["bridge"].abstained:
            tag = ("owner_not_provisioned" if "owner not provisioned" in why else
                   "not_exposed" if "not actually exposed" in why else
                   "owner_readback_failed" if "read-back failed" in why else
                   "value_mismatch" if "!= owner value" in why else
                   "accessor_read_failed" if "accessor read" in why else "other")
            by_reason[tag] = by_reason.get(tag, 0) + 1
        return {
            "enabled": True,
            "coverage": {
                "identities_attested": len(ch["attest"]._identity),
                "roles_declared": len(ch["broadcast"]._declared_role),
                "resources_observed": len(ch["broadcast"]._by_resource),
                "resources_with_readback": len(ch["read_req"]),
            },
            "funnel": {
                "broadcast_candidates": len(cands),
                "confirmed_findings": len(findings),
                "abstained_total": len(ch["bridge"].abstained),
                "abstained_by_reason": by_reason,
            },
            "findings": [{"resource": f.resource, "accessor": f.accessor,
                          "field": f.field, "owner": f.owner} for f in findings],
        }

    def _record_credential_lifecycle(self, ex: Exchange) -> None:
        """RL11: persist FINGERPRINTED cross-session facts and surface provisional
        leads for contradictions no single run could observe. Two independent
        signals, both no-ops when the store is disabled (byte-identical):
          * credential lifecycle — a credential DENIED (401/403) in a prior session
            now ALLOWED (2xx) ⇒ CREDENTIAL_RESURRECTION lead (revocation reversed);
          * single-use ledger — a successful coupon/single-use TOKEN redemption is
            recorded so the NEXT session's CouponLaw detects cross-session replay.
        Never a finding by itself — the Δstate confirmer still decides."""
        if not getattr(self, "store", None) or not self.store.enabled:
            return
        ts = float(getattr(ex, "observed_at", 0.0) or 0.0)
        status = ex.response.status
        # --- credential lifecycle (needs an Authorization credential) ---
        headers = ex.request.headers or {}
        cred = headers.get("Authorization") or headers.get("authorization")
        if cred:
            from .persistence import ALLOWED, DENIED
            status_class = ALLOWED if 200 <= status < 300 else (
                DENIED if status in (401, 403) else None)
            if status_class is not None:
                anomaly = self.store.record_credential(
                    cred, status_class, ex.request.endpoint_key(), ts)
                if anomaly:
                    from .intrinsic import Lead, Confidence
                    self.leads.append((f"obs-{self._seq}", Lead(
                        kind="CREDENTIAL_RESURRECTION", family=anomaly["endpoint"],
                        principal=ex.principal.pid, paths=[],
                        weight=8, confidence=Confidence.STRONG_LEAD, confirmable=True,
                        rationale=("a credential REJECTED (401/403) in a prior session is "
                                   "now ACCEPTED (2xx) — revocation appears reversed or the "
                                   "credential is replayable across sessions; cross-session "
                                   "evidence no single run could observe"),
                        suggested_probe="replay the previously-revoked credential now; if it "
                                        "is honoured, the revocation did not stick",
                        evidence={"cross_session": True, "fingerprint": anomaly["fp"],
                                  "first_denied": anomaly["first_denied"],
                                  "now_allowed_at": anomaly["now_allowed_at"]})))
        # --- single-use ledger (coupon/one-time TOKEN in a successful request) ---
        if 200 <= status < 300:
            from .provenance import extract_values, ValueClass
            for tv in extract_values(ex.request.body):
                if tv.value_class == ValueClass.TOKEN:
                    self.store.record_artifact(str(tv.value), ts)

    def save_store(self) -> None:
        """Persist the sealed cross-session memory (no-op when disabled)."""
        if getattr(self, "store", None):
            self.store.save()

    @staticmethod
    def _struct_body(ex: Exchange):
        """The body the STRUCTURAL engines should analyse. For a GraphQL response
        this is the `data` object graph (projected away from the {data,errors}
        envelope), so SAIE / sibling / missing-shadow / normalisation all operate
        on the real object. For REST it is the body unchanged => byte-identical."""
        body = ex.response.body
        if ex.request.is_graphql():
            from .graphql import response_data
            data = response_data(body)
            if data is not None:
                return data
        return body

    def _saie_seed(self, ex: Exchange) -> None:
        if not (200 <= ex.response.status < 300):
            return
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        family = ex.request.endpoint_key()
        key = self._stability_key(ex)
        self.stability_gate.observe_repeat(family, key, body)
        self.coherence.add(ex.principal.pid, family, key, body)

    def ingest_grammar(self, ex: Exchange) -> None:
        """Offline-ingest helper: feed a captured exchange to the SAIE grammar
        builders ONLY (no envelope ownership, no origin table). Used by the HAR
        ingest driver to establish stability/coherence across a capture before the
        analysis pass, without falsely marking cross-principal accesses as owned."""
        self._saie_seed(ex)

    @staticmethod
    def _stability_key(ex: Exchange) -> str:
        """Identity of a repeatable request: principal + endpoint family + the
        sorted object-ids that parameterise it. Repeats of THIS exact request are
        what the stability gate compares (value-blind) to prove a stable shape."""
        try:
            oids = ",".join(sorted(str(o) for o in ex.request.object_ids()))
        except Exception:
            oids = ""
        return f"{ex.principal.pid}::{ex.request.endpoint_key()}::{oids}"

    # -- phase 2: detect on a probe action --------------------------------- #
    def analyze(self, ex: Exchange, defer: bool = False) -> PipelineTrace:
        tr = PipelineTrace(
            tid="T-" + uuid.uuid4().hex[:8],
            principal=ex.principal.pid,
            method=ex.request.method,
            path=ex.request.path,
            endpoint=ex.request.endpoint_key(),
            status_code=ex.response.status,
        )

        # ⓪ Scope-Guard — fail-safe to inaction
        sg = self.scope_guard.check(ex.request)
        if sg.verdict is ScopeVerdict.HALT:
            tr.add("Scope-Guard", "halt", sg.reason)
            tr.outcome = "halted"
            return self._finish(ex, tr)
        tr.add("Scope-Guard", "ok", sg.reason)

        # Deficiency #9: the ROE contract governs every capability. Empty/inactive contract
        # is a no-op (byte-identical) so ScopeGuard stays the sole gate. When active, each
        # action must trace to an authorizing clause across every level (policy / scope /
        # data / fine-destruction); anything unauthorized fails CLOSED, and the decision is
        # written to a tamper-evident audit that cites its clause.
        contract = getattr(self, "contract_roe", None)
        if contract is not None and contract.active():
            try:
                res = ""
                oids = ex.request.object_ids()
                res = str(oids[0]) if oids else ""
            except Exception:
                res = ""
            dec = contract.authorize(ex.request.method, ex.request.path, ex.principal.pid,
                                     cross_principal=True, resource=res)
            audit = getattr(self, "audit", None)
            if audit is not None:
                audit.record(ex.request.method, ex.request.path, ex.principal.pid, dec)
            if not dec.allowed:
                tr.add("ROE", "halt", f"{dec.reason} [clause: {dec.clause}]")
                tr.outcome = "roe_halted"
                return self._finish(ex, tr)
            tr.add("ROE", "ok", f"authorized [clause: {dec.clause}]")
        # Deficiency #3 (flag-gated, default OFF). A NEGATIVE result (401/403/session-
        # expired) is trustworthy ONLY if the principal's credential was LIVE at this
        # moment. Otherwise a dead-token authN failure would masquerade as "access denied
        # = safe" (a silent false negative) or corrupt a Δstate read-back. We do NOT parse
        # the 401; we prove liveness with an independent probe (re-authing once if the
        # operator supplied a callback). Dead credential -> abstain, never "safe". This
        # makes 401-conflation impossible by construction and strengthens zero-FP.
        if getattr(self, "liveness_gating", False):
            sm = getattr(self, "session_manager", None)
            if sm is not None and sm.can_gate() and ex.response.status in (401, 403, 419, 440):
                def _apply(pr, fresh):
                    try: pr.auth.update(fresh)
                    except Exception: pass
                state = sm.ensure_live(ex.principal, apply_auth=_apply)
                if state != "live":
                    reason = ("credential attestation-closed (device-bound) — surface not "
                              "coverable by an external tool"
                              if sm.is_attestation_closed(ex.principal.pid)
                              else "credential re-authenticated — this response is stale, re-issue"
                              if state == "revived"
                              else "credential not live — authN failure, not an authZ signal")
                    tr.add("Liveness", "abstain", reason)
                    tr.outcome = "authn_contaminated"
                    self._authn_contaminated = getattr(self, "_authn_contaminated", 0) + 1
                    return self._finish(ex, tr)
                tr.add("Liveness", "ok", "credential proven live — 401/403 is a real authZ signal")

        # RL7 honesty gate (Slice 6): if the captured body is a non-JSON wire format
        # the codec could NOT structurally decode, every downstream law would see an
        # empty exchange and (falsely) report it clean. Surface the opacity HONESTLY
        # instead: an explicit "opaque body — not analyzed" outcome + a lead, so the
        # endpoint is never silently certified safe. JSON/decoded bodies are not
        # opaque, so this is inert on the calibration (byte-identical).
        from .codec import normalize_body, is_opaque
        _schema = self.schemas.get(ex.request.endpoint_key()) if getattr(self, "schemas", None) else None
        _ctype = ((ex.response.headers or {}).get("content-type")
                  if isinstance(getattr(ex.response, "headers", None), dict) else None)
        _norm = normalize_body(ex.response.body, _ctype, schema=_schema)
        if is_opaque(_norm.data):
            tr.add("Codec", "opaque",
                   f"body is an undecodable wire format ({_norm.fmt}, "
                   f"{_norm.data.get('bytes', 0)} bytes) — NOT analyzed; endpoint is "
                   f"NOT certified clean (provide a schema/decoder to analyze)")
            tr.outcome = "opaque-unanalyzed"
            from .intrinsic import Lead, Confidence
            self.leads.append((tr.tid, Lead(
                kind="OPAQUE_BODY", family=ex.request.endpoint_key(),
                principal=ex.principal.pid, paths=[],
                weight=1, confidence=Confidence.LEAD, confirmable=False,
                rationale=("response body could not be structurally decoded "
                           f"({_norm.fmt}); it was NOT analyzed and must NOT be "
                           "treated as clean — supply the wire schema to enable analysis"),
                suggested_probe="capture this endpoint with its decoded representation "
                                "or register its protobuf/format schema",
                evidence={"opaque": True, "format": _norm.fmt,
                          "bytes": _norm.data.get("bytes", 0)})))
            self.traces.append(tr)
            return tr
        # RL7/RL7.2: if a non-JSON body decoded to canonical (named, when a schema
        # is registered) structure, the rest of the pipeline operates on it. JSON
        # decodes to itself (identity) so this is byte-identical on the calibration.
        if _norm.fmt not in ("json", "empty", "scalar") and _norm.is_structured:
            ex.response.body = _norm.data

        # record this access in the cross-request ledger (dev idea #2, safe part)
        self._record_access(ex)
        self._audience_check(ex, tr)
        self._seq += 1
        cur_seq = self._seq
        self._cur_seq = cur_seq
        self.lifecycle.record(cur_seq, ex.request, ex.response, ex.principal.pid, ex.principal)
        # note a successful privilege-narrowing event (credential stays valid)
        if 200 <= ex.response.status < 300:
            aff, kind = self._role_change_eps.get(ex.request.endpoint_key(), (None, None))
            if aff is not None:
                for pid in (aff or {ex.principal.pid}):
                    self._role_narrowed.setdefault(pid, (cur_seq, kind,
                                                          ex.request.endpoint_key()))
                    # RL16: a declared role change advances the principal's epoch, so
                    # auth-shape snapshots across the change are never compared
                    # (a legitimate promotion/demotion is not a regression).
                    self._role_epoch[pid] = self._role_epoch.get(pid, 0) + 1

        # ② Contract Resolver — effect classification (only probabilistic step)
        cls = self.contract.classify(ex)
        tr.add("Contract Resolver", "ok",
               f"effect={cls.effect.value} via {cls.source.value}"
               + (" (high-caution)" if cls.high_caution else ""),
               effect=cls.effect.value, source=cls.source.value,
               high_caution=cls.high_caution)

        # ③ Value-Origin Provenance — tag values (proven). For a probe we count
        # for display but DO NOT pollute the legitimacy index before the law runs.
        tagged = self.provenance.tag_only(ex)
        tr.add("Value-Origin", "ok",
               f"tagged {tagged} structurally-significant value(s)", tagged=tagged)

        # ⑤ EIL — derived-law evaluation (against the legitimately-built store)
        ctx = LawContext(ex, cls, self.provenance, self.envelopes,
                         state_gates=self.state_gates,
                         lifecycle=self.lifecycle, seq=cur_seq, store=self.store,
                         actor_roles=self._actor_roles, role_ranks=self._role_ranks,
                         resource_parents=self._resource_parents)
        verdict = self.eil.evaluate(ctx)
        # record probe origins AFTER evaluation, into the origin table only, so
        # cross-exchange counting (e.g. coupon replay) still works.
        self.provenance.observe_response(ex, legitimate=False)
        if verdict.verdict is Verdict.SKIP:
            tr.add("EIL", "skip", verdict.reason)
            tr.outcome = "clean"
            return self._finish(ex, tr)
        if verdict.verdict is Verdict.PASS:
            tr.add("EIL", "pass", verdict.reason, law=verdict.law_name)
            tr.outcome = "clean"
            return self._finish(ex, tr)

        # CANDIDATE — must be Δstate-confirmed (RL3)
        tr.add("EIL", "candidate", f"{verdict.law_name} → {verdict.reason}",
               law=verdict.law_name, impact=verdict.impact.value if verdict.impact else None)
        cand = Candidate(
            cid="C-" + uuid.uuid4().hex[:8],
            exchange=ex,
            classification=cls,
            verdict=verdict,
            causal_origin=verdict.evidence.get("laundered_from"),
        )

        # HARD GATE (defect #1/#3): offline mode cannot CONFIRM a leak — the only
        # read-back available is the capture itself, which cannot prove ownership.
        # Demote to a lead instead of fabricating a finding.
        if self.offline and verdict.effect.value in ("OBJECT_ACCESS", "AUTHORITY"):
            tr.add("Confirmer", "unconfirmed",
                   "offline capture cannot prove Δstate ownership — emitted as a "
                   "cross-principal lead instead (run `scan` to confirm live)")
            tr.outcome = "candidate-unconfirmed"
            return self._finish(ex, tr)

        # RL6 allocator seam (Slice 3): in a budgeted run we do NOT confirm inline.
        # We score the candidate passively (zero network) and buffer it; the
        # BudgetedScanner later drains the buffer in yield-descending order under
        # the ledger, so the scarce request budget is spent on the highest-value
        # candidates first. defer=False (the default) ⇒ inline confirm, unchanged.
        if defer:
            from .economy import yield_score
            self._deferred.append((yield_score(cand), self._defer_seq(), cand, tr))
            tr.add("Allocator", "deferred",
                   "candidate buffered for value-ordered confirmation under budget")
            tr.outcome = "deferred"
            self.traces.append(tr)
            return tr

        # ⑥ Multi-Principal Differential Confirmer — confirm by Δstate
        proof = self.confirmer.confirm(cand)
        if proof is None or not proof.confirmed:
            if self._drain_instability(cand, tr):
                return self._finish(ex, tr)
            tr.add("Confirmer", "unconfirmed",
                   "no proven Δstate — candidate dropped (a status/length diff is NOT a finding)")
            tr.outcome = "candidate-unconfirmed"
            return self._finish(ex, tr)
        tr.add("Confirmer", "confirmed",
               f"Δstate proven: {proof.before} → {proof.after} (read as {proof.read_as})")

        # Cross-method enrichment (dev idea #2, safe part): if the ledger shows
        # the same actor was denied on the same object via another method, attach
        # it as corroborating evidence. Runs only on a confirmed finding.
        oid = (cand.verdict.evidence or {}).get("object_id")
        if oid is not None:
            note = self._cross_method_note(str(oid), ex.principal.pid, ex.request.method)
            if note:
                cand.verdict.evidence["cross_method_note"] = note

        # ⑦ Evidence→PoC Emitter — make it reportable
        finding = self.emitter.emit(cand, proof)
        if not self._emit_finding(finding):
            tr.outcome = "clean"
            return self._finish(ex, tr)
        tr.add("Evidence→PoC", "ok",
               f"{finding.severity.value} · {finding.impact.value}",
               finding_id=finding.fid)
        tr.outcome = "finding"
        tr.finding_id = finding.fid
        return self._finish(ex, tr)

    def _defer_seq(self) -> int:
        self._defer_counter += 1
        return self._defer_counter

    def _drain_instability(self, cand, tr) -> bool:
        """RL10: if the confirmer's read-consistency window did not stabilise for
        this candidate, surface it as an honest provisional lead (never a finding,
        never a silent drop). Inert when consistency_reads=1 (nothing is logged)."""
        unstable = getattr(self.confirmer, "_unstable", None)
        if not unstable:
            return False
        # consume entries (the window just ran for this candidate)
        entries, self.confirmer._unstable = unstable, []
        ep = cand.exchange.request.endpoint_key()
        mine = [u for u in entries if u.get("endpoint") == ep]
        if not mine:
            self.confirmer._unstable = entries        # not ours — leave intact
            return False
        from .intrinsic import Lead, Confidence
        tr.add("Confirmer", "unstable",
               "read-back did not stabilise within the consistency window — "
               "emitted as a lead for deliberate re-test (NOT cleared as safe)")
        tr.outcome = "candidate-unconfirmed"
        self.leads.append((tr.tid, Lead(
            kind="CONSISTENCY_UNSTABLE", family=ep,
            principal=cand.exchange.principal.pid, paths=[],
            weight=5, confidence=Confidence.LEAD, confirmable=True,
            rationale=("the Δstate read-back flickered across the consistency window "
                       "(eventually-consistent or flaky backend); the candidate was "
                       "neither confirmed nor cleared — re-test with a wider window"),
            suggested_probe="re-run with a larger --consistency-reads window once the "
                            "backend has converged",
            evidence={"unstable": True, "effect": cand.verdict.effect.value})))
        return True

    def _audience_check(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL9 companion: flag JWT AUDIENCE CONFUSION — a token minted for one
        service accepted by another. Conservative + provisional: emits a LEAD
        (never a finding — token validity has no Δstate proof) and ONLY when the
        signal is unambiguous: the request SUCCEEDED, carries a JWT with a
        HOST-LIKE `aud` claim (a hostname/URL, not an opaque client-id), and the
        request's host is not covered by that audience. Opaque/identifier auds are
        skipped (cannot tell), so this stays low-noise."""
        if not (200 <= ex.response.status < 300):
            return
        host = (ex.request.host or "").strip().lower()
        if not host:
            return
        auth = (ex.request.headers or {}).get("Authorization") or \
               (ex.request.headers or {}).get("authorization")
        if not auth:
            return
        from .provenance import inspect_jwt
        jwt = inspect_jwt(auth)
        if jwt is None:
            return
        aud = jwt.raw_claims.get("aud")
        auds = aud if isinstance(aud, list) else ([aud] if aud is not None else [])
        host_like = [str(a) for a in auds if _host_like(str(a))]
        if not host_like:
            return                                  # opaque/identifier aud — skip
        if any(_host_covered(host, str(a)) for a in host_like):
            return                                  # host is within the audience
        from .intrinsic import Lead, Confidence
        self.leads.append((tr.tid, Lead(
            kind="TOKEN_AUDIENCE_CONFUSION", family=ex.request.endpoint_key(),
            principal=ex.principal.pid, paths=[],
            weight=6, confidence=Confidence.STRONG_LEAD, confirmable=True,
            rationale=(f"a JWT whose declared audience {host_like} does not cover "
                       f"the service '{host}' was ACCEPTED (status {ex.response.status}) "
                       f"— possible cross-service token/audience confusion: this "
                       f"service honoured a token minted for a different audience"),
            suggested_probe=(f"replay this request's token against '{host}' and against "
                             f"its declared audience; if '{host}' accepts a token not "
                             f"minted for it, the audience check is missing"),
            evidence={"request_host": host, "token_audience": host_like,
                      "status": ex.response.status})))

    def drain_deferred(self) -> dict:
        """RL6 allocator (Slice 3): confirm buffered candidates in yield-descending
        order under the ledger. Because spend is value-prioritised, the highest-
        value findings are proven first; when the budget is exhausted the remaining
        candidates degrade to HONEST leads (tagged budget-deferred) — never silent
        drops, never status-only confirmations. Deterministic: ties broken by
        insertion order. Returns a small accounting summary."""
        # value DESC, then insertion order ASC (stable, deterministic)
        queue = sorted(self._deferred, key=lambda t: (-t[0], t[1]))
        self._deferred = []
        confirmed = budget_deferred = dropped = 0
        for score, _seq, cand, tr in queue:
            # If the ledger is already exhausted/frozen for this host, don't even
            # attempt — degrade straight to an honest budget-deferred lead.
            host = getattr(cand.exchange.request, "host", "") or ""
            if self.ledger.can_spend(host) is not None:
                self._defer_to_lead(cand, tr, score, reason="budget")
                budget_deferred += 1
                continue
            proof = self.confirmer.confirm(cand)
            if proof is None or not proof.confirmed:
                # Distinguish "proven clean / no Δstate" from "ran out of budget
                # mid-confirmation": if budget got exhausted while confirming, it's
                # a deferred lead; otherwise it's a genuine unconfirmed drop.
                if self.ledger.can_spend(host) is not None:
                    self._defer_to_lead(cand, tr, score, reason="budget")
                    budget_deferred += 1
                else:
                    tr.add("Confirmer", "unconfirmed",
                           "no proven Δstate — candidate dropped (status/length diff is NOT a finding)")
                    tr.outcome = "candidate-unconfirmed"
                    dropped += 1
                continue
            tr.add("Confirmer", "confirmed",
                   f"Δstate proven: {proof.before} → {proof.after} (read as {proof.read_as})")
            finding = self.emitter.emit(cand, proof)
            if self._emit_finding(finding):
                tr.add("Evidence→PoC", "ok",
                       f"{finding.severity.value} · {finding.impact.value}",
                       finding_id=finding.fid)
                tr.outcome = "finding"
                tr.finding_id = finding.fid
                confirmed += 1
            else:
                tr.outcome = "clean"
        return {"confirmed": confirmed, "budget_deferred": budget_deferred,
                "dropped": dropped, "ledger": self.ledger.summary()}

    def _defer_to_lead(self, cand, tr, score, reason: str) -> None:
        """Degrade an unconfirmed-for-budget candidate to an honest lead so it is
        surfaced for deliberate follow-up rather than lost."""
        from .intrinsic import Lead, Confidence
        tr.add("Allocator", "budget-deferred",
               f"value={score} — budget exhausted before confirmation; emitted as a "
               f"lead for deliberate follow-up (not a clean verdict)")
        tr.outcome = "candidate-unconfirmed"
        self.leads.append((tr.tid, Lead(
            kind=cand.verdict.effect.value,
            family=cand.exchange.request.endpoint_key(),
            principal=cand.exchange.principal.pid,
            paths=[],
            weight=int(round(score * 10)),
            confidence=Confidence.STRONG_LEAD,
            confirmable=True,
            rationale=(f"BUDGET-DEFERRED (value={score}): {cand.verdict.reason} — "
                       f"unconfirmed ONLY because the request budget was exhausted, "
                       f"NOT because it was proven clean"),
            suggested_probe="re-run with additional request budget to confirm this "
                            "high-value candidate by Δstate read-back",
            evidence={"budget_deferred": True, "yield_score": score,
                      "effect": cand.verdict.effect.value})))

    # -- SAIE additive pass (design requirement #4: additive isolation) ----------- #
    def _finish(self, ex: Exchange, tr: PipelineTrace) -> PipelineTrace:
        """Single tail for every analyze() outcome. Runs the independent SAIE
        structural pass when the main pipeline did NOT already produce a finding
        or halt, then records the trace. Deleting the single `_structural_pass`
        call below restores byte-identical behaviour to the pre-SAIE engine.

        SENTINEL S1: every additive pass runs under `_guard`, so an unexpected
        exception on a messy REAL response becomes a VISIBLE coverage-gap diagnostic
        on the trace (and a counter) instead of either crashing the whole scan or
        silently producing a false 'clean'. On well-formed data no pass raises, so
        the guard is inert and behaviour is byte-identical."""
        if tr.outcome not in ("finding", "halted"):
            self._guard("SAIE", self._structural_pass, ex, tr)
        if getattr(self, "cross_surface", False) and tr.outcome not in ("finding", "halted"):
            self._guard("CrossSurface", self._cross_surface_pass, ex, tr)
        # RL17 runs even after a cross-surface finding: it catches the SIBLING cells
        # in the same list that the single RL15 candidate did not cover.
        if getattr(self, "combinatorial", False) and tr.outcome != "halted":
            self._guard("Hypothesis", self._combinatorial_pass, ex, tr)
        if getattr(self, "temporal_shape", False) and tr.outcome not in ("finding", "halted"):
            self._guard("AuthRegression", self._auth_regression_pass, ex, tr)
        if getattr(self, "global_invariants", False) and tr.outcome not in ("finding", "halted"):
            self._guard("GlobalInvariant", self._global_invariant_pass, ex, tr)
        if getattr(self, "conservation", False) and tr.outcome not in ("finding", "halted"):
            self._guard("Conservation", self._conservation_pass, ex, tr)
        if getattr(self, "embedded_owner_exposure", False) and tr.outcome not in ("finding", "halted"):
            self._guard("EmbeddedOwner", self._embedded_owner_exposure_pass, ex, tr)
        if getattr(self, "field_exposure", False) and tr.outcome not in ("finding", "halted"):
            self._guard("FieldExposure", self._field_exposure_pass, ex, tr)
        if getattr(self, "xprincipal_write", False) and tr.outcome not in ("finding", "halted"):
            self._guard("XPrincipalWrite", self._xprincipal_write_pass, ex, tr)
        if getattr(self, "xprincipal_delete", False) and tr.outcome not in ("finding", "halted"):
            self._guard("XPrincipalDelete", self._xprincipal_delete_pass, ex, tr)
        if getattr(self, "consequence_confirmation", False) and tr.outcome not in ("finding", "halted"):
            self._guard("Consequence", self._consequence_pass, ex, tr)
        self._guard("Intrinsic", self._intrinsic_pass, ex, tr)
        self.traces.append(tr)
        return tr

    def _guard(self, name: str, passfn, ex: Exchange, tr: PipelineTrace) -> None:
        """Run an additive detection pass in isolation. An unexpected exception is
        turned into a VISIBLE diagnostic (coverage honesty) and counted, never
        swallowed into a false 'clean' and never allowed to crash the run. A finding
        already produced by the pass is unaffected (it is emitted before any raise on
        a later element only if the pass itself committed it)."""
        try:
            passfn(ex, tr)
        except Exception as exc:               # noqa: BLE001 — deliberate: isolate the pass
            self._pass_errors += 1
            tr.add(name, "errored",
                   f"additive pass raised {type(exc).__name__}: {str(exc)[:160]} — "
                   f"recorded as a coverage gap (NOT a clean result); other passes and "
                   f"exchanges continue")

    def _intrinsic_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """Mine THIS single response for reference-free structural leads (ISI).
        Leads are a separate channel: this never touches tr.stages/outcome or
        findings, so removing it leaves all verdicts and traces byte-identical.
        Skipped when the exchange already became a finding (its evidence is
        captured there) or was halted by Scope-Guard."""
        if tr.outcome in ("finding", "halted"):
            return
        # Intrinsic signals self-gate, so we interrogate ANY structural body —
        # including 4xx denials, which is where AUTHZ_ORACLE disclosures live.
        sbody = self._struct_body(ex)
        if not isinstance(sbody, (dict, list)):
            self._graphql_pass(ex, tr)              # data may be null on a full denial
            return
        try:
            from .intrinsic import interrogate
            found = interrogate(sbody, ex.request.endpoint_key(),
                                ex.principal.pid)
        except Exception:
            found = []
        for lead in found:
            self.leads.append((tr.tid, lead))
        self._graphql_pass(ex, tr)                  # GraphQL field-level authz denials
        self._active_field_probe(ex, tr)            # controlled read-only confirmation (opt-in)
        self._chain_provenance(ex, tr)              # cross-step value migration (opt-in)
        self._elevate_leads(ex, tr, found)

    def _elevate_leads(self, ex: Exchange, tr: PipelineTrace, leads: list) -> None:
        """Attempt to graduate a confirmable intrinsic lead into a gated finding via
        a single Δstate read-back (RL3). Only sibling-asymmetry leads with a
        populated carrier are confirmable; everything else stays a lead. Additive:
        if nothing confirms, the trace/findings are unchanged."""
        if tr.outcome == "finding":
            return
        from .intrinsic import LeadKind
        cls = self.contract.classify(ex)
        for lead in leads:
            if lead.kind != LeadKind.SIBLING_ASYMMETRY or not lead.confirmable:
                continue
            ev = dict(lead.evidence)
            ev["object_id"] = (ev.get("populated_ids") or [None])[0]
            ev["laundered_from"] = None
            verdict = LawVerdict(
                Verdict.CANDIDATE, "ISI: SIBLING_ASYMMETRY",
                EffectClass.FIELD_PROJECTION, lead.rationale,
                ImpactClass.FIELD_PROJECTION_LEAK, ev)
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=verdict)
            proof = self.confirmer.confirm(cand)
            if proof is None or not proof.confirmed:
                continue
            tr.add("ISI", "confirmed",
                   f"intrinsic lead elevated by Δstate: {proof.before} → {proof.after}")
            finding = self.emitter.emit(cand, proof)
            if not self._emit_finding(finding):   # D-DEDUP-BYPASS fix (pass 5)
                continue
            tr.add("Evidence→PoC", "ok",
                   f"{finding.severity.value} · {finding.impact.value}",
                   finding_id=finding.fid)
            tr.outcome = "finding"
            tr.finding_id = finding.fid
            lead.confidence = "ELEVATED"
            return        # one finding per exchange

    def _auth_regression_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL16: an additive, flag-gated temporal pass that can only ADD a finding.
        It diffs the live value-blind authorization-shape against the prior snapshot
        for this (principal, endpoint, object); a sensitive field that crossed
        withheld→populated with no declared role change is a candidate, proven live
        by an intra-principal read-back. After comparing, it updates the snapshot so
        the series advances. Inert unless a prior snapshot exists."""
        body = self._struct_body(ex)
        epoch = self._role_epoch.get(ex.principal.pid, 0)
        if isinstance(body, (dict, list)):
            ctx = LawContext(ex, self.contract.classify(ex), self.provenance,
                             self.envelopes, state_gates=self.state_gates,
                             lifecycle=self.lifecycle, seq=self._seq,
                             store=self.store, auth_shape_ledger=self.auth_shape_ledger,
                             role_epoch=epoch)
            xv = self.eil.evaluate_auth_regression(ctx)
            if xv.verdict is Verdict.CANDIDATE:
                tr.add("AuthRegression", "candidate", f"{xv.law_name} → {xv.reason}",
                       law=xv.law_name, impact=xv.impact.value if xv.impact else None)
                cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                                 classification=ctx.classification, verdict=xv)
                proof = self.confirmer.confirm(cand)
                if proof is not None and proof.confirmed:
                    tr.add("AuthRegression", "confirmed",
                           f"Δstate proven: {proof.before} → {proof.after} "
                           f"(read as {proof.read_as})")
                    finding = self.emitter.emit(cand, proof)
                    if self._emit_finding(finding):
                        tr.add("Evidence→PoC", "ok",
                               f"{finding.severity.value} · {finding.impact.value}",
                               finding_id=finding.fid)
                        tr.outcome = "finding"
                        tr.finding_id = finding.fid
                else:
                    tr.add("AuthRegression", "unconfirmed",
                           "read-back did not reproduce the exposed field — transient, abstained")
        # advance the time-series regardless of verdict (this read becomes the new T1)
        self.auth_shape_ledger.record(ex.request, ex.response, ex.principal.pid,
                                      role_epoch=epoch)

    def _global_invariant_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL18: an additive, flag-gated, READ-ONLY pass that can only ADD a finding.
        It asks whether THIS exchange completes an emergent parent/child break — the
        principal accessing a child whose declared parent it was observed forbidden.
        Any candidate is proven by read-only read-backs of both child and parent
        (no writes ever issued — AEGIS gate 3). Inert unless a declared parent link
        and a prior parent-forbidden observation exist."""
        ctx = LawContext(ex, self.contract.classify(ex), self.provenance,
                         self.envelopes, state_gates=self.state_gates,
                         lifecycle=self.lifecycle, seq=self._seq,
                         store=self.store, invariant_ledger=self.invariant_ledger)
        xv = self.eil.evaluate_global_invariant(ctx)
        if xv.verdict is not Verdict.CANDIDATE:
            return
        tr.add("GlobalInvariant", "candidate", f"{xv.law_name} → {xv.reason}",
               law=xv.law_name, impact=xv.impact.value if xv.impact else None)
        cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                         classification=ctx.classification, verdict=xv)
        proof = self.confirmer.confirm(cand)
        if proof is None or not proof.confirmed:
            tr.add("GlobalInvariant", "unconfirmed",
                   "read-only read-back did not prove child-accessible ∧ parent-forbidden "
                   "(or child declares an independent grant) — abstained, no false positive")
            return
        tr.add("GlobalInvariant", "confirmed",
               f"Δstate proven: {proof.before} → {proof.after} (read as {proof.read_as})")
        finding = self.emitter.emit(cand, proof)
        if not self._emit_finding(finding):
            return
        tr.add("Evidence→PoC", "ok",
               f"{finding.severity.value} · {finding.impact.value}",
               finding_id=finding.fid)
        tr.outcome = "finding"
        tr.finding_id = finding.fid

    def _consequence_capability(self, ex: Exchange, tr: PipelineTrace, oracle) -> None:
        """Capability-acquisition consequence: an escalation with no visible data is
        confirmed when a specific action FLIPS from denied (baseline captured before any
        attack) to allowed after the actor's write. The before/after flip is the Δstate
        the escalation necessarily entails; a still-denied action -> abstain."""
        actor = ex.principal.pid
        baseline = getattr(self, "_capability_baseline", {})
        for action in list(getattr(oracle, "actions", []) or []):
            was = baseline.get((actor, action))
            if was is not False:
                continue                                    # only a denied->allowed flip counts
            now = oracle.capability_gained(actor, action)
            if now is not True:
                continue
            from .models import (StateProof, EffectClassification, ClassificationSource,
                                 Candidate, LawVerdict, Verdict)
            proof = StateProof(
                confirmed=True,
                method="consequence Δstate (a denied action became allowed)",
                before=f"action '{action}' was DENIED to '{actor}' at baseline",
                after=f"after '{actor}'s write, action '{action}' is now ALLOWED",
                read_as=actor,
                detail=(f"privilege escalation: '{actor}' acquired capability '{action}' "
                        f"— an invisible-Δstate effect confirmed via its necessary "
                        f"capability-acquisition consequence"),
            )
            cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                       effect=EffectClass.AUTHORITY,
                                       source=ClassificationSource.INFERRED, high_caution=True)
            lv = LawVerdict(verdict=Verdict.CANDIDATE, law_name="CONSEQUENCE_CAPABILITY_GAIN",
                            effect=EffectClass.AUTHORITY,
                            reason=f"{actor} gained capability {action}",
                            evidence={"action": action, "consequence": "capability-flip"})
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=lv)
            finding = self.emitter.emit(cand, proof)
            if self._emit_finding(finding):
                tr.add("Consequence", "confirmed",
                       f"capability gain: {actor} acquired {action}", finding_id=finding.fid)
                tr.outcome = "finding"; tr.finding_id = finding.fid
            return

    def _consequence_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL26 (additive, flag-gated, default OFF). Deficiency #4 — invisible Δstate.
        Confirms an effect that has NO direct read-back by observing a CONSEQUENCE the
        effect necessarily entails, through a channel ONYX controls. First consequence:
        CREDENTIAL TAKEOVER — the actor set victim Q's credential to an attacker-chosen
        value V; if authenticating AS Q with V now succeeds, the write provably took
        effect (a random V cannot authenticate otherwise). Deterministic, so zero-FP is
        preserved: no oracle or no success -> abstain (RL5)."""
        if ex.request.method not in ("PUT", "POST", "PATCH"):
            return
        if not (200 <= ex.response.status < 300):
            return
        oracle = getattr(self, "consequence_oracle", None)
        if oracle is None:
            return
        # capability-acquisition consequence (privilege escalation with no visible data)
        if oracle.can_probe_capability():
            self._consequence_capability(ex, tr, oracle)
            if tr.outcome == "finding":
                return
        if not oracle.can_probe_credential():
            return
        body = ex.request.body if isinstance(ex.request.body, dict) else {}
        cred_keys = ("password", "passwd", "pwd", "new_password", "credential", "secret", "token")
        cred = next((body[k] for k in cred_keys
                     if isinstance(body.get(k), str) and body.get(k)), None)
        if cred is None:
            return
        actor = ex.principal.pid
        victim = self._credential_victim(ex.request, actor)
        if victim is None or victim == actor:
            return                                          # need a cross-principal target
        confirmed = oracle.credential_takeover_confirmed(victim, cred)
        if confirmed is not True:
            return                                          # None/False -> abstain (RL5)
        from .models import (StateProof, EffectClassification, ClassificationSource,
                             Candidate, LawVerdict, Verdict)
        proof = StateProof(
            confirmed=True,
            method="consequence Δstate (re-authentication proves credential takeover)",
            before=f"authenticating as '{victim}' with the attacker-chosen credential failed",
            after=f"'{actor}' set '{victim}'s credential; auth as '{victim}' with it now succeeds",
            read_as=victim,
            detail=(f"cross-principal CREDENTIAL TAKEOVER: '{actor}' changed '{victim}'s "
                    f"credential and it is now usable to authenticate as '{victim}' — an "
                    f"invisible-Δstate effect confirmed via its necessary re-auth consequence"),
        )
        cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                   effect=EffectClass.OWNERSHIP,
                                   source=ClassificationSource.INFERRED, high_caution=True)
        lv = LawVerdict(verdict=Verdict.CANDIDATE, law_name="CONSEQUENCE_CREDENTIAL_TAKEOVER",
                        effect=EffectClass.OWNERSHIP,
                        reason=f"{actor} took over {victim}'s credential",
                        evidence={"victim": victim, "consequence": "re-auth"})
        cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                         classification=cls, verdict=lv)
        finding = self.emitter.emit(cand, proof)
        if self._emit_finding(finding):
            tr.add("Consequence", "confirmed",
                   f"credential takeover: {actor} -> {victim} (re-auth consequence)",
                   finding_id=finding.fid)
            tr.outcome = "finding"; tr.finding_id = finding.fid

    def _credential_victim(self, request, actor: str) -> Optional[str]:
        """The principal whose credential this write targets: a tracked principal named in
        the path (…/{victim}/password), else a tracked id addressed in the path, else a
        victim named in the body. Returns None when it resolves to no cross-principal
        target."""
        try:
            segs = [s for s in request.path.split("/") if s]
        except Exception:
            segs = []
        # …/{victim}/password  or  …/{victim}/credential
        for i, s in enumerate(segs):
            if s.lower() in ("password", "passwd", "credential", "secret") and i > 0:
                cand = segs[i - 1]
                if cand in self.principals:
                    return cand
        for s in segs:
            if s in self.principals and s != actor:
                return s
        body = request.body if isinstance(request.body, dict) else {}
        for k in ("username", "user", "target", "victim", "id"):
            v = body.get(k)
            if isinstance(v, str) and v in self.principals and v != actor:
                return v
        return None

    def _xprincipal_delete_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL25 (additive, flag-gated, default OFF). Cross-principal DESTRUCTION —
        the FP-safe, Δstate-grounded confirmation of admin-delete BFLA. Rather than a
        fragile 'the path says /admin' role heuristic, it confirms the OBSERVABLE
        CONSEQUENCE of the broken function-level check: a principal P destroyed an
        object O that a DIFFERENT tracked principal Q provably owned.

        Chain (every link Δstate / legitimate evidence, RL3):
          * P issues a DELETE on O and the server accepts it (2xx, not a bare 202).
          * O's owner Q is resolved from `legitimate_holders(O)` — the observe-phase
            (legitimate=True) hold index, which attack probes never touch, so a
            cache-bleed cannot forge or launder ownership.
          * Q != P and Q is tracked; O is not shared to P nor public.
          * Δstate: Q could read O before (it was in Q's legitimate hold); after P's
            delete, Q's cache-busted majority re-read of O returns GONE (not 2xx).
        A legitimately-authorized delete of one's OWN object is never cross-principal,
        so this cannot fire on authorized use — the crown jewel is preserved."""
        if ex.request.method != "DELETE":
            return
        if not (200 <= ex.response.status < 300) or ex.response.status == 202:
            return
        from .confirmer import _declares_grant_to
        from .models import (StateProof, EffectClassification, ClassificationSource,
                             Candidate, LawVerdict, Verdict, HTTPRequest)
        actor = ex.principal.pid
        try:
            oids = [str(o) for o in ex.request.object_ids()]
        except Exception:
            return
        for oid in oids:
            # Owner = the principal who LEGITIMATELY (observe-phase) read O. video_ids
            # are small integers the value tracker treats as non-discriminating, so
            # value-based ownership is empty here; the ledger's legitimate GET records
            # are the sound, chaos-safe ownership signal (attack reads are legitimate=
            # False and are excluded, so a bleed cannot forge ownership).
            legit_readers = {r["pid"] for r in self.access_ledger.get(oid, [])
                             if r.get("legitimate") and r.get("method") == "GET" and r.get("ok")}
            owners = legit_readers - {actor}
            if len(owners) != 1 or actor in legit_readers:
                continue                                   # need exactly one foreign owner
            owner = next(iter(owners))
            # The object-id string can collide across resource types (report 3, order 3
            # and video 3 all key under "3"). So we try EVERY legitimate GET the owner
            # made for this id and confirm destruction on the ONE resource that has
            # transitioned to GONE — the deleted resource. The others (a same-id report/
            # order) remain 2xx, so this disambiguates without a resource-type oracle.
            owner_reads = [r for r in self.access_ledger.get(oid, [])
                           if (r.get("pid") == owner and r.get("legitimate")
                               and r.get("method") == "GET" and r.get("ok"))]
            if not owner_reads:
                continue                                   # no established read -> abstain
            destroyed_path = None
            for read_rec in owner_reads:
                get_ex = Exchange(
                    request=HTTPRequest("GET", read_rec["path"],
                                        query=dict(read_rec.get("query") or {}),
                                        host=read_rec.get("host") or ex.request.host),
                    response=ex.response, principal=self.principals[owner])
                if getattr(self.confirmer, "stability_k", 1) > 1:
                    res = self._stable_reread(get_ex, owner)
                    if res is None:
                        continue                           # unstable on this path -> try next
                    gone = not (200 <= res[0] < 300)
                else:
                    rb = self._readback(get_ex, owner)
                    gone = rb is not None and not (200 <= getattr(rb, "status", 0) < 300)
                if gone:
                    destroyed_path = read_rec["path"]
                    break
            if destroyed_path is None:
                continue                                   # nothing verifiably destroyed
            if _declares_grant_to(ex.response.body if isinstance(ex.response.body, dict) else {}, actor):
                continue
            proof = StateProof(
                confirmed=True,
                method="cross-principal destruction Δstate (foreign object deleted)",
                before=f"object {oid} legitimately held by '{owner}'",
                after=f"'{actor}' DELETE accepted (2xx); '{owner}' can no longer read it",
                read_as=owner,
                detail=(f"DELETE on object {oid} by non-owner '{actor}' was accepted and "
                        f"destroyed '{owner}'s object — a function-level authorization "
                        f"break (BFLA): the operation's admin/role guard is missing"),
            )
            cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                       effect=EffectClass.OWNERSHIP,
                                       source=ClassificationSource.INFERRED, high_caution=True)
            lv = LawVerdict(verdict=Verdict.CANDIDATE, law_name="XPRINCIPAL_DELETE",
                            effect=EffectClass.OWNERSHIP,
                            reason=f"DELETE object {oid} owned by {owner} by {actor}",
                            evidence={"object_id": oid, "owner": owner})
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=lv)
            finding = self.emitter.emit(cand, proof)
            if self._emit_finding(finding):
                tr.add("XPrincipalDelete", "confirmed",
                       f"cross-principal DELETE destroyed {owner}'s object {oid}",
                       finding_id=finding.fid)
                tr.outcome = "finding"; tr.finding_id = finding.fid
            return

    def _xprincipal_write_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL23 (additive, flag-gated, default OFF). Cross-principal WRITE: a
        state-changing request (PUT/POST/PATCH/DELETE) by principal P to an object O
        that provenance shows is owned by a DIFFERENT tracked principal Q, accepted
        by the server (2xx). A write response rarely echoes foreign data, so the
        read-leak trigger misses it — yet an accepted foreign mutation is a clear
        object-level authorization break (BOLA-write / unauthorized modification).

        Confirmation stays Δstate (RL3): a read-back must show the mutation PERSISTED
        on the foreign object (the new state for a write, or absence for a delete) —
        not a status code. FP-safety: O owned by a tracked Q != P; not shared/public;
        the write was accepted (2xx), which a correctly-guarded endpoint would 403."""
        if ex.request.method not in ("PUT", "POST", "PATCH", "DELETE"):
            return
        if not (200 <= ex.response.status < 300):
            return
        # RL3 discipline under chaos: a 202 (Accepted) means the mutation is NOT yet
        # applied — it is not a proven Δstate. Confirming on it would let an async
        # gateway's optimistic ACK (even for a request the backend later rejects)
        # forge a finding. A real confirmed mutation returns 2xx with the effect.
        if ex.response.status == 202 and not getattr(self, "follow_async_commit", False):
            return
        from .confirmer import _declares_grant_to
        from .models import StateProof, EffectClassification, ClassificationSource, \
            Candidate, LawVerdict, Verdict
        actor = ex.principal.pid
        try:
            oids = [str(o) for o in ex.request.object_ids()]
        except Exception:
            return
        for oid in oids:
            # Δstate read-back of the written object (as the actor) to (a) confirm the
            # mutation persisted and (b) read the object's declared owner identity.
            # Chaos defence (RL24): when stability_k>1 the read-back is cache-busted and
            # majority-voted, so a cache bleed cannot forge a FOREIGN owner on a SAFE
            # endpoint (the actor's own object then resolves to the actor -> skip).
            from .models import HTTPResponse as _HR
            if getattr(self.confirmer, "stability_k", 1) > 1:
                get_ex = Exchange(request=HTTPRequest("GET", ex.request.path,
                                  query=dict(ex.request.query or {}), host=ex.request.host),
                                  response=ex.response, principal=ex.principal)
                res = self._stable_reread(get_ex, actor)
                if res is None:
                    continue
                rb = _HR(res[0], res[1])
            else:
                rb = self._readback(ex, actor)
            if getattr(self, "follow_async_commit", False) and ex.response.status == 202:
                # G6: follow the async commit to its LANDED state — poll the read-back
                # and confirm only a PERSISTED effect. An optimistic ack the backend
                # later rejects never persists => abstain (zero-FP preserved).
                from .async_seam import async_seam_follow
                rb2 = async_seam_follow(
                    lambda: self._readback(ex, actor),
                    lambda r: self._write_persisted(ex, r),
                    max_polls=getattr(self, "_async_max_polls", 4), interval_s=0.0)
                if rb2 is None:
                    continue
                rb = rb2
            else:
                if not self._write_persisted(ex, rb):
                    continue
            # resolve the object's owner from its declared identity fields, matched to
            # a DIFFERENT tracked principal (the one who saw that identity privately).
            owner = self._owner_from_identity(rb, ex, actor)
            if owner is None or owner == actor:
                continue
            # chaos defence: confirm the foreign mutation persists on a cache-busted
            # majority read-back (defeats duplicate-write / stale-read artifacts).
            get_ex = Exchange(request=HTTPRequest('GET', ex.request.path,
                              query=dict(ex.request.query or {}), host=ex.request.host),
                              response=ex.response, principal=ex.principal)
            if getattr(self.confirmer, 'stability_k', 1) > 1:
                res = self._stable_reread(get_ex, actor)
                if res is None:
                    continue
            if _declares_grant_to(ex.response.body if isinstance(ex.response.body, dict) else {}, actor):
                continue
            proof = StateProof(
                confirmed=True,
                method="cross-principal write Δstate (foreign mutation persisted)",
                before=f"object {oid} owned by '{owner}'",
                after=f"'{actor}' issued {ex.request.method} accepted (2xx); change persisted",
                read_as=owner,
                detail=(f"{ex.request.method} on object {oid} by non-owner '{actor}' was "
                        f"accepted and the mutation persisted on '{owner}'s object — "
                        f"object-level write authorization is missing"),
            )
            cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                       effect=EffectClass.OWNERSHIP,
                                       source=ClassificationSource.INFERRED, high_caution=True)
            lv = LawVerdict(verdict=Verdict.CANDIDATE, law_name="XPRINCIPAL_WRITE",
                            effect=EffectClass.OWNERSHIP,
                            reason=f"{ex.request.method} object {oid} owned by {owner} by {actor}",
                            evidence={"object_id": oid, "owner": owner})
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=lv)
            finding = self.emitter.emit(cand, proof)
            if self._emit_finding(finding):
                tr.add("XPrincipalWrite", "confirmed",
                       f"cross-principal {ex.request.method} on {owner}'s object {oid}",
                       finding_id=finding.fid)
                tr.outcome = "finding"; tr.finding_id = finding.fid
            return

    def _owner_from_identity(self, readback, ex: Exchange, actor: str):
        """Read the object's declared owner identity (email/owner field) from the
        read-back (or the write response) and resolve it to the DIFFERENT tracked
        principal who saw it privately. Returns that principal id, or None."""
        for body in (getattr(readback, "body", None), ex.response.body):
            if not isinstance(body, dict):
                continue
            for key, val in _flat_kv(body):
                if not isinstance(val, str):
                    continue
                if "@" not in val:                       # identity anchor: an email
                    continue
                # chaos-robust ownership: earliest legitimate origin, not seers.
                owner = self._owner_of(val)
                if owner is not None and owner != actor:
                    return owner
        return None

    def _readback(self, ex: Exchange, as_pid: str):
        """Issue a GET of the written object as the owner, via the live target."""
        who = self.principals.get(as_pid)
        if who is None:
            return None
        try:
            from .models import HTTPRequest
            path = ex.request.path
            resp = self.target.send(HTTPRequest("GET", path, query=dict(ex.request.query or {}),
                                                host=ex.request.host), who)
            return resp
        except Exception:
            return None

    def _write_persisted(self, ex: Exchange, readback) -> bool:
        """Did the write visibly change the object? For DELETE, the object is gone
        (4xx). For PUT/PATCH/POST, a body field the actor set now appears in the
        read-back."""
        if ex.request.method == "DELETE":
            return not (200 <= getattr(readback, "status", 0) < 300)
        body = ex.request.body if isinstance(ex.request.body, dict) else {}
        rb = getattr(readback, "body", None)
        if not isinstance(rb, dict):
            return False
        for k, v in body.items():
            if rb.get(k) == v and v not in (None, "", 0, 1, True, False):
                return True
        return False

    def _field_exposure_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL22 (additive, flag-gated, default OFF). Excessive Data Exposure: a
        response the actor is ALLOWED to fetch (e.g. a community feed) that embeds a
        DISCRIMINATING, SENSITIVE field which provenance proves is ANOTHER tracked
        principal's PRIVATE data (that principal saw it first in their own
        authenticated self-access, and the actor never legitimately held it). This is
        the field-exposure coordinate the object-access trigger cannot reach: no
        foreign object id is requested, yet foreign private data is served.

        Honest boundary: fires only when the leaked identity is a TRACKED principal
        (its privacy PROVEN by that principal's own envelope). A feed of untracked
        third parties is NOT a confirmed finding — black-box replay cannot prove an
        untracked party's field is private.

        FP-safety: value discriminating (Gap#2) AND sensitive; seen privately by
        exactly one OTHER principal (not broadly shared/public); actor not a prior
        holder; object not declared shared/public. Any gate failing -> abstain."""
        if not (200 <= ex.response.status < 300):
            return
        body = ex.response.body
        if not isinstance(body, (dict, list)):
            return
        from .confirmer import _value_is_discriminating, _declares_grant_to
        from .provenance import classify_field, ValueClass
        from .models import (StateProof, EffectClassification, ClassificationSource,
                             Candidate, LawVerdict, Verdict)
        actor = ex.principal.pid
        bdict = body if isinstance(body, dict) else {}

        for key, val in _flat_kv(body):
            if not isinstance(val, (str, int)):
                continue
            if not _value_is_discriminating(val):
                continue
            vc = classify_field(key, val)
            if not _is_pii_leak(key, val, vc):
                continue
            # Attribute ownership by EARLIEST legitimate origin (chaos-robust), NOT by
            # the seers set which a cache-bleed can pollute. If the actor is the owner,
            # V is the actor's OWN data (e.g. reading its own profile) -> not a leak.
            owner = self._owner_of(val)
            if owner is None or owner == actor:
                continue
            # guard against broadly-shared values: if MANY principals legitimately hold
            # V it is not one principal's private field.
            seers = set(self.provenance.legitimate_seers(val))
            if len({s for s in seers if s != actor}) > 2:
                continue
            victim = owner
            if _declares_grant_to(bdict, actor) or _body_is_public(bdict):
                continue
            # chaos defence: a real leak survives a cache-busted majority re-read;
            # a shared-cache bleed / stale replica does not.
            if not self._signal_survives(ex, lambda st, bd, _v=val: _value_in_body(bd, _v)):
                continue
            proof = StateProof(
                confirmed=True,
                method="field-exposure value-presence (private field of another principal)",
                before=f"'{val}' is {victim}'s private field (seen first in {victim}'s own access)",
                after=f"served to '{actor}' inside {ex.request.endpoint_key()}",
                read_as=victim,
                detail=(f"response the actor may fetch exposes '{key}={val}', a "
                        f"discriminating sensitive field provably private to '{victim}' — "
                        f"excessive data exposure: foreign private data served with no "
                        f"per-object authorization"),
            )
            cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                       effect=EffectClass.OBJECT_ACCESS,
                                       source=ClassificationSource.INFERRED, high_caution=True)
            lv = LawVerdict(verdict=Verdict.CANDIDATE, law_name="FIELD_EXPOSURE",
                            effect=EffectClass.OBJECT_ACCESS,
                            reason=f"'{key}' private to {victim} exposed to {actor}",
                            evidence={"object_id": val, "victim": victim, "field": key})
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=lv)
            finding = self.emitter.emit(cand, proof)
            if self._emit_finding(finding):
                tr.add("FieldExposure", "confirmed",
                       f"EDE: '{key}' private to {victim} exposed to {actor}",
                       finding_id=finding.fid)
                tr.outcome = "finding"; tr.finding_id = finding.fid
            return

    def _stable_reread(self, ex: Exchange, as_pid: str = None):
        """RL24 chaos defence: re-issue the triggering GET with a unique CACHE-BUSTER
        query and majority-vote over k samples. A real leak is served by the backend
        every time (survives cache-bust + reproduces); a shared-cache bleed or a stale
        replica is a transient/cached artifact that vanishes. Returns the majority
        (status, body) or None if unstable. Only active when stability_k>1 (else the
        callers skip re-verification -> byte-identical)."""
        k = getattr(self.confirmer, "stability_k", 1)
        if k <= 1:
            return "SKIP"                       # no chaos defence requested
        who = self.principals.get(as_pid or ex.principal.pid)
        if who is None:
            return None
        import json, uuid as _uuid
        from collections import Counter
        from .models import HTTPRequest
        samples = []
        for _ in range(k):
            q = dict(ex.request.query or {})
            q["_cb"] = _uuid.uuid4().hex[:8]     # cache-buster -> bypass URL-keyed cache
            try:
                r = self.target.send(HTTPRequest(ex.request.method, ex.request.path,
                                                 query=q, host=ex.request.host), who)
            except Exception:
                continue
            if r is None:
                continue
            try:
                key = (r.status, json.dumps(r.body, sort_keys=True, default=str))
            except Exception:
                key = (r.status, str(r.body))
            samples.append((key, r.body, r.status))
        if not samples:
            return None
        counts = Counter(k for k, _, _ in samples)
        top, n = counts.most_common(1)[0]
        import math
        if n < max(2, math.ceil(0.8 * len(samples))):  # strong quorum or abstain   # strong quorum or abstain
            return None
        for key, body, status in samples:
            if key == top:
                return (status, body)
        return None

    def _signal_survives(self, ex: Exchange, predicate, as_pid: str = None) -> bool:
        """True iff the re-read is either not requested (SKIP -> keep old behaviour) or
        the majority re-read still satisfies `predicate(status, body)`."""
        res = self._stable_reread(ex, as_pid)
        if res == "SKIP":
            return True
        if res is None:
            return False
        status, body = res
        try:
            return bool(predicate(status, body))
        except Exception:
            return False

    def _embedded_owner_exposure_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL21 (additive, flag-gated, default OFF -> byte-identical). Cold-start
        ownership: an object whose BODY declares a discriminating owner-identity that
        belongs to NO tracked principal (an untracked third party), read successfully
        by >=2 DISTINCT tracked non-owner principals, is a broken-authorization
        exposure (any authenticated user can read any object + its owner's PII). This
        is the mechanic-report BOLA on a flat capture, which the tracked-owner
        differential cannot reach because the owner was never provisioned.

        FP-safety (the crown jewel is not weakened): fires ONLY when the owner value
        is discriminating (reuses the Gap#2 gate), is held by no tracked principal
        (so it is a genuine third party, not self and not a known peer), the object
        is read by >=2 distinct principals, and the object is NOT declared shared to
        a reader and NOT public. Any one gate failing -> abstain (RL5)."""
        if not (200 <= ex.response.status < 300):
            return
        body = ex.response.body
        if not isinstance(body, dict):
            return
        from .confirmer import _value_is_discriminating, _declares_grant_to
        from .models import StateProof
        owners = _embedded_owner_identities(body)
        if not owners:
            return
        try:
            oids = [str(o) for o in ex.request.object_ids()]
        except Exception:
            oids = []
        if not oids:
            return
        ekey = ex.request.endpoint_key()
        actor = ex.principal

        for V in owners:
            if not _value_is_discriminating(V):
                continue                                   # shared default -> skip (Gap#2)
            # RL21 targets the COLD-START case: an owner-identity belonging to NO
            # tracked principal (a genuine untracked third party). The tracked-owner
            # test must be chaos-safe: legitimate_holders indexes object-IDs, so it
            # never contains an email and cannot see that a tracked principal's own
            # identity is theirs — which let a cache-bleed on a SAFE endpoint make
            # U0's own email look "untracked" and fire a false positive.
            # legitimate_seers records ONLY legitimate (observe-phase, self-
            # authenticated) reads; attack probes are legitimate=False and never
            # update it, so a bleed during an ATTACK cannot forge tracked-ownership.
            # If V was legitimately received by any principal (their own identity),
            # the chaos-hardened tracked-owner differential owns this case -> skip.
            if self.provenance.legitimate_seers(V):
                continue
            if self.provenance.legitimate_holders(V):
                continue                                   # owner is a TRACKED principal
            #   (self or a known peer) -> handled by the existing differential; skip.
            # public / shared exonerations (RL5 fail-safe)
            if _declares_grant_to(body, actor.pid):
                continue                                   # legitimately shared to reader
            if _body_is_public(body):
                continue                                   # explicitly public object
            # multi-non-owner exposure: >=2 distinct principals read THIS object ok.
            for oid in oids:
                recs = [r for r in self.access_ledger.get(oid, [])
                        if r.get("endpoint") == ekey and r.get("ok")]
                readers = {r["pid"] for r in recs}
                if actor.pid not in readers or len(readers) < 2:
                    continue                               # need >=2 distinct readers
                # none of the readers may be the (untracked) owner -> true by the
                # legitimate_holders(V) empty check above.
                # chaos defence: the foreign owner must survive a cache-busted re-read.
                if not self._signal_survives(ex, lambda st, bd, _v=V: _value_in_body(bd, _v)):
                    return
                # Build the finding.
                proof = StateProof(
                    confirmed=True,
                    method="multi-non-owner value-presence exposure (embedded owner)",
                    before=f"object {oid} owned by untracked '{V}'",
                    after=f"read by {len(readers)} non-owner principals: {sorted(readers)}",
                    read_as=actor.pid,
                    detail=("object declares owner-identity '%s' (a third party held by "
                            "no reader) yet is served to %d distinct authenticated "
                            "non-owners with no per-object authorization and no shared/"
                            "public grant — function-level object exposure (BFLA-class)"
                            % (V, len(readers))),
                )
                from .models import (EffectClassification, ClassificationSource,
                                     Candidate, LawVerdict, Verdict)
                cls = EffectClassification(endpoint=ekey, effect=EffectClass.OBJECT_ACCESS,
                                           source=ClassificationSource.INFERRED,
                                           high_caution=True)
                lv = LawVerdict(verdict=Verdict.CANDIDATE,
                                law_name="EMBEDDED_OWNER_EXPOSURE",
                                effect=EffectClass.OBJECT_ACCESS,
                                reason=f"object {oid} owner '{V}' exposed to {sorted(readers)}",
                                evidence={"object_id": oid, "owner_identity": V,
                                          "readers": sorted(readers)})
                cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                                 classification=cls, verdict=lv)
                finding = self.emitter.emit(cand, proof)
                if self._emit_finding(finding):
                    tr.add("EmbeddedOwner", "confirmed",
                           f"cold-start exposure: object {oid} owner '{V}' served to "
                           f"{len(readers)} non-owners", finding_id=finding.fid)
                    tr.outcome = "finding"; tr.finding_id = finding.fid
                return

    def _conservation_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL19: additive, flag-gated. Catches a read that exposes a value provably
        owned by another principal's private authority (the read-leak coordinate a
        mutation verifier cannot reach). CANDIDATE -> the Δstate confirmer reads the
        object back AS THE OWNER and convicts only on reproduced private data."""
        ctx = LawContext(ex, self.contract.classify(ex), self.provenance, self.envelopes)
        xv = self.eil.evaluate_conservation(ctx)
        if xv.verdict is not Verdict.CANDIDATE:
            return
        tr.add("Conservation", "candidate", f"{xv.law_name} -> {xv.reason}",
               law=xv.law_name, impact=xv.impact.value if xv.impact else None)
        from .models import EffectClassification, ClassificationSource
        cls = EffectClassification(endpoint=ex.request.endpoint_key(),
                                   effect=EffectClass.OBJECT_ACCESS,
                                   source=ClassificationSource.INFERRED, high_caution=True)
        cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex, classification=cls,
                         verdict=xv, causal_origin=xv.evidence.get("laundered_from"))
        proof = self.confirmer.confirm(cand)
        if proof is None or not proof.confirmed:
            tr.add("Conservation", "unconfirmed",
                   "owner read-back did not reproduce the leaked private data "
                   "(shared/public or unreadable) — fail-safe drop, no false positive")
            return
        tr.add("Conservation", "confirmed",
               f"cross-principal leak proven: private data exposed to '{ex.principal.pid}' "
               f"(read back as {proof.read_as})")
        finding = self.emitter.emit(cand, proof)
        if not self._emit_finding(finding):
            return
        tr.add("Evidence->PoC", "ok", f"{finding.severity.value} - {finding.impact.value}",
               finding_id=finding.fid)
        tr.outcome = "finding"; tr.finding_id = finding.fid

    def _cross_surface_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL15: an additive, flag-gated cross-surface pass that can only ADD a
        finding (it never alters the main verdict). It asks whether THIS door
        (a non-canonical view — list/graphql/search) over-exposes a sensitive field
        that the resource's CANONICAL detail view withholds from the SAME principal,
        per the surface ledger seeded during observe(). Any CANDIDATE is proven by
        an intra-principal canonical read-back in the confirmer (RL3). Inert unless
        a canonical reference for the resource+principal exists."""
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        # APQ (#2-a): learn any hash->query registration carried by this request so
        # later hash-only requests resolve to their operation.
        self.surface_ledger.observe_persisted(ex.request)
        ctx = LawContext(ex, self.contract.classify(ex), self.provenance,
                         self.envelopes, state_gates=self.state_gates,
                         lifecycle=self.lifecycle, seq=self._seq,
                         store=self.store, surface_ledger=self.surface_ledger,
                         actor_roles=self._actor_roles, role_ranks=self._role_ranks,
                         resource_parents=self._resource_parents)
        xv = self.eil.evaluate_cross_surface(ctx)
        if xv.verdict is not Verdict.CANDIDATE:
            return
        tr.add("CrossSurface", "candidate", f"{xv.law_name} → {xv.reason}",
               law=xv.law_name, impact=xv.impact.value if xv.impact else None)
        # attach the recorded canonical endpoint path so the confirmer can read the
        # authoritative view back deterministically (no path guessing when known).
        ev = xv.evidence or {}
        cand = Candidate(
            cid="C-" + uuid.uuid4().hex[:8],
            exchange=ex,
            classification=ctx.classification,
            verdict=xv,
        )
        proof = self.confirmer.confirm(cand)
        if proof is None or not proof.confirmed:
            tr.add("CrossSurface", "unconfirmed",
                   "canonical read-back did not refute or could not be read — "
                   "no live cross-surface Δstate (surfaces agree, or view unreadable)")
            return
        tr.add("CrossSurface", "confirmed",
               f"Δstate proven: {proof.before} → {proof.after} (read as {proof.read_as})")
        finding = self.emitter.emit(cand, proof)
        if not self._emit_finding(finding):
            return
        tr.add("Evidence→PoC", "ok",
               f"{finding.severity.value} · {finding.impact.value}",
               finding_id=finding.fid)
        tr.outcome = "finding"
        tr.finding_id = finding.fid
        # RL17: generalise this PROVEN leak into a structural rule (the rule is
        # witness-1; it is now earned by a confirmed exemplar — C5). The sibling
        # campaign runs in _combinatorial_pass.
        if getattr(self, "combinatorial", False):
            rtype = ev.get("resource_type")
            field = (ev.get("field") or "")
            door = ev.get("door_endpoint") or ex.request.endpoint_key()
            if rtype and field:
                self.hypothesis.learn(rtype, field, door)
                tr.add("Hypothesis", "rule-learned",
                       f"generalised: {door} leaks '{field}' for {rtype}:* "
                       f"(strength={self.hypothesis.strength(rtype, field, door)})")

    def _combinatorial_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """RL17: the orchestrator. For a list/collection door, take every sibling
        element that MATCHES a learned structural rule (witness-1, a proven exemplar)
        and propose it as a target cell. Each proposed cell is convicted ONLY by a
        single isolated canonical read-back via the EXISTING cross-surface confirmer
        (witness-2 + C6) — so the combinatorial layer contributes targeting, never a
        new proof path, and adds no new false-positive surface. Additive: it can only
        ADD findings, and is inert unless a rule has been earned."""
        if self.hypothesis.rule_count == 0:
            return
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        from .surface_map import (classify_door, exposed_sensitive_fields,
                                  DOOR_LIST, _normalise_id, ResourceIdentity)
        from .eil import _iter_elements_with_ids, _list_resource_type
        if classify_door(ex.request) != DOOR_LIST:
            return
        rtype = _list_resource_type(ex.request)
        if not rtype:
            return
        door = ex.request.endpoint_key()
        actor = ex.principal.pid
        elements = list(_iter_elements_with_ids(body))
        family_size = len(elements)
        for elem, eid in elements:
            nid = _normalise_id(eid)
            if nid is None:
                continue
            # already convicted directly by RL15? skip (dedup across passes).
            ident = ResourceIdentity(rtype, nid)
            fields = exposed_sensitive_fields(body, element_id=eid)
            for leaf, val in fields.items():
                if not self.hypothesis.should_target(rtype, leaf, door, nid, family_size):
                    continue
                # build a derived cross-surface candidate; the confirmer will read the
                # canonical view for THIS sibling live and convict ONLY if it hides the
                # field (witness-2). The rule (witness-1) only chose to look here.
                ev = {"object_id": nid, "resource_type": rtype, "field": leaf,
                      "door": "list(derived)", "door_endpoint": door,
                      "canonical_endpoint": None, "element_id": eid,
                      "_door_value": val, "_derived": True, "laundered_from": None}
                verdict = self.eil.cross_surface._candidate(
                    f"RL17 hypothesis: rule '{door} leaks {leaf} for {rtype}:*' "
                    f"(proven on an exemplar) targets sibling {ident}; pending per-cell "
                    f"Δstate", ev)
                cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                                 classification=ex and self.contract.classify(ex),
                                 verdict=verdict)
                proof = self.confirmer.confirm(cand)
                if proof is None or not proof.confirmed:
                    tr.add("Hypothesis", "cell-cleared",
                           f"sibling {ident}: canonical read-back did not confirm — "
                           f"per-cell Δstate refuted the rule here (no false positive)")
                    continue
                finding = self.emitter.emit(cand, proof)
                if not self._emit_finding(finding):
                    continue
                self._derived_count += 1
                # strengthen the rule with this independent confirmation (C5)
                self.hypothesis.learn(rtype, leaf, door)
                tr.add("Hypothesis", "cell-confirmed",
                       f"derived finding on sibling {ident} via targeted Δstate "
                       f"(orchestrated, not observed directly)", finding_id=finding.fid)
                tr.add("Evidence→PoC", "ok",
                       f"{finding.severity.value} · {finding.impact.value}",
                       finding_id=finding.fid)
                tr.outcome = "finding"
                tr.finding_id = finding.fid

    def _structural_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """SAIE: an additive, value-blind structural-divergence check that can only
        ADD a finding (it never alters the main verdict). Gate 1 is the coherence
        breach (eil.evaluate_structural); Gates 2+3 are enforced by the confirmer
        under RL3. Inert unless the family has a stability-proven grammar."""
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        family = ex.request.endpoint_key()
        mask = self.stability_gate.trust_mask(family)
        # structural-normalisation leads (intermittent presence) — independent of the
        # relational breach below; leads-only, flag-gated, deduped per (family,path).
        self._normalization_leads(ex, tr, family)
        self._missing_shadow(ex, tr, family)
        self._temporal_drift_pass(ex, tr, family)
        if not mask.stable:
            # CONFIRMED path is silent here (no stability-proven grammar). Instead of
            # going dark, emit a lead-only relational hint from the unstable grammars.
            self._provisional_structural_leads(ex, tr, family)
            return
        ctx = LawContext(ex, self.contract.classify(ex), self.provenance,
                         self.envelopes, state_gates=self.state_gates,
                         lifecycle=self.lifecycle, seq=self._seq,
                         stability_gate=self.stability_gate,
                         coherence=self.coherence, store=self.store,
                         actor_roles=self._actor_roles, role_ranks=self._role_ranks,
                         resource_parents=self._resource_parents)
        sv = self.eil.evaluate_structural(ctx)
        if sv.verdict is not Verdict.CANDIDATE:
            return
        tr.add("SAIE", "candidate", f"{sv.law_name} → {sv.reason}", law=sv.law_name,
               impact=sv.impact.value if sv.impact else None)
        cand = Candidate(
            cid="C-" + uuid.uuid4().hex[:8],
            exchange=ex,
            classification=ctx.classification,
            verdict=sv,
        )
        proof = self.confirmer.confirm(cand)
        if proof is None or not proof.confirmed:
            tr.add("SAIE", "unconfirmed",
                   "structural lead dropped — dimensional control (Gate 2) or "
                   "functional anchor (Gate 3) not satisfied (no Δstructure finding)")
            return
        tr.add("SAIE", "confirmed",
               f"Δstructure proven: {proof.before} → {proof.after} (read as {proof.read_as})")
        finding = self.emitter.emit(cand, proof)
        if not self._emit_finding(finding):       # D-DEDUP-BYPASS fix (pass 5)
            return
        tr.add("Evidence→PoC", "ok",
               f"{finding.severity.value} · {finding.impact.value}",
               finding_id=finding.fid)
        tr.outcome = "finding"
        tr.finding_id = finding.fid

    def _provisional_structural_leads(self, ex: Exchange, tr: PipelineTrace,
                                      family: str) -> None:
        """Relational detection on UNSTABLE (single-observation) grammars — breaks the
        >=2-repeat silence. LEAD-ONLY: an unproven shape can never feed a finding, so
        this only appends a ranked, lowest-tier lead, never a verdict/trace change.
        Gated on the diverging privileged paths being strongly named, to stay
        high-signal. Default-off flag => byte-identical when disabled."""
        if not getattr(self, "provisional_leads", False):
            return
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        from .intrinsic import Confidence, Lead, LeadKind, name_sensitivity
        from .structural import fingerprint
        coh = self.coherence
        acting = ex.principal.pid
        if not coh.has_provisional(acting, family):
            return
        fp = fingerprint(body)
        if coh.fits_provisional(fp, acting, family):
            return                                  # coherent with own (unproven) grammar
        acting_rank = coh.privilege_rank_provisional(acting, family)
        matched, matched_rank = None, acting_rank
        for q in coh.principals_with_provisional(family):
            if q == acting:
                continue
            r = coh.privilege_rank_provisional(q, family)
            if coh.fits_provisional(fp, q, family) and r > acting_rank:
                if matched is None or r > matched_rank:
                    matched, matched_rank = q, r
        if matched is None:
            return
        diverging = sorted(coh.provisional_present_paths(matched, family)
                           - coh.provisional_present_paths(acting, family))
        strong = [p for p in diverging if name_sensitivity(p) >= 7]
        if not strong:
            return                                  # keep the provisional tier high-signal
        lead = Lead(
            kind=LeadKind.STRUCTURAL_PROVISIONAL, family=family, principal=acting,
            paths=strong, weight=6 + len(strong),
            confidence=Confidence.PROVISIONAL_LEAD, confirmable=True,
            rationale=(f"on an UNSTABLE (single-observation) grammar, '{acting}' received a "
                       f"shape that fits the higher-privilege grammar of '{matched}' "
                       f"(rank {matched_rank} > {acting_rank}); privileged-named path(s) "
                       f"{strong} appear that '{acting}'s own shape lacks — a relational "
                       f"breach the stability gate cannot yet confirm"),
            suggested_probe=(f"re-read this endpoint as '{acting}' and as '{matched}' twice "
                             f"each to establish stable grammars; if the breach persists it "
                             f"is promoted to a confirmable structural-divergence finding"),
            evidence={"matched": matched, "matched_rank": matched_rank,
                      "acting_rank": acting_rank, "diverging": diverging})
        self.leads.append((tr.tid, lead))

    def _normalization_leads(self, ex: Exchange, tr: PipelineTrace, family: str) -> None:
        """Surface a sensitive node that FLICKERS in presence under identical input
        (authorization-conditional emission) — a signal current tools dismiss as
        noise. LEAD-ONLY, deduped per (family,path), flag-gated => byte-identical
        when off. Value-entropy (stable presence, churning value) is normalised
        away and never flagged."""
        if not getattr(self, "provisional_leads", False):
            return
        from .intrinsic import Confidence, Lead, LeadKind, name_sensitivity
        from .structural import NodeStability
        for path, prof in self.stability_gate.normalize(family).items():
            if prof.kind != NodeStability.INTERMITTENT:
                continue
            if name_sensitivity(path) < 7:              # high-signal only
                continue
            if (family, path) in self._emitted_intermittent:
                continue
            self._emitted_intermittent.add((family, path))
            s = name_sensitivity(path)
            pct = round(prof.present_ratio * 100)
            self.leads.append((tr.tid, Lead(
                kind=LeadKind.INTERMITTENT_PRESENCE, family=family,
                principal=ex.principal.pid, paths=[path],
                weight=s + 3, confidence=Confidence.STRONG_LEAD, confirmable=True,
                rationale=(f"privileged-named field '{path}' appears in only {prof.present}/"
                           f"{prof.seen} ({pct}%) of IDENTICAL requests to {family} — a "
                           f"flickering presence under identical input points to "
                           f"authorization-conditional emission, not random noise"),
                suggested_probe=(f"replay this exact request while varying session/role state; "
                                 f"if '{path}' appears only under specific state, that condition "
                                 f"is the authorization boundary to attack"),
                evidence={"path": path, "present": prof.present, "seen": prof.seen,
                          "present_ratio": round(prof.present_ratio, 3)})))

    def _missing_shadow(self, ex: Exchange, tr: PipelineTrace, family: str) -> None:
        """Field-level authorization map across principals on the SAME object: a
        privileged-named branch PRESENT_POPULATED for one principal yet ABSENT for
        another, on an identical record sharing a common base schema. A measured
        fact (0-FP) that no passive tool builds — the residual signature in mature
        systems that authorise BEFORE serialisation (no PRESENT_NULL to find).

        LEAD-ONLY: deciding which side is the violation needs a privilege-tier
        signal ONYX does not reliably hold, so we map the differential and let the
        hunter judge. Flag-gated + deduped => byte-identical when off."""
        if not getattr(self, "provisional_leads", False):
            return
        try:
            oids = sorted(str(o) for o in ex.request.object_ids())
        except Exception:
            return
        objsig = ",".join(oids)
        if not objsig:
            return                                   # collection/no-id endpoints: not this signal
        from .intrinsic import Confidence, Lead, LeadKind, name_sensitivity, field_salience
        presence = self.coherence.object_presence(family, objsig)
        if len(presence) < 2:
            return                                   # need >=2 principals on the SAME object
        # shared base: the object must be the same logical type for all observers
        base = set.intersection(*[pres for pres, _pop in presence.values()])
        if len(base) < 2:
            return
        union = set().union(*[pres for pres, _pop in presence.values()])
        for branch in sorted(union - base):          # present for some, absent for others
            # DEFECT #5 FIX: gate on language-NEUTRAL salience. The cross-principal
            # structural differential is itself the signal; name OR value-shape
            # raises it over threshold, so 'bal'/'solde'/'الرصيد' are no longer
            # invisible just because the NAME is not an English dictionary word.
            if field_salience(branch) < 7:
                continue
            if (family, objsig, branch) in self._emitted_absence:
                continue
            carriers = sorted(p for p, (pres, pop) in presence.items()
                              if branch in pop)       # populated (a real value), not just present
            absentees = sorted(p for p, (pres, _pop) in presence.items() if branch not in pres)
            if not carriers or not absentees:
                continue
            self._emitted_absence.add((family, objsig, branch))
            self.leads.append((tr.tid, Lead(
                kind=LeadKind.ABSENCE_MAP, family=family, principal=ex.principal.pid,
                paths=[f"{family}#{objsig}.{branch}"],
                weight=name_sensitivity(branch) + 2, confidence=Confidence.STRONG_LEAD,
                confirmable=True,
                rationale=(f"on the SAME object ({objsig}), the privileged-named branch "
                           f"'{branch}' is populated for principal(s) {carriers} but entirely "
                           f"ABSENT for {absentees} — a field-level authorization differential "
                           f"on an identical record (the residual signature when authz runs "
                           f"before serialisation)"),
                suggested_probe=(f"confirm the tier of {carriers} vs {absentees}; if a lower- "
                                 f"or equal-privilege principal in {carriers} sees '{branch}' "
                                 f"that {absentees} are denied, it is a broken field-level ACL"),
                evidence={"objsig": objsig, "branch": branch,
                          "carriers": carriers, "absentees": absentees})))

    def _active_field_probe(self, ex: Exchange, tr: PipelineTrace) -> None:
        """Disciplined, READ-ONLY active confirmation (opt-in). For a field-level
        BOLA hypothesis (a field populated for one principal, authz-denied for
        another on the SAME object), reproduce the differential NOW in one
        controlled cycle: replay the identical operation as each principal through
        Scope-Guard. If the field is freshly populated for one and absent for the
        other, the passive correlation becomes a confirmed Δstate finding (RL3).
        Off by default => byte-identical; strict budget; never mutates (the
        confirmer's _read is scope-checked and the op is a read)."""
        if not getattr(self, "active_probing", False) or self._active_budget <= 0:
            return
        if tr.outcome in ("finding", "halted"):
            return
        family = ex.request.endpoint_key()
        try:
            objsig = ",".join(sorted(str(o) for o in ex.request.object_ids()))
        except Exception:
            return
        for (fam, osig, field), st in list(self._gql_field.items()):
            if fam != family or osig != objsig:
                continue
            if not (st.get("pop") and st.get("deny") and st.get("req")):
                continue
            sig = (fam, osig, field)
            if sig in self._probed_bola:
                continue
            self._probed_bola.add(sig)
            self._active_budget -= 1
            pop_pid = sorted(st["pop"])[0]
            den_pid = sorted(st["deny"])[0]
            pop_pr, den_pr = self.principals.get(pop_pid), self.principals.get(den_pid)
            if pop_pr is None or den_pr is None:
                continue
            req = st["req"]
            replay = HTTPRequest(req.method, req.path, host=req.host,
                                 headers=dict(req.headers or {}),
                                 query=dict(req.query or {}), body=req.body)
            r_pop = self.confirmer._read(replay, pop_pr)   # scope-checked, read-only
            r_den = self.confirmer._read(replay, den_pr)
            if r_pop is None or r_den is None:
                continue                                   # scope HALT / not captured -> abstain
            from .confirmer import _dig, StateProof
            from .graphql import response_data as _rd
            pop_body = _rd(r_pop.body) if req.is_graphql() else r_pop.body
            den_body = _rd(r_den.body) if req.is_graphql() else r_den.body
            p_present, p_val = _dig(pop_body or {}, field)
            d_present, d_val = _dig(den_body or {}, field)
            crossed = (p_present and p_val not in (None, "", [], {})
                       and (not d_present or d_val in (None, "", [], {})))
            if not crossed:
                continue                                   # differential did not reproduce -> abstain
            proof = StateProof(
                confirmed=True,
                method="controlled read-only replay of the identical operation as each principal",
                before=(f"the same operation as '{den_pid}' does NOT expose field '{field}' "
                        f"on object {osig} (authorization-denied)"),
                after=(f"replayed as '{pop_pid}' the field '{field}' is populated on the SAME "
                       f"object {osig} — a reproduced, principal-dependent field exposure"),
                read_as=f"{pop_pid} vs {den_pid}",
                detail=("field-level BOLA/BFLA confirmed by a controlled differential: the "
                        f"backend's exposure of '{field}' depends on the caller, not the object"))
            cls = self.contract.classify(ex)
            verdict = LawVerdict(
                Verdict.CANDIDATE, "active: GRAPHQL_FIELD_BOLA",
                EffectClass.FIELD_PROJECTION,
                f"field '{field}' crosses principals on object {osig}",
                ImpactClass.FIELD_PROJECTION_LEAK,
                {"field": field, "object_id": osig, "populated_for": pop_pid,
                 "denied_for": den_pid})
            cand = Candidate(cid="C-" + uuid.uuid4().hex[:8], exchange=ex,
                             classification=cls, verdict=verdict)
            tr.add("Active-Probe", "confirmed",
                   f"controlled differential reproduced: {proof.before} → {proof.after}")
            finding = self.emitter.emit(cand, proof)
            if not self._emit_finding(finding):   # D-DEDUP-BYPASS fix (pass 5)
                return
            tr.add("Evidence→PoC", "ok",
                   f"{finding.severity.value} · {finding.impact.value}",
                   finding_id=finding.fid)
            tr.outcome = "finding"
            tr.finding_id = finding.fid
            return                                         # one finding per exchange

    @staticmethod
    def _distinctive_value(v) -> bool:
        """A value rare enough to be a genuine identifier/token (not a common
        scalar that recurs by coincidence)."""
        if isinstance(v, bool):
            return False
        if isinstance(v, (int, float)):
            return len(str(abs(int(v)))) >= 7          # a long numeric id
        if not isinstance(v, str):
            return False
        s = v.strip()
        if len(s) >= 16:
            return True                                # token/uuid/hash territory
        return len(s) >= 8 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)

    def _chain_provenance(self, ex: Exchange, tr: PipelineTrace) -> None:
        """Cross-step value provenance (leads-only). A distinctive value that first
        surfaced in ANOTHER principal's PRIVATE response (a sensitively-named field)
        and is now consumed in THIS principal's request is a cross-principal value
        migration — a business-logic/authorization leak no payload tool sees, since
        it spans the request chain, not a single exchange. Reuses the Axis-1
        provenance table; flag-gated => byte-identical when off."""
        if not getattr(self, "chain_provenance", False):
            return
        from .provenance import extract_values
        from .intrinsic import Lead, LeadKind, Confidence, name_sensitivity
        acting = ex.principal.pid
        req = ex.request
        consumed = set()
        for tv in extract_values(req.body):
            consumed.add(tv.value)
        for v in (req.query or {}).values():
            if isinstance(v, list):
                consumed.update(x for x in v if not isinstance(x, bool))
            elif not isinstance(v, bool):
                consumed.add(v)
        for seg in (req.path or "").split("/"):
            if seg:
                consumed.add(seg)
        for v in consumed:
            if not self._distinctive_value(v):
                continue
            origin = self.provenance.first_seen_for_other_principal(v, acting)
            if origin is None:
                continue                               # not migrated across a principal boundary
            leaf = (origin.field_path or "").split(".")[-1].split("[")[0]
            token_like = isinstance(v, str) and (len(v) >= 20 or v.count(".") >= 2)
            if name_sensitivity(leaf) < 7 and not token_like:
                continue                               # public-origin value -> ignore (no signal)
            sig = (str(v), acting)
            if sig in self._emitted_chain:
                continue
            self._emitted_chain.add(sig)
            self.leads.append((tr.tid, Lead(
                kind=LeadKind.CHAIN_PROVENANCE, family=req.endpoint_key(), principal=acting,
                paths=[origin.field_path or "?"],
                weight=name_sensitivity(leaf) + (4 if token_like else 2),
                confidence=Confidence.STRONG_LEAD, confirmable=True,
                rationale=(f"a distinctive value originating in '{origin.principal_id}'s private "
                           f"response ({origin.endpoint} . {origin.field_path}) is now consumed "
                           f"in '{acting}'s request to {req.endpoint_key()} — a cross-principal "
                           f"value migration the server accepted without re-establishing scope"),
                suggested_probe=(f"replay '{acting}'s request after rotating/invalidating the "
                                 f"value as '{origin.principal_id}'; if it still succeeds, the "
                                 f"endpoint trusts a value it should re-authorize"),
                evidence={"origin_principal": origin.principal_id, "origin_endpoint": origin.endpoint,
                          "origin_field": origin.field_path, "consumed_in": req.endpoint_key()})))

    def _temporal_drift_pass(self, ex: Exchange, tr: PipelineTrace, family: str) -> None:
        """Temporal STRUCTURAL drift (leads-only): after a privilege-NARROWING event
        (role downgrade / plan change) that leaves the credential VALID, the
        principal's response still carries a privileged branch STRUCTURALLY — the
        role narrowed but the privileged code path still runs. This is strictly
        disjoint from the value-based TemporalDriftLaw, which fires only on a
        REVOKED credential; here the credential is valid, so that law passes and
        only structure betrays the drift. Flag-gated => byte-identical when off."""
        if not getattr(self, "temporal_drift", False):
            return
        from .temporal import credential_of
        from .intrinsic import Lead, LeadKind, Confidence, name_sensitivity
        from .structural import fingerprint
        pid = ex.principal.pid
        # disjoint from the revocation law: if the credential was revoked, that law
        # owns the case (a finding) — do not also emit a drift lead.
        if self.lifecycle.revocation_before(pid, credential_of(ex.request, ex.principal),
                                            self._cur_seq) is not None:
            return
        nr = self._role_narrowed.get(pid)
        if nr is None or nr[0] >= self._cur_seq:
            return                                     # no prior privilege-narrowing for this principal
        body = self._struct_body(ex)
        if not isinstance(body, (dict, list)):
            return
        branches = sorted({p for p in fingerprint(body).present_paths()
                           if p != "$" and name_sensitivity(p.split(".")[-1].split("[")[0]) >= 7})
        if not branches:
            return
        sig = (pid, family, tuple(branches))
        if sig in self._emitted_tdrift:
            return
        self._emitted_tdrift.add(sig)
        nseq, nkind, nep = nr
        self.leads.append((tr.tid, Lead(
            kind=LeadKind.TEMPORAL_STRUCTURAL_DRIFT, family=family, principal=pid,
            paths=branches,
            weight=max(name_sensitivity(b.split(".")[-1].split("[")[0]) for b in branches) + 3,
            confidence=Confidence.STRONG_LEAD, confirmable=True,
            rationale=(f"'{pid}' underwent a {nkind} event ({nep}, seq {nseq}) that should have "
                       f"narrowed its role, yet its later response on {family} still carries the "
                       f"privileged branch(es) {branches} structurally — the privileged code path "
                       f"survives a downgrade the credential itself stayed valid through (so the "
                       f"value-based revocation law cannot see it)"),
            suggested_probe=(f"after the {nkind}, replay this read as '{pid}'; if the privileged "
                             f"branch persists, the downgrade was not enforced at the field/authz "
                             f"layer"),
            evidence={"narrowing_seq": nseq, "narrowing_kind": nkind,
                      "narrowing_endpoint": nep, "branches": branches})))

    def _graphql_pass(self, ex: Exchange, tr: PipelineTrace) -> None:
        """GraphQL-native field-level authorization lens (leads-only). The server
        discloses its own field boundary: a REQUESTED field returned with an
        authz-class error is a measured authz denial (0-FP). Tracking which
        principal had a field POPULATED vs DENIED on the SAME object surfaces
        field-level BOLA/BFLA — the residual signature in GraphQL where there is
        no PRESENT_NULL. Gated on is_graphql => REST byte-identical."""
        if not ex.request.is_graphql():
            return
        from .intrinsic import Confidence, Lead, LeadKind, name_sensitivity
        from .graphql import authz_denied_paths, response_data
        from .structural import fingerprint
        family = ex.request.endpoint_key()
        try:
            objsig = ",".join(sorted(str(o) for o in ex.request.object_ids()))
        except Exception:
            objsig = ""
        denied = [d for d in authz_denied_paths(ex.response.body) if name_sensitivity(d) >= 7]
        pid = ex.principal.pid
        # reference-free recon: the server told us this field is authz-gated
        for field in denied:
            ent = self._gql_field.setdefault((family, objsig, field),
                                             {"pop": set(), "deny": set()})
            ent["deny"].add(pid)
            ent["req"] = ex.request                  # template for a controlled replay
            k = (family, objsig, field, pid, "deny")
            if k in self._emitted_gql:
                continue
            self._emitted_gql.add(k)
            self.leads.append((tr.tid, Lead(
                kind=LeadKind.GRAPHQL_FIELD_AUTHZ, family=family, principal=pid,
                paths=[field], weight=name_sensitivity(field), confidence=Confidence.LEAD,
                confirmable=True,
                rationale=(f"the server refused the requested field '{field}' on authorization "
                           f"grounds for '{pid}' — a field-level authz boundary it discloses "
                           f"itself; map it across principals/objects for BOLA"),
                suggested_probe=(f"request the identical selection of '{field}' as other "
                                 f"principals and against other object ids; a principal who "
                                 f"receives it populated where '{pid}' is denied is field-BOLA"),
                evidence={"objsig": objsig, "field": field, "code": "authz-denied"})))
        # populated sensitive fields for this principal on this object
        data = response_data(ex.response.body)
        if isinstance(data, (dict, list)):
            for p in fingerprint(data).populated_paths():
                if p != "$" and name_sensitivity(p) >= 7:
                    ent = self._gql_field.setdefault((family, objsig, p),
                                                     {"pop": set(), "deny": set()})
                    ent["pop"].add(pid)
                    ent.setdefault("req", ex.request)
        # cross-principal differential: same field+object, populated for one, denied for another
        for (fam, osig, field), st in self._gql_field.items():
            if fam != family or osig != objsig:
                continue
            if st["pop"] and st["deny"] and not (st["pop"] & st["deny"]):
                k = (fam, osig, field, "bola")
                if k in self._emitted_gql:
                    continue
                self._emitted_gql.add(k)
                self.leads.append((tr.tid, Lead(
                    kind=LeadKind.GRAPHQL_FIELD_BOLA, family=fam, principal=ex.principal.pid,
                    paths=[f"{fam}#{osig}.{field}"],
                    weight=name_sensitivity(field) + 3, confidence=Confidence.STRONG_LEAD,
                    confirmable=True,
                    rationale=(f"on the same object ({osig}), field '{field}' is POPULATED for "
                               f"{sorted(st['pop'])} yet authz-DENIED for {sorted(st['deny'])} — "
                               f"field-level BOLA/BFLA the backend itself contradicts"),
                    suggested_probe=(f"replay the populated principal's exact selection as the "
                                     f"denied principal; a Δstate confirming '{field}' crosses "
                                     f"is a confirmed field-level access-control finding"),
                    evidence={"objsig": osig, "field": field,
                              "populated_for": sorted(st["pop"]),
                              "denied_for": sorted(st["deny"])})))

    # -- snapshots for the dashboard --------------------------------------- #
    def snapshot(self) -> dict:
        envs = {pid: {"object_ids": sorted(e.object_ids),
                      "effects": sorted(x.value for x in e.effects),
                      "authority": sorted(e.granted_authority)}
                for pid, e in self.envelopes.all().items()}
        return {
            "principals": {pid: {"label": p.label, "anon": p.is_anonymous}
                           for pid, p in self.principals.items()},
            "envelopes": envs,
            "catalog": self.eil.catalog(),
            "policy_warnings": self.scope_guard.policy_warnings(),
            "findings": [self._finding_dict(f) for f in self.findings],
            "traces": [self._trace_dict(t) for t in self.traces],
            "leads": [self._lead_dict(tid, l) for tid, l in self.leads],
            "counts": self._counts(),
        }

    @staticmethod
    def _lead_dict(tid: str, lead) -> dict:
        return {
            "tid": tid, "kind": lead.kind, "confidence": lead.confidence,
            "weight": lead.weight, "family": lead.family, "principal": lead.principal,
            "paths": lead.paths, "rationale": lead.rationale,
            "confirmable": lead.confirmable, "suggested_probe": lead.suggested_probe,
            "evidence": lead.evidence,
        }

    def _counts(self) -> dict:
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            sev[f.severity.value] += 1
        return {
            "analyzed": len(self.traces),
            "findings": len(self.findings),
            "leads": len(self.leads),
            "candidates_dropped": sum(1 for t in self.traces if t.outcome == "candidate-unconfirmed"),
            "clean": sum(1 for t in self.traces if t.outcome == "clean"),
            "halted": sum(1 for t in self.traces if t.outcome == "halted"),
            "severity": sev,
        }

    @staticmethod
    def _trace_dict(t: PipelineTrace) -> dict:
        d = asdict(t)
        return d

    @staticmethod
    def _finding_dict(f: Finding) -> dict:
        return {
            "fid": f.fid, "title": f.title, "effect": f.effect.value,
            "impact": f.impact.value, "severity": f.severity.value,
            "law": f.law_name, "endpoint": f.classification.endpoint,
            "source": f.classification.source.value,
            "high_caution": f.classification.high_caution,
            "actor": f.actor_pid, "target": f.target_ref,
            "owner": f.state_proof.read_as,
            "causal_path": f.causal_path,
            "state_proof": {
                "method": f.state_proof.method, "before": f.state_proof.before,
                "after": f.state_proof.after, "read_as": f.state_proof.read_as,
                "detail": f.state_proof.detail,
            },
            "poc": {"steps": f.poc.steps, "curl": f.poc.curl, "notes": f.poc.notes},
            "cvss": {"score": f.cvss_score, "label": f.cvss_label, "vector": f.cvss_vector},
            "enumerability": {"level": f.enumerability, "note": f.enumerability_note},
            "report_markdown": f.report_markdown,
        }


def _massassign_findings(engine, self_path="/api/me"):
    """Mass-assignment (write-side BOPLA): detect privilege-bound fields (role-tied in
    observed self-bodies), then for each member confirm a write-then-read-back Δstate that
    sticks. Scope-gated (dry_run abstains). A SEPARATE channel — never touches
    engine.findings; reuses the bva bridge for the confirmer + provisioned principals.
    Empty unless `bva` was on (the bridge exists)."""
    ch = getattr(engine, "_bva", None)
    if ch is None or ch.get("bridge") is None:
        return []
    from .mass_assign import role_tied_privileged_fields
    from .models import HTTPRequest
    bridge = ch["bridge"]
    # the host must match the scope allow-list (the confirmation goes through scope.check) —
    # derive it from the target rather than leaving it empty.
    host = ""
    base = getattr(engine.target, "base_url", "")
    if base:
        from urllib.parse import urlparse
        host = urlparse(base).hostname or ""
    # collect (declared_role, self-body) per principal by reading the self endpoint
    self_bodies = []
    member_idents = []
    for pid, principal in engine.principals.items():
        try:
            resp = engine.target.send(HTTPRequest("GET", self_path, host=host), principal)
        except Exception:
            continue
        body = getattr(resp, "body", None)
        if not isinstance(body, dict):
            continue
        role = body.get("role") or body.get("type")
        self_bodies.append((role, body))
        ident = body.get("id") or pid
        if role and str(role).lower() not in (
                "admin", "administrator", "superadmin", "root", "staff", "owner"):
            member_idents.append((ident, str(role)))
    fields = role_tied_privileged_fields(self_bodies)
    out = []
    # G14: when stateful attribution is on and the object carries a free-text
    # companion field, use the attributed variant (kills the pre-existing-value FP).
    companion = None
    if getattr(bridge, "nonce_authority", None) is not None:
        from .nonce_provenance import _is_freetext
        for _r, _b in self_bodies:
            if isinstance(_b, dict):
                for k in _b:
                    if _is_freetext(k):
                        companion = k
                        break
            if companion:
                break
    for ident, _role in member_idents:
        for field, priv_value in fields:
            if companion is not None:
                # attributed path ran: TRUST its verdict (finding or abstain). Do NOT
                # fall back to the semantic-only check — that would re-introduce the
                # pre-existing-value FP the attributed path exists to kill.
                f = bridge.confirm_mass_assignment_attributed(
                    ident, self_path, field, priv_value, companion_field=companion, host=host)
            else:
                f = bridge.confirm_mass_assignment(ident, self_path, field, priv_value, host=host)
            if f is not None:
                out.append(f)
    return out


# --------------------------------------------------------------------------- #
# RL21 embedded-owner exposure helpers (cold-start ownership). Structural only  #
# (RL1-safe): read the SHAPE of owner-identity fields, never learn a baseline.  #
# --------------------------------------------------------------------------- #

_OWNER_ID_KEYS = ("email", "id", "uuid", "user_id", "username", "number", "phone")


def _embedded_owner_identities(body: dict) -> list:
    """Discriminating owner-identity values declared inside a response body, i.e.
    values that name WHO owns the object (owner/user/author sub-objects, or *_owner
    fields). Returns the concrete identity values (emails/ids) so the caller can test
    them against the reader and the tracked principals."""
    from .provenance import classify_field, ValueClass
    out, seen = [], set()

    def take(v):
        if isinstance(v, (str, int)) and str(v) not in seen:
            seen.add(str(v)); out.append(v)

    def walk(node, owner_ctx=False):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = k.lower()
                is_owner_field = kl in ("owner", "user", "author", "customer", "seller",
                                        "created_by", "createdby") or kl.endswith("owner")
                if isinstance(v, dict):
                    walk(v, owner_ctx=owner_ctx or is_owner_field)
                elif isinstance(v, list):
                    for it in v:
                        walk(it, owner_ctx=owner_ctx or is_owner_field)
                else:
                    if owner_ctx and kl in _OWNER_ID_KEYS:
                        take(v)                       # e.g. owner.email / user.id
                    elif classify_field(k, v) == ValueClass.OWNER:
                        take(v)                       # e.g. owner_email at top level
        elif isinstance(node, list):
            for it in node:
                walk(it, owner_ctx)

    walk(body)
    return out


def _body_is_public(body: dict) -> bool:
    """Explicit public-visibility markers -> the object is not private, so exposure
    to many principals is by design (RL5 exoneration)."""
    if not isinstance(body, dict):
        return False
    for k in ("visibility", "access", "scope"):
        v = body.get(k)
        if isinstance(v, str) and v.lower() in ("public", "everyone", "all"):
            return True
    for k in ("is_public", "public"):
        if body.get(k) is True:
            return True
    return False


def _flat_kv(node, _depth=0):
    """Yield (leaf_key, leaf_value) pairs from a nested body, so RL22 can inspect
    every field regardless of nesting (author.email inside posts[].author, etc.)."""
    if _depth > 8:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                yield from _flat_kv(v, _depth + 1)
            else:
                yield k, v
    elif isinstance(node, list):
        for it in node:
            yield from _flat_kv(it, _depth + 1)


_PII_FIELD_HINTS = ("email", "mail", "phone", "mobile", "number", "ssn", "vehicleid",
                    "vin", "address", "dob", "birth", "passport", "tax", "iban",
                    "card", "account")


def _is_pii_leak(key: str, val, value_class) -> bool:
    """RL22 sensitivity gate: is (key,val) a personally-identifying / identity-bearing
    field whose exposure to a non-owner matters? Structural only (RL1-safe)."""
    from .confirmer import _is_sensitive_key
    from .provenance import ValueClass
    if isinstance(val, str) and "@" in val and "." in val:
        return True                                    # email-shaped value
    kl = key.lower()
    if any(h in kl for h in _PII_FIELD_HINTS):
        return True                                    # PII-named field
    if value_class in (ValueClass.OWNER, ValueClass.TOKEN):
        return True                                    # identity / secret bearing
    if _is_sensitive_key(key):
        return True
    return False


def _value_in_body(body, val) -> bool:
    """True if `val` appears anywhere in a (possibly nested) response body."""
    try:
        for _, v in _flat_kv(body if isinstance(body, (dict, list)) else {}):
            if v == val:
                return True
    except Exception:
        pass
    return False
