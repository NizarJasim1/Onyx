"""
authpath.contradiction_detector — CONTRADICTION LEDGER (layer G).

FIVE OF THE SIX TYPES IN THE BRIEF ALREADY HAVE OWNERS
--------------------------------------------------------------------------------
Checked before writing anything, because a seventh detector for facts six
detectors already report is not a new capability — it is the same leak printed
six times.

  | brief's type                   | already produced by                        |
  |--------------------------------|--------------------------------------------|
  | 1 broadcast vs act             | FCX `contradiction_probes`, layer D anomalies |
  | 2 cross-door                   | RL15 `CrossSurfaceConsistencyLaw`, layer C |
  | 3 state-machine violation      | layer E `violations`                        |
  | 4 role-matrix anomaly          | layer D — and see below                     |
  | 5 temporal                     | RL16 `AuthShapeRegressionLaw` / `temporal_shape` |
  | 6 multi-layer convergence      | **nothing — implemented here**              |

Type 4 as written is also self-refuting: layer D's DENIED cell *is* traffic, so
"the matrix says forbidden but traffic shows access" is two traffic measurements
disagreeing — which is layer D's own CONFLICT, already reported with the ownership
caveat attached.

So layer G does not detect. It is a LEDGER: it collects what the layers already
concluded, deduplicates the same underlying fact across reporters, and accounts for
corroboration honestly. Its one new output is convergence.

THE PAIRWISE RULE IN THE BRIEF IS A FALSE-POSITIVE FACTORY
-----------------------------------------------------------
    if obs1.fact_type == "allowed" and obs2.fact_type == "forbidden":
        return True

Same resource, same principal, one allowed and one forbidden. That is not a
contradiction; on a per-object endpoint it is BOLA protection working, and on a
stateful object it is the state having changed legitimately between two reads. The
same trap was corrected twice already — in layer D (`expected_under_ownership`) and
in layer E (role divergence as "two measurements disagreeing"). Re-introducing it
here, globally and at scale, would fire on every correctly-secured application.

Layer G therefore creates NO contradiction of its own from raw allowed/forbidden
pairs. Every entry traces to a layer that already declared one, with that layer's
own caveats carried forward intact. A test pins this.

CORROBORATION ACROSS DEPENDENT LAYERS IS NOT CORROBORATION
-----------------------------------------------------------
The brief gives each observation `confidence: 1-4 (number of confirming sources)`.
Counting reporters would be wrong here for a reason that is specific to this stack:
**the layers are not independent.** Layer E consumes layer D; layer F consumes C, D
and E; layer D consumes A, B and C. When E and D "agree", that is one measurement
echoed, not two.

So `LAYER_DEPENDS_ON` is declared explicitly, and corroboration counts only a set
of reporters no two of which stand in the transitive dependency relation. A fact
reported by D and E scores **1**, not 2. This is the difference between a ledger
that informs and one that manufactures confidence.

TYPE 5 IS DELEGATED, AND THE BRIEF'S VERSION IS REFUSED
--------------------------------------------------------
"a state changed with no declared event justifying it -> anomaly" is the same error
layer E documents at length: **the capture is not a complete history.** An
unexplained change usually means the request that caused it was not observed — a
background job, a webhook, an admin console, another tab. Flagging it fires on
every normal application. Temporal work is delegated to RL16, which compares two
MEASURED value-blind fingerprints and guards against the legitimate-promotion false
positive with a role epoch.

DETERMINISM — AND WHY THERE IS NO `timestamp`
----------------------------------------------
The brief's `Observation.timestamp: float` is wall-clock, which would make the
output differ between two runs over the same capture. Ordering here is an explicit
integer sequence assigned at ingest, so the same inputs always produce the same
ledger.

NO COMBINATORIAL SEARCH
-----------------------
The brief's triple-combination search is O(n^3) per resource and,
worse, is a fishing expedition: any triple that "looks contradictory" would be
flagged. Convergence here is computed by GROUPING on an exact key — no
enumeration of tuples, and no approximate resource matching. Two layers
naming a resource differently
simply do not converge, and that recall limit is declared rather than papered
over with resemblance.

WHAT THIS MODULE IS NOT
-----------------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil`,
`confirmer` or `engine` (asserted by test). Every probe is a READ, deduplicated to
one per underlying fact instead of one per reporting layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Declared dependency graph. A layer's reports cannot corroborate a layer it
# consumes, or one that consumes it — that is one measurement echoed.
# Each entry mirrors what the layer's `plan()` actually accepts, not a diagram:
#   door_map.plan(ledger, surface=<B>)          -> C depends on B
#   role_matrix.plan(rm, surface=<B>)           -> D depends on B, and on A via
#                                                  frontend_guards
#   state_machine.plan(inf, role_matrix=<D>)    -> E depends on D, and on A via
#                                                  declare_from_frontend
#   composite_sequences.plan(state_result=<E>)  -> F depends on E
#   cross_operation                              -> FCE depends on A only
# The first draft of this table listed D as consuming C and F as consuming C/D.
# Neither is true in the code, and the error mattered: it made C and D look
# dependent, which would have suppressed the only convergence pairs that exist.
LAYER_DEPENDS_ON = {
    "A": (),                       # frontend contract (FCX)
    "B": ("A",),                   # surface aggregator
    "C": ("B",),                   # door map
    "D": ("A", "B"),               # role matrix
    "E": ("A", "D"),               # state machine
    "F": ("E",),                   # composite sequences
    "FCE": ("A",),                 # cross-operation extractor
}

# How a reported fact is grounded. Carried forward from the reporting layer.
GROUND_DECLARED = "declared"       # the target wrote it down
GROUND_MEASURED = "measured"       # we observed it
GROUND_PLANNED = "planned"         # a probe suggestion, not yet anything

_MAX_OBSERVATIONS = 50_000
_MAX_PROBES = 500

# Types the brief lists, and who owns each. A registry entry is a POINTER.
TYPE_REGISTRY = {
    "broadcast_vs_act": {
        "owner": "frontend_contract.contradiction_probes + role_matrix privilege_anomalies",
        "implemented_here": False},
    "cross_door": {
        "owner": "eil.CrossSurfaceConsistencyLaw (RL15) + door_map",
        "implemented_here": False},
    "state_machine_violation": {
        "owner": "state_machine.violations (layer E)",
        "implemented_here": False},
    "role_matrix_anomaly": {
        "owner": "role_matrix (layer D) — its DENIED cell IS traffic, so this is "
                 "two measurements disagreeing, already reported there",
        "implemented_here": False},
    "temporal": {
        "owner": "temporal_shape.AuthShapeLedger + eil.AuthShapeRegressionLaw (RL16)",
        "implemented_here": False},
    "multi_layer_convergence": {
        "owner": "authpath.contradiction_detector (layer G)",
        "implemented_here": True},
}


def _closure(layer: str, seen=None) -> set:
    """Layers `layer` transitively depends on. Declared, never discovered."""
    seen = seen if seen is not None else set()
    for dep in LAYER_DEPENDS_ON.get(layer, ()):
        if dep not in seen:
            seen.add(dep)
            _closure(dep, seen)
    return seen


def independent(a: str, b: str) -> bool:
    """True iff neither layer stands in the other's transitive dependency chain."""
    if a == b:
        return False
    return b not in _closure(a) and a not in _closure(b)


def independent_count(layers) -> int:
    """Size of the largest mutually-independent subset of reporters.

    Greedy over a sorted list, which is deterministic and can only UNDER-count —
    the fail-safe direction for a number that expresses corroboration.
    """
    chosen: list = []
    for lyr in sorted(set(layers)):
        if all(independent(lyr, c) for c in chosen):
            chosen.append(lyr)
    return len(chosen)


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Observation:
    """One conclusion a layer already reached. Layer G never derives these."""
    layer: str
    resource: str
    principal: str
    fact: str
    fact_type: str
    source: str = ""
    grounding: str = GROUND_MEASURED
    seq: int = 0                   # explicit order — NOT wall-clock (see docstring)
    caveat: str = ""               # the reporting layer's own reservation, kept

    @property
    def key(self) -> tuple:
        return (self.resource, self.principal, self.fact)


@dataclass
class Contradiction:
    resource: str
    principal: str
    fact: str
    fact_type: str
    reporters: tuple = ()          # ((layer, source), ...)
    independent_reporters: int = 0
    grounding: str = GROUND_MEASURED
    caveats: tuple = ()
    resolved: bool = False

    @property
    def key(self) -> tuple:
        return (self.resource, self.principal, self.fact)


@dataclass
class ContradictionResult:
    observations: list = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    cross_layer_conflicts: list = field(default_factory=list)
    temporal_anomalies: list = field(default_factory=list)
    deduplicated: list = field(default_factory=list)
    registry: dict = field(default_factory=dict)
    probes: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        def c(x):
            return {"resource": x.resource, "principal": x.principal,
                    "fact": x.fact, "fact_type": x.fact_type,
                    "reporters": [list(r) for r in x.reporters],
                    "independent_reporters": x.independent_reporters,
                    "grounding": x.grounding, "caveats": list(x.caveats),
                    "resolved": x.resolved}
        return {
            "observations": [{"layer": o.layer, "resource": o.resource,
                              "principal": o.principal, "fact": o.fact,
                              "fact_type": o.fact_type, "source": o.source,
                              "grounding": o.grounding, "seq": o.seq}
                             for o in self.observations],
            "contradictions": [c(x) for x in self.contradictions],
            "cross_layer_conflicts": [c(x) for x in self.cross_layer_conflicts],
            "temporal_anomalies": list(self.temporal_anomalies),
            "deduplicated": list(self.deduplicated),
            "registry": {k: dict(v) for k, v in sorted(self.registry.items())},
            "probes": list(self.probes),
            "stats": dict(sorted(self.stats.items())),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# ingest — read what each layer already concluded                              #
# --------------------------------------------------------------------------- #

class ContradictionLedger:
    """Collects layer conclusions. It derives nothing and judges nothing."""

    def __init__(self) -> None:
        self._obs: list = []
        self._seq = 0

    def add(self, layer: str, resource: str, principal: str, fact: str,
            fact_type: str, source: str = "", grounding: str = GROUND_MEASURED,
            caveat: str = "") -> None:
        if len(self._obs) >= _MAX_OBSERVATIONS:
            return
        if layer not in LAYER_DEPENDS_ON:
            return                             # unknown layer: no way in (RL5)
        res = str(resource or "").strip().lower()
        if not res or not fact:
            return
        self._seq += 1
        self._obs.append(Observation(
            layer=layer, resource=res, principal=str(principal or ""),
            fact=str(fact), fact_type=str(fact_type), source=str(source or ""),
            grounding=grounding, seq=self._seq, caveat=str(caveat or "")))

    def observations(self) -> list:
        return list(self._obs)

    # -- per-layer readers. Each reads that layer's OWN conclusions ---------- #

    def ingest_frontend(self, fc) -> None:
        """Layer A: client-side guards, which are DECLARATIONS, not policy."""
        try:
            from .frontend_contract import contradiction_probes
            for p in contradiction_probes(fc):
                self.add("A", p.get("target", ""), "", p.get("target", ""),
                         "declared_guard", p.get("declared_at", ""),
                         GROUND_DECLARED,
                         "client-side declaration only; not evidence the server "
                         "enforces or fails to enforce this role")
        except Exception:                      # noqa: BLE001
            pass

    def ingest_surface(self, sag) -> None:
        """Layer B: declaration conflicts the aggregator already refused to resolve."""
        for c in getattr(sag, "conflicts", []) or []:
            key = c.get("key") or c.get("template") or ""
            self.add("B", key, "", c.get("kind", "conflict"),
                     "source_conflict", c.get("kind", ""), GROUND_DECLARED,
                     c.get("note", ""))

    def ingest_doors(self, dm) -> None:
        """Layer C: cross-door contradictions, with RL15 coverage carried through."""
        for c in getattr(dm, "contradictions", []) or []:
            self.add("C", c.get("resource", ""), c.get("principal", ""),
                     c.get("field", ""), "field_exposed_elsewhere",
                     c.get("door_endpoint", ""), GROUND_MEASURED,
                     c.get("note", ""))

    def ingest_roles(self, rm) -> None:
        """Layer D: privilege anomalies and CONFLICT cells, caveats intact."""
        for a in getattr(rm, "privilege_anomalies", []) or []:
            self.add("D", f"{a.get('method','')} {a.get('endpoint','')}",
                     ",".join(a.get("lower_principals", []) or []),
                     f"{a.get('lower_role','')}>{a.get('higher_role','')}",
                     "privilege_anomaly", a.get("endpoint", ""), GROUND_MEASURED,
                     a.get("note", ""))
        for c in getattr(rm, "contradictions", []) or []:
            self.add("D", f"{c.get('method','')} {c.get('endpoint','')}",
                     ",".join(c.get("principals", []) or []),
                     c.get("role", ""), "role_outcome_conflict",
                     c.get("endpoint", ""), GROUND_MEASURED,
                     c.get("note", ""))

    def ingest_states(self, sm) -> None:
        """Layer E: only DECLARED-machine violations. Suspicions stay suspicions."""
        for v in getattr(sm, "violations", []) or []:
            self.add("E", v.get("resource_type", ""), "",
                     f"{v.get('from','')}->{v.get('to','')}",
                     "declared_transition_violation",
                     v.get("trigger_endpoint", ""), GROUND_DECLARED,
                     v.get("note", ""))

    def ingest_sequences(self, cs) -> None:
        """Layer F: invariant breaks, each already owned by a named invariant."""
        for b in getattr(cs, "invariant_breaks", []) or []:
            self.add("F", getattr(b, "resource", ""), getattr(b, "principal", ""),
                     getattr(b, "invariant", ""), "invariant_break",
                     getattr(b, "owner", ""), GROUND_MEASURED,
                     getattr(b, "detail", ""))

    def ingest_cross_operation(self, fce) -> None:
        """FCE: a measured refusal contradicted by a declared door."""
        for p in getattr(fce, "cross_operation_probes", []) or []:
            self.add("FCE", p.get("declared_operation", ""), p.get("principal", ""),
                     p.get("leaf", ""), "leaf_selectable_elsewhere",
                     p.get("declared_at", ""), GROUND_DECLARED,
                     p.get("epistemic_status", ""))


# --------------------------------------------------------------------------- #
# grouping — no combinations, no similarity                                    #
# --------------------------------------------------------------------------- #

def plan(ledger: ContradictionLedger, enabled: bool = False) -> ContradictionResult:
    """Deduplicate layer conclusions and count corroboration honestly.

    DEFAULT OFF. Disabled, an empty result is returned and nothing is inspected.
    """
    res = ContradictionResult()
    if not enabled:
        return res

    res.registry = {k: dict(v) for k, v in TYPE_REGISTRY.items()}
    obs = ledger.observations()
    res.observations = sorted(obs, key=lambda o: (o.resource, o.principal,
                                                  o.fact, o.layer, o.seq))

    # Group on an EXACT key. Two layers naming a resource differently simply do
    # not group — a declared recall limit, not something to close with fuzzy
    # matching (RL1).
    grouped: dict = {}
    for o in obs:
        grouped.setdefault(o.key, []).append(o)

    for key in sorted(grouped):
        items = sorted(grouped[key], key=lambda o: (o.layer, o.seq))
        layers = [o.layer for o in items]
        n_ind = independent_count(layers)
        ground = (GROUND_DECLARED if any(o.grounding == GROUND_DECLARED for o in items)
                  else items[0].grounding)
        entry = Contradiction(
            resource=key[0], principal=key[1], fact=key[2],
            fact_type=items[0].fact_type,
            reporters=tuple(sorted({(o.layer, o.source) for o in items})),
            independent_reporters=n_ind, grounding=ground,
            caveats=tuple(sorted({o.caveat for o in items if o.caveat})),
        )
        res.contradictions.append(entry)

        if len(items) > 1:
            res.deduplicated.append({
                "resource": entry.resource, "principal": entry.principal,
                "fact": entry.fact,
                "reported_by": sorted({o.layer for o in items}),
                "reports_collapsed": len(items),
                "independent_reporters": n_ind,
                "note": ("the same underlying fact was reported by several layers; "
                         "collapsed to one entry so it is not read as several "
                         "findings" if n_ind > 1 else
                         "these layers are not independent — one consumes the "
                         "other, so their agreement is one measurement echoed, "
                         "not corroboration"),
            })

        # The one genuinely new output: convergence of INDEPENDENT layers.
        if n_ind >= 2:
            res.cross_layer_conflicts.append(entry)

    res.contradictions.sort(key=lambda c: (-c.independent_reporters, c.resource,
                                           c.principal, c.fact))
    res.cross_layer_conflicts.sort(key=lambda c: (-c.independent_reporters,
                                                  c.resource, c.fact))

    # ---- probes: one per underlying FACT, never one per reporter -------------
    seen: set = set()
    for c in res.contradictions:
        if c.key in seen:
            continue
        seen.add(c.key)
        res.probes.append({
            "resource": c.resource, "principal": c.principal, "fact": c.fact,
            "fact_type": c.fact_type, "method": "GET", "writes": False,
            "reported_by": [r[0] for r in c.reporters],
            "independent_reporters": c.independent_reporters,
            "probe": ("re-read this resource as the same principal now and compare: "
                      "does the contradicting condition still hold?"),
            "carried_caveats": list(c.caveats),
            "confirmed_by": "Delta-state read-back in the existing confirmer",
            "resolved": False,
        })
    res.probes.sort(key=lambda d: (-d["independent_reporters"], d["resource"],
                                   d["principal"], d["fact"]))
    res.probes = res.probes[:_MAX_PROBES]

    res.stats = {"observations": len(obs), "facts": len(res.contradictions),
                 "converged": len(res.cross_layer_conflicts),
                 "deduplicated": len(res.deduplicated),
                 "probes": len(res.probes),
                 "layers_reporting": len({o.layer for o in obs})}

    res.notes.append("layer G detects nothing of its own: every entry traces to a "
                     "layer that already concluded it, and that layer's caveats "
                     "are carried forward intact")
    res.notes.append("a bare allowed/forbidden pair is NOT treated as a "
                     "contradiction — on a per-object endpoint that is ownership "
                     "working, and on a stateful object it is time passing")
    res.notes.append("corroboration counts only MUTUALLY INDEPENDENT layers; E "
                     "consumes D and F consumes C/D/E, so their agreement is one "
                     "measurement echoed")
    res.notes.append("temporal work is delegated to RL16; 'a state changed with no "
                     "declared cause' is refused because a capture is not a "
                     "complete history")
    res.notes.append("every probe is a READ; confirmation remains Delta-state only (RL3)")
    if not obs:
        res.notes.append("no layer reported anything — this is NOT evidence that "
                         "the target is self-consistent")
    single = [c for c in res.contradictions if c.independent_reporters < 2]
    if single:
        res.notes.append(f"{len(single)} fact(s) rest on a single independent "
                         f"reporter and are corroborated by nothing")
    res.notes = sorted(set(res.notes))
    return res


# --------------------------------------------------------------------------- #
# convenience: ingest every layer at once                                      #
# --------------------------------------------------------------------------- #

def detect(frontend=None, surface=None, doors=None, roles=None, states=None,
           sequences=None, cross_operation=None,
           enabled: bool = False) -> ContradictionResult:
    """Collect every layer's conclusions into one ledger and account for them.

    DEFAULT OFF. Zero network — every probe is DESCRIBED, never issued, and no
    write is ever proposed.
    """
    if not enabled:
        return ContradictionResult()
    led = ContradictionLedger()
    if frontend is not None:
        led.ingest_frontend(frontend)
    if surface is not None:
        led.ingest_surface(surface)
    if doors is not None:
        led.ingest_doors(doors)
    if roles is not None:
        led.ingest_roles(roles)
    if states is not None:
        led.ingest_states(states)
    if sequences is not None:
        led.ingest_sequences(sequences)
    if cross_operation is not None:
        led.ingest_cross_operation(cross_operation)
    return plan(led, enabled=True)
