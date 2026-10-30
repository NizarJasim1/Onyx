"""
authpath.composite_sequences — COMPOSITE SEQUENCES (layer F): a declared-invariant
registry that DELEGATES, plus the one invariant nothing owns.

THE HEADLINE EXAMPLE IN THE BRIEF IS RL18'S OWN DOCSTRING
--------------------------------------------------------------------------------
The brief opens with the folder/document case. That is, verbatim, the canonical
example in `global_invariants.py`:

    1. principal X owns folder F and reads doc D inside it        — permitted
    2. F's ownership is transferred away from X                    — permitted
    → D should have followed F. ... No single operation broke a rule; the global
      invariant "a child's authority follows its parent's" was broken by the
      COMPOSITION.

RL18 already ships: `InvariantLedger` observing the sequence, `EmergentBreak`,
`GlobalInvariantLaw`, `EIL.evaluate_global_invariant`, and a Δstate confirmation
path. Writing a second parent/child detector would duplicate it and drift from it
the moment either is touched. So layer F does not implement that invariant. It
delegates to the one that exists.

The same is true of three more of the brief's five:

  | brief's invariant            | already owned by            |
  |------------------------------|-----------------------------|
  | child authority follows parent | `global_invariants` + `GlobalInvariantLaw` (RL18) |
  | required predecessor          | `StateGateLaw` (declared gates) |
  | no replay after single use    | `CouponLaw` |
  | financial conservation        | `PaymentLaw` / `PriceLaw` |
  | no reverse after terminal     | **nothing** — implemented here |

Layer F is therefore a REGISTRY that names each invariant's owner, and the
implementation of the single orphan. That is a smaller claim than the brief makes
and the only honest one available.

THE BRIEF ASKS FOR SOMETHING STRUCTURALLY IMPOSSIBLE
-----------------------------------------------------
Three of its requirements cannot hold together:

    "generate every possible sequence from the state machine"
  + "confirm each break by a Δstate read-back"
  + "read only — never write" (AEGIS gate 3)

To stand in the state that follows `transfer_folder` you must PERFORM the
transfer, and that is a write. A sequence the capture never drove cannot be
confirmed without writing, so a generated sequence is not a detection mechanism at
all. RL18 says exactly this about itself: *"the engine OBSERVES the sequence in
legitimate traffic — it NEVER generates the transfer."*

So generation is kept, and demoted to what it honestly is. `sequence_hypotheses`
are enumerated from DECLARED machines, capped, and carried with
`executable=False`, `requires_writes=True` and the reason. They are a worklist for
a human with a test account, never something this module drives.

GENERATING FROM AN OBSERVED MACHINE WOULD RE-IMPORT THE INDUCTION LAYER E REMOVED
--------------------------------------------------------------------------------
Layer E marks a machine built from traffic `authority="coverage_record"` precisely
because a transition absent from our sample is not thereby illegitimate. Feeding
that machine into a path generator and calling the deviations "invariant breaks"
is the same error one level up — anomaly detection against our own sample.

Only `is_declared` machines generate here. An observed-only machine produces no
hypotheses and says so.

DEPTH 1 IS LAYER E's JOB
-------------------------
The brief lists `[ship]` — a single transition — as a composite finding. A lone
transition contradicting a declared machine is exactly layer E's
`contradicts_declared_machine`. Emitting it again here would double-report it, so
hypotheses start at length 2 and the reason is recorded.

WHAT LAYER F ACTUALLY ADDS
--------------------------
1. `no_reverse_after_terminal` — an object observed in a DECLARED terminal state
   and later observed in an earlier one. Nothing owns this: `StateGateLaw` checks
   forward gates, not reversal, and layer E compares adjacent pairs without a
   notion of terminality. It is checked on timelines the capture ALREADY drove, so
   no write is needed to reach the state.
2. The delegation registry above, so a future layer cannot quietly re-implement a
   law that exists.
3. Read-only probe plans for whatever the observation turned up.

WHAT THIS MODULE IS NOT
-----------------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil` or
`engine`, and it does not re-implement `global_invariants` — it instantiates the
real `InvariantLedger` and reads its answers. Every probe is a READ; nothing here
can propose a write.

DETERMINISM
-----------
Same observations in, same output. Everything sorted; hypotheses are enumerated in
a fixed order; no set iteration reaches the output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Hard ceilings. The brief's depth-5 over a branching machine is b^5 paths, so the
# caps are the difference between a worklist and a hang.
MAX_DEPTH = 5
MIN_DEPTH = 2                      # depth 1 belongs to layer E — see the docstring
_MAX_HYPOTHESES = 500
_MAX_PROBES = 500
_MAX_OBSERVATIONS = 50_000

# Invariant names, and who owns each. A registry entry is a POINTER, never a
# second implementation.
INV_CHILD_FOLLOWS_PARENT = "child_authority_follows_parent"
INV_REQUIRED_PREDECESSOR = "required_predecessor"
INV_SINGLE_USE = "no_replay_after_single_use"
INV_FINANCIAL = "financial_conservation"
INV_NO_REVERSE = "no_reverse_after_terminal"

INVARIANT_REGISTRY = {
    INV_CHILD_FOLLOWS_PARENT: {
        "owner": "authpath.global_invariants + eil.GlobalInvariantLaw (RL18)",
        "implemented_here": False,
        "note": "layer F instantiates the real InvariantLedger and reads its "
                "answers; re-implementing it would create a second detector that "
                "drifts from the first",
    },
    INV_REQUIRED_PREDECESSOR: {
        "owner": "eil.StateGateLaw (declared gates) + layer E prior_state_requirements",
        "implemented_here": False,
        "note": "a target state's predecessor predicates are already declared and "
                "already evaluated against the Delta-state read-back",
    },
    INV_SINGLE_USE: {
        "owner": "eil.CouponLaw",
        "implemented_here": False,
        "note": "single-use consumption is an existing effect-routed law",
    },
    INV_FINANCIAL: {
        "owner": "eil.PaymentLaw / eil.PriceLaw",
        "implemented_here": False,
        "note": "amount conservation is an existing effect-routed law",
    },
    INV_NO_REVERSE: {
        "owner": "authpath.composite_sequences (layer F)",
        "implemented_here": True,
        "note": "nothing owned this: StateGateLaw checks forward gates, not "
                "reversal, and layer E compares adjacent pairs with no notion of "
                "terminality",
    },
}


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SequenceHypothesis:
    """A path a DECLARED machine says is walkable. Not a finding, not executed."""
    resource_type: str
    states: tuple = ()                 # ("created", "paid", "shipped")
    depth: int = 0
    executable: bool = False           # always False — see `requires_writes`
    requires_writes: bool = True
    reason: str = ""

    @property
    def key(self) -> str:
        return f"{self.resource_type}:" + "->".join(self.states)


@dataclass(frozen=True)
class InvariantBreak:
    """An invariant contradicted by observations the capture ALREADY holds."""
    invariant: str
    resource: str
    principal: str
    detail: str
    evidence: tuple = ()
    owner: str = ""
    resolved: bool = False


@dataclass
class CompositeResult:
    sequences: list = field(default_factory=list)
    invariant_breaks: list = field(default_factory=list)
    delegated: list = field(default_factory=list)
    registry: dict = field(default_factory=dict)
    probes: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sequences": [{"key": s.key, "resource_type": s.resource_type,
                           "states": list(s.states), "depth": s.depth,
                           "executable": s.executable,
                           "requires_writes": s.requires_writes,
                           "reason": s.reason}
                          for s in self.sequences],
            "invariant_breaks": [{"invariant": b.invariant, "resource": b.resource,
                                  "principal": b.principal, "detail": b.detail,
                                  "evidence": list(b.evidence), "owner": b.owner,
                                  "resolved": b.resolved}
                                 for b in self.invariant_breaks],
            "delegated": list(self.delegated),
            "registry": {k: dict(v) for k, v in sorted(self.registry.items())},
            "probes": list(self.probes),
            "stats": dict(sorted(self.stats.items())),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# stage 1 — hypotheses, from DECLARED machines only                            #
# --------------------------------------------------------------------------- #

def enumerate_sequences(machine, max_depth: int = MAX_DEPTH) -> list:
    """Paths a DECLARED machine says are walkable, depth-bounded.

    Returns [] for an observed-only machine: generating paths from a coverage
    record and treating the deviations as breaks is anomaly detection against our
    own sample, which is what layer E exists to refuse.

    Paths shorter than `MIN_DEPTH` are omitted — a single transition contradicting
    a declared machine is layer E's `contradicts_declared_machine`, and emitting it
    here would double-report it.
    """
    if machine is None or not getattr(machine, "is_declared", False):
        return []
    dmap = dict(getattr(machine, "declared_map", {}) or {})
    if not dmap:
        return []
    depth = max(MIN_DEPTH, min(int(max_depth or MAX_DEPTH), MAX_DEPTH))
    rtype = getattr(machine, "resource_type", "")

    out: list = []
    # Breadth-first over states in sorted order, so enumeration is deterministic
    # and the cap truncates the same paths every run.
    frontier = [(s,) for s in sorted(dmap)]
    while frontier and len(out) < _MAX_HYPOTHESES:
        nxt: list = []
        for path in frontier:
            for succ in dmap.get(path[-1], []):
                if succ in path:
                    continue                 # a cycle adds no new reachability
                extended = path + (succ,)
                if len(extended) >= MIN_DEPTH:
                    out.append(extended)
                    if len(out) >= _MAX_HYPOTHESES:
                        break
                if len(extended) < depth:
                    nxt.append(extended)
            if len(out) >= _MAX_HYPOTHESES:
                break
        frontier = nxt

    seen: set = set()
    hyps: list = []
    for path in sorted(set(out)):
        if path in seen:
            continue
        seen.add(path)
        hyps.append(SequenceHypothesis(
            resource_type=rtype, states=path, depth=len(path),
            executable=False, requires_writes=True,
            reason=("standing in the state this path ends in requires PERFORMING "
                    "its transitions, which are writes; this module never writes, "
                    "so the path is a worklist for an operator with a test "
                    "account, not something confirmable from here"),
        ))
    return hyps[:_MAX_HYPOTHESES]


# --------------------------------------------------------------------------- #
# stage 2 — the one invariant nothing owns                                     #
# --------------------------------------------------------------------------- #

def _terminal_states(machine) -> tuple:
    """States a DECLARED machine gives no outgoing transition. Declared, not
    guessed: a state absent from the map's keys, or mapped to an empty list."""
    if machine is None or not getattr(machine, "is_declared", False):
        return ()
    dmap = dict(getattr(machine, "declared_map", {}) or {})
    reachable: set = set(dmap)
    for nexts in dmap.values():
        reachable |= set(nexts or [])
    return tuple(sorted(s for s in reachable if not dmap.get(s)))


def _rank(machine) -> dict:
    """Distance of each state from a declared start, for ordering only.

    A state with no declared predecessor is a start. Ranks are used solely to say
    "this state comes before that one" under the DECLARED map — never to invent an
    order the map does not contain.
    """
    dmap = dict(getattr(machine, "declared_map", {}) or {})
    has_pred: set = set()
    for nexts in dmap.values():
        has_pred |= set(nexts or [])
    starts = sorted(set(dmap) - has_pred) or sorted(dmap)
    rank: dict = {s: 0 for s in starts}
    frontier = list(starts)
    step = 0
    while frontier and step < MAX_DEPTH * 4:
        step += 1
        nxt: list = []
        for s in frontier:
            for succ in dmap.get(s, []):
                if succ not in rank:
                    rank[succ] = step
                    nxt.append(succ)
        frontier = nxt
    return rank


def detect_reversals(timelines: dict, machines: dict) -> list:
    """`no_reverse_after_terminal`, on timelines the capture already drove.

    An object observed in a DECLARED terminal state and later observed in a state
    the DECLARED map ranks earlier. Both observations are measurements and the
    terminality is a declaration, so nothing is inferred. Without a declared
    machine there is no terminal state and no order — abstain.
    """
    out: list = []
    for (rtype, rid), line in sorted(timelines.items()):
        m = machines.get(rtype)
        terminals = _terminal_states(m)
        if not terminals:
            continue
        rank = _rank(m)
        seen_terminal: Optional[tuple] = None
        for entry in line:
            state = entry["state"]
            if seen_terminal is not None:
                tstate, tseq = seen_terminal
                if state != tstate and rank.get(state, 99) < rank.get(tstate, 99):
                    out.append(InvariantBreak(
                        invariant=INV_NO_REVERSE,
                        resource=f"{rtype}:{rid}",
                        principal=entry.get("principal", ""),
                        detail=(f"object reached DECLARED terminal state "
                                f"'{tstate}' at observation {tseq}, then was "
                                f"observed in earlier state '{state}' at "
                                f"observation {entry['seq']}"),
                        evidence=(f"terminal={tstate}@{tseq}",
                                  f"later={state}@{entry['seq']}",
                                  f"declared_by={getattr(m, 'inferred_from', '')}"),
                        owner=INVARIANT_REGISTRY[INV_NO_REVERSE]["owner"],
                    ))
                    break                    # one break per object is enough
            if state in terminals:
                seen_terminal = (state, entry["seq"])
    return out


# --------------------------------------------------------------------------- #
# stage 3 — delegation, never re-implementation                                #
# --------------------------------------------------------------------------- #

def delegate_parent_child(exchanges, parent_map=None) -> list:
    """Run RL18's OWN ledger over the capture and report what IT found.

    `InvariantLedger` is instantiated, not copied. The parent link stays declared
    (`resource_parents`), the fail-safes stay RL18's, and if RL18 changes this
    changes with it.
    """
    out: list = []
    if not parent_map:
        return out                           # no declared link ⇒ no invariant here
    try:
        from .global_invariants import InvariantLedger
    except Exception:                        # noqa: BLE001
        return out
    # RL18 keys its ledger on `str(surface_map.identify(...))`, which normalises the
    # id to lower case. An operator writing `{"doc:D1": "folder:F1"}` would silently
    # match nothing, so the DECLARED map is aligned to that form here. This is
    # case-folding to meet an existing convention, not a rewrite of the declaration.
    ledger = InvariantLedger({str(k).lower(): str(v).lower()
                              for k, v in parent_map.items()})
    for ex in (exchanges or [])[:_MAX_OBSERVATIONS]:
        try:
            pid = getattr(getattr(ex, "principal", None), "pid", "") or ""
            brk = ledger.break_for(ex.request, ex.response, pid)
            if brk is not None:
                out.append(InvariantBreak(
                    invariant=INV_CHILD_FOLLOWS_PARENT,
                    resource=brk.child, principal=brk.principal,
                    detail=(f"child {brk.child} still accessible to "
                            f"'{brk.principal}' while its DECLARED parent "
                            f"{brk.parent} has been observed forbidden"),
                    evidence=(f"parent={brk.parent}", f"child={brk.child}"),
                    owner=INVARIANT_REGISTRY[INV_CHILD_FOLLOWS_PARENT]["owner"],
                ))
            ledger.observe(ex.request, ex.response, pid)
        except Exception:                    # noqa: BLE001
            continue
    return out


# --------------------------------------------------------------------------- #
# planning                                                                     #
# --------------------------------------------------------------------------- #

def plan(state_result=None, exchanges=None, parent_map=None,
         max_depth: int = MAX_DEPTH, enabled: bool = False) -> CompositeResult:
    """Enumerate declared-machine hypotheses, check the orphan invariant, and
    delegate the rest.

    DEFAULT OFF. Disabled, an empty result is returned and nothing is inspected.

    `state_result` is layer E's `StateMachineResult`; `exchanges` are the capture's
    parsed exchanges; `parent_map` is the DECLARED child→parent map RL18 consumes.
    """
    res = CompositeResult()
    if not enabled:
        return res

    res.registry = {k: dict(v) for k, v in INVARIANT_REGISTRY.items()}
    machines = {m.resource_type: m
                for m in getattr(state_result, "state_machines", []) or []}

    # ---- stage 1: hypotheses, declared machines only --------------------------
    for rtype in sorted(machines):
        res.sequences.extend(enumerate_sequences(machines[rtype], max_depth))
    res.sequences = sorted(res.sequences, key=lambda s: (s.resource_type, s.depth,
                                                         s.states))[:_MAX_HYPOTHESES]

    # ---- stage 2: the orphan invariant, on observed timelines -----------------
    timelines = _timelines(state_result)
    res.invariant_breaks.extend(detect_reversals(timelines, machines))

    # ---- stage 3: delegation --------------------------------------------------
    delegated = delegate_parent_child(exchanges, parent_map)
    res.invariant_breaks.extend(delegated)
    for name, entry in sorted(INVARIANT_REGISTRY.items()):
        if not entry["implemented_here"]:
            res.delegated.append({"invariant": name, "owner": entry["owner"],
                                  "note": entry["note"]})

    res.invariant_breaks.sort(key=lambda b: (b.invariant, b.resource, b.principal))

    # ---- probes: reads only ---------------------------------------------------
    probes: list = []
    for b in res.invariant_breaks:
        probes.append({
            "kind": b.invariant, "resource": b.resource, "principal": b.principal,
            "method": "GET",
            "probe": ("re-read this resource as the same principal now: does the "
                      "contradicting condition still hold? " + b.detail),
            "writes": False,
            "confirmed_by": "Delta-state read-back in the existing confirmer",
            "resolved": False,
        })
    seen: set = set()
    for p in probes:
        k = (p["kind"], p["resource"], p["principal"])
        if k not in seen:
            seen.add(k)
            res.probes.append(p)
    res.probes.sort(key=lambda d: (d["kind"], d["resource"], d["principal"]))
    res.probes = res.probes[:_MAX_PROBES]

    res.stats = {
        "declared_machines": sum(1 for m in machines.values()
                                 if getattr(m, "is_declared", False)),
        "machines": len(machines), "hypotheses": len(res.sequences),
        "breaks": len(res.invariant_breaks), "probes": len(res.probes),
        "delegated_invariants": len(res.delegated),
    }

    res.notes.append("sequence hypotheses are NOT executable from here: standing in "
                     "the state a path ends in requires performing its transitions, "
                     "and this module never writes")
    res.notes.append("hypotheses come only from DECLARED machines; generating paths "
                     "from an observed coverage record and calling the deviations "
                     "breaks would be anomaly detection against our own sample")
    res.notes.append("four of the five invariants are DELEGATED to the components "
                     "that already own them; only no_reverse_after_terminal is "
                     "implemented here")
    res.notes.append("every probe is a READ; confirmation remains Delta-state only (RL3)")
    if not parent_map:
        res.notes.append("no declared parent map supplied, so RL18's parent/child "
                         "invariant was not exercised — absence of a break here is "
                         "NOT evidence that authority propagated")
    undeclared = sorted(r for r, m in machines.items()
                        if not getattr(m, "is_declared", False))
    if undeclared:
        res.notes.append("no declared machine for: " + ", ".join(undeclared) +
                         " — no hypotheses and no reversal check for these (fail-safe)")
    if not res.sequences and not res.invariant_breaks:
        res.notes.append("nothing produced — this is NOT evidence that every "
                         "sequence preserves every invariant")
    res.notes = sorted(set(res.notes))
    return res


def _timelines(state_result) -> dict:
    """(rtype, rid) -> ordered observations, rebuilt from layer E's own records.

    Layer E already keyed and ordered these; layer F reads them rather than
    re-deriving them, so the two cannot disagree about what was observed.
    """
    out: dict = {}
    inf = getattr(state_result, "_inferrer", None)
    obs = getattr(inf, "observations", None)
    records = obs() if callable(obs) else None
    if not records:
        records = getattr(state_result, "observations", None) or []
    for o in records:
        try:
            key = (o.rtype, o.rid)
            out.setdefault(key, []).append(
                {"seq": o.seq, "state": o.state, "principal": o.principal,
                 "endpoint": o.endpoint})
        except Exception:                    # noqa: BLE001
            continue
    for k in out:
        out[k].sort(key=lambda d: d["seq"])
    return out


# --------------------------------------------------------------------------- #
# capture bridge                                                               #
# --------------------------------------------------------------------------- #

def composite_from_har(har: dict, in_scope_hosts=None, frontend_contract=None,
                       declared_machines=None, parent_map=None,
                       max_depth: int = MAX_DEPTH,
                       enabled: bool = False) -> CompositeResult:
    """Build layer E's machines from a capture, then run layer F over them.

    DEFAULT OFF. Zero network — every probe is DESCRIBED, never issued, and no
    write is ever proposed.
    """
    if not enabled:
        return CompositeResult()
    from .harimport import parse_har_exchanges
    from .state_machine import StateInferrer, plan as state_plan, SOURCE_DECLARED_CONTRACT

    inf = StateInferrer()
    if frontend_contract is not None:
        inf.declare_from_frontend(frontend_contract)
    for rtype, mapping in (declared_machines or {}).items():
        inf.declare_machine(rtype, mapping, SOURCE_DECLARED_CONTRACT)
    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                        # noqa: BLE001
        exchanges = []
    for ex in exchanges:
        try:
            inf.observe(ex.request, ex.response, ex.principal)
        except Exception:                    # noqa: BLE001
            continue
    sres = state_plan(inf, enabled=True)
    sres._inferrer = inf
    return plan(sres, exchanges, parent_map, max_depth, enabled=True)
