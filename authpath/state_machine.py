"""
authpath.state_machine — STATE MACHINES (layer E): declared vs measured.

THE TITLE OF THE BRIEF IS THE PROBLEM
--------------------------------------------------------------------------------
"State machine INFERENCE" — build the machine from observed sequences, then treat
any transition outside it as a violation — is anomaly detection against a learned
baseline. It is the exact move RL1 exists to forbid, and it is worth spelling out
because it looks so reasonable:

    we observed  created -> paid -> shipped -> delivered
    we then see  created -> delivered
    therefore    a violation

The middle step is the error. A capture is a SAMPLE of traffic, not a
specification of the workflow. If nobody happened to cancel an order while we were
recording, `created -> cancelled` never appears — and that says nothing whatever
about whether cancelling is legitimate. A machine built from observations is a
COVERAGE RECORD. It cannot be the reference it is measured against, because then
the tool is only measuring its own sample.

So this module keeps the two apart at the type level:

  * a DECLARED machine (from layer A's `FrontendContract.state_machines`, or from
    the operator's contract) is a reference. The target wrote it down. Comparing a
    measurement to it is transcription vs measurement — the same epistemology as
    OpenAPI vs observed traffic, and legitimate.
  * an OBSERVED machine carries `authority="coverage_record"` and is STRUCTURALLY
    incapable of producing a violation. It answers "what did we see", never "what
    is allowed".

THE CAPTURE IS NOT A COMPLETE HISTORY
-------------------------------------
Second correction, equally load-bearing. Seeing `status=created` at T1 and
`status=delivered` at T2 does NOT prove a jump occurred. Between those two reads a
background job, a webhook, an admin console, another browser tab or a second
client may have driven every intermediate transition off-camera. We did not
observe a jump; we failed to observe the middle.

Every transition therefore carries an `attribution`:

  * `single_request`     — a MUTATION on that resource sits between the two
                           observations, and no other observation of it does. The
                           transition is attributable to that request. Even this
                           is not proof: another actor may still have intervened,
                           which is why nothing here is a finding.
  * `observed_adjacency` — the state differs between two reads with no mutation of
                           ours between them. Something happened, and we do not
                           know what. This can never become a violation.

ROLE-FORBIDDEN TRANSITIONS ARE CIRCULAR AS SPECIFIED
-----------------------------------------------------
The brief says: layer D says `viewer` cannot do `paid -> shipped`, we saw `viewer`
do it, therefore a violation. But a DENIED cell in layer D means "we observed a
refusal", not "policy forbids". Using one measurement as the policy oracle for
another measurement proves only that the two measurements disagree — and ownership
or the object's own state explains that just as well. Role divergence is therefore
recorded as SUSPICIOUS with the ambiguity stated, never as a violation.

WHAT IS REUSED RATHER THAN REBUILT
----------------------------------
  state detection ... `provenance.extract_values` + `ValueClass.STATE`, the closed
                      hint vocabulary `StateGateLaw._terminal_state` already uses.
                      No second state-field lexicon is introduced.
  resource identity . `surface_map.identify` — the same structural parse layers C
                      and D use, so a resource means one thing across all of them.
  declared machines . layer A's `FrontendContract.state_machines`.

WHY NO GATES ARE AUTO-GENERATED FOR `StateGateLaw`
---------------------------------------------------
It would be convenient to turn a declared machine into `StateGateLaw` gates, and
it would be wrong. That law asks "does field X hold value V on the object NOW"
(`{"field": "paid", "equals": True}`). A machine says "the PRIOR state was P".
Turning `paid -> shipped` into `{"field": "paid", "equals": True}` invents a
boolean field that may not exist on the object at all. So the mapping is not
performed. `prior_state_requirements` is emitted instead, in its own shape and
clearly labelled, for an operator to review and install deliberately.

WHAT THIS MODULE IS NOT
-----------------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil`,
`confirmer` or `engine` (asserted by test). Every violation and every suspicion is
a place to look; confirmation stays Delta-state (RL3).

DETERMINISM
-----------
Same observations in, same machines out. Everything sorted; no set iteration
reaches the output; observation order within a resource is preserved by an
explicit sequence number, never by dict ordering.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Machine provenance. The distinction is the whole design.
SOURCE_DECLARED_FRONTEND = "declared_frontend"
SOURCE_DECLARED_CONTRACT = "declared_contract"
SOURCE_OBSERVED = "observed"
_DECLARED_SOURCES = frozenset({SOURCE_DECLARED_FRONTEND, SOURCE_DECLARED_CONTRACT})

# How firmly a transition is tied to a request of ours.
ATTR_SINGLE_REQUEST = "single_request"
ATTR_ADJACENCY = "observed_adjacency"

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_STATE_LEN = 64
_MAX_RESOURCES = 5000
_MAX_OBSERVATIONS = 50_000
_MAX_PROBES = 500

# A transition must be seen this many times before it may be called a violation.
# One sighting can be an artefact of an incomplete capture; since this layer
# confirms nothing either way, the conservative split costs nothing — both lists
# receive probes.
DEFAULT_MIN_OBSERVATIONS = 2


# --------------------------------------------------------------------------- #
# state extraction — reusing the project's own closed vocabulary               #
# --------------------------------------------------------------------------- #

def state_values(body: Any) -> tuple:
    """State-class values in a body, via `provenance.extract_values`.

    The vocabulary is `provenance.STATE_HINTS`, the same closed list
    `StateGateLaw` already consults. Values must be short scalar strings: a
    `status: 200` is an HTTP code, not a workflow state, and a `status: {...}` is
    a sub-document. Both are dropped rather than coerced.
    """
    out: list = []
    try:
        from .provenance import extract_values, ValueClass
    except Exception:                                # noqa: BLE001
        return ()
    try:
        vals = extract_values(body)
    except Exception:                                # noqa: BLE001
        return ()
    for tv in vals:
        if getattr(tv, "value_class", None) != ValueClass.STATE:
            continue
        v = getattr(tv, "value", None)
        if not isinstance(v, str):
            continue                                 # numeric/complex: not a state
        s = v.strip().lower()
        if not s or len(s) > _MAX_STATE_LEN or s.isdigit():
            continue
        path = str(getattr(tv, "path", "") or "")
        if (path, s) not in out:
            out.append((path, s))
    return tuple(sorted(out))


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class State:
    name: str
    resource_type: str
    is_terminal: bool = False
    observed_count: int = 0
    source: str = SOURCE_OBSERVED


@dataclass(frozen=True)
class Transition:
    from_state: str
    to_state: str
    resource_type: str
    trigger_endpoint: str = ""          # "" when no request of ours can be blamed
    attribution: str = ATTR_ADJACENCY
    observed_count: int = 0
    by_roles: tuple = ()
    principals: tuple = ()
    resources: tuple = ()

    @property
    def key(self) -> str:
        return f"{self.resource_type}:{self.from_state}->{self.to_state}"


@dataclass
class StateMachine:
    resource_type: str
    states: dict = field(default_factory=dict)       # name -> State
    transitions: list = field(default_factory=list)
    inferred_from: str = SOURCE_OBSERVED
    declared_map: dict = field(default_factory=dict)  # state -> [allowed next]

    @property
    def is_declared(self) -> bool:
        return self.inferred_from in _DECLARED_SOURCES

    @property
    def authority(self) -> str:
        """A declared machine is a REFERENCE. An observed one is a record of what
        we happened to see, and may never be used as the standard."""
        return "reference" if self.is_declared else "coverage_record"

    def allows(self, frm: str, to: str) -> Optional[bool]:
        """True/False under a DECLARED map, or None when it cannot say."""
        if not self.is_declared or frm not in self.declared_map:
            return None
        return to in (self.declared_map.get(frm) or [])


@dataclass
class StateMachineResult:
    state_machines: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    suspicious_transitions: list = field(default_factory=list)
    prior_state_requirements: dict = field(default_factory=dict)
    probes: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "state_machines": [
                {"resource_type": m.resource_type, "inferred_from": m.inferred_from,
                 "authority": m.authority,
                 "states": [{"name": s.name, "is_terminal": s.is_terminal,
                             "observed_count": s.observed_count, "source": s.source}
                            for s in sorted(m.states.values(), key=lambda x: x.name)],
                 "transitions": [{"from": t.from_state, "to": t.to_state,
                                  "trigger_endpoint": t.trigger_endpoint,
                                  "attribution": t.attribution,
                                  "observed_count": t.observed_count,
                                  "by_roles": list(t.by_roles)}
                                 for t in m.transitions],
                 "declared_map": {k: list(v) for k, v in sorted(m.declared_map.items())}}
                for m in self.state_machines
            ],
            "transitions": [{"key": t.key, "from": t.from_state, "to": t.to_state,
                             "resource_type": t.resource_type,
                             "trigger_endpoint": t.trigger_endpoint,
                             "attribution": t.attribution,
                             "observed_count": t.observed_count,
                             "by_roles": list(t.by_roles)}
                            for t in self.transitions],
            "violations": list(self.violations),
            "suspicious_transitions": list(self.suspicious_transitions),
            "prior_state_requirements": {k: dict(v) for k, v
                                         in sorted(self.prior_state_requirements.items())},
            "probes": list(self.probes),
            "stats": dict(sorted(self.stats.items())),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# the inferrer — observation only                                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Obs:
    seq: int
    rtype: str
    rid: str
    state: str
    endpoint: str
    method: str
    principal: str
    roles: tuple
    mutating: bool


class StateInferrer:
    """Record state observations per resource, and hold declared machines.

    This class issues no request and reaches no conclusion; `plan()` does the
    comparison.
    """

    def __init__(self, role_overrides=None) -> None:
        self._obs: list = []
        self._seq = 0
        self._declared: dict = {}                    # rtype -> (map, source)
        self.role_overrides = dict(role_overrides or {})

    # -- declarations ------------------------------------------------------ #

    def declare_machine(self, resource_type: str, transitions: dict,
                        source: str = SOURCE_DECLARED_CONTRACT) -> None:
        """Register a DECLARED machine: {state: [allowed next states]}."""
        rtype = _singularise(str(resource_type or "").strip().lower())
        if not rtype or not isinstance(transitions, dict):
            return
        clean: dict = {}
        for k, v in transitions.items():
            ks = str(k).strip().lower()
            if not ks or len(ks) > _MAX_STATE_LEN:
                continue
            nxt = []
            for item in (v if isinstance(v, (list, tuple)) else [v]):
                s = str(item).strip().lower()
                if s and len(s) <= _MAX_STATE_LEN and s not in nxt:
                    nxt.append(s)
            clean[ks] = sorted(nxt)
        if clean:
            self._declared[rtype] = (clean, source)

    def declare_from_frontend(self, fc) -> None:
        """Adopt layer A's declared state machines.

        FCX keys them by the identifier the author wrote (`ORDER_STATES`), so the
        resource type is recovered by stripping the declared vocabulary suffix and
        singularising — a transcription of a written name, not a similarity match.
        """
        machines = getattr(fc, "state_machines", fc)
        if not isinstance(machines, dict):
            return
        for name, mapping in sorted(machines.items()):
            rtype = _rtype_from_declared_name(name)
            if rtype:
                self.declare_machine(rtype, mapping, SOURCE_DECLARED_FRONTEND)

    # -- observation ------------------------------------------------------- #

    def observe(self, request, response, principal=None) -> None:
        """Record every state value this exchange revealed, per resource."""
        if len(self._obs) >= _MAX_OBSERVATIONS:
            return
        try:
            from .surface_map import identify
            ident = identify(request)
        except Exception:                            # noqa: BLE001
            ident = None
        if ident is None:
            return                                   # unidentifiable: no machine row

        body = getattr(response, "body", None)
        states = state_values(body)
        if not states:
            return

        try:
            from .role_matrix import roles_of_principal
            roles = tuple(r for r, _s in roles_of_principal(principal, request,
                                                            self.role_overrides))
        except Exception:                            # noqa: BLE001
            roles = ()

        method = (getattr(request, "method", "") or "").upper()
        try:
            endpoint = request.endpoint_key()
        except Exception:                            # noqa: BLE001
            endpoint = f"{method} {getattr(request, 'path', '')}"
        pid = getattr(principal, "pid", None) or ""

        for _path, value in states:
            self._seq += 1
            self._obs.append(_Obs(self._seq, ident.rtype, ident.rid, value,
                                  endpoint, method, str(pid), roles,
                                  method in _MUTATING))

    def observations(self) -> list:
        return list(self._obs)


def _singularise(noun: str) -> str:
    try:
        from .surface_map import _singular
        return _singular(noun)
    except Exception:                                # noqa: BLE001
        return noun[:-1] if noun.endswith("s") and len(noun) > 2 else noun


# Declared-name suffixes layer A recognises. Closed, and only ever STRIPPED — a
# name that keeps none of them is still accepted as the type itself.
_DECLARED_SUFFIXES = ("statemachines", "statemachine", "statetransitions",
                      "allowedtransitions", "transitions", "nextstates",
                      "workflows", "workflow", "states", "fsm")


def _rtype_from_declared_name(name: str) -> str:
    n = "".join(ch for ch in str(name).lower() if ch.isalnum())
    for suf in _DECLARED_SUFFIXES:
        if n.endswith(suf) and len(n) > len(suf):
            return _singularise(n[:-len(suf)])
    return ""


# --------------------------------------------------------------------------- #
# planning                                                                     #
# --------------------------------------------------------------------------- #

def plan(inferrer: StateInferrer, role_matrix=None,
         min_observations: int = DEFAULT_MIN_OBSERVATIONS,
         enabled: bool = False) -> StateMachineResult:
    """Build the machines and compare measurements against DECLARED references.

    DEFAULT OFF. Disabled, an empty result is returned and nothing is inspected.

    `role_matrix` is layer D's result; it is used only to note where a role's
    outcome here disagrees with a measurement there — never to decide anything.
    """
    res = StateMachineResult()
    if not enabled:
        return res

    obs = inferrer.observations()

    # ---- per-resource timelines, ordered by the explicit sequence number -----
    timelines: dict = {}
    for o in obs:
        if len(timelines) >= _MAX_RESOURCES:
            break
        timelines.setdefault((o.rtype, o.rid), []).append(o)
    for k in timelines:
        timelines[k].sort(key=lambda x: x.seq)

    # ---- stage 1: states ------------------------------------------------------
    seen_states: dict = {}
    for o in obs:
        c = seen_states.setdefault((o.rtype, o.state), 0)
        seen_states[(o.rtype, o.state)] = c + 1

    # ---- stage 2: transitions, with honest attribution ------------------------
    raw: dict = {}
    for (rtype, _rid), line in sorted(timelines.items()):
        for prev, cur in zip(line, line[1:]):
            if prev.state == cur.state:
                continue
            # A mutation of ours sitting on the later observation is the only
            # thing that lets us name a trigger. Even then another actor may have
            # intervened, which is why nothing here is a finding.
            if cur.mutating:
                attribution, trigger = ATTR_SINGLE_REQUEST, cur.endpoint
            else:
                attribution, trigger = ATTR_ADJACENCY, ""
            key = (rtype, prev.state, cur.state, attribution, trigger)
            slot = raw.setdefault(key, {"count": 0, "roles": set(),
                                        "pids": set(), "rids": set()})
            slot["count"] += 1
            slot["roles"].update(cur.roles)
            if cur.principal:
                slot["pids"].add(cur.principal)
            slot["rids"].add(_rid)

    transitions = [
        Transition(from_state=f, to_state=t, resource_type=rt,
                   trigger_endpoint=trig, attribution=attr,
                   observed_count=v["count"], by_roles=tuple(sorted(v["roles"])),
                   principals=tuple(sorted(v["pids"])),
                   resources=tuple(sorted(v["rids"])[:8]))
        for (rt, f, t, attr, trig), v in sorted(raw.items())
    ]
    transitions.sort(key=lambda t: (t.resource_type, t.from_state, t.to_state,
                                    t.attribution, t.trigger_endpoint))
    res.transitions = transitions

    # ---- stage 3: machines ----------------------------------------------------
    rtypes = sorted({rt for rt, _s in seen_states} | set(inferrer._declared))
    for rtype in rtypes:
        declared = inferrer._declared.get(rtype)
        dmap, dsource = (declared if declared else ({}, None))
        states: dict = {}
        for name in sorted(dmap):
            states[name] = State(name, rtype, source=dsource)
            for nxt in dmap[name]:
                states.setdefault(nxt, State(nxt, rtype, source=dsource))
        for (rt, name), count in sorted(seen_states.items()):
            if rt != rtype:
                continue
            prior = states.get(name)
            states[name] = State(name, rtype,
                                 is_terminal=False,
                                 observed_count=count,
                                 source=prior.source if prior else SOURCE_OBSERVED)
        outgoing = {t.from_state for t in transitions if t.resource_type == rtype}
        for name, st in list(states.items()):
            declared_out = bool(dmap.get(name))
            if not declared_out and name not in outgoing:
                states[name] = State(st.name, st.resource_type, True,
                                     st.observed_count, st.source)
        res.state_machines.append(StateMachine(
            resource_type=rtype, states=states,
            transitions=[t for t in transitions if t.resource_type == rtype],
            inferred_from=dsource or SOURCE_OBSERVED,
            declared_map={k: list(v) for k, v in sorted(dmap.items())},
        ))
    res.state_machines.sort(key=lambda m: m.resource_type)
    machines = {m.resource_type: m for m in res.state_machines}

    # ---- stage 4: violations require a DECLARED reference ---------------------
    for t in transitions:
        m = machines.get(t.resource_type)
        allowed = m.allows(t.from_state, t.to_state) if m else None

        if allowed is False and t.attribution == ATTR_SINGLE_REQUEST \
                and t.observed_count >= min_observations:
            res.violations.append({
                "kind": "contradicts_declared_machine",
                "resource_type": t.resource_type, "from": t.from_state,
                "to": t.to_state, "trigger_endpoint": t.trigger_endpoint,
                "declared_next": list(m.declared_map.get(t.from_state, [])),
                "declared_by": m.inferred_from,
                "observed_count": t.observed_count,
                "by_roles": list(t.by_roles), "resolved": False,
                "note": ("the target's OWN declared machine does not list this "
                         "target state as reachable from that state; measured "
                         "against a declaration, not against our sample"),
            })
            continue

        why = None
        if allowed is False and t.attribution != ATTR_SINGLE_REQUEST:
            why = ("contradicts the declared machine, but no request of ours sits "
                   "between the two reads — the intermediate steps may simply have "
                   "happened off-camera")
        elif allowed is False:
            why = (f"contradicts the declared machine but was seen only "
                   f"{t.observed_count}x (< {min_observations}); a single sighting "
                   f"can be an artefact of an incomplete capture")
        elif allowed is None and m is not None and m.is_declared:
            why = ("the declared machine says nothing about this starting state, "
                   "so it cannot be the reference here")
        elif m is not None and not m.is_declared:
            why = ("no declared machine for this resource type — the observed "
                   "machine is a COVERAGE RECORD and can never be the standard "
                   "a transition is judged against")
        if why:
            res.suspicious_transitions.append({
                "kind": "unreferenced_transition", "resource_type": t.resource_type,
                "from": t.from_state, "to": t.to_state,
                "trigger_endpoint": t.trigger_endpoint,
                "attribution": t.attribution, "observed_count": t.observed_count,
                "by_roles": list(t.by_roles), "resolved": False, "note": why,
            })

    # ---- role divergence: two measurements disagreeing, never a verdict -------
    for item in _role_divergences(transitions, role_matrix):
        res.suspicious_transitions.append(item)

    # ---- the operator-reviewable artefact -------------------------------------
    for m in res.state_machines:
        if not m.is_declared:
            continue
        for frm, nexts in sorted(m.declared_map.items()):
            for to in nexts:
                req = res.prior_state_requirements.setdefault(
                    f"{m.resource_type}:{to}",
                    {"resource_type": m.resource_type, "target_state": to,
                     "prior_state_in": [], "source": m.inferred_from,
                     "auto_installed": False,
                     "note": ("StateGateLaw asks whether a FIELD holds a value now; "
                              "this says what the PRIOR STATE must have been. The "
                              "shapes differ, so no gate is generated — review and "
                              "install deliberately")})
                if frm not in req["prior_state_in"]:
                    req["prior_state_in"] = sorted(req["prior_state_in"] + [frm])

    # ---- probes ---------------------------------------------------------------
    probes: list = []
    for v in res.violations:
        probes.append(_probe("declared_contradiction", v["resource_type"],
                             v["from"], v["to"], v.get("trigger_endpoint", ""), 100,
                             "re-drive this transition on another object of the "
                             "same type and read the object back: does the target "
                             "state persist, and is the declared predecessor still "
                             "absent?"))
    for s in res.suspicious_transitions:
        probes.append(_probe(s["kind"], s.get("resource_type", ""), s.get("from", ""),
                             s.get("to", ""), s.get("trigger_endpoint", ""), 50,
                             s.get("note", "")))
    res.probes = _dedup(probes)[:_MAX_PROBES]

    res.stats = {
        "observations": len(obs), "resources": len(timelines),
        "machines": len(res.state_machines),
        "declared_machines": sum(1 for m in res.state_machines if m.is_declared),
        "transitions": len(transitions),
        "attributed": sum(1 for t in transitions
                          if t.attribution == ATTR_SINGLE_REQUEST),
        "violations": len(res.violations),
        "suspicious": len(res.suspicious_transitions), "probes": len(res.probes),
    }

    res.notes.append("an OBSERVED machine is a coverage record, never a reference: "
                     "a transition absent from our sample is not thereby illegitimate")
    res.notes.append("a capture is not a complete history — a state difference "
                     "between two reads may have been driven off-camera, which is "
                     "what `attribution` records")
    res.notes.append("nothing here is a finding; every entry is a place to look, "
                     "and confirmation remains Delta-state only (RL3)")
    undeclared = [m.resource_type for m in res.state_machines if not m.is_declared]
    if undeclared:
        res.notes.append("no declared machine for: " + ", ".join(sorted(undeclared)) +
                         " — no violation can be raised for these (fail-safe)")
    if not res.state_machines:
        res.notes.append("no state field was observed and none was declared, so no "
                         "machine was built — this is NOT evidence that the target "
                         "has no workflow")
    res.notes = sorted(set(res.notes))
    return res


def _role_divergences(transitions, role_matrix) -> list:
    """Where a role drove a transition here while layer D measured a refusal for
    that role on the same endpoint.

    Reported as a disagreement between two MEASUREMENTS. Layer D's DENIED means
    "we observed a refusal", not "policy forbids", so treating it as an oracle
    would be circular — ownership or the object's own state explains the
    difference just as well.
    """
    out: list = []
    cells = getattr(role_matrix, "matrix", None)
    if not cells:
        return out
    denied: dict = {}
    try:
        from .role_matrix import DENIED
    except Exception:                                # noqa: BLE001
        return out
    for c in cells:
        if getattr(c, "decision", "") == DENIED:
            denied.setdefault((c.role, f"{c.method} {c.endpoint}"), True)
    for t in transitions:
        if not t.trigger_endpoint:
            continue
        for role in t.by_roles:
            if (role, t.trigger_endpoint) in denied:
                out.append({
                    "kind": "role_divergence", "resource_type": t.resource_type,
                    "from": t.from_state, "to": t.to_state,
                    "trigger_endpoint": t.trigger_endpoint, "role": role,
                    "attribution": t.attribution,
                    "observed_count": t.observed_count, "resolved": False,
                    "note": ("layer D measured a refusal for this role on this "
                             "endpoint while this role drove the transition here; "
                             "two measurements disagree — ownership or object state "
                             "explains that as readily as a policy break, so this "
                             "is a place to look, not a violation"),
                })
    out.sort(key=lambda d: (d["resource_type"], d["from"], d["to"], d["role"]))
    return out


def _probe(kind, rtype, frm, to, endpoint, priority, why) -> dict:
    return {"kind": kind, "resource_type": rtype, "from": frm, "to": to,
            "trigger_endpoint": endpoint, "priority": priority, "because": why,
            "confirmed_by": "Delta-state read-back in the existing confirmer"}


def _dedup(items: list) -> list:
    seen, out = set(), []
    for it in items:
        k = (it["kind"], it["resource_type"], it["from"], it["to"],
             it["trigger_endpoint"])
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    out.sort(key=lambda d: (-d["priority"], d["kind"], d["resource_type"],
                            d["from"], d["to"]))
    return out


# --------------------------------------------------------------------------- #
# capture bridge                                                               #
# --------------------------------------------------------------------------- #

def state_machines_from_har(har: dict, in_scope_hosts=None, frontend_contract=None,
                            declared_machines=None, role_matrix=None,
                            role_overrides=None,
                            min_observations: int = DEFAULT_MIN_OBSERVATIONS,
                            enabled: bool = False) -> StateMachineResult:
    """Observe a capture's state values and compare them to declared machines.

    DEFAULT OFF. Zero network — probes are DESCRIBED, never issued.
    """
    if not enabled:
        return StateMachineResult()
    from .harimport import parse_har_exchanges
    inf = StateInferrer(role_overrides=role_overrides)
    if frontend_contract is not None:
        inf.declare_from_frontend(frontend_contract)
    for rtype, mapping in (declared_machines or {}).items():
        inf.declare_machine(rtype, mapping, SOURCE_DECLARED_CONTRACT)
    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                                # noqa: BLE001
        exchanges = []
    for ex in exchanges:
        try:
            inf.observe(ex.request, ex.response, ex.principal)
        except Exception:                            # noqa: BLE001
            continue
    return plan(inf, role_matrix=role_matrix, min_observations=min_observations,
                enabled=True)
