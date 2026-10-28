"""
authpath.door_map — DOOR MAP (layer C): reachability planning for RL15.

READ THIS FIRST — WHAT LAYER C IS *NOT*, AND WHY
--------------------------------------------------------------------------------
The layer-C brief asks for five stages: identity unification, door classification,
exposure recording, contradiction detection, probe emission. Before writing a line,
each was checked against the tree. All five already exist:

  stage 1  identity unification ....... `surface_map.identify`, `identify_graphql`,
                                        `_secondary_key_identity`, `_normalise_id`
                                        (idformat decoding: 900 / acc_900 /
                                        b64 "Account:900" all collapse)
  stage 2  door classification ........ `surface_map.classify_door` with
                                        DOOR_CANONICAL / LIST / SEARCH / GRAPHQL /
                                        OTHER
  stage 3  exposure recording ......... `surface_map.DoorExposure`,
                                        `exposed_sensitive_fields`,
                                        `SurfaceLedger.record`, `.record_denials`
  stage 4  contradiction detection .... `eil.CrossSurfaceConsistencyLaw` — with the
                                        directional kill-test, the sensitive-only
                                        guard, the agreement nullifier and the
                                        no-reference abstain ALREADY in it
  stage 5  Delta-state confirmation ... `confirmer._confirm_cross_surface`

Writing a `DoorMap` that unifies identities, classifies doors and compares
exposures would therefore be a SECOND implementation of RL15 — one that drifts
from the first the moment either is touched. The brief itself forbids exactly
this ("nothing is rewritten"). So this module rewrites nothing. It imports the
RL15 primitives and delegates to them.

THE ACTUAL GAP, WHICH IS NARROW AND REAL
----------------------------------------
`SurfaceLedger` is fed only from OBSERVED exchanges, and the law fires only when a
non-canonical door is seen live *while* a canonical reference (or an explicit
GraphQL denial) already exists for the same (resource, principal). That leaves RL15
structurally blind in two situations — and layers A and B can now see both:

  BLIND SPOT 1 — the canonical door was never opened.
      The capture exercised `GET /api/accounts` (a list leaking `iban`) but never
      `GET /api/accounts/900`. `canonical_for()` returns None, so the law abstains.
      That abstention is CORRECT — without the authoritative view there is no
      reference and a verdict would be a guess. But the contradiction may be real
      and nothing in ONYX ever suggests opening the one door that would settle it.

  BLIND SPOT 2 — the other door was never opened.
      The capture exercised only `GET /api/accounts/900`. Layer A found
      `fetch("/api/accounts")` written in the bundle and layer B lists it. The law
      never runs, because no non-canonical exchange exists to evaluate.

In both cases the missing ingredient is an OBSERVATION, not a rule. So layer C's
whole job is: given the resources the capture touched and the doors layers A and B
say exist, emit the GET probes that would hand RL15's EXISTING law and confirmer
the observation they are missing.

That is the bridge the brief's own diagram describes — between "knowing the doors"
and "comparing them" — and it duplicates nothing.

RELATIONSHIP TO `SurfaceLedger` (the same shape as SAG vs `SurfaceGraph`)
--------------------------------------------------------------------------------
`SurfaceLedger` deliberately retains ONLY the canonical door, because in the live
engine the non-canonical door *is* the exchange under test. Planning needs the full
per-door picture, so `DoorLedger` observes every door additionally, and delegates
canonical and denial bookkeeping to a real `SurfaceLedger` rather than keeping a
private copy of that logic. `SurfaceLedger` is never modified, and its behaviour is
verified unchanged by test.

WHAT THIS MODULE EMITS
----------------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil`,
`confirmer` or `engine` (asserted by test). Its `contradictions` list is a REPORT:
entries where both doors were observed are tagged `covered_by_rl15=True`, because
the engine's own law already fires on them and layer C claims no novelty there.
The novel output is `probes` — GET-only read plans, every one of which still has to
survive `ScopeGuard` and still has to be proven by the Delta-state confirmer (RL3).

FIVE CONSTRAINTS, AND WHERE EACH IS HELD
----------------------------------------
1. Structural only (RL1). Identity comes from `surface_map.identify`. A probe is
   emitted for a candidate door ONLY if constructing that door's concrete path and
   re-identifying it yields the IDENTICAL `ResourceIdentity` — a round-trip through
   the project's own parser, not a name comparison. No similarity matching exists
   in this file.
2. Sensitive only. A divergence on a non-sensitive field is dropped, via
   `exposed_sensitive_fields`, which records sensitive leaves and nothing else.
3. Direction is fixed. The canonical door being RICHER than a list is by design and
   never reported. Only a non-canonical door exposing what the canonical withholds
   counts, mirroring the law's kill-test.
4. No reference means abstain (RL5). Without a canonical observation or an explicit
   denial, layer C reports NO contradiction — it emits a probe to go get the
   reference instead.
5. Confirmation stays Delta-state (RL3). A probe is a plan to look, never a
   discovery.

Probes are GET-only and capped. A planner that could propose a write would be a
planner that could cause damage; this one structurally cannot.

DETERMINISM
-----------
Same observations in, same plan out. Everything sorted; no set iteration reaches
the output; probes are deduplicated on their full descriptor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .surface_map import (
    ResourceIdentity, SurfaceLedger, identify, classify_door,
    exposed_sensitive_fields, _normalise_id, _singular,
    DOOR_CANONICAL, DOOR_LIST, DOOR_GRAPHQL, DOOR_SEARCH, DOOR_OTHER,
)

_MAX_PROBES = 500
_MAX_RESOURCES = 5000

# Probe kinds — both are READS. There is no third kind, by design.
PROBE_OPEN_CANONICAL = "open_canonical"   # fetch the missing authoritative reference
PROBE_OPEN_DOOR = "open_door"             # open a declared door nobody exercised


@dataclass(frozen=True)
class DoorRecord:
    """What one door revealed for one resource, for one principal.

    A thin projection of `surface_map.DoorExposure` carrying the fields planning
    needs. `denied_fields` are ones the server itself refused on authorization
    grounds — the strongest reference available, because it is the target stating
    its own policy rather than us inferring one from an absence.
    """
    door: str
    endpoint: str
    method: str
    path: str
    sensitive_fields: tuple = ()      # ((leaf, value), ...)
    denied_fields: tuple = ()         # (leaf, ...)

    @property
    def field_names(self) -> tuple:
        return tuple(k for k, _ in self.sensitive_fields)


@dataclass
class DoorMapResult:
    door_ledger: dict = field(default_factory=dict)
    contradictions: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    unopened_doors: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "door_ledger": {
                k: [{"door": r.door, "endpoint": r.endpoint,
                     "sensitive_fields": sorted(r.field_names),
                     "denied_fields": sorted(r.denied_fields)}
                    for r in v]
                for k, v in sorted(self.door_ledger.items())
            },
            "contradictions": list(self.contradictions),
            "probes": list(self.probes),
            "unopened_doors": list(self.unopened_doors),
            "stats": dict(sorted(self.stats.items())),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# the ledger — observes every door; delegates canonical/denials to RL15        #
# --------------------------------------------------------------------------- #

class DoorLedger:
    """Full per-door observation record, built on a real `SurfaceLedger`.

    Canonical references and GraphQL authorization denials are recorded by
    delegating to `SurfaceLedger`, so the null-is-not-a-denial kill-test and the
    sensitivity filter used here are literally the ones RL15 uses — there is no
    second copy to drift.
    """

    def __init__(self, pq_registry=None) -> None:
        self.surface = SurfaceLedger(pq_registry)
        # (rtype, rid, principal) -> {door_kind: DoorRecord}
        self._doors: dict = {}

    @property
    def pq_registry(self):
        return self.surface.pq_registry

    def observe(self, request, response, principal_id: str) -> None:
        """Record one exchange against every resource identity it addresses.

        Delegates to `SurfaceLedger` first so canonical/denial bookkeeping stays
        identical to the engine's, then keeps the additional per-door detail that
        `SurfaceLedger` intentionally discards.
        """
        try:
            self.surface.record(request, response, principal_id)
            self.surface.record_denials(request, response, principal_id)
        except Exception:                            # noqa: BLE001 — never break planning
            pass

        body = getattr(response, "body", None)
        if not isinstance(body, (dict, list)):
            return
        try:
            door = classify_door(request)
        except Exception:                            # noqa: BLE001
            return

        for ident, element_id in self._identities(request, body):
            if len(self._doors) >= _MAX_RESOURCES:
                return
            try:
                fields = exposed_sensitive_fields(body, element_id=element_id)
            except Exception:                        # noqa: BLE001
                fields = {}
            denied = tuple(sorted(self.surface.denials_for(ident, principal_id)))
            key = (ident.rtype, ident.rid, principal_id)
            rec = DoorRecord(
                door=door,
                endpoint=_safe(request, "endpoint_key", f"{request.method} {request.path}"),
                method=(getattr(request, "method", "") or "").upper(),
                path=getattr(request, "path", "") or "",
                sensitive_fields=tuple(sorted((k, str(v)) for k, v in fields.items())),
                denied_fields=denied,
            )
            bucket = self._doors.setdefault(key, {})
            # a later observation of the SAME door kind replaces the earlier one:
            # the most recent view of that door is the live one, matching
            # SurfaceLedger.record's own most-recent-wins rule.
            bucket[door] = rec

    def _identities(self, request, body) -> list:
        """(identity, element_id) pairs this exchange addresses.

        A single-object door yields its own identity. A list door yields one per
        element it carries, attributed to that element's OWN id, so a comparison is
        never made across two different resources.
        """
        out: list = []
        try:
            ident = identify(request, self.pq_registry)
        except Exception:                            # noqa: BLE001
            ident = None
        if ident is not None:
            return [(ident, None)]
        try:
            if classify_door(request) != DOOR_LIST:
                return out
        except Exception:                            # noqa: BLE001
            return out
        rtype = _list_rtype(request)
        if not rtype:
            return out
        for eid in _element_ids(body):
            nid = _normalise_id(eid)
            if nid:
                out.append((ResourceIdentity(rtype, nid), eid))
        return out

    def resources(self) -> list:
        """Sorted (rtype, rid, principal) keys — deterministic iteration order."""
        return sorted(self._doors)

    def doors_for(self, key) -> dict:
        return dict(self._doors.get(tuple(key), {}))

    def as_ledger(self) -> dict:
        return {f"{rt}:{rid}|{pid}": [self._doors[(rt, rid, pid)][d]
                                      for d in sorted(self._doors[(rt, rid, pid)])]
                for (rt, rid, pid) in self.resources()}


def _safe(obj, meth, default):
    try:
        return getattr(obj, meth)()
    except Exception:                                # noqa: BLE001
        return default


def _list_rtype(request) -> str:
    """Resource type a list door enumerates: the singularised last collection
    segment. Structural, and the same rule `surface_map` uses elsewhere."""
    path = (getattr(request, "path", "") or "").split("?")[0]
    segs = [s for s in path.split("/") if s]
    return _singular(segs[-1]) if segs else ""


def _element_ids(body) -> list:
    """Ids carried by a collection body, in document order. Structural: an `id`
    (or `<thing>_id`) leaf on a dict element. Never a value-shape guess."""
    out: list = []
    items = body if isinstance(body, list) else None
    if items is None and isinstance(body, dict):
        for v in body.values():
            if isinstance(v, list):
                items = v
                break
    for elem in (items or []):
        if not isinstance(elem, dict):
            continue
        for k, v in elem.items():
            kl = str(k).lower()
            if (kl == "id" or kl.endswith("_id")) and isinstance(v, (str, int)):
                out.append(str(v))
                break
    return out


# --------------------------------------------------------------------------- #
# planning                                                                     #
# --------------------------------------------------------------------------- #

def _canonical_path_for(rec: DoorRecord, ident: ResourceIdentity) -> Optional[str]:
    """Concrete canonical path for `ident`, built from a door that reached it.

    Structural only: a collection path plus the object's own id. Returns None when
    no such path can be constructed, which makes the probe simply not exist rather
    than be guessed at.
    """
    base = (rec.path or "").split("?")[0].rstrip("/")
    if not base.startswith("/"):
        return None
    segs = [s for s in base.split("/") if s]
    if not segs:
        return None
    if _singular(segs[-1]) == ident.rtype:
        return f"{base}/{ident.rid}"
    # a canonical/search door already ending in an id: swap the trailing segment
    if len(segs) >= 2 and _singular(segs[-2]) == ident.rtype:
        return "/" + "/".join(segs[:-1] + [ident.rid])
    return None


def _same_identity(path: str, rtype: str, rid: str) -> bool:
    """Does `path` re-identify to exactly (rtype, rid)?

    The round-trip that replaces name matching: a candidate door is only accepted
    when the project's OWN parser, handed the constructed path, returns the very
    same identity. A near-miss fails and the probe is dropped (RL5).
    """
    try:
        from .models import HTTPRequest
        ident = identify(HTTPRequest("GET", path))
    except Exception:                                # noqa: BLE001
        return False
    return ident is not None and ident.rtype == rtype and ident.rid == rid


def plan(ledger: DoorLedger, surface=None, enabled: bool = False) -> DoorMapResult:
    """Turn observations plus the layer-B surface into a read plan.

    DEFAULT OFF. Disabled, an empty result is returned and nothing is inspected.

    `surface` is an `AggregatedSurface` (layer B) or any iterable of objects with
    `.method` and `.template`; it supplies the doors that EXIST but were never
    opened. Without it, only blind spot 1 can be planned for.
    """
    res = DoorMapResult()
    if not enabled:
        return res

    templates = _surface_templates(surface)
    probes: list = []
    unopened: list = []
    n_res = 0

    for key in ledger.resources():
        rtype, rid, pid = key
        ident = ResourceIdentity(rtype, rid)
        doors = ledger.doors_for(key)
        n_res += 1
        canonical = doors.get(DOOR_CANONICAL)
        denials = ledger.surface.denials_for(ident, pid)

        # ---- report: both doors observed -> RL15's own law already covers it ----
        for kind, rec in sorted(doors.items()):
            if kind == DOOR_CANONICAL:
                continue
            for leaf, val in rec.sensitive_fields:
                if canonical is not None and leaf not in dict(canonical.sensitive_fields):
                    res.contradictions.append({
                        "resource": str(ident), "principal": pid, "field": leaf,
                        "door": kind, "door_endpoint": rec.endpoint,
                        "canonical_endpoint": canonical.endpoint,
                        "reference": "canonical_withholds",
                        "covered_by_rl15": True,
                        "note": "the engine's CrossSurfaceConsistencyLaw already "
                                "fires on this pair; reported here as a cross-check, "
                                "not as a new discovery",
                    })
                elif leaf in denials:
                    res.contradictions.append({
                        "resource": str(ident), "principal": pid, "field": leaf,
                        "door": kind, "door_endpoint": rec.endpoint,
                        "canonical_endpoint": denials[leaf].get("endpoint"),
                        "reference": "explicit_denial",
                        "covered_by_rl15": True,
                        "note": "the server itself refused this field on authorization "
                                "grounds — the strongest reference; already covered",
                    })

        # ---- BLIND SPOT 1: a door exposes something, no reference exists --------
        if canonical is None and not denials:
            for kind, rec in sorted(doors.items()):
                if not rec.sensitive_fields:
                    continue
                cpath = _canonical_path_for(rec, ident)
                if cpath is None or not _same_identity(cpath, rtype, rid):
                    continue
                probes.append({
                    "kind": PROBE_OPEN_CANONICAL, "principal": pid,
                    "method": "GET", "path": cpath, "resource": str(ident),
                    "because": (f"door '{kind}' ({rec.endpoint}) exposed sensitive "
                                f"field(s) {sorted(f for f, _ in rec.sensitive_fields)} "
                                f"for {ident}, but no canonical view and no explicit "
                                f"denial was ever observed for this principal"),
                    "enables": ("supplies the authoritative reference RL15 needs; "
                                "the law abstains without it and no verdict is "
                                "implied by this probe"),
                    "confirmed_by": "Delta-state read-back in confirmer._confirm_cross_surface",
                })

        # ---- BLIND SPOT 2: declared doors nobody opened for this resource -------
        opened = {(r.method, r.path.split("?")[0]) for r in doors.values()}
        for method, template in templates:
            if method != "GET":
                continue                              # planner emits reads only
            cpath = _concrete(template, rid)
            if cpath is None:
                continue
            if (method, cpath) in opened:
                continue
            is_list = "{" not in template
            if is_list:
                if _singular([s for s in template.split("/") if s][-1]) != rtype:
                    continue
            elif not _same_identity(cpath, rtype, rid):
                continue
            entry = {"resource": str(ident), "principal": pid,
                     "method": method, "path": cpath, "template": template,
                     "door": DOOR_LIST if is_list else DOOR_CANONICAL}
            unopened.append(entry)
            probes.append({
                "kind": PROBE_OPEN_DOOR, "principal": pid,
                "method": method, "path": cpath, "resource": str(ident),
                "because": (f"layers A/B declare {method} {template} exists, but no "
                            f"principal ever opened it for {ident}; RL15 cannot "
                            f"compare a door that was never observed"),
                "enables": ("supplies the missing door observation so the existing "
                            "law can compare surfaces"),
                "confirmed_by": "Delta-state read-back in confirmer._confirm_cross_surface",
            })

    res.door_ledger = ledger.as_ledger()
    res.contradictions.sort(key=lambda c: (c["resource"], c["principal"],
                                           c["field"], c["door"]))
    res.probes = _dedup(probes)[:_MAX_PROBES]
    res.unopened_doors = _dedup(unopened)
    res.stats = {"resources": n_res, "doors": sum(len(v) for v in res.door_ledger.values()),
                 "contradictions": len(res.contradictions), "probes": len(res.probes)}
    res.notes.append("every probe is a READ and a PLAN — it implies no verdict; "
                     "confirmation remains Delta-state only (RL3)")
    res.notes.append("contradictions marked covered_by_rl15 are already handled by "
                     "the engine's own law; this layer claims novelty only for the "
                     "probes it emits")
    if not res.probes and not res.contradictions:
        res.notes.append("no plan produced — this is NOT evidence that the doors agree")
    if surface is None:
        res.notes.append("no layer-B surface supplied: only missing-canonical probes "
                         "could be planned, never unopened-door probes")
    res.notes = sorted(set(res.notes))
    return res


def _surface_templates(surface) -> list:
    """(method, template) pairs from a layer-B `AggregatedSurface` or any iterable
    of endpoint-like objects. Total: an unreadable item is skipped, never repaired."""
    if surface is None:
        return []
    items = getattr(surface, "unified_surface", surface)
    out: set = set()
    try:
        iter(items)
    except TypeError:
        return []
    for e in items:
        try:
            method = (getattr(e, "method", None) or (e.get("method") if isinstance(e, dict) else "")) or ""
            template = (getattr(e, "template", None)
                        or getattr(e, "path", None)
                        or (e.get("template") or e.get("path") if isinstance(e, dict) else "")) or ""
            method = str(method).upper()
            template = str(template)
            if method and template.startswith("/"):
                out.add((method, template))
        except Exception:                            # noqa: BLE001
            continue
    return sorted(out)


def _concrete(template: str, rid: str) -> Optional[str]:
    """Substitute a single `{param}` with the object's id. Multi-parameter
    templates are refused: filling the wrong segment would address a different
    resource, which is precisely the cross-object bleed RL1 forbids."""
    if "{" not in template:
        return template
    if template.count("{") != 1:
        return None
    head, rest = template.split("{", 1)
    if "}" not in rest:
        return None
    tail = rest.split("}", 1)[1]
    return f"{head}{rid}{tail}"


def _dedup(items: list) -> list:
    seen, out = set(), []
    for it in items:
        k = tuple(sorted((str(a), str(b)) for a, b in it.items()))
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    out.sort(key=lambda d: (str(d.get("resource", "")), str(d.get("principal", "")),
                            str(d.get("kind", "")), str(d.get("path", ""))))
    return out


# --------------------------------------------------------------------------- #
# capture bridge                                                               #
# --------------------------------------------------------------------------- #

def door_map_from_har(har: dict, scope=None, in_scope_hosts=None, surface=None,
                      enabled: bool = False) -> DoorMapResult:
    """Observe a capture's doors and plan the reads RL15 is missing.

    DEFAULT OFF. Zero network — every probe is DESCRIBED, never issued; issuing one
    remains the engine's business, under `ScopeGuard` and the budget ledger.
    """
    if not enabled:
        return DoorMapResult()
    from .harimport import parse_har_exchanges
    ledger = DoorLedger()
    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                                # noqa: BLE001
        exchanges = []
    for ex in exchanges:
        try:
            ledger.observe(ex.request, ex.response, ex.principal.pid)
        except Exception:                            # noqa: BLE001
            continue
    return plan(ledger, surface=surface, enabled=True)
