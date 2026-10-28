"""
authpath.surface_aggregator — SURFACE AGGREGATOR (SAG, layer B).

WHY A SEPARATE LAYER AND NOT AN EXTENSION OF `surface.SurfaceGraph`
--------------------------------------------------------------------------------
Checked first, because a layer with no justification should not be built. The
answer is structural:

    def add(self, ep):
        prev = self._eps.get(ep.key)
        if prev is None or _conf(ep.source) > _conf(prev.source):
            self._eps[ep.key] = ep

`SurfaceGraph` is **lossy by design**: one endpoint per key, the highest-confidence
source, the rest discarded. Exactly right for probe synthesis, which needs a single
endpoint per key; exactly wrong for coverage, which must know that four sources saw
it and which four. Making it multi-source would change what every existing caller
receives and break the byte-identical guarantee.

SAG is therefore a READ-ONLY OBSERVER. It reads the four sources, mutates none of
them (tested), and owns nothing the engine depends on.

WHAT IT IS NOT
--------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil`,
`confirmer` or `engine`, and nothing from `economy` either — asserted by test.
Zero network requests, so there is no spend to account for. It changes WHAT an
operator tests, never WHETHER something is reported; the verdict still comes from
the Delta-state confirmer.

Its worst failure is steering a request at the wrong endpoint. That costs one
request. It is not a false finding, because it produces no findings.

RL1 — THREE INFERENCES THAT ARE REFUSED
---------------------------------------
  * name-similarity extrapolation. `/api/orders` and `/api/invoices` never conjure
    `/api/payments`. Unification is structural only: normalised template + method.
  * agreement as truth. `confidence` is a COUNT of declaring sources. Never a
    probability, never a threshold, and it gates nothing.
  * conflict resolution by preference. When two sources disagree, both
    declarations survive and `resolved` stays False. Choosing a winner is a guess
    dressed up as a merge.

RL2 — `priority` IS AN ORDERING, NOT EVIDENCE
---------------------------------------------
Fixed integer weights, specified in advance, identical every run. Nothing learned,
fitted or tuned; no threshold reads it. `discovery._idor_score` is the existing
precedent for exactly this kind of ranking. It must never be read as a likelihood
of vulnerability.

THE FOUR SOURCES ARE NOT EPISTEMICALLY EQUAL — AND `confidence` CANNOT SEE THAT
--------------------------------------------------------------------------------
This is the sharpest limitation of the specified model, so it is stated plainly
rather than smoothed over.

Three sources report something a human WROTE: the capture saw a real request, the
spec declares an endpoint, the bundle contains a literal. The fourth, `derived`,
reports something WE CONSTRUCTED — `surface.generalize()` extrapolates siblings and
parents from observed patterns. That is legitimate structural derivation, but it is
a construction, not a declaration.

`confidence` counts all four equally, so under the specified formula a
derived-only gap and a frontend-declared-only gap both score 7 — a path we invented
ranks level with a path a developer wrote. Handled additively, without altering any
specified field:

  * every entry carries `is_declared` — True when any of observed/spec/frontend
    saw it, False when only `derived` did;
  * `derived_only` is a first-class output beside `orphans` and `spec_only`, so a
    constructed gap is never mistaken for a declared one at a glance.

A NOTE ON THE +4 GUARD BONUS
-----------------------------
"in the frontend with a role guard" depends on FCX's guard extraction, whose recall
is deliberately low (syntactic containment only, no control-flow analysis). An
endpoint that really is guarded in the client but whose guard FCX could not link
scores 4 points lower. **Absence of the guard bonus is not evidence of absence of a
guard** — low recall in layer A must not be read as a low-value signal in layer B.

RL5 — FAIL-SAFE ON BAD INPUT
----------------------------
Sources are lists handed in by callers, and a caller may be broken. Every item goes
through one total coercion function that cannot raise. A malformed item is
QUARANTINED with a mechanical reason and never merged, while sound items from the
same source are still used — source-level rejection would throw away real surface
because of one bad line. Per-source offered/accepted/rejected counts keep "the
source was empty" distinguishable from "the source was rejected". All sources empty
yields an empty surface and says so; it never invents one.

DETERMINISM
-----------
Same inputs, same output. Everything sorted, no set iteration in the output, ties
break on the endpoint key. Input ORDER is irrelevant (tested).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .frontend_contract import _normalise_template

# The four declared sources, in fixed order. This tuple is the whole vocabulary;
# an unknown source name is not accommodated, because silently accepting one would
# let a caller invent a fifth axis of confidence.
SOURCE_NAMES = ("observed", "spec", "derived", "frontend")

# Sources that report something a human WROTE, as opposed to something we
# constructed. See the module docstring.
DECLARING_SOURCES = frozenset({"observed", "spec", "frontend"})

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE",
                            "HEAD", "OPTIONS", "TRACE", "CONNECT"})
UNKNOWN_METHOD = "UNKNOWN"

_MAX_ITEMS_PER_SOURCE = 20_000
_MAX_PATH_LEN = 2048

# rejection reasons — all mechanical, none a judgment about content
R_NOT_COERCIBLE = "not-coercible"
R_NO_PATH = "missing-path"
R_EMPTY_TEMPLATE = "empty-template"
R_PATH_NOT_ABSOLUTE = "path-not-absolute"
R_PATH_TOO_LONG = "path-too-long"
R_OVER_CAP = "over-item-cap"

_PRIORITY_NOTE = (
    "priority is an ORDERING of a work queue, not evidence and not a likelihood "
    "of vulnerability; no threshold reads it"
)
_EQUALITY_NOTE = (
    "confidence counts all four sources equally, but `derived` reports what "
    "surface.generalize() CONSTRUCTED while observed/spec/frontend report what "
    "someone WROTE — use `is_declared` and `derived_only` to tell a constructed "
    "gap from a declared one"
)
_GUARD_RECALL_NOTE = (
    "the +4 guard bonus depends on FCX guard extraction, whose recall is "
    "deliberately low; absence of the bonus is NOT evidence that no client-side "
    "guard exists"
)


# --------------------------------------------------------------------------- #
# coercion — one total function: cannot raise, cannot invent                   #
# --------------------------------------------------------------------------- #

def _coerce(item: Any) -> tuple[Optional[tuple[str, str, str, str]], str]:
    """Normalise one input item to (method, template, effect, provenance).

    Accepts a `discovery.Endpoint`, a mapping, or a "GET /api/x" string, because
    the four upstream sources genuinely return different shapes; demanding one
    shape would push the conversion out into callers where it is untested.

    Returns (value, "") or (None, reason). It NEVER raises and NEVER fills in a
    missing field: an unreadable method becomes `UNKNOWN`, and an unreadable path
    is rejected rather than repaired.
    """
    method = path = None
    effect = ""
    provenance = ""

    try:
        if item is None:
            return None, R_NOT_COERCIBLE

        if isinstance(item, str):
            parts = item.strip().split(None, 1)
            if len(parts) == 2:
                method, path = parts[0], parts[1]
            elif len(parts) == 1 and parts[0].startswith("/"):
                method, path = UNKNOWN_METHOD, parts[0]
            else:
                return None, R_NOT_COERCIBLE
        elif isinstance(item, dict):
            method = item.get("method")
            path = item.get("template") or item.get("path")
            effect = item.get("effect") or ""
            provenance = item.get("found_in") or item.get("source") or ""
        else:
            method = getattr(item, "method", None)
            path = getattr(item, "path", None)
            effect = getattr(item, "effect", "") or ""
            provenance = getattr(item, "source", "") or ""
            if path is None and method is None:
                return None, R_NOT_COERCIBLE

        if path is None or not isinstance(path, str) or not path.strip():
            return None, R_NO_PATH
        path = path.strip()
        if len(path) > _MAX_PATH_LEN:
            return None, R_PATH_TOO_LONG
        if not path.startswith("/"):
            # a base-relative path cannot be compared with anything the engine
            # normalises, and resolving it needs a base URL we do not have.
            return None, R_PATH_NOT_ABSOLUTE

        if method is None or not isinstance(method, str) or not method.strip():
            method = UNKNOWN_METHOD                  # declared absence, not a guess
        method = method.strip().upper()
        if method not in _KNOWN_METHODS and method != UNKNOWN_METHOD:
            method = UNKNOWN_METHOD

        if not isinstance(effect, str):
            effect = ""
        if not isinstance(provenance, str):
            provenance = ""

        template = _normalise_template(path)
        if not template or not template.strip() or not template.startswith("/"):
            return None, R_EMPTY_TEMPLATE
        return (method, template, effect, provenance), ""
    except Exception:                                # noqa: BLE001 — total by contract
        return None, R_NOT_COERCIBLE


def _guard_keys(guards: Any) -> set:
    """Endpoint keys carrying a client-side role guard.

    Only `api_call` guards count. `ui_route` guards describe router paths, which
    live in a different namespace from server paths — a distinction
    `frontend_contract` draws deliberately, and erasing it here would smuggle
    invented endpoints in through the back door.
    """
    out: set = set()
    if guards is None:
        return out
    items = getattr(guards, "guards", guards)
    try:
        iter(items)
    except TypeError:
        return out
    for g in items:
        try:
            if isinstance(g, str):
                parts = g.strip().split(None, 1)
                if len(parts) == 2:
                    out.add(f"{parts[0].upper()} {_normalise_template(parts[1])}".upper())
                continue
            kind = getattr(g, "kind", None) or (g.get("kind") if isinstance(g, dict) else None)
            target = getattr(g, "target", None) or (g.get("target") if isinstance(g, dict) else None)
            if kind is not None and kind != "api_call":
                continue
            if not isinstance(target, str) or not target.strip():
                continue
            parts = target.strip().split(None, 1)
            if len(parts) != 2:
                continue
            out.add(f"{parts[0].upper()} {_normalise_template(parts[1])}".upper())
        except Exception:                            # noqa: BLE001
            continue
    return out


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AggregatedEndpoint:
    method: str
    template: str
    sources: tuple = ()
    confidence: int = 0            # a COUNT of declaring sources (1-4); not a probability
    has_observed_id: bool = False
    frontend_guard: bool = False
    priority: int = 0
    is_gap: bool = False           # seen by exactly one source
    is_declared: bool = False      # written by someone, vs constructed by `derived`
    effects: tuple = ()            # ((source, effect), ...) AS DECLARED, unreconciled
    provenance: tuple = ()         # ((source, where), ...) e.g. ("frontend","bundle.js:41")

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"


@dataclass
class SourceIngestReport:
    name: str
    offered: int = 0
    accepted: int = 0
    rejected: int = 0
    reasons: dict = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.accepted > 0


@dataclass
class AggregatedSurface:
    unified_surface: list = field(default_factory=list)
    coverage_matrix: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)
    orphans: list = field(default_factory=list)
    spec_only: list = field(default_factory=list)
    derived_only: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    priority_queue: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        def ent(e):
            d = {"method": e.method, "template": e.template,
                 "sources": list(e.sources), "confidence": e.confidence,
                 "has_observed_id": e.has_observed_id,
                 "frontend_guard": e.frontend_guard, "priority": e.priority,
                 "is_gap": e.is_gap, "is_declared": e.is_declared}
            if e.effects:
                d["effects"] = {s: v for s, v in e.effects}
            if e.provenance:
                d["provenance"] = {s: v for s, v in e.provenance}
            return d

        return {
            "unified_surface": [ent(e) for e in self.unified_surface],
            "coverage_matrix": {k: dict(v) for k, v in sorted(self.coverage_matrix.items())},
            "gaps": [ent(e) for e in self.gaps],
            "orphans": [ent(e) for e in self.orphans],
            "spec_only": [ent(e) for e in self.spec_only],
            "derived_only": [ent(e) for e in self.derived_only],
            "conflicts": list(self.conflicts),
            "priority_queue": [{"key": e.key, "priority": e.priority,
                                "confidence": e.confidence, "is_gap": e.is_gap,
                                "sources": list(e.sources)}
                               for e in self.priority_queue],
            "sources": [{"name": s.name, "offered": s.offered,
                         "accepted": s.accepted, "rejected": s.rejected,
                         "usable": s.usable, "reasons": dict(sorted(s.reasons.items()))}
                        for s in self.sources],
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# priority — the specified formula, implemented verbatim                       #
# --------------------------------------------------------------------------- #

def compute_priority(sources: tuple, is_gap: bool, frontend_guard: bool,
                     has_observed_id: bool, method: str) -> int:
    """The specified ordering weight:

        (confidence * 2)
      + 5  it is a gap (exactly one source saw it)
      + 4  it is in the frontend AND carries a role guard
      + 3  it is in the spec AND was never exercised
      + 2  a concrete id for it was observed in the capture
      + 1  it is a write

    The `+5` gap bonus is what makes this ordering match its own stated intent.
    Going from one source to two costs the bonus (-5) and gains the count (+2), a
    net -3, so a lone sighting genuinely outranks a corroborated one at the
    boundary that matters. (An earlier draft weighted only agreement, where the
    same step was +2 — the wrong direction.)

    Residual tension, stated rather than hidden: a maximally decorated four-source
    endpoint still reaches 15 while a bare frontend-only GET scores 7. `gaps`,
    `orphans`, `spec_only` and `derived_only` are first-class outputs precisely so
    that finding hidden surface never depends on the queue order.

    `UNKNOWN` never earns the write point — inventing a verb to score is the
    smallest possible version of the guess this project forbids.
    """
    exercised = "observed" in sources
    p = len(sources) * 2
    if is_gap:
        p += 5
    if "frontend" in sources and frontend_guard:
        p += 4
    if "spec" in sources and not exercised:
        p += 3
    if has_observed_id:
        p += 2
    if method in _WRITE_METHODS:
        p += 1
    return p


# --------------------------------------------------------------------------- #
# aggregation                                                                  #
# --------------------------------------------------------------------------- #

def aggregate(observed_endpoints=None, spec_endpoints=None, derived_endpoints=None,
              frontend_endpoints=None, observed_ids_by_template=None,
              frontend_guards=None, enabled: bool = False,
              capture_endpoints=None) -> AggregatedSurface:
    """Merge the four surface sources into one read-only view.

    DEFAULT OFF. With `enabled=False` an empty `AggregatedSurface` is returned
    without touching the inputs, so a call site that has not opted in behaves
    exactly as if this module did not exist.

    `capture_endpoints` is accepted as a backward-compatible alias for
    `observed_endpoints`.

    No network. No execution. No mutation of any argument. No candidate, no
    finding, no verdict.
    """
    out = AggregatedSurface()
    if not enabled:
        return out

    if observed_endpoints is None:
        observed_endpoints = capture_endpoints

    raw = {
        "observed": observed_endpoints,
        "spec": spec_endpoints,
        "derived": derived_endpoints,
        "frontend": frontend_endpoints,
    }

    seen: dict[str, dict[str, tuple[str, str]]] = {}      # key -> {source: (effect, where)}
    methods_by_template: dict[str, dict[str, set]] = {}

    for sname in SOURCE_NAMES:
        rep = SourceIngestReport(name=sname)
        out.sources.append(rep)
        items = raw.get(sname)
        if items is None:
            continue
        try:
            seq = list(items)
        except Exception:                            # noqa: BLE001
            rep.offered = rep.rejected = 1
            rep.reasons[R_NOT_COERCIBLE] = 1
            continue

        rep.offered = len(seq)
        for n, item in enumerate(seq):
            if n >= _MAX_ITEMS_PER_SOURCE:
                rep.rejected += 1
                rep.reasons[R_OVER_CAP] = rep.reasons.get(R_OVER_CAP, 0) + 1
                continue
            val, reason = _coerce(item)
            if val is None:
                rep.rejected += 1
                rep.reasons[reason] = rep.reasons.get(reason, 0) + 1
                continue
            method, template, effect, where = val
            rep.accepted += 1
            key = f"{method} {template}"
            # de-duplication WITHIN a source; never arbitration BETWEEN sources
            seen.setdefault(key, {}).setdefault(sname, (effect, where))
            methods_by_template.setdefault(template, {}).setdefault(sname, set()).add(method)

    ids = observed_ids_by_template if isinstance(observed_ids_by_template, dict) else {}
    guard_keys = _guard_keys(frontend_guards)

    for key in sorted(seen):
        per_source = seen[key]
        srcs = tuple(s for s in SOURCE_NAMES if s in per_source)
        method, template = key.split(" ", 1)
        is_gap = len(srcs) == 1
        has_id = bool(ids.get(template))
        guarded = key.upper() in guard_keys
        entry = AggregatedEndpoint(
            method=method, template=template, sources=srcs, confidence=len(srcs),
            has_observed_id=has_id, frontend_guard=guarded,
            priority=compute_priority(srcs, is_gap, guarded, has_id, method),
            is_gap=is_gap,
            is_declared=any(s in DECLARING_SOURCES for s in srcs),
            effects=tuple(sorted((s, per_source[s][0]) for s in srcs if per_source[s][0])),
            provenance=tuple(sorted((s, per_source[s][1]) for s in srcs if per_source[s][1])),
        )
        out.unified_surface.append(entry)
        out.coverage_matrix[key] = {s: (s in per_source) for s in SOURCE_NAMES}

        declared = sorted({v[0] for v in per_source.values() if v[0]})
        if len(declared) > 1:
            out.conflicts.append({
                "kind": "effect_disagreement", "key": key,
                "declarations": [{"source": s, "effect": per_source[s][0]}
                                 for s in srcs if per_source[s][0]],
                "resolved": False,
                "note": "sources disagree on the declared effect class; "
                        "no source is preferred",
            })

    # Gap 4: the same template declared with different methods by different
    # sources. Reported and left standing. Noted honestly: GET plus POST on one
    # template is ordinary REST as often as it is a real disagreement — which is
    # exactly why this is surfaced for inspection instead of acted on.
    for template in sorted(methods_by_template):
        per = methods_by_template[template]
        distinct = {tuple(sorted(v)) for v in per.values()}
        if len(per) > 1 and len(distinct) > 1:
            out.conflicts.append({
                "kind": "method_divergence", "template": template,
                "by_source": {s: sorted(per[s]) for s in SOURCE_NAMES if s in per},
                "resolved": False,
                "note": "sources declare different methods for this template; "
                        "often legitimate REST, reported for inspection only",
            })

    out.unified_surface.sort(key=lambda e: (e.method, e.template))
    out.gaps = [e for e in out.unified_surface if e.is_gap]
    out.orphans = [e for e in out.unified_surface if e.sources == ("frontend",)]
    out.spec_only = [e for e in out.unified_surface if e.sources == ("spec",)]
    out.derived_only = [e for e in out.unified_surface if e.sources == ("derived",)]
    out.priority_queue = sorted(out.unified_surface, key=lambda e: (-e.priority, e.key))
    out.conflicts.sort(key=lambda c: (c["kind"], c.get("key") or c.get("template", "")))

    out.notes.append(_PRIORITY_NOTE)
    out.notes.append(_EQUALITY_NOTE)
    out.notes.append(_GUARD_RECALL_NOTE)
    if not out.unified_surface:
        out.notes.append("no source produced a usable endpoint — empty surface "
                         "emitted (fail-safe); this is NOT evidence that the "
                         "target has no endpoints")
    unusable = [s.name for s in out.sources if s.offered and not s.usable]
    if unusable:
        out.notes.append("source(s) offered items but none survived coercion, so "
                         "nothing from them was merged: " + ", ".join(sorted(unusable)))
    if out.conflicts:
        out.notes.append(f"{len(out.conflicts)} source conflict(s) reported and "
                         f"deliberately left unresolved")
    if out.derived_only:
        out.notes.append(f"{len(out.derived_only)} gap(s) rest on structural "
                         f"derivation alone — constructed, not declared")
    unknown = [e for e in out.unified_surface if e.method == UNKNOWN_METHOD]
    if unknown:
        out.notes.append(f"{len(unknown)} endpoint(s) carry method=UNKNOWN; the "
                         f"verb was never declared and was not guessed")
    out.notes = sorted(set(out.notes))
    return out


# --------------------------------------------------------------------------- #
# convenience bridge over a whole capture                                      #
# --------------------------------------------------------------------------- #

def aggregate_from_har(har: dict, scope=None, in_scope_hosts=None,
                       openapi_doc=None, graphql_introspection=None,
                       spec_endpoints=None, derived_endpoints=None,
                       exclude_declared_assets: bool = True,
                       enabled: bool = False) -> AggregatedSurface:
    """Build all four source lists from one capture and aggregate them.

    Every source is read with the module that owns it — `harimport` for the
    capture, `surface.generalize` / `observed_ids_by_template` for derivation,
    `discovery.parse_openapi` / `parse_graphql_introspection` for specs, and
    `frontend_contract` for the bundle. SAG introduces no parser and no normaliser
    of its own, so it cannot drift from any of them.

    `exclude_declared_assets` drops capture entries the SERVER declared to be
    script assets via Content-Type, so one bundle request does not spawn six
    derived phantom templates. It is a declaration we read, not a shape we
    guessed; set it False to see the raw union.

    DEFAULT OFF. Zero network: a spec must be HANDED IN, never fetched.
    """
    if not enabled:
        return AggregatedSurface()

    from .harimport import parse_har_exchanges
    from .surface import generalize, observed_ids_by_template as ids_by_template
    from .frontend_contract import from_har, to_endpoints

    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                                # noqa: BLE001
        exchanges = []

    # A capture contains static assets alongside API traffic, and `generalize`
    # will happily derive `/bundle.js/{id}`, `POST /bundle.js` and friends from
    # one script request — six phantom templates per asset, burying the real
    # gaps. They are excluded here on a DECLARED basis, never a guessed one: the
    # server's own Content-Type said the response was a script, which is the same
    # class of fact FCX reads a `fetch()` argument from. Path shape is not
    # consulted, so nothing is filtered because it "looks static".
    asset_paths: set = set()
    if exclude_declared_assets:
        from .frontend_contract import js_sources_from_har
        try:
            asset_paths = {s.name for s in js_sources_from_har(har, scope, in_scope_hosts)}
        except Exception:                            # noqa: BLE001
            asset_paths = set()
    kept = []
    for ex in exchanges:
        try:
            if getattr(ex.request, "path", None) in asset_paths:
                continue
        except Exception:                            # noqa: BLE001
            pass
        kept.append(ex)
    exchanges = kept

    observed: list = []
    for ex in exchanges:
        try:
            observed.append(ex.request.endpoint_key())
        except Exception:                            # noqa: BLE001
            continue

    derived = list(derived_endpoints or [])
    try:
        derived += generalize(exchanges).derived_only()
    except Exception:                                # noqa: BLE001
        pass
    try:
        ids = ids_by_template(exchanges)
    except Exception:                                # noqa: BLE001
        ids = {}

    specs = list(spec_endpoints or [])
    if openapi_doc is not None:
        from .discovery import parse_openapi
        try:
            specs += parse_openapi(openapi_doc)
        except Exception:                            # noqa: BLE001
            pass
    if graphql_introspection is not None:
        from .discovery import parse_graphql_introspection
        try:
            specs += parse_graphql_introspection(graphql_introspection)
        except Exception:                            # noqa: BLE001
            pass

    fc = from_har(har, scope, in_scope_hosts)
    return aggregate(
        observed_endpoints=observed,
        spec_endpoints=specs,
        derived_endpoints=derived,
        frontend_endpoints=to_endpoints(fc),
        observed_ids_by_template=ids,
        frontend_guards=fc,
        enabled=True,
    )
