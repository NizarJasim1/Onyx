"""
authpath.surface — the SURFACE model (RL8: SURFACE ENUMERATION).

ONYX could only find a vulnerability in an endpoint a human had already walked:
the testable surface == the captured traffic (plus a spec doc you happened to
hand it). On a hyperscale target with millions of endpoints and a 200-request
capture, that is blindness to ~everything. The root was architectural: ONYX had
an *analysis* model but no *surface* model — it treated "the surface to test" as
an input, never as something to be DERIVED.

This module is the missing peer. From the exchanges already observed it ENUMERATES
the surrounding surface — sibling collections, parent resources, the REST verb
family — as a deterministic, value-blind, NETWORK-FREE derivation, records each
endpoint with its source + confidence in a SurfaceGraph, and synthesizes read-only
cross-principal probes. The probes are then fed to the existing engine + RL6
allocator, so:

  * SOUND   — derivation only proposes WHERE to look; the Δstate confirmer still
              has the final word. A derived endpoint that 404s is "absent", never
              a finding. Discovery NEVER promotes a finding by itself.
  * SAFE    — GET / read-only probes by default (RL5). Mutating verbs are recorded
              in the graph for visibility but never auto-probed.
  * BOUNDED — every probe is drawn from the RL6 budget and allocated by value, so
              an enormous derived surface cannot blow the request/reputation budget.
  * HONEST  — every endpoint carries its provenance (observed vs derived-collection
              vs derived-parent vs derived-method vs acquired-spec) and confidence.
  * VALUE-BLIND / NEVER FABRICATE — derivation uses path SHAPE + the REST resource
              model only; it never invents an endpoint as vulnerable and never
              fabricates an id it did not observe.

Deterministic and pure: the derivation issues no requests and uses no clock.
"""
from __future__ import annotations

import re as _re
from typing import Iterable

from .discovery import Endpoint, _infer_effect, _idor_score

_PARAM = _re.compile(r"\{[^}]+\}")

# confidence by source — observed traffic is ground truth; derivations are ranked
# below acquired specs, which are below observed.
_CONFIDENCE = {
    "observed": 100,
    "acquired-spec": 80,
    "derived-collection": 60,
    "derived-parent": 55,
    "derived-method": 40,
    "inferred-path": 20,
}

# REST verb families used for method expansion (recorded, GET-only probed).
_ITEM_VERBS = ("GET", "PUT", "PATCH", "DELETE")
_COLLECTION_VERBS = ("GET", "POST")


# --------------------------------------------------------------------------- #
# Slice 3 — the Surface Graph (dedup registry with provenance + confidence)   #
# --------------------------------------------------------------------------- #

class SurfaceGraph:
    """A deterministic registry of (method, template) → Endpoint, keeping the
    HIGHEST-confidence source when an endpoint is seen via several routes."""
    def __init__(self):
        self._eps: dict[str, Endpoint] = {}

    def add(self, ep: Endpoint) -> None:
        prev = self._eps.get(ep.key)
        if prev is None or _conf(ep.source) > _conf(prev.source):
            self._eps[ep.key] = ep

    def add_all(self, eps: Iterable[Endpoint]) -> None:
        for e in eps:
            self.add(e)

    def endpoints(self) -> list:
        # deterministic order: confidence desc, then idor_score desc, then key
        return sorted(self._eps.values(),
                      key=lambda e: (-_conf(e.source), -e.idor_score, e.key))

    def derived_only(self) -> list:
        return [e for e in self.endpoints() if e.source != "observed"]

    def summary(self) -> dict:
        by_source: dict = {}
        for e in self._eps.values():
            by_source[e.source] = by_source.get(e.source, 0) + 1
        return {"total": len(self._eps), "by_source": by_source,
                "derived": len(self.derived_only())}


def _conf(source: str) -> int:
    return _CONFIDENCE.get(source, 0)


# --------------------------------------------------------------------------- #
# Slice 2 — capture generalization (the core: derive surface from traffic)    #
# --------------------------------------------------------------------------- #

def generalize(exchanges) -> SurfaceGraph:
    """Build a SurfaceGraph from observed exchanges by deriving the surrounding
    REST surface. Network-free and deterministic. For each observed request we add:

      * the observed endpoint itself (template form);
      * its COLLECTION (drop the trailing id segment): /orders/{id} -> /orders;
      * every PARENT in the resource hierarchy (collection + item), via the RL7.2
        resource-name model: /projects/{p}/datasets/{d} -> /projects/{p} and
        /projects/{p}/datasets and /projects;
      * the REST VERB FAMILY for the item/collection templates (recorded for
        visibility; only GET is probed).
    """
    g = SurfaceGraph()
    for ex in exchanges:
        req = ex.request if hasattr(ex, "request") else ex
        template = _template_of(req)
        method = req.method.upper()
        _add_endpoint(g, method, template, "observed")
        _derive_from_template(g, method, template)
    return g


def _template_of(req) -> str:
    """Concrete path -> template (id segments replaced by {id}), reusing the same
    id-recognition as endpoint_key()."""
    parts = ["{id}" if is_id else seg for seg, is_id in req.segments()]
    return "/" + "/".join(parts) if parts else "/"


def _derive_from_template(g: SurfaceGraph, method: str, template: str) -> None:
    segs = [s for s in template.strip("/").split("/") if s]
    if not segs:
        return
    # collection of THIS resource: drop a trailing id segment
    if segs[-1] == "{id}" and len(segs) >= 2:
        collection = "/" + "/".join(segs[:-1])
        for v in _COLLECTION_VERBS:
            _add_endpoint(g, v, collection,
                          "observed" if (v == method and collection == template) else "derived-collection")
        # method family on the item template
        for v in _ITEM_VERBS:
            if not (v == method):
                _add_endpoint(g, v, template, "derived-method")
    else:
        # a COLLECTION endpoint -> derive the ITEM template (the killer pattern:
        # a list endpoint implies a per-item endpoint where full records — and PII —
        # live). e.g. observing GET /api/orders derives GET /api/orders/{id}.
        item = template.rstrip("/") + "/{id}"
        for v in _ITEM_VERBS:
            _add_endpoint(g, v, item,
                          "derived-collection" if v == "GET" else "derived-method")
        for v in _COLLECTION_VERBS:
            if v != method:
                _add_endpoint(g, v, template, "derived-method")

    # parent chain: walk up the (collection, id) pairs
    parents = _parent_templates(segs)
    for ptemplate, _kind in parents:
        for v in (_ITEM_VERBS if ptemplate.endswith("{id}") else _COLLECTION_VERBS):
            _add_endpoint(g, v, ptemplate,
                          "derived-parent" if v == "GET" else "derived-method")


def _parent_templates(segs: list) -> list:
    """All ancestor resource templates of a path. For [a,{id},b,{id}] yields
    /a/{id}/b (collection), /a/{id} (parent item), /a (grandparent collection)."""
    out = []
    # work on a copy we progressively shorten
    cur = list(segs)
    # strip the final id (already handled as 'this resource')
    if cur and cur[-1] == "{id}":
        cur = cur[:-1]
    while len(cur) >= 1:
        tmpl = "/" + "/".join(cur)
        if cur[-1] == "{id}":
            out.append((tmpl, "item"))
            cur = cur[:-1]
        else:
            out.append((tmpl, "collection"))
            # drop the collection noun to ascend to its parent id (if any)
            cur = cur[:-1]
    return out


def _add_endpoint(g: SurfaceGraph, method: str, template: str, source: str) -> None:
    has_param = bool(_PARAM.search(template))
    effect = _infer_effect(method, template, has_param)
    g.add(Endpoint(method=method.upper(), path=template,
                   params=_PARAM.findall(template),
                   effect=effect, source=source,
                   idor_score=_idor_score(method, template, has_param)))


# --------------------------------------------------------------------------- #
# Slice 4 — probe synthesis (read-only, value-ordered via RL6 downstream)     #
# --------------------------------------------------------------------------- #

def observed_ids_by_template(exchanges) -> dict:
    """template -> sorted set of object-ids observed for it (for cross-principal
    probe synthesis). Combines path ids with ids HARVESTED from list/collection
    RESPONSE BODIES, so a collection that reveals ids feeds per-item probes (the
    classic list->item PII-leak pivot). Value-blind: harvests ID-class values only."""
    out: dict = {}
    for ex in exchanges:
        req = ex.request if hasattr(ex, "request") else ex
        tmpl = _template_of(req)
        for oid in req.object_ids():
            out.setdefault(tmpl, set()).add(str(oid))
        # harvest ids from a collection's response body -> the ITEM template
        body = getattr(getattr(ex, "response", None), "body", None)
        if not _PARAM.search(tmpl) and isinstance(body, (dict, list)):
            item_tmpl = tmpl.rstrip("/") + "/{id}"
            for hid in _harvest_ids(body):
                out.setdefault(item_tmpl, set()).add(str(hid))
    return {k: sorted(v) for k, v in out.items()}


def _harvest_ids(body, depth: int = 0) -> list:
    """Pull ID-class values out of a (list) response body, value-blind: it reuses
    the provenance id classifier, so only id-shaped/id-named values are harvested
    — never arbitrary strings."""
    if depth > 5:
        return []
    from .provenance import extract_values, ValueClass
    try:
        tvs = extract_values(body)
    except Exception:
        return []
    return [tv.value for tv in tvs if tv.value_class == ValueClass.ID]


_GENERIC_ROOTS = {"api", "rest", "graphql", "gql", "v1", "v2", "v3", "v4",
                  "v0", "internal", "public", "service", "services"}


def synth_probes(graph: SurfaceGraph, ids_by_template: dict,
                 attacker_pid: str, max_probes: int = 500) -> list:
    """Turn the surface graph into GET-only probe requests (read-only, RL5):

      * OBJECT_ACCESS templates with an observed id  -> cross-principal IDOR probe
        (attacker requests an id the capture shows belongs to someone else);
      * derived COLLECTION GETs                       -> enumeration probe (does the
        attacker see a collection it should not?).
    Bounded + deterministic. NEVER emits a mutating verb. Generic version/prefix
    roots (/api, /v1, …) are not probed as collections (they are not resources)."""
    probes = []
    for e in graph.endpoints():
        if e.method != "GET":
            continue                                  # read-only only (RL5)
        params = _PARAM.findall(e.path)
        if e.effect == "OBJECT_ACCESS" and len(params) == 1:
            for oid in ids_by_template.get(e.path, []):
                concrete = _PARAM.sub(lambda m: str(oid), e.path, count=1)
                probes.append({"principal": attacker_pid, "method": "GET",
                               "path": concrete, "_source": e.source,
                               "_kind": "idor"})
                if len(probes) >= max_probes:
                    return probes
        elif not params:
            segs = [s for s in e.path.strip("/").split("/") if s]
            if len(segs) == 1 and segs[0].lower() in _GENERIC_ROOTS:
                continue                              # /api, /v1 are not resources
            # a collection GET — enumerate it as the attacker (BOLA at the list level)
            probes.append({"principal": attacker_pid, "method": "GET",
                           "path": e.path, "_source": e.source,
                           "_kind": "collection"})
            if len(probes) >= max_probes:
                return probes
    return probes
