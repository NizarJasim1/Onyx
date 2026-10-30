"""
SAIE — Structural Authorization Interrogation Engine.
Layer 0 (stability gate) + Layer 1 (value-blind fingerprint) + the deterministic
divergence primitive.  PURE module: no engine coupling, no I/O, no randomness, no
learning (RL1).  A JSON response is a 2-D shadow of a multi-dimensional backend
object; this module measures the *shape* of that shadow so a later layer can prove
that an under-privileged principal was served by a privileged code path.

Design contract (keyed to SAIE_HANDOFF Part D / Part F Step 1):
  * fingerprint(body, trust_mask) -> StructuralFingerprint   (Layer 1, value-blind)
  * StabilityGate                                            (Layer 0, the 0-FP gate)
  * divergence(fp_a, fp_b, trust_mask) -> DivergenceReport   (deterministic diff)

Two distinct notions of "comparison" live here and MUST NOT be conflated:
  * divergence(): fine-grained diff.  Reports absence-STATE differences
    (PRESENT_POPULATED vs PRESENT_NULL vs PRESENT_EMPTY vs ABSENT), type/array
    differences, and order differences.  Used for the L3 magnitude ranking and as
    the raw structural delta.  A privileged-shape vs value-filtered-shape pair
    DIVERGES here (states differ) — that is the Step-1 self-test.
  * presence-level matching ("fits", Layer 2, in CoherenceModel) ignores the
    populated/null/empty STATE and compares only which paths exist + their types +
    (where trusted) their order.  A value-filtered response therefore *fits* the
    privileged grammar — same shape, emptied values.  That gap between "fits the
    privileged shape" and "diverges in state from my own shape" is the leak.

Path convention matches provenance._walk: top-level keys are bare (`buyer`),
nested keys are dotted (`buyer.tier`), array elements are indexed (`items[0]`).
The synthetic root container is recorded under "$".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Closed vocabularies (true by definition — never learned)                    #
# --------------------------------------------------------------------------- #

class AbsenceState:
    """The four states a field path can be in, relative to the union of schemas.
    The PRESENT_NULL vs ABSENT distinction is the heart of path inference:
    PRESENT_NULL means the backend object HAS the branch and emptied it; ABSENT
    means the branch never executed for this principal."""
    PRESENT_POPULATED = "PRESENT_POPULATED"
    PRESENT_NULL = "PRESENT_NULL"
    PRESENT_EMPTY = "PRESENT_EMPTY"      # "" / [] / {}
    ABSENT = "ABSENT"                    # comparison-relative; never stored in one fp


class NodeStability:
    """Layer-0 classification of a node across repeats of an identical request."""
    STRUCT_LIKE = "STRUCT_LIKE"          # topology + order identical -> all signals trusted
    MAP_LIKE = "MAP_LIKE"                # topology identical, order varies -> order disabled
    VOLATILE = "VOLATILE"                # topology itself varies -> node excluded entirely
    INTERMITTENT = "INTERMITTENT"        # present in SOME identical-request repeats, absent in
    #                                      others — value-entropy is normalised away, but a
    #                                      flickering PRESENCE under identical input is itself a
    #                                      signal (authorization-conditional emission). Leads-only.


# node types (value-blind): object/array/scalar/null/bool.  null and bool are kept
# distinct from scalar for honest type comparison, but emptiness is a shape fact.
_T_OBJECT = "object"
_T_ARRAY = "array"
_T_SCALAR = "scalar"
_T_NULL = "null"
_T_BOOL = "bool"

_ROOT = "$"
_T_LEAF = "leaf"


def shape_kind(node_type: str) -> str:
    """Collapse the fine node type to a SHAPE kind for topology/fit comparison.
    object and array are distinct shapes; scalar/null/bool are all "leaf" — a
    field going populated->null is a VALUE filtering (an absence-STATE fact),
    never a shape change.  This is what lets a value-filtered response *fit* a
    privileged grammar: same leaf shape, emptied value."""
    if node_type == _T_OBJECT:
        return _T_OBJECT
    if node_type == _T_ARRAY:
        return _T_ARRAY
    return _T_LEAF


# --------------------------------------------------------------------------- #
# Layer 1 — Structural Fingerprint (value-blind)                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class StructuralFingerprint:
    """A canonical, value-erased fingerprint of one response body.

    absence_map : path -> AbsenceState (for every PRESENT path; ABSENT is derived
                  at comparison time, never stored).
    types       : path -> node type (object/array/scalar/null/bool).
    order       : object-path -> tuple of child keys in serialization order.
    array_counts: array-path -> element count.
    quantities  : derived aggregates (richness, depth, ratios) for fast compare
                  and the L3 magnitude.  Never a decision input on its own.
    """
    absence_map: dict[str, str]
    types: dict[str, str]
    order: dict[str, tuple]
    array_counts: dict[str, int]
    quantities: dict[str, float]

    def present_paths(self) -> set[str]:
        return set(self.absence_map.keys())

    def populated_paths(self) -> set[str]:
        return {p for p, s in self.absence_map.items()
                if s == AbsenceState.PRESENT_POPULATED}


def _node_type(node: Any) -> str:
    if node is None:
        return _T_NULL
    if isinstance(node, bool):
        return _T_BOOL
    if isinstance(node, dict):
        return _T_OBJECT
    if isinstance(node, list):
        return _T_ARRAY
    return _T_SCALAR


def _absence_state(node: Any) -> str:
    if node is None:
        return AbsenceState.PRESENT_NULL
    if isinstance(node, str) and node == "":
        return AbsenceState.PRESENT_EMPTY
    if isinstance(node, (list, dict)) and len(node) == 0:
        return AbsenceState.PRESENT_EMPTY
    # 0, 0.0, False are real values -> populated (value-blindness: we never branch
    # on WHICH value, only on presence/emptiness/type).
    return AbsenceState.PRESENT_POPULATED


def _child_path(parent: str, key: str) -> str:
    return key if parent == _ROOT else f"{parent}.{key}"


_MAX_FP_DEPTH = 64   # defect R5: bound structural recursion (fail-safe, no DoS)

def _walk(node: Any, path: str, absence: dict, types: dict,
          order: dict, arr_counts: dict, depths: list, depth: int) -> None:
    if depth > _MAX_FP_DEPTH:
        return
    t = _node_type(node)
    types[path] = t
    absence[path] = _absence_state(node)
    if t == _T_OBJECT:
        order[path] = tuple(node.keys())
        if not node:
            depths.append(depth)
        for k, v in node.items():
            _walk(v, _child_path(path, str(k)), absence, types, order,
                  arr_counts, depths, depth + 1)
    elif t == _T_ARRAY:
        arr_counts[path] = len(node)
        if not node:
            depths.append(depth)
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", absence, types, order,
                  arr_counts, depths, depth + 1)
    else:
        depths.append(depth)


def fingerprint(body: Any, trust_mask: "Optional[TrustMask]" = None
                ) -> StructuralFingerprint:
    """Compute a value-blind fingerprint of a response body.  Pure function of
    (body, trust_mask).  When a trust_mask is supplied, VOLATILE nodes are pruned
    so an unstable branch never reaches a downstream comparison (RL5: unproven =>
    excluded).  Without a mask, the full shape is recorded (used during seeding and
    in unit tests)."""
    absence: dict[str, str] = {}
    types: dict[str, str] = {}
    order: dict[str, tuple] = {}
    arr_counts: dict[str, int] = {}
    depths: list[int] = []
    root = body if isinstance(body, (dict, list)) else {} if body is None else body
    _walk(root, _ROOT, absence, types, order, arr_counts, depths, 0)

    if trust_mask is not None:
        absence = {p: s for p, s in absence.items() if trust_mask.admissible(p)}
        types = {p: v for p, v in types.items() if trust_mask.admissible(p)}
        order = {p: v for p, v in order.items() if trust_mask.admissible(p)}
        arr_counts = {p: v for p, v in arr_counts.items() if trust_mask.admissible(p)}

    populated = sum(1 for s in absence.values()
                    if s == AbsenceState.PRESENT_POPULATED)
    nulls = sum(1 for s in absence.values() if s == AbsenceState.PRESENT_NULL)
    empties = sum(1 for s in absence.values() if s == AbsenceState.PRESENT_EMPTY)
    leaf_depths = depths or [0]
    quantities = {
        "total_paths": float(len(absence)),
        "populated": float(populated),
        "null": float(nulls),
        "empty": float(empties),
        "objects": float(sum(1 for v in types.values() if v == _T_OBJECT)),
        "arrays": float(sum(1 for v in types.values() if v == _T_ARRAY)),
        "max_depth": float(max(leaf_depths)),
        "mean_depth": round(sum(leaf_depths) / len(leaf_depths), 4),
        # populated:null ratio — derived only, never a verdict input.
        "populated_null_ratio": round(populated / nulls, 4) if nulls else float(populated),
    }
    return StructuralFingerprint(absence, types, order, arr_counts, quantities)


# --------------------------------------------------------------------------- #
# Layer 0 — Stability + container-classification gate (the 0-FP guarantee)    #
# --------------------------------------------------------------------------- #

@dataclass
class TrustMask:
    """Per-endpoint-family declaration of which sub-signals are admissible.
    Anything not PROVEN stable is excluded from every finding (RL5)."""
    node_stability: dict[str, str]      # path -> NodeStability
    state_trusted: set[str]             # paths whose absence-STATE was constant across repeats
    order_trusted: set[str]             # object-paths whose key order was constant (STRUCT_LIKE)
    stable: bool                        # family has >=1 request series with >=2 repeats
    samples: int                        # number of qualifying (>=2-repeat) series in the family

    def admissible(self, path: str) -> bool:
        """A path is admissible iff neither it nor any ancestor is VOLATILE.
        Unknown paths (never seen at seed time) are admissible by default during
        a single-fingerprint walk; the family-level checks restrict them later."""
        if self.node_stability.get(path) == NodeStability.VOLATILE:
            return False
        # walk ancestors: buyer.tier -> buyer ; items[0].sku -> items[0] -> items
        cur = path
        while True:
            cut = max(cur.rfind("."), cur.rfind("["))
            if cut <= 0:
                break
            cur = cur[:cut]
            if self.node_stability.get(cur) == NodeStability.VOLATILE:
                return False
        return True

    def state_is_trusted(self, path: str) -> bool:
        """The populated/null/empty STATE at this path may feed rank/anchor only if
        it was constant across repeats AND the node is admissible."""
        return path in self.state_trusted and self.admissible(path)


_OPEN_MASK = TrustMask({}, set(), set(), True, 1)   # everything admissible (no proof needed)


@dataclass
class NodeProfile:
    """Cumulative per-node evidence for STRUCTURAL NORMALISATION (additive, never
    feeds a finding). Built per identical-request series so 'intermittent' means a
    flicker under IDENTICAL input, not legitimate per-object variation.

    The discipline (from the design critique): we normalise ONLY along the VALUE
    axis (value/state entropy with stable presence+type is safe to ignore); a
    flicker along the PRESENCE/TOPOLOGY axis is NOT noise — it is surfaced."""
    seen: int = 0              # repeats of the identical request observed
    present: int = 0           # repeats in which this path was present
    state_distinct: int = 1    # distinct absence-states while present (value/state entropy)
    topo_stable: bool = True   # shape kind constant whenever present

    @property
    def present_ratio(self) -> float:
        return self.present / self.seen if self.seen else 0.0

    @property
    def kind(self) -> str:
        if not self.topo_stable:
            return NodeStability.VOLATILE                 # shape itself changed
        if self.seen and self.present == self.seen:
            return NodeStability.STRUCT_LIKE              # always present (value entropy ok)
        if self.present > 0:
            return NodeStability.INTERMITTENT            # flickering presence under identical input
        return NodeStability.VOLATILE


class StabilityGate:
    """Layer 0.  Observes repeats of identical requests, then classifies each node
    struct-like / map-like / volatile.  Compares FINGERPRINTS (value-blind), so a
    field whose VALUE changes across repeats stays stable; only presence/type/order
    changes move a node toward map-like or volatile."""

    MIN_REPEATS = 2     # a request series is trusted only after >=2 identical observations

    def __init__(self) -> None:
        # stability_key -> list[StructuralFingerprint]
        self._series: dict[str, list[StructuralFingerprint]] = {}
        # family -> set[stability_key]
        self._fam_keys: dict[str, set[str]] = {}
        # memoised masks, invalidated on observe
        self._mask_cache: dict[str, TrustMask] = {}

    def observe_repeat(self, family: str, stability_key: str, body: Any) -> None:
        """Record one observation of an identical request.  No analysis, no
        findings (Part F Step 3)."""
        fp = fingerprint(body)   # raw (un-masked) — the gate is what BUILDS the mask
        self._series.setdefault(stability_key, []).append(fp)
        self._fam_keys.setdefault(family, set()).add(stability_key)
        self._mask_cache.pop(family, None)

    def _classify_series(self, fps: list[StructuralFingerprint]
                         ) -> tuple[dict[str, str], set[str]]:
        """Classify each node within ONE request's repeats.
        Returns (node_stability, state_constant_paths)."""
        node_stability: dict[str, str] = {}
        state_constant: set[str] = set()
        if len(fps) < self.MIN_REPEATS:
            # not enough repeats to prove anything -> every observed node volatile
            for p in fps[0].types if fps else {}:
                node_stability[p] = NodeStability.VOLATILE
            return node_stability, state_constant
        all_paths = set().union(*[set(fp.types) for fp in fps])
        for p in all_paths:
            present_everywhere = all(p in fp.types for fp in fps)
            if not present_everywhere:
                node_stability[p] = NodeStability.VOLATILE      # appears/disappears
                continue
            # collapse {scalar,null,bool} into "leaf" so a value<->null flip is NOT
            # a topology change; it is a STATE fact handled separately.
            def shape_type(fp):
                t = fp.types[p]
                return _T_OBJECT if t == _T_OBJECT else _T_ARRAY if t == _T_ARRAY else "leaf"
            if len({shape_type(fp) for fp in fps}) != 1:
                node_stability[p] = NodeStability.VOLATILE      # object<->array etc.
                continue
            kind = shape_type(fps[0])
            if kind == _T_ARRAY:
                if len({fp.array_counts.get(p) for fp in fps}) != 1:
                    node_stability[p] = NodeStability.VOLATILE  # element count varies
                    continue
                node_stability[p] = NodeStability.STRUCT_LIKE
            elif kind == _T_OBJECT:
                if len({fp.order.get(p) for fp in fps}) != 1:
                    node_stability[p] = NodeStability.MAP_LIKE  # reorder -> order disabled
                else:
                    node_stability[p] = NodeStability.STRUCT_LIKE
            else:
                node_stability[p] = NodeStability.STRUCT_LIKE
            # state constancy (populated/null/empty identical across repeats)
            if len({fp.absence_map.get(p) for fp in fps}) == 1:
                state_constant.add(p)
        return node_stability, state_constant

    def trust_mask(self, family: str) -> TrustMask:
        """Aggregate a family-wide trust mask across every request series in the
        family.  Conservative aggregation: a node is VOLATILE in the family if it
        is volatile in ANY series; MAP_LIKE if order varies in any (topology
        stable); STRUCT_LIKE only where every series agrees."""
        if family in self._mask_cache:
            return self._mask_cache[family]
        keys = self._fam_keys.get(family, set())
        node_stability: dict[str, str] = {}
        state_trusted: set[str] = set()
        state_seen: set[str] = set()
        samples = 0
        for key in keys:
            fps = self._series.get(key, [])
            if len(fps) >= self.MIN_REPEATS:
                samples += 1
            ns, sc = self._classify_series(fps)
            for p, cls in ns.items():
                cur = node_stability.get(p)
                # precedence: VOLATILE > MAP_LIKE > STRUCT_LIKE
                if cur is None:
                    node_stability[p] = cls
                elif cls == NodeStability.VOLATILE:
                    node_stability[p] = NodeStability.VOLATILE
                elif cls == NodeStability.MAP_LIKE and cur == NodeStability.STRUCT_LIKE:
                    node_stability[p] = NodeStability.MAP_LIKE
            for p in sc:
                state_trusted.add(p)
            for p in ns:
                state_seen.add(p)
        # a state is trusted only if constant in EVERY series that saw it
        # (state_trusted currently holds union; intersect with "constant everywhere")
        confirmed_state: set[str] = set()
        for p in state_seen:
            constant_everywhere = True
            for key in keys:
                fps = self._series.get(key, [])
                if len(fps) < self.MIN_REPEATS:
                    continue
                if p in fps[0].types:
                    if len({fp.absence_map.get(p) for fp in fps}) != 1:
                        constant_everywhere = False
                        break
            if constant_everywhere and p in state_trusted:
                confirmed_state.add(p)
        order_trusted = {p for p, c in node_stability.items()
                         if c == NodeStability.STRUCT_LIKE}
        mask = TrustMask(node_stability, confirmed_state, order_trusted,
                         stable=samples >= 1, samples=samples)
        self._mask_cache[family] = mask
        return mask

    def normalize(self, family: str) -> dict[str, NodeProfile]:
        """STRUCTURAL-NORMALISATION profile (additive; never feeds a finding).

        For every node, computed PER identical-request series and merged to the
        strongest evidence: how often it was present, whether its shape stayed
        stable, and how much its state churned. Lets the leads layer (a) tolerate
        production value-entropy and (b) surface a flickering PRESENCE under
        identical input — the authorization-conditional signal current tools read
        as mere noise. The CONFIRMED trust_mask above is untouched."""
        profiles: dict[str, NodeProfile] = {}
        for key in self._fam_keys.get(family, set()):
            fps = self._series.get(key, [])
            if len(fps) < self.MIN_REPEATS:
                continue
            paths = set().union(*[set(fp.types) for fp in fps])
            for p in paths:
                if p == _ROOT:
                    continue
                present = [fp for fp in fps if p in fp.types]
                kinds = {shape_kind(fp.types[p]) for fp in present}
                states = {fp.absence_map.get(p) for fp in present}
                prof = NodeProfile(seen=len(fps), present=len(present),
                                   state_distinct=len(states),
                                   topo_stable=(len(kinds) == 1))
                prev = profiles.get(p)
                # keep the profile with the STRONGEST intermittency evidence
                # (lowest present_ratio while still observed somewhere).
                if prev is None or (0 < prof.present_ratio < prev.present_ratio) \
                        or (not prof.topo_stable and prev.topo_stable):
                    profiles[p] = prof
        return profiles


# --------------------------------------------------------------------------- #
# Deterministic divergence primitive                                          #
# --------------------------------------------------------------------------- #

@dataclass
class DivergenceReport:
    """Result of comparing two fingerprints over admissible sub-signals.
    diverged is True iff any admissible sub-signal differs.  magnitude is a coarse
    ordinal for L3 work-queue ranking ONLY — it never enters a verdict (RL3)."""
    diverged: bool
    absence_div: list[tuple]            # (path, state_a, state_b) incl. PRESENT<->ABSENT
    topology_div: list[str]             # type / array-count differences
    order_div: list[str]                # struct-like-only key-order differences
    magnitude: int = 0


def divergence(fp_a: StructuralFingerprint, fp_b: StructuralFingerprint,
               trust_mask: Optional[TrustMask] = None) -> DivergenceReport:
    """Fine-grained, deterministic structural diff restricted to admissible
    sub-signals.  Reports absence-STATE differences (the primary signal), type/
    array differences, and — only on struct-like nodes — key-order differences."""
    mask = trust_mask or _OPEN_MASK
    A, B = fp_a.absence_map, fp_b.absence_map
    union = {p for p in (set(A) | set(B)) if mask.admissible(p)}

    absence_div: list[tuple] = []
    for p in sorted(union):
        sa = A.get(p, AbsenceState.ABSENT)
        sb = B.get(p, AbsenceState.ABSENT)
        if sa != sb:
            absence_div.append((p, sa, sb))

    topology_div: list[str] = []
    for p in sorted(set(fp_a.types) & set(fp_b.types)):
        if not mask.admissible(p):
            continue
        if shape_kind(fp_a.types[p]) != shape_kind(fp_b.types[p]):
            topology_div.append(p)
        elif (shape_kind(fp_a.types[p]) == _T_ARRAY
              and fp_a.array_counts.get(p) != fp_b.array_counts.get(p)):
            topology_div.append(f"{p}#count")

    order_div: list[str] = []
    for p in sorted(set(fp_a.order) & set(fp_b.order)):
        if not mask.admissible(p):
            continue
        if trust_mask is not None and p not in mask.order_trusted:
            continue        # order signal disabled for map-like nodes (Layer 0)
        if fp_a.order[p] != fp_b.order[p]:
            order_div.append(p)

    magnitude = len(absence_div) * 3 + len(topology_div) * 2 + len(order_div)
    diverged = bool(absence_div or topology_div or order_div)
    return DivergenceReport(diverged, absence_div, topology_div, order_div, magnitude)


# --------------------------------------------------------------------------- #
# Layer 2 — Self-coherence model (per-principal, per-family grammars)         #
# --------------------------------------------------------------------------- #

class CoherenceModel:
    """Builds, per (principal, endpoint-family), the grammar of structural
    fingerprints that principal LEGITIMATELY receives, and answers the two
    questions Gate 1 needs:

      * fits(fp, P, family)      -> does fp look like something P normally gets?
                                    PRESENCE + shape kind (+ trusted order),
                                    STATE-BLIND, so a value-filtered response fits
                                    the privileged grammar it was filtered from.
      * privilege_rank(P, family)-> structural richness = count of admissible,
                                    state-trusted PRESENT_POPULATED paths.

    Only fingerprints from request series the StabilityGate has proven stable
    (>= MIN_REPEATS identical observations) ever enter a grammar (RL5)."""

    MIN_REPEATS = StabilityGate.MIN_REPEATS

    def __init__(self, gate: StabilityGate) -> None:
        self._gate = gate
        # (principal, family) -> {stability_key: [fp, ...]}
        self._obs: dict[tuple, dict[str, list[StructuralFingerprint]]] = {}

    def add(self, principal: str, family: str, stability_key: str, body: Any) -> None:
        self._obs.setdefault((principal, family), {}) \
            .setdefault(stability_key, []).append(fingerprint(body))

    def _trusted_fps(self, principal: str, family: str) -> list[StructuralFingerprint]:
        series = self._obs.get((principal, family), {})
        return [fps[-1] for fps in series.values() if len(fps) >= self.MIN_REPEATS]

    def has_grammar(self, principal: str, family: str) -> bool:
        return len(self._trusted_fps(principal, family)) >= 1

    def principals_with_grammar(self, family: str) -> set[str]:
        return {p for (p, f) in self._obs
                if f == family and self.has_grammar(p, f)}

    @staticmethod
    def _adm_present(fp: StructuralFingerprint, mask: TrustMask) -> set[str]:
        return {p for p in fp.present_paths()
                if p != _ROOT and mask.admissible(p)}

    def _shape_sig(self, fp: StructuralFingerprint, mask: TrustMask) -> tuple:
        """STATE-blind structural signature: which paths exist, each path's shape
        kind, and key order ONLY on order-trusted (struct-like) object nodes."""
        paths = self._adm_present(fp, mask)
        kinds = tuple(sorted((p, shape_kind(fp.types[p])) for p in paths))
        orders = tuple(sorted((p, fp.order[p]) for p in paths
                              if p in fp.order and p in mask.order_trusted))
        return (kinds, orders)

    def fits(self, fp: StructuralFingerprint, principal: str, family: str,
             mask: TrustMask) -> bool:
        target = self._shape_sig(fp, mask)
        return any(self._shape_sig(g, mask) == target
                   for g in self._trusted_fps(principal, family))

    def privilege_rank(self, principal: str, family: str, mask: TrustMask) -> int:
        best = 0
        for g in self._trusted_fps(principal, family):
            pop = {p for p in g.populated_paths()
                   if p != _ROOT and mask.state_is_trusted(p)}
            best = max(best, len(pop))
        return best

    def grammar_present_paths(self, principal: str, family: str,
                              mask: TrustMask) -> set[str]:
        out: set[str] = set()
        for g in self._trusted_fps(principal, family):
            out |= self._adm_present(g, mask)
        return out

    def representative(self, principal: str, family: str,
                       mask: TrustMask) -> Optional[StructuralFingerprint]:
        """Richest trusted fingerprint (most admissible present paths)."""
        best, best_n = None, -1
        for g in self._trusted_fps(principal, family):
            n = len(self._adm_present(g, mask))
            if n > best_n:
                best, best_n = g, n
        return best

    # ----------------------------------------------------------------------- #
    # PROVISIONAL tier — single-observation grammars, LEAD-ONLY (never findings)
    # These break the >=2-repeat silence for the relational engine on one-shot
    # endpoints. They use an OPEN admissibility (stability is NOT proven), so they
    # may NEVER feed a finding; the engine emits them only as ranked leads, gated
    # on the diverging paths being privileged-named. The CONFIRMED methods above
    # are entirely untouched, so every existing verdict stays byte-identical.
    # ----------------------------------------------------------------------- #

    def _provisional_fps(self, principal: str, family: str) -> list[StructuralFingerprint]:
        series = self._obs.get((principal, family), {})
        return [fps[-1] for fps in series.values() if len(fps) >= 1]

    def has_provisional(self, principal: str, family: str) -> bool:
        return len(self._provisional_fps(principal, family)) >= 1

    def principals_with_provisional(self, family: str) -> set[str]:
        return {p for (p, f) in self._obs
                if f == family and self.has_provisional(p, f)}

    @staticmethod
    def _open_present(fp: StructuralFingerprint) -> set[str]:
        return {p for p in fp.present_paths() if p != _ROOT}

    def _open_sig(self, fp: StructuralFingerprint) -> tuple:
        paths = self._open_present(fp)
        return tuple(sorted((p, shape_kind(fp.types[p])) for p in paths))

    def fits_provisional(self, fp: StructuralFingerprint, principal: str,
                         family: str) -> bool:
        target = self._open_sig(fp)
        return any(self._open_sig(g) == target
                   for g in self._provisional_fps(principal, family))

    def privilege_rank_provisional(self, principal: str, family: str) -> int:
        best = 0
        for g in self._provisional_fps(principal, family):
            best = max(best, len({p for p in g.populated_paths() if p != _ROOT}))
        return best

    def provisional_present_paths(self, principal: str, family: str) -> set[str]:
        out: set[str] = set()
        for g in self._provisional_fps(principal, family):
            out |= self._open_present(g)
        return out

    def object_presence(self, family: str, objsig: str) -> dict[str, tuple[set, set]]:
        """For one concrete object (family + object signature), return per principal
        who observed it: (present_paths, populated_paths). The substrate for the
        'missing shadow' — a field-level authorization map measured across
        principals on the SAME record, so absence cannot be blamed on a different
        object. Uses the LATEST observation per principal."""
        out: dict[str, tuple[set, set]] = {}
        for (pid, fam), series in self._obs.items():
            if fam != family:
                continue
            fps = series.get(f"{pid}::{family}::{objsig}")
            if not fps:
                continue
            fp = fps[-1]
            present = {p for p in fp.present_paths() if p != _ROOT}
            populated = {p for p in fp.populated_paths() if p != _ROOT}
            out[pid] = (present, populated)
        return out
