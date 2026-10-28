"""
Capability graph / chain synthesis (deficiency #5).
================================================================================
ONYX reported each finding in isolation. Real criticality is usually a CHAIN: the OUTPUT
of one confirmed primitive ENABLES the next — a BOLA leaks an admin token, the token
authorizes an admin action, that action deletes a resource. Each hop alone is lower
severity; composed, it is critical, and some target states no single law reaches at all.

The model: a CAPABILITY GRAPH.
  * NODES are capabilities ONYX has CONFIRMED it can obtain — "possess token T", "access
    resource R", "acquire role ADMIN". A capability is a typed, concrete asset.
  * EDGES are confirmed PRIMITIVES: a primitive CONSUMES a capability and PRODUCES another,
    and it carries the Δstate-confirmed finding that proves it.
  * A CHAIN is a path from ONYX's starting capabilities to a high-value target capability.

FP-safety split (the same discipline as the generative grammar, #8): composition does NOT
relax confirmation. A chain is reported ONLY if EVERY edge is an independently
Δstate-confirmed primitive. A hop that cannot be confirmed breaks the chain there and it is
never reported. So chaining raises the severity and recall of escalation PATHS but can
never manufacture a false positive — GP5 holds by construction. The search is bounded in
depth, so there is no combinatorial blow-up.

Declared wall: ONYX composes only the CONFIRMABLE sub-graph, bounded-depth. A path that
needs a hop ONYX cannot confirm (an external or unobservable effect) is not synthesized —
not every conceivable path, only the proven ones.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional, Any


@dataclass(frozen=True)
class Capability:
    """A concrete asset ONYX has confirmed it can hold. `kind` e.g. 'token','resource',
    'role'; `ref` the concrete identifier; `principal` who wields it."""
    kind: str
    ref: str
    principal: str = ""

    def key(self) -> str:
        return f"{self.kind}:{self.ref}"


@dataclass
class Primitive:
    """A confirmed edge: consuming `consumes` (or a start capability) yields `produces`.
    `finding_id` ties the edge to the Δstate proof that confirmed it — an edge with no
    confirmed finding is never admitted to the graph."""
    consumes: Optional[Capability]
    produces: Capability
    finding_id: str
    law: str = ""
    confirmed: bool = True


@dataclass
class Chain:
    steps: list                       # ordered list[Primitive]
    def target(self) -> Capability:
        return self.steps[-1].produces
    def finding_ids(self) -> list:
        return [s.finding_id for s in self.steps]
    def confirmed(self) -> bool:
        return all(s.confirmed and s.finding_id for s in self.steps)
    def describe(self) -> str:
        parts = []
        for s in self.steps:
            src = s.consumes.key() if s.consumes else "∅(start)"
            parts.append(f"{src} --[{s.law or s.finding_id}]--> {s.produces.key()}")
        return "  ⇒  ".join(parts)


class CapabilityGraph:
    """Accumulates confirmed capabilities and primitives, then synthesises confirmed chains
    to a high-value target. Only Δstate-confirmed primitives are admitted, so any chain it
    yields is sound end-to-end."""

    def __init__(self, max_depth: int = 6):
        self.start: set = set()                 # capabilities ONYX holds at t0
        self._by_consume: dict = {}             # capability.key -> list[Primitive]
        self._starts: list = []                 # primitives with no precondition
        self.max_depth = max_depth

    def add_start(self, cap: Capability):
        self.start.add(cap.key())

    def add_primitive(self, prim: Primitive):
        """Admit a confirmed edge only. An unconfirmed/finding-less primitive is refused —
        this is what makes every synthesised chain FP-safe."""
        if not (prim.confirmed and prim.finding_id):
            return False
        if prim.consumes is None:
            self._starts.append(prim)
            self.start.add(prim.produces.key())
        else:
            self._by_consume.setdefault(prim.consumes.key(), []).append(prim)
        return True

    def synthesize(self, is_target: Callable[[Capability], bool]) -> list:
        """Return confirmed chains (bounded depth) from a start capability to any capability
        satisfying `is_target`. Every edge on every returned chain is Δstate-confirmed."""
        chains = []
        held = set(self.start)

        def walk(cap_key: str, path: list, seen: set):
            if len(path) > self.max_depth:
                return
            for prim in self._by_consume.get(cap_key, []):
                if prim.produces.key() in seen:
                    continue                        # no cycles
                new_path = path + [prim]
                if is_target(prim.produces):
                    ch = Chain(new_path)
                    if ch.confirmed():
                        chains.append(ch)
                walk(prim.produces.key(), new_path, seen | {prim.produces.key()})

        # seed from start primitives and from any held start capability
        for prim in self._starts:
            if is_target(prim.produces) and Chain([prim]).confirmed():
                chains.append(Chain([prim]))
            walk(prim.produces.key(), [prim], {prim.produces.key()})
        for cap_key in list(held):
            walk(cap_key, [], {cap_key})
        # dedup by the sequence of finding ids
        uniq, seen_ids = [], set()
        for ch in chains:
            sig = tuple(ch.finding_ids())
            if sig not in seen_ids:
                seen_ids.add(sig); uniq.append(ch)
        return uniq
