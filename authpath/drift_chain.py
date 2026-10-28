"""
㉔ Drift × chain composition (Gap G15) — pure logic.

Register confirmed drift findings as first-class capability-graph edges so escalation
paths (drift -> token -> admin action) can be composed. Rule preserved: EVERY edge
stays independently Δstate-confirmed; a composed path is reported only if all its
edges are confirmed.

FP gate: CH-0 a drift edge is added only if the finding is confirmed; CH-1
composition requires every edge independently confirmed (no speculative chains); CH-2
a composed path reports only if all edges confirmed; CH-3 default-OFF.
"""
from __future__ import annotations
from typing import Optional

_DRIFT_KINDS = ("authz_drift", "second_order_oob_leak", "mass_assignment")


def drift_to_capability_edge(drift_finding) -> Optional[dict]:
    """Turn a CONFIRMED drift finding into a capability-graph edge; else None (CH-0)."""
    if drift_finding is None:
        return None
    kind = getattr(drift_finding, "kind", None)
    if kind not in _DRIFT_KINDS:
        return None
    return {
        "from": getattr(drift_finding, "accessor", None),
        "to": getattr(drift_finding, "resource", None),
        "capability": kind,
        "confirmed": True,
        "evidence": getattr(drift_finding, "why", ""),
    }


def compose_path(edges) -> Optional[dict]:
    """Compose a path only if EVERY edge is confirmed=True (CH-1/CH-2)."""
    if not edges:
        return None
    if not all(e and e.get("confirmed") is True for e in edges):
        return None
    return {"path": [e["capability"] for e in edges],
            "hops": [(e["from"], e["to"]) for e in edges],
            "confirmed": True}
