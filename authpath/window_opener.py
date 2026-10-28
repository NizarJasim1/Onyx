"""
㉖ Window-opener (Gap G4) — single-packet / deferred-collision, LOGIC LAYER only.

Drift sometimes needs the check<->mutate<->commit interleave forced into a <1ms
window. The timing is PROBABILISTIC and never enters the verdict — the report rests
ENTIRELY on a persisted Δstate read-back after the race (reusing G3 convergence). The
synchronous-send I/O is a thin injected adapter (not exercised here).

FP gate: SP-0 timing is a probabilistic trigger only, zero reports from it; SP-1 the
report is solely from a persisted Δstate read-back after the race (via convergence);
SP-2 a race that did not land => zero report; SP-3 default-OFF.
"""
from __future__ import annotations


def plan_single_packet_batch(base_request, n: int = 20) -> list:
    """Plan n identical requests for synchronous dispatch (single-packet / last-byte
    -sync). Pure planning; actual dispatch is an injected I/O adapter."""
    return [base_request for _ in range(max(1, n))]


def deferred_collision_plan(request_a, request_b, gap_seconds: float) -> dict:
    """Deferred-collision mode: two conflicting requests separated by a gap, then a
    read-back. Planning only."""
    return {"first": request_a, "second": request_b, "gap_s": gap_seconds, "then": "readback"}


def race_result_confirmed(*, post_race_readback, persisted, control_visible) -> bool:
    """After the race (however probabilistic), confirm ONLY via a persisted Δstate
    read-back at convergence. Timing never enters this decision (SP-0/SP-1)."""
    from .convergence import converged_persisted
    return converged_persisted(lambda: post_race_readback, persisted, control_visible,
                               max_polls=1, interval_s=0.0)
