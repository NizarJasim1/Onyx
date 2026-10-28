"""
authpath/state_pin.py — ownership pinning in logical time (GAP L1-8: scale & dynamic
objects).

THE PROBLEM
===========
On a giant with thousands of objects, and in a multi-step drive (state_driver, GAP-8)
that CREATES objects mid-run, ownership inferred at moment T can shift by the moment of
confirmation — an eventually-consistent graph drifting under the test. The literature
names this a real false-positive source: confirming a "cross-principal" access against a
boundary that moved. ONYX's answer must keep precision first.

THE MECHANISM (zookie / snapshot style)
=======================================
Pin (object_ref -> owner, logical token) at the moment ownership is established (e.g. at
creation during a drive). A confirmation on that object is sound ONLY if the live owner
still matches the pinned owner. If it drifted, the drive's state is UNSTABLE and the
probe must ABSTAIN — never confirm against a shifted boundary. This is the same fail-safe
discipline as the Confirmer's read-consistency window, extended to dynamic objects so a
multi-step plan cannot manufacture a false positive out of consistency drift.

Deterministic, pure stdlib. Off the detection path: it only decides whether the state is
stable enough to let an existing oracle confirm.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Pin:
    object_ref: str
    owner_pid: str
    token: int               # logical timestamp at which this ownership was pinned


class OwnershipLedger:
    """Pins object ownership in logical time so confirmations ride a STABLE snapshot."""

    def __init__(self):
        self._pins: dict = {}
        self._clock = 0

    def pin(self, object_ref: str, owner_pid: str) -> Pin:
        self._clock += 1
        p = Pin(object_ref=object_ref, owner_pid=str(owner_pid), token=self._clock)
        self._pins[object_ref] = p
        return p

    def current_pin(self, object_ref: str):
        return self._pins.get(object_ref)

    @staticmethod
    def consistent(pin: Pin, live_owner_pid) -> bool:
        """Consistent iff the live owner still matches what was pinned. Drift => False =>
        the confirmation must abstain (fail-safe)."""
        return pin is not None and str(live_owner_pid) == str(pin.owner_pid)


class DriveStabilityGuard:
    """Before a driven law fires, every object the drive created/touched must still have
    its pinned owner. Any drift => UNSTABLE => abstain, so a multi-step plan never confirms
    against a boundary that moved under it."""

    def stable(self, checks) -> tuple:
        """`checks`: iterable of (Pin, live_owner_pid). Returns (is_stable, drifted_refs)."""
        drifted = [pin.object_ref for (pin, live) in checks
                   if not OwnershipLedger.consistent(pin, live)]
        return (not drifted, sorted(drifted))
