"""
authpath.temporal_shape — AUTHORIZATION-SHAPE TIME-SERIES (RL16).

THE SHIFT THIS MODULE ENCODES
-----------------------------
Every prior ONYX component measures the authorization *state* at one moment. But
on a continuously-deployed target the authorization boundary MOVES: a field that
was filtered yesterday is exposed today because a deploy regressed the serializer.
That window — opened by a 3pm deploy, closed by a 9pm hotfix — is invisible to any
point-in-time scanner and to a human who has no snapshot of yesterday to diff. The
vulnerability does not live in the value of the shape; it lives in its DERIVATIVE,
the change of the authorization-shape over time.

This module gives ONYX a TIME AXIS. It records, per (principal, endpoint, object),
the VALUE-BLIND structural authorization-shape (which sensitive paths are
populated / nulled / absent) with a timestamp, and flags the moment a sensitive
path that was withheld becomes exposed for a principal whose declared role did NOT
change in between — an authorization regression.

LOAD-BEARING DISCIPLINE (red lines preserved by construction)
-------------------------------------------------------------
  * RL1 (no induction): the comparison is TWO MEASURED FINGERPRINTS (T1 vs T2),
    both value-blind structural facts. It never says "this change is anomalous";
    it says "this sensitive path was structurally ABSENT/NULL at T1 and POPULATED
    at T2." No baseline model, no learned threshold.
  * RL3 (Δstate): a regression becomes a finding only when a live read-back proves
    the newly-exposed field is STILL populated now (the regression is live).
  * RL5 (fail-safe): no prior snapshot, a role-epoch change between snapshots, or a
    non-sensitive change ⇒ abstain. The role-epoch guard (below) is the defence
    against the single worst false positive: a legitimate role promotion.

The store is VALUE-BLIND (it holds path names + absence-states + timestamps, never
values), so it is inherently sealed and safe to persist across sessions. Disabled
by default at the engine (the `temporal_shape` flag) ⇒ never consulted ⇒
byte-identical to the pre-RL16 engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .structural import fingerprint, divergence, AbsenceState


# states that mean "this principal was NOT being shown a populated value here"
_WITHHELD = {AbsenceState.ABSENT, AbsenceState.PRESENT_NULL, AbsenceState.PRESENT_EMPTY}


@dataclass
class ShapeSnapshot:
    """One value-blind authorization-shape observation at a point in time."""
    absence_map: dict          # path -> AbsenceState (value-blind)
    observed_at: float
    role_epoch: int            # the principal's declared-role epoch at capture time
    endpoint: str


@dataclass
class Regression:
    """A sensitive path that crossed from withheld → populated over time."""
    path: str
    prior_state: str
    now_state: str
    prior_at: float
    now_at: float


class AuthShapeLedger:
    """Per (principal, endpoint-family, object-id) time-series of value-blind
    authorization-shapes, plus the regression detector. In-memory within a run
    (T1 then T2); the snapshots are value-blind so the same structure persists
    across sessions via a sealed store when the operator wires durability."""

    def __init__(self) -> None:
        # (principal, family, object_id) -> ShapeSnapshot (the most recent)
        self._last: dict = {}

    @staticmethod
    def _key(principal_id: str, request) -> Optional[tuple]:
        family = request.endpoint_key()
        try:
            oid = request.primary_object_id()
        except Exception:
            oid = None
        # a stable per-resource key; a list/no-id door has no single-object shape
        # to track over time here (cross-surface handles those), so we skip it.
        if oid is None:
            return None
        return (principal_id, family, str(oid))

    def snapshot_for(self, principal_id: str, request) -> Optional[ShapeSnapshot]:
        key = self._key(principal_id, request)
        return self._last.get(key) if key else None

    def record(self, request, response, principal_id: str,
               role_epoch: int = 0) -> None:
        """Record the current value-blind authorization-shape for this
        (principal, endpoint, object). Overwrites the prior snapshot (we keep the
        most recent as the reference; a sealed store keeps the full series)."""
        key = self._key(principal_id, request)
        if key is None:
            return
        body = getattr(response, "body", None)
        if not isinstance(body, (dict, list)):
            return
        fp = fingerprint(body)
        self._last[key] = ShapeSnapshot(
            absence_map=dict(fp.absence_map),
            observed_at=float(getattr(response, "observed_at", 0.0)
                              or getattr(request, "observed_at", 0.0) or 0.0),
            role_epoch=int(role_epoch),
            endpoint=request.endpoint_key())

    def regressions(self, request, response, principal_id: str,
                    role_epoch: int = 0) -> list[Regression]:
        """Compare the CURRENT shape to the prior snapshot for this
        (principal, endpoint, object). Return sensitive paths that crossed from
        WITHHELD (absent / null / empty) to PRESENT_POPULATED — but ONLY when the
        principal's declared role-epoch is UNCHANGED since the prior snapshot (a
        role promotion legitimately widens what it sees, so we abstain on it: the
        single worst false positive, defused). Returns [] otherwise."""
        prior = self.snapshot_for(principal_id, request)
        if prior is None:
            return []
        if prior.role_epoch != int(role_epoch):
            return []   # role changed between snapshots → legitimate widening → abstain
        body = getattr(response, "body", None)
        if not isinstance(body, (dict, list)):
            return []
        now_fp = fingerprint(body)
        # reconstruct a fingerprint-like object for the prior absence_map to reuse
        # the structural divergence helper (one source of truth).
        prior_fp = _FrozenFP(prior.absence_map)
        rep = divergence(prior_fp, now_fp)
        from .confirmer import _is_sensitive_key
        try:
            from .intrinsic import name_sensitivity
        except Exception:                      # pragma: no cover
            name_sensitivity = lambda _p: 0    # noqa: E731
        out: list[Regression] = []
        for path, sa, sb in rep.absence_div:
            if sb != AbsenceState.PRESENT_POPULATED or sa not in _WITHHELD:
                continue
            leaf = path.split(".")[-1].split("[")[0].lower()
            if _is_sensitive_key(leaf) or name_sensitivity(path) >= 6:
                out.append(Regression(path=path, prior_state=sa, now_state=sb,
                                      prior_at=prior.observed_at,
                                      now_at=float(getattr(response, "observed_at", 0.0) or 0.0)))
        return out


class _FrozenFP:
    """Minimal fingerprint-shaped wrapper around a stored absence_map so the
    existing `divergence()` helper can diff a persisted snapshot against a live
    fingerprint without re-deriving it. Only the fields divergence() reads on the
    'a' side over absence are populated; types/order/array are empty (absence is
    the only signal we compare here, which is the value-blind authorization fact)."""
    def __init__(self, absence_map: dict):
        self.absence_map = dict(absence_map)
        self.types: dict = {}
        self.order: dict = {}
        self.array_counts: dict = {}
