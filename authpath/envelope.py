"""
④ Principal-Envelope Engine — Axis 2 (§4.2).

For each authenticated principal, maintain the *envelope*: the set of authorities
and object-ids the principal LEGITIMATELY exercised this session.  This is a
measured fact — grown only by the principal's own successful authenticated
actions — never an induced rule about "what traffic usually looks like" (RL1).

`self_envelope` is precisely what makes the law `object_id ∈ self_envelope`
checkable instead of guessed.
"""

from __future__ import annotations

from .models import EffectClass, Envelope, Exchange
from .provenance import ValueClass, extract_values


class EnvelopeEngine:
    def __init__(self) -> None:
        self._envelopes: dict[str, Envelope] = {}

    def envelope_for(self, principal_id: str) -> Envelope:
        if principal_id not in self._envelopes:
            self._envelopes[principal_id] = Envelope(principal_id=principal_id)
        return self._envelopes[principal_id]

    def all(self) -> dict[str, Envelope]:
        return dict(self._envelopes)

    def observe(self, ex: Exchange, effect: EffectClass) -> None:
        """
        Grow the acting principal's envelope from a SUCCESSFUL authenticated action.
        Only 2xx responses count — a denied/errored action grants no authority,
        so it never widens the envelope (measured, not assumed).
        """
        if not (200 <= ex.response.status < 300):
            return
        env = self.envelope_for(ex.principal.pid)
        env.effects.add(effect)
        host = (ex.request.host or "").strip().lower()
        host_set = env.object_ids_by_host.setdefault(host, set())

        def _hold(oid: str):
            env.object_ids.add(oid)        # global (non-host-aware callers)
            host_set.add(oid)              # RL9: host-scoped hold

        # Object-ids the principal legitimately holds: ids it created OR ids the
        # server returned to it AS ITS OWN OBJECT. D-ENVELOPE-OVERBROAD fix: only
        # a TOP-LEVEL response id (field_path with no array index and no nesting,
        # e.g. "id"/"owner_id") is the addressed object's own identity. A list
        # element id ("orders[0].id") or a nested related id ("items[0].pid") is
        # merely VISIBLE, not HELD — absorbing it would authorise the actor for
        # objects it only glimpsed in a listing, silently clearing list→item IDORs.
        for tv in extract_values(ex.response.body):
            top_level = ("[" not in tv.field_path) and ("." not in tv.field_path)
            if tv.value_class in (ValueClass.ID, ValueClass.OWNER) and top_level:
                _hold(str(tv.value))
            if tv.value_class == ValueClass.AMOUNT:
                self._widen_range(env, "PAYMENT", _num(tv.value))
            if tv.value_class == ValueClass.ROLE:        # R4: record held privileged values
                leaf = tv.field_path.split(".")[-1].split("[")[0]
                env.held_field_values.setdefault(leaf, set()).add(str(tv.value))
        for tv in extract_values(ex.request.body):
            if tv.value_class in (ValueClass.ID, ValueClass.OWNER):
                # an id the principal itself supplied AND the server accepted (2xx)
                _hold(str(tv.value))
        # ids embedded in the path of a successful request also belong to it
        for oid in ex.request.object_ids():
            _hold(oid)

        # Function-level authority: a successful privileged action proves the
        # principal *held* that authority this session.
        if effect == EffectClass.AUTHORITY:
            env.granted_authority.add(ex.request.endpoint_key())

    @staticmethod
    def _widen_range(env: Envelope, key: str, value: float | None) -> None:
        if value is None:
            return
        lo, hi = env.value_ranges.get(key, (value, value))
        env.value_ranges[key] = (min(lo, value), max(hi, value))


def _num(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
