"""
㉑ Discriminating-value learning (Gap G12) — pure logic.

`strict_leak` suppresses shared-default false positives, but if it over-suppresses it
throws away real leaks (lost recall). Learn per field whether its value is
DISCRIMINATING (differs across principals) or a SHARED DEFAULT (same for everyone),
and suppress only the proven shared default — pass the discriminating value.

FP gate: DV-0 a field seen for <2 principals is treated as shared (suppressed —
conservative); DV-1 a value is discriminating only if >=2 distinct values across >=2
principals; DV-2 does NOT loosen strict_leak, only narrows it to the proven shared
default; DV-3 default-OFF.
"""
from __future__ import annotations


class DiscriminatingValueLearner:
    def __init__(self):
        self._by_field = {}    # field -> {principal -> set(values)}

    def observe(self, principal, field, value):
        self._by_field.setdefault(field, {}).setdefault(principal, set()).add(str(value))

    def is_discriminating(self, field) -> bool:
        """>=2 distinct values across >=2 principals (not a shared default)."""
        pv = self._by_field.get(field, {})
        if len(pv) < 2:
            return False                                  # DV-0
        distinct = set()
        for s in pv.values():
            distinct |= s
        return len(distinct) >= 2                          # DV-1

    def is_shared_default(self, field, value=None) -> bool:
        """Proven shared default: seen for >=2 principals and identical for all."""
        pv = self._by_field.get(field, {})
        if len(pv) < 2:
            return False
        vals = [v for s in pv.values() for v in s]
        shared = len(vals) >= 2 and len(set(vals)) == 1
        if value is None:
            return shared
        return shared and str(value) in set(vals)

    def should_suppress(self, field, value) -> bool:
        """Suppress ONLY a proven shared default; never a discriminating value (DV-2)."""
        return self.is_shared_default(field, value) and not self.is_discriminating(field)
