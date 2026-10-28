"""
Bypass-shape recognition (dev-session idea #1).

ONYX is an ANALYSIS engine over captured traffic — never a payload generator
(RL3). This module does NOT craft bypass attempts. It RECOGNISES, in traffic the
tester already captured, the well-known IDOR/BOLA bypass shapes:

  * HTTP Parameter Pollution  — ?id=self&id=victim   (multi-valued query param)
  * Array wrapping            — {"id": [victim]}      (singular id field, array value)
  * Nested-object wrapping    — {"user": {"id": victim}} where the wrapper is not
                                 the natural resource body
  * Multi-value id array      — {"user_id": [self, victim]}

Why this matters: when an object is reached THROUGH one of these shapes, it
proves the server HAS an authorization control that is being CIRCUMVENTED — a
strictly more severe and more clearly-reportable condition than authorization
simply being absent. We surface the mechanism in the causal path and let the
emitter escalate severity accordingly.

ZERO-FP DISCIPLINE: the hard part is distinguishing a bypass from a legitimate
API shape. A *plural* field carrying an array (`ids`, `user_ids`, `items`) is a
NORMAL batch operation and is explicitly NOT flagged. Only a *singular* id field
wrapped in an array — i.e. a name that should hold one value but holds many — is
suspicious. When in doubt, we do not flag (fail-safe to silence).
"""

from __future__ import annotations

from dataclasses import dataclass

from .provenance import classify_field, ValueClass


# Singular id-bearing field names: holding an ARRAY here is anomalous.
# Built from the same closed ID vocabulary the classifier uses, minus anything
# already plural.
def _is_singular_id_name(name: str) -> bool:
    n = name.lower().rstrip()
    if n.endswith("s"):           # plural → legitimate batch, never a bypass
        return False
    cls = classify_field(n, "x")
    return cls in (ValueClass.ID, ValueClass.OWNER)


@dataclass
class BypassShape:
    kind: str                # "hpp" | "array_wrap" | "nested_wrap" | "multi_value_id"
    field: str               # the field/param name involved
    values: list             # all values observed for it (self + victim candidates)
    detail: str              # human-readable mechanism description


def detect_bypass_shapes(request) -> list[BypassShape]:
    """Inspect a captured request for known bypass shapes. Pure analysis — no
    network, no payload synthesis. Conservative: returns [] unless a shape is
    unambiguous."""
    shapes: list[BypassShape] = []

    # --- query HTTP Parameter Pollution ---------------------------------- #
    # A query param carrying MULTIPLE values for a singular id name is HPP.
    for k, v in (request.query or {}).items():
        if isinstance(v, (list, tuple)) and len(v) > 1 and _is_singular_id_name(k):
            shapes.append(BypassShape(
                "hpp", k, list(v),
                f"query parameter '{k}' supplied {len(v)} times with differing "
                f"values — HTTP parameter pollution against a singular id field",
            ))

    # --- body shapes ----------------------------------------------------- #
    body = request.body if isinstance(request.body, dict) else {}
    for k, v in _iter_shallow(body):
        # array wrapping / multi-value id: singular id name holding a list
        if isinstance(v, list) and _is_singular_id_name(k):
            if len(v) == 1:
                shapes.append(BypassShape(
                    "array_wrap", k, list(v),
                    f"singular id field '{k}' wrapped in a single-element array "
                    f"{{'{k}': [{v[0]!r}]}} — classic array-wrap authorization bypass",
                ))
            else:
                shapes.append(BypassShape(
                    "multi_value_id", k, list(v),
                    f"singular id field '{k}' carries {len(v)} values {v!r} — "
                    f"multi-value id-array bypass (server may authorize on one, "
                    f"act on another)",
                ))
        # nested-object wrap: {"user": {"id": victim}} — a wrapper object whose
        # ONLY meaningful child is an id field. The natural shape would carry the
        # id at the top level; nesting it can evade a top-level authz check.
        if isinstance(v, dict):
            inner_ids = [ik for ik, iv in v.items()
                         if _is_singular_id_name(ik) and not isinstance(iv, (dict, list))]
            non_id = [ik for ik in v.keys() if ik not in inner_ids]
            if inner_ids and not non_id:
                for ik in inner_ids:
                    shapes.append(BypassShape(
                        "nested_wrap", f"{k}.{ik}", [v[ik]],
                        f"id '{ik}' nested under wrapper '{k}' "
                        f"({{'{k}': {{'{ik}': {v[ik]!r}}}}}) — nested-object wrap "
                        f"that can evade a top-level authorization check",
                    ))
    return shapes


def _iter_shallow(d: dict):
    if isinstance(d, dict):
        yield from d.items()


def bypass_values(shapes: list[BypassShape]) -> list[str]:
    """All distinct object-id values referenced across detected bypass shapes —
    used to ensure the engine treats every polluted value as 'touched', not just
    the one the JSON/query parser happened to keep."""
    out: list[str] = []
    seen = set()
    for s in shapes:
        for v in s.values:
            sv = str(v)
            if sv not in seen:
                seen.add(sv); out.append(sv)
    return out
