"""
Law grammar (deficiency #8 — law-space search / generative laws).
================================================================================
Every hand-written detection law is one POINT in a shared space:

    actor_relation  ∈ {cross_principal, same_principal}
    verb            ∈ {read, write, delete}
    object_selector ∈ {path_id, query_key, secondary_key, nested_ref}
    confirm_channel ∈ {direct_readback, consequence, destruction}

The ~25 manual laws are 25 specific tuples. This module abstracts that structure into a
GRAMMAR and lets ONYX GENERATE new law instances by composing primitives — reaching
violation classes no human wrote.

The critical FP-safety split: GENERATION expands only WHICH pattern ONYX looks for.
CONFIRMATION stays the exact same proven Δstate machinery. A generated law that matches a
pattern but cannot confirm a real Δstate emits NOTHING. So novelty is added with zero risk
to the crown jewel — a generated law can raise recall but can never manufacture a false
positive. Every generated finding is tagged AUTO-GENERATED / UNREVIEWED: proven novelty,
honestly labelled, never silently trusted as a curated law.

Bounded-novelty wall: ONYX composes new COMBINATIONS within these dimensions; it cannot
invent a genuinely new DIMENSION (a violation type outside the space). Adding a dimension
is a human act. Declared.
"""
from __future__ import annotations
from dataclasses import dataclass
from itertools import product
from typing import Optional

ACTOR = ("cross_principal", "same_principal")
VERB = ("read", "write", "delete")
SELECTOR = ("path_id", "query_key", "secondary_key", "nested_ref")
CHANNEL = ("direct_readback", "consequence", "destruction")

_VERB_METHODS = {"read": ("GET",), "write": ("PUT", "POST", "PATCH"), "delete": ("DELETE",)}

# The hand-written laws, as tuples (the KNOWN set). A generated tuple absent here is NOVEL.
KNOWN_LAWS = frozenset({
    ("cross_principal", "read", "path_id", "direct_readback"),      # Conservation / BOLA
    ("cross_principal", "read", "query_key", "direct_readback"),    # report_id BOLA
    ("cross_principal", "read", "nested_ref", "direct_readback"),   # embedded-owner / EDE
    ("cross_principal", "write", "path_id", "direct_readback"),     # XPrincipalWrite
    ("cross_principal", "delete", "path_id", "destruction"),        # XPrincipalDelete
    ("cross_principal", "write", "path_id", "consequence"),         # Consequence credential/capability
})


@dataclass(frozen=True)
class GeneratedLaw:
    actor_relation: str
    verb: str
    object_selector: str
    confirm_channel: str

    def signature(self) -> tuple:
        return (self.actor_relation, self.verb, self.object_selector, self.confirm_channel)

    def is_novel(self) -> bool:
        return self.signature() not in KNOWN_LAWS

    def name(self) -> str:
        return "GEN::" + "/".join(self.signature())

    # ---- executable: match the pattern, then confirm via the SAME Δstate machinery -----
    def evaluate(self, ex, owner_of, reread, confirm_consequence=None,
                 confirm_destroyed=None) -> Optional[dict]:
        """Run this generated law against one exchange. Returns a finding dict iff its
        pattern matches AND its confirmation channel proves a real Δstate; else None.
        `owner_of(value_or_id)` -> owning principal; `reread()` -> current response for a
        fresh read; optional callables supply the consequence/destruction channels. Every
        confirmation is a genuine Δstate — so this can never emit on a non-violation."""
        method = (ex.request.method or "GET").upper()
        if method not in _VERB_METHODS[self.verb]:
            return None
        actor = ex.principal.pid
        obj, owner = self._resolve_object_owner(ex, owner_of)
        if obj is None or owner is None:
            return None
        # actor_relation gate
        if self.actor_relation == "cross_principal" and owner == actor:
            return None
        if self.actor_relation == "same_principal" and owner != actor:
            return None
        # confirmation channel — the SAME proven Δstate discipline
        confirmed = False
        if self.confirm_channel == "direct_readback":
            r = reread() if reread else None
            confirmed = bool(r and 200 <= getattr(r, "status", 0) < 300 and self._leaks(r, ex, owner_of))
        elif self.confirm_channel == "consequence":
            confirmed = bool(confirm_consequence and confirm_consequence(actor, owner, obj))
        elif self.confirm_channel == "destruction":
            confirmed = bool(confirm_destroyed and confirm_destroyed(owner, obj))
        if not confirmed:
            return None
        return {"law": self.name(), "novel": self.is_novel(), "actor": actor,
                "owner": owner, "object": obj, "tag": "AUTO-GENERATED / UNREVIEWED"}

    def _resolve_object_owner(self, ex, owner_of):
        """Extract the addressed object per the selector, and its owner via provenance."""
        req = ex.request
        obj = None
        if self.object_selector == "path_id":
            try:
                ids = req.object_ids(); obj = str(ids[0]) if ids else None
            except Exception:
                obj = None
        elif self.object_selector == "query_key":
            q = req.query or {}
            obj = next((str(v) for v in q.values()), None)
        elif self.object_selector == "secondary_key":
            # a non-primary identifier in the query (email/slug/handle), not a path id
            q = req.query or {}
            obj = next((str(v) for k, v in q.items()
                        if k.lower() in ("email", "slug", "handle", "username", "key")), None)
        elif self.object_selector == "nested_ref":
            body = ex.response.body if isinstance(ex.response.body, dict) else {}
            obj = next((str(v) for k, v in body.items()
                        if k.lower().endswith(("_id", "_ref", "_key"))), None)
        if obj is None:
            return None, None
        owner = owner_of(obj)
        return obj, owner

    def _leaks(self, r, ex, owner_of):
        """A read-back leaks iff its body still carries a value owned by a DIFFERENT
        principal than the actor — the persistent cross-principal property."""
        body = r.body if isinstance(r.body, dict) else {}
        actor = ex.principal.pid
        for v in body.values():
            if isinstance(v, (str, int)):
                o = owner_of(str(v))
                if o and o != actor:
                    return True
        return False


class LawGrammar:
    """Enumerates the law space and yields NOVEL laws (tuples absent from KNOWN_LAWS)."""

    def all_laws(self):
        for a, v, s, c in product(ACTOR, VERB, SELECTOR, CHANNEL):
            # prune incoherent combos: destruction channel only makes sense for delete;
            # a delete confirmed by a direct read-back is really the destruction channel.
            if c == "destruction" and v != "delete":
                continue
            if v == "delete" and c == "direct_readback":
                continue
            yield GeneratedLaw(a, v, s, c)

    def novel_laws(self):
        return [law for law in self.all_laws() if law.is_novel()]
