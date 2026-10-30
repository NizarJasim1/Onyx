"""
authpath/graphql_fields.py — nested/aliased GraphQL field extraction (GAP-3) and a
field-level authorization oracle that confirms over-exposure VALUELESSLY (GAP-9).

ONE SEAM, TWO SIDES
===================
GAP-3: the existing GraphQL parser reads only TOP-LEVEL root selections
("field-level detail is unnecessary on the hot path"). So a restricted field smuggled
via an ALIAS or a NESTED selection inside an otherwise-authorized query is invisible to
the request-side lens. ``parse_field_leaves`` closes that: it walks the whole selection
set and returns every leaf as its RESPONSE path (alias-resolved), at any depth.

GAP-9: ONYX can already confirm structurally without reading a value (SAIE), but only as
an OPTIONAL, wired-in adjunct — the hot path matches the victim's value, which you can
only do for principals you own. The most valuable giant leaks are third-party fields you
must NOT harvest. So this oracle confirms on the **structural-contract** basis by default:
a field the backend's OWN disclosed contract says is denied for this principal, yet
PRESENT+POPULATED in the principal's response, is an authorization break — proven without
reading the value. A real owned value-leak only RAISES severity.

Both plug into the Oracle Registry (GAP-5), whose zero-FP guard now enforces the
structural-contract basis just as strictly as value-match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import Candidate, EffectClass, StateProof
from .oracle_registry import Oracle, OracleVerdict, VerdictKind


# --------------------------------------------------------------------------- #
# GAP-3 — full nested + aliased selection-set parser (best-effort, RL1)       #
# --------------------------------------------------------------------------- #
_FIELD_RE = re.compile(r"(?:(?P<alias>[A-Za-z_]\w*)\s*:\s*)?(?P<name>[A-Za-z_]\w*)")


def _skip_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] in " \t\r\n,":
        i += 1
    return i


def _skip_balanced(s: str, i: int, open_ch: str, close_ch: str) -> int:
    """Skip a balanced ``(...)`` argument group starting at s[i] == open_ch."""
    depth = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def parse_field_leaves(query: str) -> list[str]:
    """Every LEAF field of the query, as the dotted RESPONSE path (alias when present,
    else field name), at any depth. Best-effort and tolerant — like the existing
    top-level parser, it reads a measured fact off the request, never a policy (RL1).

    Example: ``query { me { id secret: ssn orders { internal } } }``
      -> ['me.id', 'me.secret', 'me.orders.internal']
    """
    s = query or ""
    start = s.find("{")
    if start < 0:
        return []
    leaves: list[str] = []
    n = len(s)

    def parse_selset(idx: int, prefix: list[str]) -> int:
        while idx < n:
            idx = _skip_ws(s, idx)
            if idx >= n:
                break
            c = s[idx]
            if c == "}":
                return idx + 1
            if c == "#":                                   # comment to end of line
                nl = s.find("\n", idx)
                idx = n if nl < 0 else nl + 1
                continue
            if s.startswith("...", idx):                   # fragment spread / inline fragment
                idx += 3
                while True:                                # skip 'on' and/or TypeName / fragment-name tokens
                    idx = _skip_ws(s, idx)
                    m = _FIELD_RE.match(s, idx)
                    if not m:
                        break
                    idx = m.end()
                idx = _skip_ws(s, idx)
                if idx < n and s[idx] == "{":              # inline fragment body -> descend (same depth)
                    idx = parse_selset(idx + 1, prefix)
                continue
            m = _FIELD_RE.match(s, idx)
            if not m:
                idx += 1
                continue
            alias, name = m.group("alias"), m.group("name")
            idx = m.end()
            key = alias or name
            idx = _skip_ws(s, idx)
            if idx < n and s[idx] == "(":                  # skip arguments
                idx = _skip_balanced(s, idx, "(", ")")
                idx = _skip_ws(s, idx)
            if idx < n and s[idx] == "{":                  # has children -> not a leaf
                idx = parse_selset(idx + 1, prefix + [key])
            else:
                leaves.append(".".join(prefix + [key]))
        return idx

    parse_selset(start + 1, [])
    return leaves


# --------------------------------------------------------------------------- #
# GAP-9 — field-level authz oracle, valueless (structural-contract) by default #
# --------------------------------------------------------------------------- #
@dataclass
class GraphQLFieldProbe:
    """One field-level over-exposure lead.

    ``contract_denied_paths`` are field-paths the BACKEND ITSELF disclosed as
    authorization-denied for this principal (e.g. from ``graphql.authz_denied_paths`` on
    a representative request) — a measured fact, not an assumption (RL1).
    ``present_populated_paths`` are leaves PRESENT+POPULATED (value-blind) in the
    attacker's response. ``requested_leaves`` is the full nested/aliased parse of the
    attacker's query. ``owned_value_leaked`` is an optional escalator: True only when a
    value the TESTER owns actually crossed (never a third party's)."""
    attacker_pid: str
    requested_leaves: list
    contract_denied_paths: list
    present_populated_paths: list
    owned_value_leaked: bool = False


class GraphQLFieldAuthzOracle(Oracle):
    """Confirms a restricted field returned via alias/nested selection. Default basis is
    structural-contract (valueless): a field the backend's own contract denies for this
    principal is present+populated in its response. No victim value is read."""
    name = "graphql-field-authz"
    effects = frozenset({EffectClass.GRAPHQL_FIELD_AUTHZ})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("gql_field_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("gql_field_probe")
        if probe is None:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.GRAPHQL_FIELD_AUTHZ,
                                 oracle_name=self.name, reason="no graphql field probe attached")

        denied = set(probe.contract_denied_paths or [])
        present = set(probe.present_populated_paths or [])
        # a field the backend's OWN contract denies, yet present+populated for the attacker
        over_exposed = sorted(denied & present)
        attacker_owned = bool(probe.attacker_pid)

        if over_exposed and attacker_owned:
            leak_note = (" · a tester-owned value actually leaked (severity raised)"
                         if probe.owned_value_leaked else "")
            proof = StateProof(
                confirmed=True,
                method=(f"field(s) {over_exposed} are DENIED by the backend's own disclosed "
                        f"contract for principal {probe.attacker_pid}, yet present+populated "
                        f"in its response (selected via alias/nested path){leak_note}"),
                before=f"backend contract: {over_exposed} denied/filtered for {probe.attacker_pid}",
                after=f"response: {over_exposed} present+populated",
                read_as="contract",
                detail=("field-level authorization break (BOPLA via alias/nested smuggling), "
                        "confirmed valuelessly against the backend's own disclosed contract"),
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.GRAPHQL_FIELD_AUTHZ,
                oracle_name=self.name, proof=proof,
                reason="field over-exposure confirmed against the target's own contract",
                observed_out_of_band=True,
                confirmation_basis="structural-contract",
                contract_anchored=True,            # the denied set came from the backend itself
                attacker_owned=attacker_owned,
            )

        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.GRAPHQL_FIELD_AUTHZ, oracle_name=self.name,
            reason=("no field both denied-by-contract and present — the backend filtered it "
                    "(no finding)"))
