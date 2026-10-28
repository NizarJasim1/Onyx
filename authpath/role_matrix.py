"""
authpath.role_matrix — ROLE x ENDPOINT COVERAGE MATRIX (layer D).

THREE THINGS IN THE BRIEF HAD TO CHANGE BEFORE ANY OF IT COULD BE BUILT
--------------------------------------------------------------------------------

(1) "200 -> ALLOWED, 401/403 -> DENIED" IS A STATUS-CODE ORACLE.
    This is the one rule ONYX exists to refuse. The confirmer says it in every
    strategy it has: a 2xx is not evidence, only a Delta-state read-back is. A
    matrix filled from status codes would record ALLOWED for a 200 carrying
    `{"data": null}`, for a 200 soft-deny page, and for a 200 empty list.

    So a cell is ALLOWED only when the response succeeded AND carried a
    SUBSTANTIVE object — content that a read-back could actually observe. It is
    DENIED only on an explicit authorization-class refusal. A bare success with
    nothing in it is NOT a third decision: it stays UNTESTED, with the reason
    recorded, because "the server said 200 and gave us nothing" is not knowledge
    about access. Doubt resolves to abstention, never to a filled cell.

(2) THE SPECIFIED CONTRADICTION RULE FIRES ON CORRECT AUTHORIZATION.
    The brief's own example — `viewer` may GET /api/orders/101 but not
    /api/orders/102 — is not a bug. It is BOLA protection working. Two objects of
    one type legitimately have different owners; a role is not an ACL. A rule that
    flags this fires on every correctly-secured application, which is the opposite
    of a zero-false-positive tool.

    So per-object divergence is never reported as a contradiction. The matrix is
    keyed on the endpoint TEMPLATE, and when one role gets both outcomes on one
    template the cell is marked CONFLICT and turned into a PROBE with the
    ambiguity stated: this is either ownership working or a real inconsistency,
    and only Delta-state can tell them apart. The brief's second example, "admin
    may DELETE /api/users/1 but not /api/users/2", has the same shape — a
    protected system account explains it just as well.

(3) SYSTEMATICALLY FIRING EVERY VERB AT EVERY ENDPOINT IS DESTRUCTIVE.
    The brief asks the matrix to fill each UNTESTED cell by sending the request,
    across GET/POST/PUT/DELETE/PATCH. Sweeping DELETE across a role x endpoint
    grid on a live target destroys data. `matrix.py` already refuses this for the
    N-principal case — "GET-only ... never multiplies a mutation across
    identities" — and layer D inherits that refusal exactly.

    This module therefore SENDS NOTHING. It plans, and every plan is a read.
    Mutating cells stay UNTESTED forever and are reported as unplannable, with the
    reason given. Issuing a probe stays the engine's business, under `ScopeGuard`
    and the budget ledger.

WHAT LAYER D REUSES RATHER THAN REBUILDS
----------------------------------------
  role rank ...... `iam.RoleModel` — a DECLARED, reviewed ladder (RL13's own),
                   plus operator overrides. Never learned.
  roles from
  traffic ........ `provenance.inspect_jwt().authority_claims` — the existing
                   closed claim vocabulary (role/roles/scope/permissions/...).
  sensitivity .... `intrinsic.name_sensitivity` — the existing closed lexicon.
  endpoints ...... layer B's aggregated surface.
  declared roles . layer A's `FrontendContract.roles`.

RL1 — WHERE ROLES COME FROM, AND WHERE THEY DO NOT
---------------------------------------------------
A role is admitted only when it was DECLARED (layer A / a spec) or OBSERVED (a JWT
authority claim, an explicit role header, a principal's own `role` attribute). A
principal with no readable role is EXCLUDED from the matrix and reported — never
assigned a default, because a guessed role assignment would put a real measurement
in the wrong row, which is worse than an empty row.

`RoleModel.rank()` returns 50 for any unrecognised role, which is right for RL13
(the confirmer still decides) and wrong here: it would manufacture an ordering
between `viewer` and some custom role purely out of a fallback. So layer D uses
`declared_rank()`, which returns None unless the ladder or an override actually
matched. No declared rank on BOTH sides means NO privilege comparison (RL5).

WHAT THIS MODULE IS NOT
-----------------------
No `Candidate`, no `Finding`, no verdict. It imports nothing from `eil`,
`confirmer` or `engine` (asserted by test). Its probes are read plans, and every
one of them still has to be proven by the Delta-state confirmer (RL3).

DETERMINISM
-----------
Same observations in, same matrix out. Cells are sorted by (role, method,
template); probes by priority then key; no set iteration reaches the output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Cell decisions. Four states, exactly as specified — with the discipline that a
# bare 2xx does NOT earn ALLOWED and never becomes a fifth state either; it
# resolves to UNTESTED, because doubt must abstain.
ALLOWED = "ALLOWED"
DENIED = "DENIED"
UNTESTED = "UNTESTED"
CONFLICT = "CONFLICT"

# Why a cell that saw traffic still ended UNTESTED. Measured facts, not judgments.
WHY_NEVER_SEEN = "never-observed"
WHY_NO_SUBSTANCE = "success-carried-no-substantive-object"
WHY_NON_AUTHZ_ERROR = "non-authorization-error"
WHY_BUDGET = "budget-exhausted"

# Verbs a planner may propose. Reads only — see point (3) in the module docstring.
PLANNABLE_METHODS = ("GET",)
MATRIX_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

_MAX_CELLS = 20_000
_MAX_PROBES = 500

# Header names that carry a role explicitly. A CLOSED list: a header outside it is
# not read as a role, because "a header whose name looks role-ish" is the
# induction RL1 forbids.
_ROLE_HEADERS = ("x-role", "x-user-role", "x-roles", "x-auth-role", "role")


# --------------------------------------------------------------------------- #
# role sourcing — declared or observed, never invented                         #
# --------------------------------------------------------------------------- #

def declared_rank(role: str, role_model=None) -> Optional[int]:
    """Rank of `role` ONLY when the declared ladder actually matched it.

    `iam.RoleModel.rank()` falls back to 50 for anything unrecognised. That
    fallback is correct for RL13 and unusable here: comparing `viewer` (30) with an
    unmatched custom role (50) would invent a hierarchy out of a default value.
    Returning None instead makes the comparison abstain, which is the fail-safe.
    """
    if not role:
        return None
    from .iam import RoleModel, _DEFAULT_RANKS
    rm = role_model or RoleModel()
    r = str(role).lower()
    if r in rm.overrides:
        return rm.overrides[r]
    for key, rank in rm.overrides.items():
        if key in r:
            return rank
    for sub, rank in _DEFAULT_RANKS:
        if sub in r:
            return rank
    return None                      # unrecognised => no ordering, no comparison


def roles_of_principal(principal, request=None, overrides=None) -> tuple:
    """Roles this principal DECLARES or was OBSERVED carrying, plus the source.

    Sources, in fixed order: an operator-supplied mapping, an explicit `role`
    attribute, a JWT authority claim, an explicit role header. Returns
    ((role, source), ...) — empty when nothing readable was found, which excludes
    the principal from the matrix rather than placing it in a guessed row.

    `Principal` is a frozen dataclass with no `role` field, so on a real capture
    the readable sources are the JWT claim, an explicit role header, or the
    operator's own mapping. That is by design.

    INHERITED BOUNDARY: `harimport.parse_har_exchanges` groups a capture by
    CREDENTIAL IDENTITY, so two tokens sharing a `sub` become one principal and one
    header set. A role is therefore read per PRINCIPAL, not per request, on that
    path — which is semantically right, since one identity holds one set of roles,
    but it does mean a capture that reuses a subject across roles cannot be split
    apart here. Use `role_overrides` when that is the shape of the capture.

    DELIBERATE DEVIATION FROM `matrix._tier_of`: the principal's `label` is NOT
    read. A label is free text ("Alice (victim)"), and pulling a role out of it
    would be reading a role from prose — the guess this layer exists to refuse.
    `_tier_of` may do it for its coarse tiering; layer D files real measurements
    into rows, where a wrong row is worse than an empty one.
    """
    out: list = []
    seen: set = set()

    def add(val, source):
        for item in (val if isinstance(val, (list, tuple)) else [val]):
            s = str(item).strip()
            if s and s.lower() not in seen and len(s) <= 64:
                seen.add(s.lower())
                out.append((s, source))

    pid = getattr(principal, "pid", None) or str(principal)
    if isinstance(overrides, dict) and pid in overrides:
        add(overrides[pid], "operator_declared")

    role_attr = getattr(principal, "role", None)
    if role_attr:
        add(role_attr, "principal_attribute")

    headers: dict = {}
    for src in (getattr(principal, "auth", None), getattr(request, "headers", None)):
        if isinstance(src, dict):
            headers.update({str(k).lower(): v for k, v in src.items()})

    from .provenance import inspect_jwt
    for hv in headers.values():
        try:
            jwt = inspect_jwt(hv if isinstance(hv, str) else "")
        except Exception:                            # noqa: BLE001
            jwt = None
        if jwt and jwt.authority_claims:
            for k in ("role", "roles"):
                if k in jwt.authority_claims:
                    add(jwt.authority_claims[k], "jwt_claim")

    for h in _ROLE_HEADERS:
        if h in headers and isinstance(headers[h], str):
            add([p.strip() for p in headers[h].split(",")], "role_header")

    return tuple(out)


# --------------------------------------------------------------------------- #
# evidence reading — substantive object, or nothing                            #
# --------------------------------------------------------------------------- #

def _is_substantive(body: Any) -> bool:
    """Did the response actually carry an object a read-back could observe?

    An empty dict, an empty list, a null payload, or a bare envelope with no data
    is NOT substance. This is what stops a 200 from meaning `ALLOWED`.
    """
    if isinstance(body, list):
        return any(_is_substantive(x) for x in body)
    if isinstance(body, dict):
        if not body:
            return False
        for k, v in body.items():
            kl = str(k).lower()
            if kl in ("errors", "error", "message", "detail", "status", "code"):
                continue
            if kl in ("data", "result", "results", "items", "records", "rows",
                      "edges", "nodes", "content"):
                if _is_substantive(v):
                    return True
                continue
            if v not in (None, "", [], {}):
                return True
        return False
    return body not in (None, "", [], {})


def _authz_refused(status: int, body: Any) -> bool:
    """An EXPLICIT authorization refusal: a 401/403, or a GraphQL authz error.

    A 404 is deliberately not counted — it is ambiguous between "forbidden and
    hidden" and "does not exist", and resolving that ambiguity here would be a
    guess. Ambiguity abstains.
    """
    if status in (401, 403):
        return True
    try:
        from .graphql import authz_denied_paths
        return bool(authz_denied_paths(body))
    except Exception:                                # noqa: BLE001
        return False


def read_outcome(status: int, body: Any) -> tuple:
    """(decision, why) for one observation. Never a fifth state, never a guess."""
    if _authz_refused(status, body):
        return DENIED, ""
    if 200 <= int(status or 0) < 300:
        if _is_substantive(body):
            return ALLOWED, ""
        return UNTESTED, WHY_NO_SUBSTANCE       # a 2xx carrying nothing proves nothing
    return UNTESTED, WHY_NON_AUTHZ_ERROR


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass
class RoleMatrixCell:
    role: str
    method: str
    endpoint: str                      # the TEMPLATE, never a concrete object path
    decision: str = UNTESTED
    observed_status: Optional[int] = None   # only when ONE distinct status was seen
    observed_statuses: tuple = ()           # sorted, so order of arrival cannot leak
    observed_count: int = 0
    principals_tested: tuple = ()
    source: str = ""
    is_gap: bool = True
    is_anomaly: bool = False
    why_untested: str = WHY_NEVER_SEEN
    outcomes: tuple = ()               # ((decision, count), ...) as OBSERVED
    sample_paths: tuple = ()           # concrete paths behind the template

    @property
    def key(self) -> str:
        return f"{self.role}|{self.method} {self.endpoint}"


@dataclass
class RoleMatrixResult:
    matrix: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    privilege_anomalies: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    excluded_principals: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        def cell(c):
            return {"role": c.role, "method": c.method, "endpoint": c.endpoint,
                    "decision": c.decision, "observed_status": c.observed_status,
                    "observed_statuses": list(c.observed_statuses),
                    "observed_count": c.observed_count,
                    "principals_tested": list(c.principals_tested),
                    "source": c.source, "is_gap": c.is_gap,
                    "is_anomaly": c.is_anomaly,
                    "why_untested": c.why_untested if c.decision == UNTESTED else ""}
        return {
            "matrix": [cell(c) for c in self.matrix],
            "gaps": [{**cell(c), "severity": s} for c, s in self.gaps],
            "contradictions": list(self.contradictions),
            "privilege_anomalies": list(self.privilege_anomalies),
            "probes": list(self.probes),
            "roles": list(self.roles),
            "excluded_principals": list(self.excluded_principals),
            "stats": dict(sorted(self.stats.items())),
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# the matrix                                                                   #
# --------------------------------------------------------------------------- #

class RoleMatrix:
    """Observe (role x endpoint x verb) cells, then plan the reads that would
    fill the empty ones. Observation only — this class issues no request."""

    def __init__(self, role_model=None, role_overrides=None) -> None:
        self.role_model = role_model
        # operator-supplied {principal_id: role}. A DECLARATION by the tester, the
        # same standing as a spec entry — and the only way to attach a role to the
        # frozen `Principal` the engine builds.
        self.role_overrides = dict(role_overrides or {})
        self._cells: dict = {}
        self._roles: set = set()
        self._role_source: dict = {}
        self._excluded: dict = {}

    # -- stage 1/2: build and fill from MEASUREMENTS ------------------------ #

    def observe(self, request, response, principal) -> None:
        """Record one real exchange into every cell its principal's roles occupy.

        A principal whose role cannot be read is excluded and reported. Nothing is
        recorded for it, because a measurement filed under a guessed role is worse
        than no measurement at all.
        """
        pid = getattr(principal, "pid", None) or str(principal)
        roles = roles_of_principal(principal, request, self.role_overrides)
        if not roles:
            self._excluded[pid] = "no declared or observed role"
            return

        try:
            template = _template_of(request)
            method = (request.method or "").upper()
            status = int(getattr(response, "status", 0) or 0)
            body = getattr(response, "body", None)
        except Exception:                            # noqa: BLE001
            return
        if not template or not method:
            return

        decision, why = read_outcome(status, body)
        for role, source in roles:
            self._roles.add(role)
            self._role_source.setdefault(role, source)
            self._merge(role, method, template, decision, why, status, pid,
                        source, getattr(request, "path", ""))

    def declare_roles(self, roles, source: str = "declared") -> None:
        """Admit roles declared by layer A or a spec, with no measurement yet.
        They open empty rows; they never fill a cell."""
        for r in roles or []:
            s = str(r).strip()
            if s and len(s) <= 64:
                self._roles.add(s)
                self._role_source.setdefault(s, source)

    def _merge(self, role, method, template, decision, why, status, pid, source, path):
        key = (role, method, template)
        cell = self._cells.get(key)
        if cell is None:
            if len(self._cells) >= _MAX_CELLS:
                return
            cell = RoleMatrixCell(role=role, method=method, endpoint=template)
            self._cells[key] = cell
        counts = dict(cell.outcomes)
        counts[decision] = counts.get(decision, 0) + 1
        cell.outcomes = tuple(sorted(counts.items()))
        cell.observed_count += 1
        # Recording the MOST RECENT status made the cell order-dependent: the same
        # two observations arriving in the other order produced a different value.
        # Keep the sorted set instead, and expose a single status only when there
        # is genuinely one — an ambiguous cell reports None rather than picking.
        if status not in cell.observed_statuses:
            cell.observed_statuses = tuple(sorted(cell.observed_statuses + (status,)))
        cell.observed_status = (cell.observed_statuses[0]
                                if len(cell.observed_statuses) == 1 else None)
        cell.source = source
        if pid not in cell.principals_tested:
            cell.principals_tested = tuple(sorted(cell.principals_tested + (pid,)))
        if path and path not in cell.sample_paths and len(cell.sample_paths) < 8:
            cell.sample_paths = tuple(sorted(cell.sample_paths + (path,)))

        decided = {d for d in counts if d in (ALLOWED, DENIED)}
        if len(decided) > 1:
            cell.decision, cell.why_untested = CONFLICT, ""
        elif decided:
            cell.decision, cell.why_untested = decided.pop(), ""
        else:
            cell.decision, cell.why_untested = UNTESTED, why or WHY_NEVER_SEEN
        cell.is_gap = cell.decision == UNTESTED

    def cells(self) -> list:
        return [self._cells[k] for k in sorted(self._cells)]

    def cell(self, role, method, template):
        return self._cells.get((role, method, template))


def _template_of(request) -> str:
    """Endpoint template for a request, via the engine's own `endpoint_key()`.

    Keying on the template rather than the concrete path is what stops the matrix
    from treating two objects of one type as two different permissions.
    """
    try:
        key = request.endpoint_key()
        return key.split(" ", 1)[1] if " " in key else ""
    except Exception:                                # noqa: BLE001
        return (getattr(request, "path", "") or "").split("?")[0]


# --------------------------------------------------------------------------- #
# stages 3-6: gaps, conflicts, anomalies, probes                               #
# --------------------------------------------------------------------------- #

def _severity(role: str, method: str, template: str, role_model=None) -> str:
    """Gap severity: a LOW declared role against a SENSITIVE endpoint is critical.

    Sensitivity comes from `intrinsic.name_sensitivity`, the existing closed
    lexicon. A role with no declared rank yields 'medium' — we decline to rate
    what we cannot order, rather than assume the worst or the best.
    """
    try:
        from .intrinsic import name_sensitivity
        sens = name_sensitivity(template.replace("/", "."))
    except Exception:                                # noqa: BLE001
        sens = 0
    rank = declared_rank(role, role_model)
    write = method in ("POST", "PUT", "PATCH", "DELETE")
    if rank is None:
        return "medium"
    if rank <= 30 and (sens >= 6 or write):
        return "critical"
    if rank <= 70 and (sens >= 6 or write):
        return "high"
    if rank >= 90 and sens < 6 and not write:
        return "low"
    return "medium"


def plan(rm: RoleMatrix, surface=None, max_probes: int = _MAX_PROBES,
         enabled: bool = False) -> RoleMatrixResult:
    """Assemble the matrix and plan the reads that would fill it.

    DEFAULT OFF. Disabled, an empty result is returned and nothing is inspected.

    `surface` is layer B's `AggregatedSurface` (or any iterable of endpoint-like
    objects); it supplies the endpoints that EXIST but no role ever exercised.
    Without it the matrix covers only what traffic already touched.
    """
    res = RoleMatrixResult()
    if not enabled:
        return res

    roles = sorted(rm._roles)
    res.roles = [{"role": r, "source": rm._role_source.get(r, ""),
                  "declared_rank": declared_rank(r, rm.role_model)} for r in roles]
    res.excluded_principals = [{"principal": p, "reason": why}
                               for p, why in sorted(rm._excluded.items())]

    observed = {c.key: c for c in rm.cells()}
    cells = list(rm.cells())

    # ---- stage 1 completion: every (role x declared endpoint x verb) exists ----
    templates = _surface_templates(surface)
    for role in roles:
        for method, template in templates:
            key = f"{role}|{method} {template}"
            if key in observed:
                continue
            if len(cells) >= _MAX_CELLS:
                break
            cells.append(RoleMatrixCell(role=role, method=method, endpoint=template,
                                        decision=UNTESTED, source="surface",
                                        why_untested=WHY_NEVER_SEEN))

    cells.sort(key=lambda c: (c.role, c.method, c.endpoint))
    res.matrix = cells

    # ---- stage 3: gaps -------------------------------------------------------
    res.gaps = [(c, _severity(c.role, c.method, c.endpoint, rm.role_model))
                for c in cells if c.decision == UNTESTED]
    res.gaps.sort(key=lambda t: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[t[1]],
                                 t[0].key))

    # ---- stage 4: same role, same TEMPLATE, both outcomes --------------------
    # Reported honestly: on a per-object endpoint this is what correct ownership
    # looks like. It becomes a probe, never a contradiction claim.
    for c in cells:
        if c.decision != CONFLICT:
            continue
        per_object = "{" in c.endpoint
        res.contradictions.append({
            "role": c.role, "method": c.method, "endpoint": c.endpoint,
            "outcomes": {d: n for d, n in c.outcomes},
            "principals": list(c.principals_tested),
            "sample_paths": list(c.sample_paths),
            "resolved": False,
            "expected_under_ownership": per_object,
            "note": ("this endpoint takes an object id, so divergent outcomes for one "
                     "role are what per-object ownership looks like when it WORKS; "
                     "only Delta-state can tell that apart from a real inconsistency"
                     if per_object else
                     "no object id in this template, so one role receiving both "
                     "outcomes is not explained by ownership — worth a look"),
        })

    # ---- stage 5: a lower declared role reaching what a higher one cannot -----
    ranked = [(r, declared_rank(r, rm.role_model)) for r in roles]
    ranked = [(r, k) for r, k in ranked if k is not None]
    by_cell: dict = {}
    for c in cells:
        by_cell.setdefault((c.method, c.endpoint), {})[c.role] = c
    for (method, template), per_role in sorted(by_cell.items()):
        for low, lrank in ranked:
            lo = per_role.get(low)
            if lo is None or lo.decision != ALLOWED:
                continue
            for high, hrank in ranked:
                if hrank <= lrank:
                    continue
                hi = per_role.get(high)
                if hi is None or hi.decision != DENIED:
                    continue                  # no reference on the higher side
                lo.is_anomaly = True
                res.privilege_anomalies.append({
                    "method": method, "endpoint": template,
                    "lower_role": low, "lower_rank": lrank,
                    "higher_role": high, "higher_rank": hrank,
                    "lower_principals": list(lo.principals_tested),
                    "higher_principals": list(hi.principals_tested),
                    "resolved": False,
                    "note": (f"'{low}' (rank {lrank}) obtained a substantive object "
                             f"where '{high}' (rank {hrank}) was explicitly refused; "
                             f"both ranks come from the DECLARED ladder, and neither "
                             f"outcome is a verdict until Delta-state confirms it"),
                })

    # ---- stage 6: probes — reads only, budget-bounded -------------------------
    probes: list = []
    unplannable = 0
    for a in res.privilege_anomalies:
        if a["method"] not in PLANNABLE_METHODS:
            unplannable += 1
            continue
        probes.append(_probe("privilege_anomaly", a["lower_role"], a["method"],
                             a["endpoint"], 100,
                             f"'{a['lower_role']}' reached what '{a['higher_role']}' "
                             f"could not; re-read with another principal holding "
                             f"'{a['lower_role']}' to see whether the outcome repeats"))
    for c in res.contradictions:
        if c["method"] not in PLANNABLE_METHODS:
            unplannable += 1
            continue
        probes.append(_probe("conflict", c["role"], c["method"], c["endpoint"], 80,
                             "one role received both outcomes on this template; "
                             "re-read another object of the same type as the same "
                             "role to separate ownership from inconsistency"))
    for c, sev in res.gaps:
        if c.method not in PLANNABLE_METHODS:
            unplannable += 1
            continue
        probes.append(_probe("gap", c.role, c.method, c.endpoint,
                             {"critical": 60, "high": 40, "medium": 20, "low": 5}[sev],
                             f"{sev} gap: no principal holding '{c.role}' was ever "
                             f"observed on this endpoint"))

    probes = _dedup(probes)
    res.probes = probes[:max(0, int(max_probes))]
    truncated = len(probes) - len(res.probes)

    res.stats = {"roles": len(roles), "cells": len(cells),
                 "allowed": sum(1 for c in cells if c.decision == ALLOWED),
                 "denied": sum(1 for c in cells if c.decision == DENIED),
                 "untested": sum(1 for c in cells if c.decision == UNTESTED),
                 "conflict": sum(1 for c in cells if c.decision == CONFLICT),
                 "probes": len(res.probes)}

    res.notes.append("a cell is ALLOWED only when a success carried a SUBSTANTIVE "
                     "object; a bare 2xx proves nothing and leaves the cell UNTESTED")
    res.notes.append("every probe is a READ and a PLAN — it implies no verdict; "
                     "confirmation remains Delta-state only (RL3)")
    if unplannable:
        res.notes.append(f"{unplannable} cell(s) involve a mutating verb and were "
                         f"NOT planned; sweeping writes across a role matrix would "
                         f"destroy data, so they stay UNTESTED by design")
    if truncated:
        res.notes.append(f"{truncated} probe(s) dropped at the budget limit; those "
                         f"cells remain UNTESTED and were NOT guessed (RL6)")
    if rm._excluded:
        res.notes.append(f"{len(rm._excluded)} principal(s) excluded: no declared or "
                         f"observed role, and a role is never assigned by default")
    unranked = [r for r in roles if declared_rank(r, rm.role_model) is None]
    if unranked:
        res.notes.append("no declared rank for " + ", ".join(sorted(unranked)) +
                         " — these take part in no privilege comparison (fail-safe)")
    if not cells:
        res.notes.append("empty matrix — this is NOT evidence that no role can "
                         "reach anything")
    res.notes = sorted(set(res.notes))
    return res


def _probe(kind, role, method, endpoint, priority, why) -> dict:
    return {"kind": kind, "role": role, "method": method, "endpoint": endpoint,
            "priority": priority, "because": why,
            "confirmed_by": "Delta-state read-back in the existing confirmer"}


def _dedup(items: list) -> list:
    seen, out = set(), []
    for it in items:
        k = (it["kind"], it["role"], it["method"], it["endpoint"])
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    out.sort(key=lambda d: (-d["priority"], d["kind"], d["role"],
                            d["method"], d["endpoint"]))
    return out


def _surface_templates(surface) -> list:
    """(method, template) pairs from layer B, or any iterable of endpoint-likes.

    An item with no readable verb is skipped: opening a matrix column for a verb
    nobody declared would be inventing one. Multi-verb expansion is likewise NOT
    done — the matrix covers verbs that a source actually declared.
    """
    if surface is None:
        return []
    items = getattr(surface, "unified_surface", surface)
    out: set = set()
    try:
        iter(items)
    except TypeError:
        return []
    for e in items:
        try:
            method = (getattr(e, "method", None)
                      or (e.get("method") if isinstance(e, dict) else "")) or ""
            template = (getattr(e, "template", None) or getattr(e, "path", None)
                        or (e.get("template") or e.get("path")
                            if isinstance(e, dict) else "")) or ""
            method, template = str(method).upper(), str(template)
            if method in MATRIX_METHODS and template.startswith("/"):
                out.add((method, template))
        except Exception:                            # noqa: BLE001
            continue
    return sorted(out)


# --------------------------------------------------------------------------- #
# capture bridge                                                               #
# --------------------------------------------------------------------------- #

def role_matrix_from_har(har: dict, in_scope_hosts=None, surface=None,
                         declared_roles=None, role_model=None,
                         role_overrides=None, max_probes: int = _MAX_PROBES,
                         enabled: bool = False) -> RoleMatrixResult:
    """Build the matrix from a capture and plan the missing reads.

    DEFAULT OFF. Zero network — probes are DESCRIBED, never issued.
    """
    if not enabled:
        return RoleMatrixResult()
    from .harimport import parse_har_exchanges
    rm = RoleMatrix(role_model=role_model, role_overrides=role_overrides)
    rm.declare_roles(declared_roles or [], source="declared")
    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                                # noqa: BLE001
        exchanges = []
    for ex in exchanges:
        try:
            rm.observe(ex.request, ex.response, ex.principal)
        except Exception:                            # noqa: BLE001
            continue
    return plan(rm, surface=surface, max_probes=max_probes, enabled=True)
