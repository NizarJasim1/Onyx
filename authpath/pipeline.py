"""
INTEGRATION BRIDGE — turns a capture into inputs for discovery (problem 1) and the
N-principal matrix (problem 2), and unifies them into the scan pipeline:

        discover (expand contract)  ->  observe seed  ->  build matrix from
        OBSERVED legitimate accesses  ->  GET-only cross-principal probes  ->
        existing engine confirms each by Δstate.

Both expansions are OPT-IN and only widen WHAT is tested. Every verdict is still
the engine's Δstate confirmation, so the bridge cannot introduce a false positive.
"""
from __future__ import annotations

import re

_PARAM = re.compile(r"\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>")


def _template_to_regex(template: str):
    """Turn an endpoint TEMPLATE (/api/orders/{id}) into an anchored regex that
    captures each variable segment."""
    parts = []
    last = 0
    for m in _PARAM.finditer(template):
        parts.append(re.escape(template[last:m.start()]))
        parts.append(r"([^/]+)")
        last = m.end()
    parts.append(re.escape(template[last:]))
    return re.compile("^" + "".join(parts) + "$")


def _endpoint_template(key: str) -> tuple[str, str]:
    """'GET /api/orders/{id}' -> ('GET', '/api/orders/{id}')."""
    bits = key.split(None, 1)
    return (bits[0].upper(), bits[1]) if len(bits) == 2 else ("GET", key)


def match_template(method: str, concrete_path: str, contract: dict):
    """Find the contract template that matches a concrete request; return
    (template_key, [captured values]) or (None, [])."""
    for key in contract or {}:
        m, tmpl = _endpoint_template(key)
        if m != method.upper():
            continue
        rx = _template_to_regex(tmpl)
        got = rx.match(concrete_path)
        if got:
            return key, list(got.groups())
    return None, []


def observed_accesses(spec: dict, contract: dict) -> list:
    """Extract legitimate GET object-accesses from the spec's seed: who (owner_pid)
    legitimately read which object (object_id) on which endpoint (template)."""
    out = []
    for item in spec.get("seed", []):
        if (item.get("method", "GET").upper() != "GET"):
            continue
        path = item.get("path", "")
        key, vals = match_template("GET", path, contract)
        if not key or not vals:
            continue
        eff = (contract.get(key) or {}).get("effect", "")
        if eff != "OBJECT_ACCESS":
            continue
        out.append({"owner_pid": item["principal"], "method": "GET",
                    "endpoint": key, "path": path,
                    "object_id": vals[0]})            # first captured id
    return out


def ids_by_template(accesses: list) -> dict:
    """template -> [object ids] (for discovery.generate_probes)."""
    out = {}
    for a in accesses:
        _, tmpl = _endpoint_template(a["endpoint"])
        out.setdefault(tmpl, [])
        if a["object_id"] not in out[tmpl]:
            out[tmpl].append(a["object_id"])
    return out


def merge_contract(base: dict | None, discovered: dict) -> dict:
    """Merge a discovered contract into the spec's contract WITHOUT overriding any
    effect the user declared explicitly (user intent wins)."""
    merged = dict(base or {})
    for key, meta in (discovered or {}).items():
        merged.setdefault(key, meta)
    return merged
