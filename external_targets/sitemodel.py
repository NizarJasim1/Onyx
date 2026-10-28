#!/usr/bin/env python3
"""
sitemodel.py — LAYER 1 of the ONYX deep-recon system (DEEP build).

Builds a rich Object-Relation-Authority model of a target from captured traffic (HAR)
and/or an OpenAPI spec, and emits a high-signal report a reasoning agent (the analyst) can
use to locate deep authorization / business-logic flaws — while ONYX proves them.

ZERO-FALSE-POSITIVE CONTRACT (structural, not a promise):
  * READ-ONLY ANALYSIS. Never sends a probe, never emits a finding, never imports or
    touches the detection path (onyx_recon / serve / engine). It maps; it does not judge.
    Therefore it cannot change any accept/reject decision — it cannot add a false positive.
  * Every FACT rests on an external signal present in the captured data (a field equals
    another object's id; a value differs by owner; the server allowed X but denied Y).
    Name-based guesses (PII hints) are a separate, clearly-labelled tier — never mixed in.

Dual output: a compact Markdown brief (for the analyst) and a full JSON model (for Layers 2-4).
"""
from __future__ import annotations
import json, re, argparse, sys
from collections import defaultdict
from urllib.parse import urlparse

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{8,}$")
_INT = re.compile(r"^[0-9]{1,19}$")
_HEXY = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
_ID_KEYS = ("id", "uuid", "guid", "_id")
_PII_HINT = ("email", "phone", "mobile", "ssn", "vin", "card", "iban", "address",
             "name", "dob", "token", "secret", "password", "pin", "credit", "balance")


def templatize_path(path):
    out = []
    for seg in (path or "").split("/"):
        out.append("{id}" if (_INT.match(seg) or _UUID.match(seg) or _HEXY.match(seg)) else seg)
    return "/".join(out) or "/"


def _is_id_value(v):
    if isinstance(v, bool) or v is None:
        return False
    s = str(v)
    if " " in s or "\t" in s or "@" in s:
        return False
    return bool(_INT.match(s) or _UUID.match(s) or _HEXY.match(s) or _TOKEN.match(s))


def _scalars(obj):
    return {str(k): v for k, v in obj.items()
            if isinstance(v, (str, int, float)) and not isinstance(v, bool)}


def _fingerprint(obj):
    return ",".join(sorted(str(k) for k in obj.keys()))


def _looks_like_object(d):
    return isinstance(d, dict) and any(
        k.lower() in _ID_KEYS or k.lower().endswith("_id") or k.lower().endswith("id")
        for k in d.keys())


def _op_of(method):
    m = (method or "GET").upper()
    return {"GET": "read", "POST": "create", "PUT": "update",
            "PATCH": "update", "DELETE": "delete"}.get(m, m.lower())


class SiteModel:
    def __init__(self):
        self.objects = {}
        self.types = defaultdict(lambda: {"count": 0, "owners": set(), "fingerprints": set(),
                                          "fields": set(), "pii_hints": set(), "ops": set(),
                                          "methods": set()})
        self.field_obs = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        self.references = []
        self.decisions = defaultdict(lambda: {"ok": set(), "denied": set()})
        self._id_index = {}
        self.endpoints = {}

    def _own(self, otype, oid, owner, obj, method):
        key = f"{otype}|{oid}"
        rec = self.objects.get(key)
        if not rec:
            rec = {"type": otype, "id": str(oid) if oid is not None else None,
                   "owners": set(), "fields": {}}
            self.objects[key] = rec
        rec["owners"].add(owner)
        sc = _scalars(obj)
        rec["fields"].update(sc)
        t = self.types[otype]
        t["count"] += 1; t["owners"].add(owner); t["fingerprints"].add(_fingerprint(obj))
        t["ops"].add(_op_of(method)); t["methods"].add((method or "GET").upper())
        for k, v in sc.items():
            t["fields"].add(k)
            if any(h in k.lower() for h in _PII_HINT):
                t["pii_hints"].add(k)
            self.field_obs[otype][k][owner].add(str(v))
        if oid is not None:
            self._id_index[str(oid)] = (otype, owner)

    def _walk(self, node, path_type, owner, method):
        if isinstance(node, dict):
            if _looks_like_object(node):
                oid = None
                for k, v in node.items():
                    if k.lower() in _ID_KEYS and _is_id_value(v):
                        oid = v; break
                otype = path_type or ("struct:" + _fingerprint(node))
                self._own(otype, oid, owner, node, method)
            for v in node.values():
                self._walk(v, path_type, owner, method)
        elif isinstance(node, list):
            for v in node:
                self._walk(v, path_type, owner, method)

    def ingest_entry(self, method, url, status, body, owner):
        pattern = templatize_path(urlparse(url).path)
        key = f"{(method or 'GET').upper()} {pattern}"
        self.endpoints.setdefault(key, {"source": "har", "params": []})
        if isinstance(status, int):
            if 200 <= status < 300:
                self.decisions[key]["ok"].add(owner)
            elif status in (401, 403) or 400 <= status < 500:
                self.decisions[key]["denied"].add(owner)
        data = None
        if isinstance(body, str) and body.strip():
            try:
                data = json.loads(body)
            except ValueError:
                data = None
        elif isinstance(body, (dict, list)):
            data = body
        if data is not None:
            self._walk(data, pattern, owner, method)

    def ingest_openapi(self, doc):
        for raw, ops in (doc.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            pattern = templatize_path(raw)
            for method, op in ops.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                key = f"{method.upper()} {pattern}"
                params = [p.get("name") for p in ((op or {}).get("parameters") or [])
                          if isinstance(p, dict)]
                self.endpoints.setdefault(key, {"source": "openapi", "params": params})
                _ = self.types[pattern]

    def build(self):
        self._relations()
        return self

    def _relations(self):
        self.references.clear()
        for rec in self.objects.values():
            owner = next(iter(rec["owners"]), None)
            for field, val in rec["fields"].items():
                fl = field.lower()
                if fl == "id" or fl in _ID_KEYS:
                    continue
                if not _is_id_value(val):
                    continue
                ref = self._id_index.get(str(val))
                if not ref or (ref[0] == rec["type"] and str(val) == rec["id"]):
                    continue
                to_type, to_owner = ref
                self.references.append({
                    "from_type": rec["type"], "from_id": rec["id"], "from_owner": owner,
                    "field": field, "to_type": to_type, "to_id": str(val),
                    "to_owner": to_owner,
                    "cross_ownership": bool(owner and to_owner and owner != to_owner)})

    def _owner_distinguishing(self, otype):
        out = []
        for field, per_owner in self.field_obs.get(otype, {}).items():
            if field.lower() in _ID_KEYS or field.lower() == "id":
                continue
            owners = [o for o in per_owner if o != "anon"]
            if len(owners) < 2:
                continue
            vals = [per_owner[o] for o in owners]
            common = set.intersection(*vals) if vals else set()
            if not common:
                out.append(field)
        return out

    def _chains(self, max_depth=4, max_out=20):
        adj = defaultdict(list)
        for r in self.references:
            adj[(r["from_type"], r["from_id"])].append(r)
        chains = []
        for start in list(adj.keys()):
            stack = [(start, [], {start})]
            while stack and len(chains) < max_out * 4:
                node, path, seen = stack.pop()
                for r in adj.get(node, []):
                    nxt = (r["to_type"], r["to_id"])
                    npath = path + [r]
                    if len(npath) >= 2 and any(e["cross_ownership"] for e in npath):
                        chains.append(npath)
                    if len(npath) < max_depth and nxt not in seen:
                        stack.append((nxt, npath, seen | {nxt}))
        uniq, sig = [], set()
        for c in sorted(chains, key=len, reverse=True):
            k = tuple((e["from_type"], e["field"], e["to_type"]) for e in c)
            if k not in sig:
                sig.add(k); uniq.append(c)
        return uniq[:max_out]

    def _roles(self):
        privileged = defaultdict(int); principals = set()
        for key, d in self.decisions.items():
            principals |= d["ok"] | d["denied"]
            if d["ok"] and d["denied"] and not (d["ok"] & d["denied"]):
                for p in d["ok"]:
                    privileged[p] += 1
        principals.discard("anon")
        ranking = sorted(((p, privileged.get(p, 0)) for p in principals), key=lambda x: -x[1])
        admin_like = ranking[0][0] if ranking and ranking[0][1] > 0 else None
        return {"ranking": ranking, "admin_like": admin_like}

    def report(self):
        cross = [dict(r) for r in self.references if r["cross_ownership"]]
        for r in cross:
            r["score"] = 90
        chains = self._chains()
        roles = self._roles()
        decision_points = [
            {"endpoint": k, "allowed_for": sorted(d["ok"]), "denied_for": sorted(d["denied"]), "score": 80}
            for k, d in self.decisions.items()
            if d["ok"] and d["denied"] and not (d["ok"] & d["denied"])]
        type_rows = []
        for ot, t in sorted(self.types.items()):
            type_rows.append({
                "type": ot, "instances": t["count"],
                "owners": sorted(o for o in t["owners"] if o != "anon"),
                "operations": sorted(t["ops"]), "shapes": len(t["fingerprints"]),
                "owner_distinguishing_fields": self._owner_distinguishing(ot),
                "pii_hint_fields": sorted(t["pii_hints"])})
        chain_rows = []
        for c in chains:
            hops = " ".join([f"{c[0]['from_type']}({c[0]['from_owner']})"] +
                            [f".{e['field']}->{e['to_type']}({e['to_owner']})" for e in c])
            chain_rows.append({"hops": hops, "length": len(c), "score": 95 + len(c),
                               "crosses": sum(1 for e in c if e["cross_ownership"])})
        attention = []
        for r in cross:
            attention.append((r["score"], "cross-ownership",
                              f"{r['from_type']}({r['from_owner']}).{r['field']} -> "
                              f"{r['to_type']}({r['to_owner']})"))
        for c in chain_rows:
            attention.append((c["score"], "authority-inheritance chain", c["hops"]))
        for d in decision_points:
            attention.append((d["score"], "decision point (rule exists)",
                              f"{d['endpoint']} allowed={d['allowed_for']} denied={d['denied_for']}"))
        if roles["admin_like"]:
            attention.append((85, "role", f"principal '{roles['admin_like']}' looks privileged"))
        attention.sort(key=lambda x: -x[0])
        return {
            "counts": {"objects": len(self.objects), "types": len(self.types),
                       "endpoints": len(self.endpoints), "references": len(self.references),
                       "cross_ownership": len(cross), "chains": len(chain_rows),
                       "decision_points": len(decision_points)},
            "roles": roles, "object_types": type_rows,
            "cross_ownership_relations": cross,
            "authority_inheritance_chains": chain_rows,
            "decision_points": decision_points,
            "attention_list": [{"score": s, "kind": k, "detail": d} for s, k, d in attention]}


def _principal_of(headers, token_map):
    hv = cv = ""
    for h in headers or []:
        if isinstance(h, dict):
            n = h.get("name", "").lower()
            if n == "authorization":
                hv = h.get("value", "")
            elif n == "cookie":
                cv = h.get("value", "")
    for token, label in (token_map or {}).items():
        if token and (token in hv or token in cv):
            return label
    return "anon"


def from_sources(har=None, openapi=None, token_map=None):
    m = SiteModel()
    if openapi:
        m.ingest_openapi(openapi)
    if har:
        for e in ((har.get("log") or {}).get("entries") or []):
            req = e.get("request") or {}; resp = e.get("response") or {}
            body = ((resp.get("content") or {}).get("text")) or ""
            m.ingest_entry(req.get("method", "GET"), req.get("url", ""), resp.get("status", 0),
                           body, _principal_of(req.get("headers"), token_map))
    return m.build()


def render_markdown(rep):
    L = ["# ONYX site model - Layer 1 (objects, relations, authority)\n",
         f"objects={rep['counts']['objects']}  types={rep['counts']['types']}  "
         f"endpoints={rep['counts']['endpoints']}  cross-ownership={rep['counts']['cross_ownership']}  "
         f"chains={rep['counts']['chains']}  decision-points={rep['counts']['decision_points']}\n"]
    if rep["roles"]["admin_like"]:
        L.append(f"**Likely privileged principal:** `{rep['roles']['admin_like']}` "
                 f"(ranking: {rep['roles']['ranking']})\n")
    L.append("## Attention list (highest-signal seams first)")
    for a in rep["attention_list"][:25]:
        L.append(f"- **[{a['score']}] {a['kind']}** - {a['detail']}")
    L.append("\n## Object types")
    for t in rep["object_types"]:
        s = f"  owner-distinguishing={t['owner_distinguishing_fields']}" if t["owner_distinguishing_fields"] else ""
        L.append(f"- `{t['type']}` x{t['instances']}  ops={t['operations']}  owners={t['owners']}{s}")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX Layer-1 site model (read-only; zero-FP by construction).")
    ap.add_argument("--har"); ap.add_argument("--openapi"); ap.add_argument("--tokens")
    ap.add_argument("--out"); ap.add_argument("positional", nargs="?")
    args = ap.parse_args(argv)
    har_path = args.har or args.positional
    if not har_path and not args.openapi:
        ap.error("give --har <file> and/or --openapi <file>")
    har = json.load(open(har_path)) if har_path else None
    spec = json.load(open(args.openapi)) if args.openapi else None
    token_map = json.loads(args.tokens) if args.tokens else None
    rep = from_sources(har=har, openapi=spec, token_map=token_map).report()
    print(render_markdown(rep))
    if args.out:
        json.dump(rep, open(args.out, "w"), indent=2, default=list)
        print(f"\n[full JSON model written to {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
