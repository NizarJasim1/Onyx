#!/usr/bin/env python3
"""
graphql_surface.py — Phase 3 of the six-phase roadmap: REAL GraphQL SURFACE.

Giant targets expose GraphQL, and generic scanners barely test it — so object-authorization
bugs survive there. ONYX's engine already understands GraphQL (parse_graphql_request,
extract_variable_ids, contract_from_introspection), so this module does NOT reimplement any
verdict: it is a TRANSPORT ADAPTER that presents GraphQL node-by-id queries to the untouched
engine as object-access doors. The engine then confirms cross-owner reads by Δstate exactly as
it does for REST — over a surface REST tooling never reached.

HOW (zero engine change, zero new accept logic):
  1. INTROSPECT the endpoint (__schema) → node-by-id query fields (e.g. order(id:ID)), their
     id argument, scalar fields, and list fields that return owned ids.
  2. HARVEST each principal's OWN ids from list fields (ownership = disjoint per-principal sets,
     the same rule onyx_recon.harvest uses).
  3. The GraphQLTarget adapter maps a virtual object-access request `/__gql__/<field>/<id>` to a
     REAL `POST /graphql { query, variables:{id} }`, returning the node's fields as the response
     body. serve.run_engagement drives cross-principal probes over it → the engine's proven
     Δstate logic accepts/rejects. A GraphQL-native IARC re-confirmation (the doubled gate:
     reproducible + not-public + object-scoped, checked via GraphQL) drops any residual FP.

Guarantees: no invented ids (every id came from a real list response); cross-owner only
(the engine compares owner-distinguishing fields); reads only (queries, never mutations).
"""
from __future__ import annotations
import json, argparse, sys, os, re
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR
from authpath.models import HTTPRequest, HTTPResponse, Exchange, Principal
from authpath.scope_guard import ScopeConfig

_VDOOR = re.compile(r"^/__gql__/([^/]+)/(.+)$")

_INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { "
             "queryType { name } "
             "types { name kind fields { name args { name type { kind name ofType { kind name } } } "
             "type { kind name ofType { kind name ofType { kind name } } } } } } }"
}


# --------------------------------------------------------------------------- #
# low-level GraphQL POST                                                       #
# --------------------------------------------------------------------------- #
def _post(client, url, query, variables, token):
    import requests
    headers = {"Content-Type": "application/json",
               "User-Agent": client.ua if hasattr(client, "ua") else "ONYX-GraphQL/1.0"}
    if token:
        headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    r = requests.post(url, json={"query": query, "variables": variables or {}},
                      headers=headers, timeout=getattr(client, "timeout", 15),
                      verify=getattr(client, "verify", True))
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def _unwrap_type(t):
    """GraphQL type ref → (named_type, is_list). Drills through NON_NULL/LIST wrappers."""
    is_list = False
    while isinstance(t, dict):
        if t.get("kind") == "LIST":
            is_list = True
        if t.get("name"):
            return t["name"], is_list
        t = t.get("ofType")
    return None, is_list


def introspect(client, url, token):
    """Return {node_fields: {field: {id_arg, id_type, scalars}}, list_fields: {field: item_type}}."""
    _, body = _post(client, url, _INTROSPECTION["query"], {}, token)
    schema = ((body or {}).get("data") or {}).get("__schema") or {}
    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    # scalar fields per object type
    def scalars_of(type_name):
        t = types.get(type_name) or {}
        out = []
        for f in (t.get("fields") or []):
            named, _ = _unwrap_type(f.get("type"))
            if named in ("String", "Int", "Float", "Boolean", "ID") or (types.get(named, {}).get("kind") == "SCALAR"):
                out.append(f["name"])
        return out or ["id"]
    qtype = (schema.get("queryType") or {}).get("name")
    query_fields = (types.get(qtype, {}) or {}).get("fields") or []
    node_fields, list_fields = {}, {}
    for f in query_fields:
        named, is_list = _unwrap_type(f.get("type"))
        args = f.get("args") or []
        id_arg = next((a for a in args
                       if a["name"].lower() in ("id", f"{f['name'].lower()}id", "uuid", "oid")
                       or a["name"].lower().endswith("id")), None)
        if id_arg and not is_list and named in types:
            at, _ = _unwrap_type(id_arg.get("type"))
            node_fields[f["name"]] = {"id_arg": id_arg["name"], "id_type": at or "ID",
                                      "scalars": scalars_of(named), "type": named}
        elif is_list and named in types and not args:
            list_fields[f["name"]] = {"type": named, "scalars": scalars_of(named)}
    return {"node_fields": node_fields, "list_fields": list_fields}


# --------------------------------------------------------------------------- #
# harvest owned ids from list fields (disjointness ownership)                  #
# --------------------------------------------------------------------------- #
def harvest_gql(client, url, principals, list_fields):
    per = {}   # field -> pid -> set(ids)
    for field, meta in list_fields.items():
        q = f"query {{ {field} {{ {' '.join(meta['scalars'])} }} }}"
        for pid, tok in principals.items():
            _, body = _post(client, url, q, {}, tok)
            data = ((body or {}).get("data") or {}).get(field) or []
            ids = set()
            for node in (data if isinstance(data, list) else [data]):
                if isinstance(node, dict):
                    for k, v in node.items():
                        if k.lower() == "id" or k.lower().endswith("id"):
                            if isinstance(v, (str, int)):
                                ids.add(str(v))
            per.setdefault(field, {}).setdefault(pid, set()).update(ids)
    # per-id ownership: exactly one principal saw it
    id_owner = {}
    for field, pmap in per.items():
        for pid, s in pmap.items():
            for i in s:
                id_owner.setdefault(i, set()).add(pid)
    pool = {pid: [] for pid in principals}
    for i, owners in id_owner.items():
        if len(owners) == 1:
            p = next(iter(owners))
            if i not in pool[p]:
                pool[p].append(i)
    return pool


# --------------------------------------------------------------------------- #
# transport adapter: virtual object-access door → real GraphQL POST            #
# --------------------------------------------------------------------------- #
class GraphQLTarget:
    """Presents GraphQL node-by-id queries to the engine as REST object-access. .send() maps
    /__gql__/<field>/<id> to a real POST /graphql and returns the node's fields as the body."""
    def __init__(self, url, node_fields, scope, researcher="", verify=True, timeout=15):
        self.url = url
        self.node_fields = node_fields
        self.scope = scope
        self.ua = f"ONYX-GraphQL/1.0 (authorized-testing){'; ' + researcher if researcher else ''}"
        self.verify = verify
        self.timeout = timeout
        self.n = 0

    def _token(self, principal):
        return (principal.auth or {}).get("Authorization") if principal else None

    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse:
        m = _VDOOR.match(req.path or "")
        if not m:
            return HTTPResponse(status=404, body={})
        field, oid = m.group(1), m.group(2)
        meta = self.node_fields.get(field)
        if not meta:
            return HTTPResponse(status=404, body={})
        q = (f"query($v: {meta['id_type']}!){{ {field}({meta['id_arg']}: $v) "
             f"{{ {' '.join(meta['scalars'])} }} }}")
        self.n += 1
        status, body = _post(self, self.url, q, {"v": oid}, self._token(principal))
        node = ((body or {}).get("data") or {}).get(field)
        errs = (body or {}).get("errors")
        if isinstance(node, dict):
            return HTTPResponse(status=200, body=node)
        if errs and any("auth" in json.dumps(e).lower() or "forbid" in json.dumps(e).lower()
                        or "denied" in json.dumps(e).lower() for e in errs):
            return HTTPResponse(status=403, body={})
        return HTTPResponse(status=404, body={})


# --------------------------------------------------------------------------- #
# GraphQL-native IARC (the doubled gate, checked over GraphQL)                 #
# --------------------------------------------------------------------------- #
def _read_node(target, field, oid, principal, k=1):
    reads = []
    for _ in range(k):
        r = target.send(HTTPRequest(method="GET", path=f"/__gql__/{field}/{oid}"), principal)
        reads.append(r.body if (200 <= r.status < 300 and isinstance(r.body, dict)) else None)
    return reads


def gql_reconfirm(target, field, finding, principals, pool):
    """Independent re-confirmation over GraphQL. Drops ONLY on positive FP evidence."""
    A = str(finding.get("actor", "")); X = str(finding.get("target", ""))
    if A not in principals or not X:
        return True, "insufficient context"
    a_reads = _read_node(target, field, X, principals[A], k=2)
    if not a_reads[0] or not all(a_reads):
        return False, "not reproducible"
    stable = {kk: v for kk, v in a_reads[0].items() if all(r.get(kk) == v for r in a_reads)}
    substantive = {kk: v for kk, v in stable.items() if kk.split(".")[-1].lower() != "id" and v != X}
    if not substantive:
        return False, "no substantive field"
    anon = _read_node(target, field, X, Principal("anon", "anon", is_anonymous=True), k=1)
    if anon[0] and any(anon[0].get(kk) == v for kk, v in substantive.items()):
        return False, "public: anonymous reproduces"
    own = [i for i in (pool.get(A) or []) if str(i) != X]
    if own:
        o = _read_node(target, field, own[0], principals[A], k=1)
        if o[0] and {kk: o[0].get(kk) for kk in substantive} == substantive:
            return False, "server ignores id"
    return True, "independently re-confirmed over GraphQL"


# --------------------------------------------------------------------------- #
# orchestrate: introspect → harvest → probe via engine → GraphQL IARC          #
# --------------------------------------------------------------------------- #
def run_graphql(base_url, principals, *, graphql_path="/graphql", scope=None,
                researcher="", verify=True):
    from authpath import serve
    url = base_url.rstrip("/") + graphql_path
    host = urlparse(base_url).hostname
    scope = scope or [host]
    cli = OR.Client(scope, researcher=researcher, verify=verify)
    # introspect as the first principal
    first_tok = next(iter(principals.values()))
    schema = introspect(cli, url, first_tok)
    if not schema["node_fields"]:
        return {"confirmed": [], "raw": 0, "node_fields": [], "reason": "no node-by-id query fields"}
    pool = harvest_gql(cli, url, principals, schema["list_fields"])
    if sum(len(v) for v in pool.values()) == 0:
        return {"confirmed": [], "raw": 0, "node_fields": list(schema["node_fields"]),
                "reason": "no owned ids harvested"}

    target = GraphQLTarget(url, schema["node_fields"], scope, researcher=researcher, verify=verify)
    princ = {pid: Principal(pid, pid, auth={"Authorization": f"Bearer {tok}"})
             for pid, tok in principals.items()}
    # one virtual object-access endpoint per node field, ids = harvested owned pool
    endpoints = [{"method": "GET", "path": f"/__gql__/{field}/{{id}}", "effect": "object-access",
                  "ids": {pid: pool[pid][:6] for pid in princ if pool[pid]}}
                 for field in schema["node_fields"]]
    endpoints = [e for e in endpoints if e["ids"]]
    if not endpoints:
        return {"confirmed": [], "raw": 0, "node_fields": list(schema["node_fields"]),
                "reason": "no probeable endpoints"}

    eng, _ = serve.run_engagement(target, princ, host, dry_run=True, endpoints=endpoints,
                                  researcher=researcher, engagement_id="gql",
                                  contract={f"GET /__gql__/{f}/{{id}}": {"effect": "OBJECT_ACCESS",
                                            "critical_params": ["id"]} for f in schema["node_fields"]})
    raw = list(eng.findings)
    snap = eng.snapshot()
    # gate + GraphQL-IARC
    confirmed = []
    for fd in snap["findings"]:
        field = None
        mm = _VDOOR.match(str(fd.get("endpoint", "")).split(" ", 1)[-1].replace("{id}", str(fd.get("target", ""))))
        m2 = re.search(r"/__gql__/([^/]+)/", str(fd.get("endpoint", "")))
        field = m2.group(1) if m2 else None
        if not field or field not in schema["node_fields"]:
            continue
        if not OR._looks_like_id(fd.get("target", "")):
            continue
        ok, _why = gql_reconfirm(target, field, fd, princ, pool)
        if ok:
            fd = dict(fd); fd["surface"] = "graphql"
            confirmed.append(fd)
    return {"confirmed": confirmed, "raw": len(snap["findings"]),
            "node_fields": list(schema["node_fields"]), "pool": pool}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX GraphQL surface — introspect + confirm cross-owner node reads via the proven engine (zero new accept logic).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--graphql-path", default="/graphql")
    ap.add_argument("--scope"); ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized (you affirm scope + permission).")
    principals = {}
    for spec in args.principal:
        pid, tok = spec.split(":", 1); principals[pid.strip()] = tok.strip()
    if len(principals) < 2:
        sys.exit("need >=2 --principal PID:TOKEN")
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    res = run_graphql(args.base_url, principals, graphql_path=args.graphql_path,
                      scope=scope, researcher=args.researcher)
    print(f"node-fields={res.get('node_fields')}  raw={res['raw']}  CONFIRMED={len(res['confirmed'])}")
    for f in res["confirmed"]:
        print(f"  [CONFIRMED graphql] {f.get('actor')} -> {f.get('target')}  {f.get('endpoint')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
