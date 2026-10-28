#!/usr/bin/env python3
"""
explorer.py — Phase 2 of the six-phase roadmap: DEEP AUTHENTICATED REACH.

The whole system runs off a capture. A human browsing for a few minutes captures a sliver of
a giant app's surface, and the best bugs live on the endpoints and states nobody browsed. The
Explorer replaces "what a human happened to click" with "what the app actually exposes,
visited as EVERY principal": it crawls authenticated, read-only, scope-guarded, and emits a
HAR-shaped capture the Conductor consumes unchanged. More reach → more for the proven path to
confirm. It adds ZERO confirmation logic — it only produces a richer capture.

WHY THIS IS ZERO-FALSE-POSITIVE AND SAFE:
  * Read-only by default: GET only. It never issues a write, and it hard-skips destructive
    or session-ending paths (logout/delete/deactivate/…). It cannot change target state.
  * Scope-guarded: every request goes through onyx_recon.Client, which blocks off-scope hosts
    and attaches the researcher User-Agent. It honors a hard request budget and an inter-request
    delay (rate-limit friendly).
  * No fabrication: every capture entry is a REAL request/response the server returned. The
    Explorer discovers endpoints only from (a) the server's own responses (ids, reference
    links, pagination) and (b) an optional OpenAPI spec — it never invents paths.
  * It does NOT decide findings. The capture flows to the Conductor → the proven path decides.

WHAT IT DISCOVERS THAT A HUMAN CAPTURE MISSES:
  1. collection → item expansion: a list endpoint's ids become item reads, visited as every
     principal → surfaces cross-owner ids and allowed/denied decisions (BOLA/BFLA fuel).
  2. reference following: a response field that is a path or in-scope URL is a new endpoint.
  3. per-principal decision map: hitting each door as each principal records the authz rules
     (401/403 vs 200) that Layer 4 learns from.
"""
from __future__ import annotations
import json, argparse, sys, os, re
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR
import sitemodel as SM

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _is_id_segment(seg, known):
    """Stricter than sitemodel._is_id_value (which treats a plain word like 'orders' as an id
    and would make every collection look like an item). A path segment is an ITEM id only if
    it is numeric, a UUID, a digit-bearing token, or an id we've actually seen in a response."""
    return bool(seg) and (seg.isdigit() or bool(_UUID.match(seg))
                          or any(c.isdigit() for c in seg) or seg in known)

# paths whose mere GET could end a session or mutate/destroy — never visited
_DESTRUCTIVE = re.compile(
    r"(logout|signout|sign-out|log-out|/delete|/remove|/destroy|/deactivate|/disable|"
    r"/close|/cancel|/revoke|/reset|/purge|/wipe|/drop)", re.I)


def _is_ref(v):
    """A response value that names another endpoint: an absolute path or a URL."""
    if not isinstance(v, str) or len(v) > 512:
        return False
    return v.startswith("/") or bool(re.match(r"^https?://", v))


def _refs_in(obj, acc):
    if isinstance(obj, dict):
        for v in obj.values():
            _refs_in(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _refs_in(v, acc)
    elif _is_ref(obj):
        acc.add(obj)
    return acc


def _entry(method, url, token, status, body):
    """A HAR entry in exactly the shape sitemodel/normalize/conductor consume."""
    return {"request": {"method": method, "url": url,
            "headers": [{"name": "Authorization", "value": f"Bearer {token}"}]},
            "response": {"status": status, "content": {"text": json.dumps(body) if body is not None else ""}}}


def _item_templates_from(path):
    """A collection path → its likely item path (collection + /{id}). Kept as a concrete-id
    filler at crawl time; the model templatizes later."""
    return path.rstrip("/") + "/{id}"


def crawl(base_url, principals, *, scope=None, seeds=None, openapi=None, researcher="",
          max_requests=400, max_ids_per_collection=8, delay=(0.0, 0.0), insecure=False):
    """Authenticated, read-only BFS. Returns (har, stats)."""
    host = urlparse(base_url).hostname
    scope = scope or [host]
    cli = OR.Client(scope, researcher=researcher, verify=not insecure, delay=delay)
    base = base_url.rstrip("/")

    # seed frontier: explicit seeds + OpenAPI GET paths (collections first)
    frontier = list(seeds or [])
    if openapi:
        for raw, ops in (openapi.get("paths") or {}).items():
            if isinstance(ops, dict) and any(m.lower() == "get" for m in ops):
                frontier.append(raw)
    if not frontier:
        frontier = ["/"]

    entries = []
    visited = set()          # (concrete_path, pid) — concrete so each id is probed per principal
    budget = max_requests
    seen_paths = set()
    known_ids = set()        # every id seen in any response, to tell item paths from collections

    def enqueue(path):
        if path.startswith("http"):
            if not cli.in_scope(path):
                return
            path = urlparse(path).path
        if not path.startswith("/") or _DESTRUCTIVE.search(path):
            return
        if path not in seen_paths:
            seen_paths.add(path)
            frontier.append(path)

    while frontier and budget > 0:
        path = frontier.pop(0)
        if _DESTRUCTIVE.search(path):
            continue
        for pid, tok in principals.items():
            if budget <= 0:
                break
            if (path, pid) in visited:           # per CONCRETE path × principal (cross-owner probing)
                continue
            visited.add((path, pid))
            url = base + path
            if not cli.in_scope(url):
                continue
            try:
                r = cli.req("GET", url, token=tok)
            except Exception:
                continue
            budget -= 1
            try:
                body = r.json()
            except Exception:
                body = None
            entries.append(_entry("GET", url, tok, r.status_code, body))
            if body is None or not (200 <= r.status_code < 300):
                continue
            found = _collect_ids(body)
            known_ids.update(found)
            # (1) collection → item expansion — ONLY for a collection path (its last segment is
            # not itself an item id). Expanding an item path would recurse forever
            # (…/orders/1001/1001/…), so items are read but never re-expanded.
            last = [s for s in path.split("/") if s]
            is_collection = not (last and _is_id_segment(last[-1], known_ids))
            if is_collection and found:
                item = _item_templates_from(path)
                for i in list(found)[:max_ids_per_collection]:
                    enqueue(item.replace("{id}", str(i)))
            # (2) reference following
            for ref in _refs_in(body, set()):
                enqueue(ref)
            # (3) pagination
            nxt = _next_url(body)
            if nxt:
                enqueue(nxt)

    stats = {"requests": len(entries), "endpoints": len({SM.templatize_path(urlparse(e['request']['url']).path) for e in entries}),
             "principals": list(principals), "budget_left": budget}
    return {"log": {"entries": entries}}, stats


def _collect_ids(body):
    acc = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif SM._is_id_value(v):
                    acc.add(str(v))
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(body)
    return acc


def _next_url(body):
    if isinstance(body, dict):
        for k in ("next", "next_url", "nextPage", "next_page"):
            v = body.get(k)
            if isinstance(v, str) and v:
                return v
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX Explorer — authenticated read-only reach crawler (produces a capture; confirms nothing).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--openapi"); ap.add_argument("--scope"); ap.add_argument("--tokens")
    ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--seed", action="append", default=[], help="seed path (repeatable)")
    ap.add_argument("--max-requests", type=int, default=400)
    ap.add_argument("--researcher", default=""); ap.add_argument("--out", required=True,
                    help="write the discovered HAR here (feed it to conductor.py --har)")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized (you affirm scope + permission).")
    principals = {}
    for spec in args.principal:
        pid, tok = spec.split(":", 1); principals[pid.strip()] = tok.strip()
    if len(principals) < 2:
        sys.exit("need >=2 --principal PID:TOKEN")
    spec = json.load(open(args.openapi)) if args.openapi else None
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    har, stats = crawl(args.base_url, principals, scope=scope, seeds=args.seed, openapi=spec,
                       researcher=args.researcher, max_requests=args.max_requests)
    json.dump(har, open(args.out, "w"), indent=2)
    print(f"explorer: {stats['requests']} requests · {stats['endpoints']} endpoints discovered "
          f"· principals={stats['principals']} · budget_left={stats['budget_left']}")
    print(f"[capture → {args.out}]  next: conductor.py --har {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
