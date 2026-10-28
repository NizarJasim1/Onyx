"""
AuthPath v3 — command-line interface.

  python -m authpath serve        # launch the control center (dashboard)
  python -m authpath demo         # run the labeled calibration to the console
  python -m authpath scan SPEC    # run a real scan from a traffic spec (JSON)

The `scan` command targets a LIVE authorised host via HTTPTarget so the confirmer
can perform genuine Δstate read-backs. SPEC schema (JSON):

  {
    "base_url": "https://api.target.com",
    "scope":   {"allowed_hosts":["api.target.com"], "dry_run":true,
                "automation_permitted":true, "allow_destructive":false},
    "principals": [
       {"pid":"A","label":"victim","auth":{"Authorization":"Bearer ..."}},
       {"pid":"B","label":"attacker","auth":{"Authorization":"Bearer ..."}},
       {"pid":"anon","label":"anon","auth":{},"is_anonymous":true}
    ],
    "contract": {"GET /api/orders/{id}": {"effect":"OBJECT_ACCESS"}, ...},
    "seed":  [{"principal":"A","method":"GET","path":"/api/orders/101"}, ...],
    "probe": [{"principal":"B","method":"GET","path":"/api/orders/101"}, ...]
  }

Only ever run `scan` within a program's authorised scope and rules.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .engine import AuthPathEngine
from .models import HTTPRequest, Principal
from .scope_guard import ScopeConfig
from .transport import HTTPTarget, make_exchange


def _cmd_serve(a):
    from .serve import serve
    serve(a.host, a.port, open_browser=not a.no_open)


def _cmd_demo(a):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from tests.test_calibration import __file__ as _  # noqa
    import runpy
    runpy.run_path(os.path.join(root, "tests", "test_calibration.py"), run_name="__main__")


def _principals(spec) -> dict[str, Principal]:
    out = {}
    for p in spec["principals"]:
        out[p["pid"]] = Principal(p["pid"], p.get("label", p["pid"]),
                                  p.get("auth", p.get("headers", {})),
                                  p.get("is_anonymous", p.get("anonymous", False)),
                                  profile_headers=p.get("profile_headers", {}))
    return out


def _req(item, host) -> HTTPRequest:
    return HTTPRequest(item["method"], item["path"], item.get("query", {}),
                       item.get("headers", {}), item.get("body"), host=host)


def _cmd_scan(a):
    spec = json.load(open(a.spec))
    base = spec["base_url"]
    host = base.split("://", 1)[-1].split("/", 1)[0]
    principals = _principals(spec)
    scope = ScopeConfig(**{**{"allowed_hosts": [host]}, **spec.get("scope", {})})
    target = HTTPTarget(base, verify_tls=not a.insecure, scope=scope)

    # PROBLEM 1: optionally EXPAND the contract from a discovery doc (OpenAPI /
    # GraphQL introspection). Only widens what is tested; user-declared effects win.
    contract = spec.get("contract") or {}
    if getattr(a, "discover", None):
        from . import discovery as _disc, pipeline as _pipe
        import json as _json
        doc = _json.load(open(a.discover))
        eps = (_disc.parse_graphql_introspection(doc.get("data", doc))
               if getattr(a, "discover_graphql", False) else _disc.parse_openapi(doc))
        discovered = _disc.build_contract(eps)
        before = len(contract)
        contract = _pipe.merge_contract(contract, discovered)
        print(f"  discovery: +{len(contract) - before} endpoint(s) into the contract "
              f"({_disc.summarize(eps)['object_access_GET']} object-access GETs)")
    engine = AuthPathEngine(target, principals, scope, contract)
    # opt-in: both detection nerves + raw-exchange capture for the diagnostics export.
    if getattr(a, "export", None):
        engine.nerve = True
        engine.bva = True
        engine.capture = []

    seed_items = spec.get("seed", [])
    for item in seed_items:
        ex = make_exchange(target, _req(item, host), principals[item["principal"]])
        engine.observe(ex)

    # OBSTACLE-3: per-principal benign GET paths (the principal's OWN captured
    # legitimate traffic) used as verdict-neutral session warm-up before probes.
    warmup_n = getattr(scope, "session_warmup", 0)
    benign_by_pid = {}
    if warmup_n:
        for it in seed_items:
            if (it.get("method", "GET").upper() == "GET"):
                benign_by_pid.setdefault(it["principal"], []).append(it["path"])

    probe_items = list(spec.get("probe", []))

    # PROBLEM 2: optionally AUTO-GENERATE the N-principal probe matrix from the
    # legitimate accesses just observed. GET-only, owner-excluded, Δstate-gated.
    if getattr(scope, "auto_matrix", False):
        from . import pipeline as _pipe, matrix as _mtx
        accesses = _pipe.observed_accesses(spec, contract)
        pairs = _mtx.build_matrix(accesses, principals,
                                  max_pairs=getattr(scope, "matrix_max_pairs", 500))
        added = _mtx.to_probe_items(pairs)
        probe_items.extend(added)
        summ = _mtx.summarize(pairs)
        print(f"  matrix: +{summ['total_pairs']} cross-principal probe(s) "
              f"({summ['horizontal']} horizontal, {summ['vertical']} vertical) "
              f"across {summ['objects_covered']} object(s)")

    for item in probe_items:
        pid = item["principal"]
        if warmup_n and benign_by_pid.get(pid):
            # shape the footprint into a session; never analysed, never observed.
            target.warmup(principals[pid], benign_by_pid[pid][:warmup_n])
        ex = make_exchange(target, _req(item, host), principals[pid])
        # SENTINEL S1: isolate per-exchange failures against a real target.
        try:
            engine.analyze(ex)
        except Exception as exc:               # noqa: BLE001
            engine._pass_errors += 1
            print(f"  [analyze-error] {item.get('path','?')}: "
                  f"{type(exc).__name__}: {str(exc)[:120]} (skipped, run continues)")

    # OBSTACLE-5: run declarative multi-step business-logic chains (opt-in).
    chain_results = []
    if spec.get("chains"):
        from .chains import run_chains
        chain_results = run_chains(engine, target, engine.scope_guard, principals, spec, host)
        for cr in chain_results:
            tag = ("BREACH" if cr.invariant_breached else
                   ("ABORTED" if cr.aborted else "ok"))
            print(f"  chain '{cr.name}': {tag}"
                  + (f" — {cr.aborted}" if cr.aborted else "")
                  + (f" — {cr.evidence}" if cr.invariant_breached else ""))

    c = engine._counts()
    print(f"\nanalyzed={c['analyzed']}  findings={c['findings']}  "
          f"Δstate-dropped={c['candidates_dropped']}  clean={c['clean']}\n")
    # SENTINEL S1/S4: report coverage gaps HONESTLY — a non-zero count means some
    # exchanges hit an unexpected condition and were not fully analysed, so the
    # operator never mistakes incomplete coverage for a clean result.
    if getattr(engine, "_pass_errors", 0):
        print(f"  ⚠ coverage gaps: {engine._pass_errors} pass error(s) on real responses "
              f"— those exchanges were NOT fully analysed (not counted as clean)\n")
    for f in engine.findings:
        print(f"  {f.fid}  [{f.severity.value}]  {f.title}  ({f.classification.endpoint})")
    if a.out and engine.findings:
        os.makedirs(a.out, exist_ok=True)
        for f in engine.findings:
            with open(os.path.join(a.out, f"{f.fid}.md"), "w") as fh:
                fh.write(f.report_markdown)
        print(f"\nreports written to {a.out}/")

    if getattr(a, "export", None):
        from .diag_export import build_export, to_json_bytes
        export = build_export(engine, getattr(engine, "capture", []), scope=scope,
                              meta={"tool": "ONYX/AuthPath", "command": "scan",
                                    "spec": a.spec})
        with open(a.export, "wb") as fh:
            fh.write(to_json_bytes(export))
        print(f"\n✓ diagnostics exported → {a.export}")
        print(f"  ({export['run']['exchange_count']} raw exchanges · nerve reach: "
              f"{export['metrics']['nerve'].get('reach_note','n/a')})")
        print("  secrets redacted, PII hashed — safe to share for diagnosis.")


def _cmd_import_har(a):
    from .harimport import parse_har, to_spec
    har = json.load(open(a.har))
    hosts = a.scope.split(",") if a.scope else None
    result = parse_har(har, hosts)
    spec = to_spec(result, redact=not a.keep_tokens)
    out = a.out or "spec.json"
    with open(out, "w") as fh:
        json.dump(spec, fh, indent=2)
    print(f"\nimported {len(result.requests)} in-scope request(s) → {out}")
    print(f"principals detected: {', '.join(result.principals)}")
    if result.skipped_hosts:
        top = sorted(result.skipped_hosts.items(), key=lambda x: -x[1])[:5]
        print("out-of-scope hosts skipped: "
              + ", ".join(f"{h}({c})" for h, c in top))
    if result.pairs:
        print(f"\n⚑ {len(result.pairs)} high-value cross-principal object pair(s):")
        for p in result.pairs[:8]:
            print(f"   object {p['object_id']} touched by {p['principals']}")
    for n in result.notes:
        print(f"\n!  {n}")
    if not a.keep_tokens:
        print("\ntokens redacted to $TOKEN_<pid> placeholders — replace before scanning.")


def _cmd_ingest(a):
    """Analyse a HAR capture FULLY OFFLINE (no live target): findings where the
    capture corroborates them + ranked reference-free leads."""
    from .harimport import ingest_har
    har = json.load(open(a.har))
    hosts = a.scope.split(",") if a.scope else None
    host = hosts[0] if hosts else "*"
    scope = ScopeConfig(allowed_hosts=([host] if host != "*" else []),
                        automation_permitted=True, dry_run=True)
    engine = ingest_har(har, scope, in_scope_hosts=hosts,
                        provisional=not a.no_provisional)
    snap = engine.snapshot()
    c = snap["counts"]
    print(f"\noffline HAR analysis — analyzed={c['analyzed']}  findings={c['findings']}  "
          f"leads={c['leads']}  Δstate-dropped={c['candidates_dropped']}\n")
    for f in engine.findings:
        print(f"  {f.fid}  [{f.severity.value}]  {f.title}  ({f.classification.endpoint})")
    if snap["leads"]:
        print(f"\n  leads ({len(snap['leads'])}, ranked):")
        for L in sorted(snap["leads"], key=lambda d: -d["weight"])[:20]:
            print(f"   [{L['confidence']:16}] {L['kind']:22} {L['paths']}  ({L['family']})")
    if a.out and engine.findings:
        os.makedirs(a.out, exist_ok=True)
        for f in engine.findings:
            with open(os.path.join(a.out, f"{f.fid}.md"), "w") as fh:
                fh.write(f.report_markdown)
        print(f"\nreports written to {a.out}/")


def _cmd_diagnostics(a):
    import json
    from .diagnostics import run_self_diagnostics
    rep = run_self_diagnostics(perf=not a.no_perf)
    blob = json.dumps(rep, indent=2, ensure_ascii=False)
    if getattr(a, "out", None):
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(blob)
        r = rep["run"]; sel = rep["selectivity"]
        print(f"diagnostics → {a.out}")
        print(f"  analyzed={r['analyzed']} findings={r['findings']} leads={r['leads']} "
              f"Δ-dropped={r['candidates_dropped']}")
        print(f"  Δstate selectivity: confirm={sel['confirm_rate_pct']}% "
              f"drop={sel['drop_rate_pct']}% · reported FP={sel['reported_false_positives']}")
        print(f"  effect-class coverage: {rep['detectors']['coverage_pct']}%")
    else:
        print(blob)


def _cmd_classify(a):
    import json as _json
    from . import surface_intel as _si
    cap = _json.load(open(a.capture))
    verdict = _si.classify_surface(
        request_headers=cap.get("request_headers"),
        response_headers=cap.get("response_headers"),
        response_body=cap.get("response_body"),
        content_type=cap.get("content_type", ""),
        probe_portable=cap.get("probe_portable"))
    rep = _si.report(verdict)
    print(f"surface reach: {rep['reach']}  (token={rep['token_binding']}, channel={rep['channel']})")
    for r in rep["reasons"]:
        print(f"   - {r}")
    print(f"recommendation: {rep['recommendation']}")
    print(f"caveat: {rep['caveat']}")
    return rep


def _cmd_discover(a):
    import json as _json
    from . import discovery as _disc
    with open(a.doc) as fh:
        doc = _json.load(fh)
    if a.graphql:
        schema = doc.get("data", doc) if isinstance(doc, dict) else doc
        eps = _disc.parse_graphql_introspection(schema)
    else:
        eps = _disc.parse_openapi(doc)
    contract = _disc.build_contract(eps)
    summary = _disc.summarize(eps)
    print(f"discovered {summary['total']} endpoint(s); "
          f"{summary['object_access_GET']} object-access GET(s) — prime IDOR surface")
    for key in summary["top_idor_candidates"]:
        print(f"   [IDOR-candidate] {key}")
    out = {"contract": contract,
           "endpoints": [{"method": e.method, "path": e.path, "effect": e.effect,
                          "idor_score": e.idor_score, "source": e.source} for e in eps],
           "summary": summary}
    if a.out:
        with open(a.out, "w") as fh:
            _json.dump(out, fh, indent=2)
        print(f"contract + candidates written to {a.out} — feed the contract into a scan spec")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="authpath", description="ONYX: deterministic black-box authorization testing")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="launch the control center dashboard")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8787)
    s.add_argument("--no-open", action="store_true"); s.set_defaults(fn=_cmd_serve)

    d = sub.add_parser("demo", help="run the labeled calibration to the console")
    d.set_defaults(fn=_cmd_demo)

    sc = sub.add_parser("scan", help="run a real scan from a traffic spec (JSON)")
    sc.add_argument("--discover", help="OpenAPI/Swagger or GraphQL-introspection JSON "
                                       "to expand the tested contract")
    sc.add_argument("--discover-graphql", action="store_true",
                    help="treat --discover input as a GraphQL introspection result")
    sc.add_argument("spec"); sc.add_argument("--out", help="write finding reports to this dir")
    sc.add_argument("--insecure", action="store_true", help="skip TLS verification")
    sc.add_argument("--export", metavar="FILE", help="write a full diagnostics export "
                    "(metrics + nerve self-diagnosis + every raw exchange, secrets "
                    "redacted / PII hashed) to FILE — the file to send back for analysis")
    sc.set_defaults(fn=_cmd_scan)

    ih = sub.add_parser("import-har",
                        help="convert a Burp/DevTools HAR capture into an ONYX spec.json")
    ih.add_argument("har", help="path to the .har capture file")
    ih.add_argument("--scope", help="comma-separated in-scope hosts "
                                     "(default: most frequent host in capture)")
    ih.add_argument("--out", help="output spec path (default: spec.json)")
    ih.add_argument("--keep-tokens", action="store_true",
                    help="do NOT redact live credentials (unsafe — needed only "
                         "if you scan immediately from this file)")
    ih.set_defaults(fn=_cmd_import_har)

    ig = sub.add_parser("ingest",
                        help="analyse a HAR capture FULLY OFFLINE (no live target)")
    ig.add_argument("har", help="path to the .har capture file")
    ig.add_argument("--scope", help="comma-separated in-scope hosts "
                                    "(default: most frequent host in capture)")
    ig.add_argument("--out", help="write finding reports to this dir")
    ig.add_argument("--no-provisional", action="store_true",
                    help="suppress lead-only hints from single-observation grammars")
    ig.set_defaults(fn=_cmd_ingest)

    dg = sub.add_parser("diagnostics",
                        help="emit a read-only statistics report (for export/sharing)")
    dg.add_argument("--out", help="write the JSON report to this path "
                                  "(default: print to stdout)")
    dg.add_argument("--no-perf", action="store_true", help="skip the performance probe")
    dg.set_defaults(fn=_cmd_diagnostics)

    dsc = sub.add_parser("discover",
                         help="expand the tested surface from an OpenAPI/Swagger or "
                              "GraphQL-introspection doc (read-only discover->test bridge)")
    dsc.add_argument("doc", help="path to an OpenAPI/Swagger JSON or a GraphQL "
                                 "introspection-result JSON")
    dsc.add_argument("--graphql", action="store_true",
                     help="treat the input as a GraphQL introspection result")
    dsc.add_argument("--out", help="write the derived contract+candidates JSON here")
    dsc.set_defaults(fn=_cmd_discover)

    cl = sub.add_parser("classify",
                        help="read-only strategic surface classification "
                             "(ONYX arena vs out-of-reach) from a captured request JSON")
    cl.add_argument("capture", help="JSON: {request_headers, response_headers, "
                                    "response_body, content_type}")
    cl.set_defaults(fn=_cmd_classify)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
