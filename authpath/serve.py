"""
ONYX local control-center server.

Pure stdlib (http.server) so it runs anywhere with zero install, bound to
loopback only. It serves the dashboard and a small JSON API the dashboard drives:

  GET  /                  -> the control center (dashboard/index.html)
  GET  /api/snapshot      -> current engine state (envelopes, catalog, findings, traces)
  POST /api/run-demo      -> run the labeled demo scenario, return snapshot + timeline
  POST /api/scan          -> run a REAL authorized scan from a UI engagement config
  POST /api/ping          -> read-only connectivity + auth check (one GET per principal)
  POST /api/report-bundle -> zip of submission-ready markdown for the current findings
  POST /api/reset         -> clear engine state

Run:  python -m authpath.serve         (then open http://127.0.0.1:8787)
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import AuthPathEngine
from .scope_guard import ScopeConfig

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ensure_paths() -> None:
    """Put the repo root and external_targets on sys.path so the submission-pack
    writer (external_targets/bounty_report.py) and fixtures import cleanly."""
    for p in (_ROOT, os.path.join(_ROOT, "external_targets")):
        if p not in sys.path:
            sys.path.insert(0, p)


DASHBOARD = os.path.join(_ROOT, "dashboard", "index.html")


class _State:
    """Holds the live engine + the most recent demo timeline for the dashboard."""
    engine: AuthPathEngine | None = None
    timeline: list[dict] = []


def _build_demo() -> tuple[AuthPathEngine, list[dict]]:
    # imported lazily so the package works without the fixtures on the path
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from fixtures.demo_scenario import run_demo

    def factory(target, principals, contract):
        scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                            automation_permitted=True)
        eng = AuthPathEngine(target, principals, scope, contract)
        eng.nerve = True            # populate the nerve self-diagnosis for the export
        eng.capture = []            # retain raw exchanges so the export is complete
        eng._export_scope = scope
        return eng

    engine, steps = run_demo(factory)
    # Build an ordered timeline aligning probe steps with their traces.
    timeline = []
    probes = [s for s in steps if s.kind == "probe"]
    for step, tr in zip(probes, engine.traces):
        timeline.append({
            "label": step.label,
            "expect": step.expect,
            "expect_effect": step.expect_effect,
            "trace": engine._trace_dict(tr),
        })
    # also expose the seed (legitimate) actions for the "envelope build" view
    seeds = [{"label": s.label, "principal": s.principal,
              "method": s.request.method, "path": s.request.path}
             for s in steps if s.kind == "seed"]
    return engine, [{"seeds": seeds}] + timeline


# --------------------------------------------------------------------------- #
# Live authorized scan — driven by the dashboard's engagement config.
# This is the turnkey, in-GUI equivalent of external_targets/live_hunt.py: it
# wires the SAME engine flags and plans, but keeps the engine so the dashboard
# renders a real run with the exact snapshot+timeline shape it already consumes.
# --------------------------------------------------------------------------- #

class ScanError(Exception):
    """A refusal or misconfiguration surfaced to the operator (never a crash)."""


def _timeline_for(engine) -> list[dict]:
    """Build the ordered timeline the dashboard replays, from real traces.
    Mirrors _build_demo's per-probe alignment; live runs have no ground-truth
    `expect`, so those fields are omitted (the UI treats them as optional)."""
    timeline = [{
        "label": f"{tr.method} {tr.path}",
        "trace": engine._trace_dict(tr),
    } for tr in engine.traces]
    seeds = [{"label": f"{ex.principal.pid} {ex.request.method} {ex.request.path}",
              "principal": ex.principal.pid,
              "method": ex.request.method, "path": ex.request.path}
             for ex in getattr(engine, "_observed_seeds", [])]
    return [{"seeds": seeds}] + timeline


def _auth_headers(spec) -> dict:
    """Build a principal's auth headers from a UI value. `spec` is either a bare
    string (treated as a Bearer token) or a dict {value, type, header}. Supported
    types: bearer (default), authorization (raw value), cookie, header (custom)."""
    if isinstance(spec, str):
        spec = {"value": spec, "type": "bearer"}
    value = (spec.get("value") or "").strip()
    if not value:
        return {}
    kind = (spec.get("type") or "bearer").lower()
    if kind == "cookie":
        return {"Cookie": value}
    if kind == "header":
        name = (spec.get("header") or "Authorization").strip() or "Authorization"
        return {name: value}
    if kind in ("authorization", "raw"):
        return {"Authorization": value}
    # default: bearer
    return {"Authorization": value if value.lower().startswith("bearer ") else f"Bearer {value}"}


def run_engagement(target, principals, host, *, dry_run=True, tenant=None,
                   test_resources=None, endpoints=None, researcher="",
                   program="", engagement_id="UI-LIVE-1", contract=None, seeds=None):
    """Wire ONYX exactly like byo_runner.run_target / live_hunt, but retain the
    engine and return (engine, timeline). `target` is any object with
    .send(request, principal); `principals` maps pid -> Principal. Pure orchestration
    — no network assumptions live here, which is what makes it verifiable in-process.
    `contract` is an optional endpoint→effect map (same shape the demo declares); it
    lets the operator tag an endpoint's effect-class so the money/logic laws classify
    it. Omitted → inference-only (unchanged behaviour, catches IDOR/BOLA by provenance).
    `seeds` is an optional list of (pid, method, path) collection/list reads observed up
    front so cross-principal ids gain provenance even when the object read echoes the id
    under a non-standard field (e.g. a list endpoint that returns the owning ids).
    """
    from .models import HTTPRequest, Exchange
    from .policy import IsolationInvariant
    from .roe import EngagementContract, TamperEvidentAudit

    tenant = tenant or {}
    test_resources = {str(x) for x in (test_resources or [])}
    endpoints = endpoints or []
    contract = contract or {}

    scope = ScopeConfig(allowed_hosts=[host], automation_permitted=True,
                        target_provenance="third_party", dry_run=bool(dry_run),
                        researcher_id=researcher, attribution_in_ua=bool(researcher))

    eng = AuthPathEngine(target, principals, scope, contract=contract)
    # same capability set byo_runner.run_target arms for a real hunt
    for flag in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, flag, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = eng.field_exposure = True
    eng.xprincipal_write = eng.xprincipal_delete = True
    if tenant:
        eng.policy_hypothesis = IsolationInvariant("tenant-isolation",
                                                   dict(tenant)).to_hypothesis()
    # ROE fine-destruction gate: it matches the PATH object-id against test_resources.
    # Body-addressed resources (e.g. POST /api/checkout with order_id in the body) have
    # no path id, so we union "" in — that relaxes ONLY the no-path-id case (which the
    # operator declared explicitly as an endpoint), while path-addressed writes like
    # DELETE /api/orders/{id} still require their id to be a declared test resource.
    roe_resources = set(test_resources)
    if roe_resources:
        roe_resources = roe_resources | {""}
    eng.contract_roe = EngagementContract(engagement_id=engagement_id,
                                          test_principals=set(principals),
                                          allowed_paths=["/*"],
                                          test_resources=roe_resources)
    eng.audit = TamperEvidentAudit()
    # retained so /api/export and /api/report-bundle work for live runs too
    eng.nerve = True
    eng.capture = []
    eng._observed_seeds = []
    eng._export_scope = scope
    eng._program = program
    eng._researcher = researcher

    def mk(method, path, body=None, query=None):
        return HTTPRequest(method=method, path=path, host=host, body=body, query=query or {})

    def _body_for(ep):
        raw = ep.get("body")
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            import json as _json
            parsed = _json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            return None

    def _req_for(ep, method, tmpl, oid, body):
        """Place the object id in the path {id} slot, or — for query-addressed
        resources (e.g. ?report_id={id}) — in the query dict, which HTTPTarget sends
        and the engine's object_ids() reads. Pure orchestration; engine unchanged."""
        qid = ep.get("query_id")
        if qid:
            return mk(method, tmpl, body, {qid: str(oid)})
        return mk(method, tmpl.replace("{id}", str(oid)), body)

    # Two probe shapes, chosen per endpoint by its effect-class:
    #   • cross-principal (BOLA/BFLA): baseline-read own ids, then have every OTHER
    #     principal try them — the classic object/function authz probe.
    #   • self-abuse (PAYMENT/PRICE/STATE_GATE/COUPON/OWNERSHIP/INVENTORY): the abuse
    #     is a principal acting on its OWN resource, so it must be ANALYZED, not just
    #     observed. Mutating verbs with a non-read effect default to this shape too.
    SELF_ABUSE = {"PAYMENT", "PRICE", "STATE_GATE", "COUPON", "OWNERSHIP",
                  "INVENTORY", "TEMPORAL_DRIFT"}
    observe, attack = [], []
    for ep in endpoints:
        method = (ep.get("method") or "GET").upper()
        tmpl = ep.get("path") or ""
        owned = ep.get("ids") or {}
        body = _body_for(ep)
        eff = (ep.get("effect") or "").strip().upper().replace("-", "_")
        self_abuse = (eff in SELF_ABUSE) or (
            method in ("POST", "PUT", "PATCH", "DELETE")
            and eff not in ("OBJECT_ACCESS", "AUTHORITY", ""))
        for pid, ids in owned.items():
            for oid in ids:
                req = _req_for(ep, method, tmpl, oid, body)
                (attack if self_abuse else observe).append((pid, req))
        # cross-principal probes (BOLA/BFLA) — always worth trying
        for actor in principals:
            for owner, ids in owned.items():
                if owner == actor:
                    continue
                for oid in ids:
                    attack.append((actor, _req_for(ep, method, tmpl, oid, body)))

    if not observe and not attack:
        raise ScanError("no endpoints to probe — add at least one endpoint with owned ids")

    # Seed provenance from list/collection reads first: each principal reads its own
    # collections, so the ids it owns are tagged to it before any cross-principal probe.
    for pid, method, path in (seeds or []):
        if pid not in principals:
            continue
        try:
            req = HTTPRequest(method=(method or "GET").upper(), path=path, host=host)
            ex = Exchange(request=req, response=target.send(req, principals[pid]),
                          principal=principals[pid])
            eng.capture.append(ex)
            eng._observed_seeds.append(ex)
            eng.observe(ex)
        except Exception:
            continue

    for pid, req in observe:
        if pid not in principals:
            continue
        ex = Exchange(request=req, response=target.send(req, principals[pid]),
                      principal=principals[pid])
        eng.capture.append(ex)
        eng._observed_seeds.append(ex)
        eng.observe(ex)
    for pid, req in attack:
        if pid not in principals:
            continue
        ex = Exchange(request=req, response=target.send(req, principals[pid]),
                      principal=principals[pid])
        eng.capture.append(ex)
        eng.analyze(ex)
    eng.drain_deferred()
    return eng, _timeline_for(eng)


def _build_scan(cfg: dict) -> tuple[AuthPathEngine, list[dict]]:
    """Turn a UI engagement config into a live HTTP scan. Raises ScanError with a
    human message for anything the operator must fix (unauthorized, no target,
    no principals, requests not installed)."""
    from urllib.parse import urlparse

    base_url = (cfg.get("base_url") or "").strip()
    if not base_url:
        raise ScanError("base URL is required")
    if not cfg.get("authorized"):
        raise ScanError("authorization not affirmed — tick the box confirming you are "
                        "authorized to test this target and every id is in scope")

    parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
    host = parsed.hostname or ""
    if not host:
        raise ScanError(f"could not parse a host from base URL: {base_url!r}")

    principals_in = cfg.get("principals") or {}
    from .models import Principal
    principals = {}
    for pid, spec in principals_in.items():
        auth = _auth_headers(spec)
        if not pid or not auth:
            continue
        principals[pid] = Principal(pid, pid, auth=auth)
    if not principals:
        raise ScanError("at least one principal (a test account id + its credential) is required")

    try:
        import requests  # noqa: F401
    except ImportError:
        raise ScanError("the live HTTP client needs `requests` (pip install requests). "
                        "Also: real scans must run on YOUR machine — this environment "
                        "has no network egress.")

    from .transport import HTTPTarget
    target = HTTPTarget(base_url, scope=ScopeConfig(
        allowed_hosts=[host], automation_permitted=True, target_provenance="third_party",
        dry_run=bool(cfg.get("dry_run", True)),
        researcher_id=(cfg.get("researcher") or "").strip(),
        attribution_in_ua=bool((cfg.get("researcher") or "").strip())))

    # Build an endpoint→effect contract from any per-endpoint effect hints the
    # operator set. Same shape the demo declares; unlocks the money/logic laws.
    import json as _json
    _VALID = {"OBJECT_ACCESS", "OWNERSHIP", "AUTHORITY", "PAYMENT", "PRICE",
              "STATE_GATE", "INVENTORY", "COUPON", "TEMPORAL_DRIFT", "READ", "NONE"}
    contract = {}
    for ep in (cfg.get("endpoints") or []):
        eff = (ep.get("effect") or "").strip().upper().replace("-", "_")
        path = (ep.get("path") or "").strip()
        method = (ep.get("method") or "GET").upper()
        if not path or eff in ("", "AUTO") or eff not in _VALID:
            continue
        crit = []
        raw = ep.get("body")
        if raw:
            try:
                b = raw if isinstance(raw, dict) else _json.loads(raw)
                if isinstance(b, dict):
                    crit = list(b.keys())
            except (ValueError, TypeError):
                crit = []
        if "{id}" in path and "id" not in crit:
            crit.append("id")
        contract[f"{method} {path}"] = {"effect": eff, "critical_params": crit}

    return run_engagement(
        target, principals, host,
        dry_run=bool(cfg.get("dry_run", True)),
        tenant=cfg.get("tenant_domains") or {},
        test_resources=cfg.get("test_resources") or [],
        endpoints=cfg.get("endpoints") or [],
        researcher=(cfg.get("researcher") or "").strip(),
        program=(cfg.get("program") or "").strip(),
        engagement_id=(cfg.get("engagement_id") or "UI-LIVE-1").strip() or "UI-LIVE-1",
        contract=contract,
        seeds=cfg.get("seeds") or None,
    )


def _ping(cfg: dict) -> dict:
    """Read-only connectivity + auth check: one GET per principal to the base URL
    (optionally a probe path), returning status + latency. No engine, no mutation
    — a fast 'are my tokens live and in scope?' check before a full sweep."""
    from urllib.parse import urlparse
    base_url = (cfg.get("base_url") or "").strip()
    if not base_url:
        raise ScanError("base URL is required")
    parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
    host = parsed.hostname or ""
    if not host:
        raise ScanError(f"could not parse a host from base URL: {base_url!r}")
    try:
        import requests
    except ImportError:
        raise ScanError("connection test needs `requests` (pip install requests), "
                        "run on your own machine.")
    path = (cfg.get("path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    url = base_url.rstrip("/") + path
    ua = f"ONYX-AuthPath/3.0 (connection-test){' ' + cfg['researcher'] if cfg.get('researcher') else ''}"
    out = {}
    for pid, spec in (cfg.get("principals") or {}).items():
        headers = _auth_headers(spec)
        if not pid or not headers:
            continue
        headers["User-Agent"] = ua
        t0 = time.time()
        try:
            r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            out[pid] = {"status": r.status_code, "ms": int((time.time() - t0) * 1000),
                        "ok": r.status_code < 400}
        except Exception as e:
            out[pid] = {"status": None, "ms": int((time.time() - t0) * 1000),
                        "ok": False, "error": type(e).__name__}
    if not out:
        raise ScanError("add at least one principal with a credential to test")
    return {"host": host, "path": path, "results": out}


def _report_bundle_zip(engine) -> bytes:
    """Zip the submission-ready markdown for the current findings, in memory."""
    _ensure_paths()
    from bounty_report import submission_pack   # external_targets/bounty_report.py
    pack = submission_pack(engine.findings,
                           program=getattr(engine, "_program", "") or "",
                           researcher=getattr(engine, "_researcher", "") or "")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, md in pack.items():
            z.writestr(name, md)
    return buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthPath/3.0"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(DASHBOARD, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, b"dashboard/index.html not found", "text/plain")
            return
        if self.path == "/api/diagnostics":
            # read-only: builds a fresh demo engine, reads it, returns stats.
            from .diagnostics import run_self_diagnostics
            try:
                self._json(run_self_diagnostics(perf=True))
            except Exception as e:
                self._json({"error": str(e)}, code=500)
            return
        if self.path == "/api/export":
            # the full downloadable diagnostics file for the CURRENT run (the one to
            # send back for analysis): metrics + nerve self-diagnosis + every raw
            # exchange, secrets redacted / PII hashed.
            if _State.engine is None:
                self._json({"error": "no run yet — run a scan (or the demo) first"}, code=409)
                return
            from .diag_export import build_export, to_json_bytes
            eng = _State.engine
            export = build_export(eng, getattr(eng, "capture", []),
                                  scope=getattr(eng, "_export_scope", None),
                                  meta={"tool": "ONYX/AuthPath", "source": "control-center"})
            body = to_json_bytes(export)
            ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="onyx_diagnostics_{ts}.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/snapshot":
            if _State.engine is None:
                self._json({"empty": True})
            else:
                snap = _State.engine.snapshot()
                snap["timeline"] = _State.timeline
                self._json(snap)
            return
        self._send(404, b"not found", "text/plain")

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else {}
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_POST(self):
        if self.path == "/api/run-demo":
            engine, timeline = _build_demo()
            _State.engine = engine
            _State.timeline = timeline
            snap = engine.snapshot()
            snap["timeline"] = timeline
            self._json(snap)
            return
        if self.path == "/api/scan":
            cfg = self._read_json()
            try:
                engine, timeline = _build_scan(cfg)
            except ScanError as e:
                # an operator-fixable refusal/misconfig — not a server fault
                self._json({"error": str(e)}, code=422)
                return
            except Exception as e:
                # a live target that refused/timed out/unreachable, etc.
                self._json({"error": f"scan failed: {e}"}, code=502)
                return
            _State.engine = engine
            _State.timeline = timeline
            snap = engine.snapshot()
            snap["timeline"] = timeline
            self._json(snap)
            return
        if self.path == "/api/ping":
            cfg = self._read_json()
            try:
                self._json(_ping(cfg))
            except ScanError as e:
                self._json({"error": str(e)}, code=422)
            except Exception as e:
                self._json({"error": f"connection test failed: {e}"}, code=502)
            return
        if self.path == "/api/report-bundle":
            if _State.engine is None or not _State.engine.findings:
                self._json({"error": "no confirmed findings yet — run a scan first"},
                           code=409)
                return
            try:
                body = _report_bundle_zip(_State.engine)
            except Exception as e:
                self._json({"error": f"could not build report pack: {e}"}, code=500)
                return
            ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition",
                             f'attachment; filename="onyx_submission_{ts}.zip"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/reset":
            _State.engine = None
            _State.timeline = []
            self._json({"ok": True})
            return
        self._send(404, b"not found", "text/plain")


def serve(host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True):
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"ONYX control center → {url}")
    print("  (loopback only; Ctrl-C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ONYX control center")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true", help="don't auto-open a browser")
    a = ap.parse_args()
    serve(a.host, a.port, open_browser=not a.no_open)
