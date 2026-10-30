"""
OBSTACLE 5 — multi-step business-logic chains.

ONYX's detection unit is a single Exchange. Real business-logic vulnerabilities are
STATE MACHINES: ordered steps, live data dependencies (a step's output feeds the
next step's input), a per-step actor, and an invariant asserted on the final state.

This module adds an ORCHESTRATION layer ABOVE the engine. It does NOT add a new
judgment path and does NOT touch single-exchange detection:

  * each executed step is fed to the existing engine -> every existing detector
    (Δstate, provenance value-threading, EIL laws) fires exactly as before, now
    reaching values that are MINTED LIVE during the chain;
  * the chain's own verdict is a DECLARATIVE invariant the user states, CONFIRMED
    by an owner-side read-back (the same Δstate philosophy, RL3) — so a chain
    finding requires a real, observed breach, never merely "the requests worked".

Everything is opt-in (a `chains` block in the spec). With no chains the engine
behaves byte-identically.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import (HTTPRequest, Finding, StateProof, PoC,
                     EffectClassification, EffectClass, ImpactClass, Severity,
                     ClassificationSource)
from .scope_guard import ScopeVerdict

_VAR = re.compile(r"\{\{([^}]+)\}\}")


@dataclass
class ChainStep:
    as_pid: str
    method: str
    path: str
    body: Any = None
    query: dict = field(default_factory=dict)
    save: dict = field(default_factory=dict)         # {var_name: response.field.path}
    expect_status: int = 0                            # optional 2xx gate


@dataclass
class ChainResult:
    name: str
    executed: list                                    # ordered "as PID: METHOD path -> status"
    vars: dict
    aborted: str = ""                                 # reason if the chain stopped early
    invariant_breached: bool = False
    evidence: str = ""


def _dig(body, path: str):
    cur = body
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _subst(value, ctx: dict):
    """Replace {{var}} in strings / nested structures from the chain context only
    (no eval, no external input — RISK 5). Unknown vars are left intact so the step
    is visibly 'unmet' rather than silently wrong."""
    if isinstance(value, str):
        def repl(m):
            key = m.group(1).strip()
            return str(ctx[key]) if key in ctx else m.group(0)
        return _VAR.sub(repl, value)
    if isinstance(value, dict):
        return {k: _subst(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, ctx) for v in value]
    return value


class ChainRunner:
    """Drives a declarative chain. Reuses the engine for detection; emits at most
    one DECLARATIVE-invariant finding per chain, confirmed by an owner read-back."""

    def __init__(self, engine, target, scope, principals: dict):
        self.engine = engine
        self.target = target
        self.scope = scope
        self.principals = principals

    # -- helpers ----------------------------------------------------------- #
    def _send(self, pid: str, method: str, path: str, body, query, host):
        principal = self.principals[pid]
        req = HTTPRequest(method.upper(), path, query=query or {}, body=body, host=host)
        d = self.scope.check(req)
        if d.verdict is ScopeVerdict.HALT:
            return None, f"scope-guard HALT on {method} {path} ({d.reason})"
        resp = self.target.send(req, principal)
        # mid-chain WAF / auth-expiry guard (RISK 6): never assert off a challenge.
        try:
            from .transport import detect_block, detect_auth_expiry
            if resp is not None and (detect_block(resp.status, resp.body,
                                                   getattr(resp, "headers", {}))
                                     or detect_auth_expiry(resp.status, resp.body)):
                return None, f"blocked/expired at {method} {path}"
        except Exception:
            pass
        return resp, ""

    # -- public ------------------------------------------------------------ #
    def run(self, chain: dict, host: str, consts: dict | None = None) -> ChainResult:
        from .transport import make_exchange
        ctx = dict(consts or {})
        ctx.update(chain.get("vars", {}) or {})
        res = ChainResult(name=chain.get("name", "chain"), executed=[], vars=ctx)

        for raw in chain.get("steps", []):
            step = ChainStep(
                as_pid=raw.get("as") or raw.get("principal"),
                method=raw.get("method", "GET"),
                path=_subst(raw.get("path", "/"), ctx),
                body=_subst(raw.get("body"), ctx),
                query=_subst(raw.get("query", {}), ctx),
                save=raw.get("save", {}) or {},
                expect_status=raw.get("expect_status", 0),
            )
            if step.as_pid not in self.principals:
                res.aborted = f"unknown principal {step.as_pid!r}"; return res
            if _VAR.search(step.path):
                res.aborted = f"unresolved variable in path {step.path!r}"; return res

            # feed the step through the engine so EVERY existing detector fires on it
            principal = self.principals[step.as_pid]
            req = HTTPRequest(step.method.upper(), step.path, query=step.query,
                              body=step.body, host=host)
            # mutating steps must clear may_mutate (dry_run / allow_destructive); a
            # read step only needs the scope check. A HALT aborts the whole chain.
            if step.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                d = self.scope.may_mutate(req)
            else:
                d = self.scope.check(req)
            if d.verdict is ScopeVerdict.HALT:
                res.aborted = f"scope-guard HALT on {step.method} {step.path} ({d.reason})"; return res
            ex = make_exchange(self.target, req, principal)
            try:
                self.engine.analyze(ex)                  # incidental detection (zero new FP path)
            except Exception:                            # noqa: BLE001 — never let a step crash the chain
                self.engine._pass_errors += 1
            status = ex.response.status if ex.response else 0
            res.executed.append(f"as {step.as_pid}: {step.method} {step.path} -> {status}")

            from .transport import detect_block, detect_auth_expiry
            body = ex.response.body if ex.response else None
            if ex.response and (detect_block(status, body, getattr(ex.response, "headers", {}))
                                or detect_auth_expiry(status, body)):
                res.aborted = f"blocked/expired at step {step.method} {step.path}"; return res
            if step.expect_status and status != step.expect_status:
                res.aborted = f"step {step.method} {step.path} returned {status}, expected {step.expect_status}"
                return res

            for var, fieldpath in step.save.items():
                val = _dig(body, fieldpath)
                if val is not None:
                    ctx[var] = val

        res.vars = ctx
        # declarative final invariant -> confirmed by an OWNER read-back (RL3).
        assertion = chain.get("assert")
        if assertion:
            self._check_invariant(chain, assertion, ctx, host, res)
        return res

    def _check_invariant(self, chain, assertion, ctx, host, res: ChainResult):
        """`assert.read` reads the final state as the legitimate owner; the chain is
        BREACHED if `assert.violated_if` matches (the cross-object effect stuck)."""
        read = assertion.get("read", {})
        rpid = read.get("as")
        if rpid not in self.principals:
            res.evidence = "invariant read principal unknown — cannot confirm; abstaining"
            return
        path = _subst(read.get("path", "/"), ctx)
        if _VAR.search(path):
            res.evidence = "invariant read path has unresolved vars — abstaining"
            return
        resp, err = self._send(rpid, read.get("method", "GET"), path,
                               _subst(read.get("body"), ctx), read.get("query", {}), host)
        if resp is None or not (200 <= resp.status < 300):
            res.evidence = f"owner read-back did not succeed ({err or (resp and resp.status)}) — abstaining"
            return
        cond = assertion.get("violated_if", {})
        field_path = cond.get("field", "")
        observed = _dig(resp.body, field_path)
        breached = False
        if "equals" in cond:
            breached = (observed == cond["equals"])
        elif "not_equals" in cond:
            breached = (observed != cond["not_equals"])
        elif "present" in cond:
            breached = (observed is not None) == bool(cond["present"])
        if not breached:
            return
        res.invariant_breached = True
        res.evidence = (f"owner ({rpid}) read of {path} shows {field_path}={observed!r} — "
                        f"a state only the chain's cross-object action could produce")
        self._emit_finding(chain, ctx, res, rpid, path, field_path, observed)

    def _emit_finding(self, chain, ctx, res, owner_pid, read_path, field_path, observed):
        actor = chain.get("actor") or (chain.get("steps", [{}])[-1].get("as", "") if chain.get("steps") else "")
        fid = f"AP-CHAIN-{abs(hash(chain.get('name','chain'))) & 0xFFFFFF:06X}"
        causal = [f"chain '{chain.get('name','chain')}' — multi-step business-logic"] + res.executed + [
            f"invariant breached: {res.evidence}"]
        proof = StateProof(
            confirmed=True,
            method=f"owner-side read-back of {read_path} as {owner_pid}",
            before="(invariant expected to hold for the owner)",
            after=f"{field_path}={observed!r}",
            read_as=owner_pid,
            detail=res.evidence,
        )
        curl = [f"# step {i+1}: {s}" for i, s in enumerate(res.executed)]
        poc = PoC(steps=res.executed, curl=curl,
                  notes="multi-step chain; live-minted ids were threaded between steps.")
        cls = EffectClassification(endpoint=read_path, effect=EffectClass.OWNERSHIP,
                                   source=ClassificationSource.CONTRACT,
                                   critical_params=[field_path],
                                   notes="business-logic chain invariant")
        f = Finding(
            fid=fid,
            title=f"Business-logic chain — {chain.get('name','chain')}",
            effect=EffectClass.OWNERSHIP,
            impact=ImpactClass.WORKFLOW_BYPASS,
            severity=Severity.HIGH,
            causal_path=causal,
            state_proof=proof,
            poc=poc,
            classification=cls,
            law_name="ChainInvariant",
            actor_pid=actor,
            target_ref=read_path,
        )
        # reuse the existing deterministic CVSS scorer so a chain finding carries a
        # real vector/score instead of a misleading 0.0 (final-critique fix).
        try:
            from .cvss import derive_score
            f.cvss_score, f.cvss_label, f.cvss_vector = derive_score(f)
        except Exception:
            pass
        self.engine.findings.append(f)


def run_chains(engine, target, scope, principals: dict, spec: dict, host: str) -> list:
    """Entry point: run every chain in spec['chains']. Returns ChainResults.
    No-op (empty list) when the spec declares no chains."""
    runner = ChainRunner(engine, target, scope, principals)
    consts = spec.get("vars", {}) or {}
    return [runner.run(c, host, consts) for c in spec.get("chains", []) or []]
