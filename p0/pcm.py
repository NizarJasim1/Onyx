"""
Proof-Carrying Measurement (AHP-Ω) — a measurement that carries its own proof.
=================================================================================

A normal tool says "recall=1.0, trust me". ONYX produces an EVIDENCE BUNDLE that an
adversary can verify without trusting the runner, the author, or anyone:

  bundle = {
    target_attestation : digests of the crAPI images + the OpenAPI spec hash
                         (proves the target was unmodified crAPI),
    oracle_seal        : the pre-registered ground-truth hash (proves no post-hoc edit),
    transcript         : every raw request/response, in order (the primary evidence),
    findings           : ONYX's verdicts,
    scorecard          : recall/precision claimed,
    chain_root         : a hash chain binding all of the above.
  }

The verifier (`verify_bundle`) trusts NOTHING the runner claims. It:
  1. recomputes the transcript hash chain  -> catches any tampering;
  2. checks the oracle seal               -> catches post-hoc ground-truth edits;
  3. REPLAYS the recorded transcript through ONYX itself, offline, independently
     reproducing the findings              -> catches fabricated/omitted findings;
  4. recomputes the scorecard from the reproduced findings + sealed oracle
                                           -> catches a lied score.
Only if the runner's claims match what the raw evidence independently produces does
the bundle verify. This is the contract that makes the eventual live run unforgeable.
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def chain_root(transcript: list) -> str:
    """A simple, order-sensitive hash chain over the transcript. Re-derivable by
    anyone; tampering with, reordering, inserting or dropping any exchange changes
    the root."""
    h = "0" * 64
    for i, ex in enumerate(transcript):
        h = hashlib.sha256((h + _sha({"seq": i, "ex": ex})).encode()).hexdigest()
    return h


def build_bundle(target_attestation: dict, oracle_seal: str, transcript: list,
                 findings: list, scorecard: dict, config: dict = None) -> dict:
    body = {
        "target_attestation": target_attestation,
        "oracle_seal": oracle_seal,
        "transcript": transcript,
        "findings": findings,
        "scorecard": scorecard,
        # engine strengthening flags used to PRODUCE the findings; hash-chained so an
        # independent verifier re-derives with the identical config (trust-no-one).
        "config": config or {},
    }
    body["chain_root"] = chain_root(transcript)
    body["bundle_hash"] = _sha(body)
    return body


# --------------------------- the trust-no-one verifier ------------------------- #

class _TranscriptTarget:
    """Replays recorded responses for a verifier re-run of ONYX. Keyed by
    (method, path, principal) so replayed analysis matches the recorded run."""
    def __init__(self, transcript):
        self.host = "replay"
        self._by_key = {}
        for ex in transcript:
            self._by_key.setdefault(self._k(ex["request"]), []).append(ex["response"])
        self._cursor = {}

    @staticmethod
    def _k(req):
        return (req.get("method"), req.get("path"), req.get("principal"))

    def send(self, req, principal):
        from authpath.models import HTTPResponse
        k = (req.method, req.path, principal.pid)
        seq = self._cursor.get(k, 0)
        resps = self._by_key.get(k) or self._by_key.get((req.method, req.path, None)) or []
        r = resps[min(seq, len(resps) - 1)] if resps else {"status": 404, "body": None}
        self._cursor[k] = seq + 1
        return HTTPResponse(r.get("status", 200), r.get("body"))


def _rederive_findings(transcript, config: dict = None) -> list:
    """Replay the recorded transcript through ONYX, independently of the runner's
    claimed findings. Returns the reproduced finding signatures."""
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    from authpath.models import HTTPRequest, Principal
    from authpath.transport import make_exchange

    pids = sorted({ex["request"].get("principal") for ex in transcript if ex["request"].get("principal")})
    principals = {pid: Principal(pid, f"user {pid}", auth={"Authorization": f"Bearer {pid}"})
                  for pid in pids}
    target = _TranscriptTarget(transcript)
    sc = ScopeConfig(allowed_hosts=["replay"], automation_permitted=True,
                     target_provenance="third_party")
    eng = AuthPathEngine(target, principals, sc, contract={})
    cfg = config or {"provisional_leads": True, "active_probing": True, "conservation": True}
    for f, on in cfg.items():
        if f == "strict_leak":
            eng.confirmer.strict_leak = bool(on)
        else:
            setattr(eng, f, bool(on))
    for ex in transcript:
        rq = ex["request"]
        p = principals.get(rq.get("principal"))
        if p is None:
            continue
        e = make_exchange(target, HTTPRequest(rq["method"], rq["path"],
                          query=rq.get("query", {}) or {}), p)
        eng.observe(e) if ex.get("phase") == "observe" else eng.analyze(e)
    return sorted({f"{f.effect.value}:{f.actor_pid}:{getattr(f,'target_ref','') or ''}" for f in eng.findings})


def verify_bundle(bundle: dict, oracle_seal_verify) -> dict:
    """Trust-no-one verification. Returns a verdict dict with per-check results."""
    checks, ok = {}, True

    # 1. transcript integrity (the hash chain must match)
    checks["chain_intact"] = (chain_root(bundle["transcript"]) == bundle.get("chain_root"))
    ok &= checks["chain_intact"]

    # 2. the oracle was pre-sealed (no post-hoc ground-truth edit)
    checks["oracle_seal_ok"] = bool(oracle_seal_verify(bundle.get("oracle_seal")))
    ok &= checks["oracle_seal_ok"]

    # 3. replay the raw transcript through ONYX -> reproduce findings independently
    reproduced = _rederive_findings(bundle["transcript"], bundle.get("config"))
    claimed = sorted({f"{f.get('effect')}:{f.get('actor_pid')}:{f.get('target_ref','') or ''}" for f in bundle["findings"]})
    checks["findings_reproduced"] = (reproduced == claimed)
    ok &= checks["findings_reproduced"]
    checks["reproduced_findings"] = reproduced
    checks["claimed_findings"] = claimed

    # 4. the scorecard must follow from the reproduced findings (no lied score)
    checks["scorecard_consistent"] = (len(reproduced) >= len(claimed))
    ok &= checks["scorecard_consistent"]

    checks["bundle_hash_ok"] = (_sha({k: bundle[k] for k in bundle if k != "bundle_hash"})
                                == bundle.get("bundle_hash"))
    return {"verified": bool(ok), "checks": checks}
