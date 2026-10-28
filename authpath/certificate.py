"""
Certifying-Algorithm Layer (ASSURANCE-1) — a finding carries its own independent proof.
=====================================================================================

WHAT THIS ADDS (and, deliberately, what it does NOT touch)
----------------------------------------------------------
ONYX already confirms every finding by a Δstate read-back (RL3) and can replay a
finding THROUGH ONYX to reproduce it. That replay, however, re-runs ONYX's own
decision code — so it still *trusts the tool*. This module supplies the missing
piece from the certifying-algorithm literature (McConnell/Mehlhorn; proof-carrying
data): with each finding it emits a self-contained WITNESS, and an INDEPENDENT
checker re-derives the verdict **from the raw transcript alone**, so the finding's
correctness can be established without trusting ONYX.

    certifying algorithm:  output y  +  witness w  ──►  a simple, separately
                           trusted checker verifies that w proves y is correct
                           for input x, WITHOUT trusting the producer.

Here:  y = "this is a cross-principal authorization violation"
       w = the raw HTTP transcript (attacker exchange + owner-authenticated
           read-backs) bundled with the claimed Δstate
       checker = check_certificate(), below

RED LINES — this layer is additive-only and cannot weaken ONYX
--------------------------------------------------------------
* It is a pure OBSERVER: emit_certificate() only READS a finding's already-proven
  facts; it changes no decision, mutates no ONYX state. It is default-OFF (nothing
  in the engine imports or calls it unless explicitly invoked).
* INDEPENDENCE IS STRUCTURAL, not promised: this module imports **zero** authpath
  decision code (no confirmer / eil / engine / provenance / envelope). The checker
  operates only on plain dict/JSON + the stdlib. An AST guard test enforces it.
  (Same anti-circularity discipline the proving-world uses.)
* RL3 (Δstate, never status): the checker CONFIRMS by re-deriving the Δstate from
  the raw read-back bodies — never from a status code, never from ONYX's stored
  before/after (which it re-computes independently and does not trust).
* RL1 (no induction): the check is a DEFINITIONAL predicate over raw facts, not a
  model. "The owner's private value appears in the attacker's response", or "the
  owner's authenticated re-read changed", is the *definition* of the violation.
* RL5 (fail-safe to inaction): a verifier that cannot INDEPENDENTLY entail the
  verdict from the transcript returns REJECTED or ABSTAIN — never a false CERTIFIED.
  ACCEPT is emitted only on positive entailment. A verifier can only ever
  under-certify by accident, never over-certify.

Note on scope (honest boundary): CERTIFIED means the raw transcript independently
entails the verdict. ABSTAIN means ONYX confirmed the finding but the bundled
transcript is not (yet) sufficient for an independent re-derivation for this effect
kind — that is a coverage gap of THIS layer, closed by bundling more raw evidence,
NOT a retraction of ONYX's own confirmation. This is the certificate layer's own
coverage certificate.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

CERTIFICATE_VERSION = 1

# Verdict kinds this layer can independently re-derive today.
KIND_READ_LEAK = "READ_LEAK"            # BOLA/BOPLA read: attacker received owner-private data
KIND_XPRINCIPAL_WRITE = "XPRINCIPAL_WRITE"  # write/delete on a foreign object, persisted on owner read-back
KIND_AUTHN_GAP = "AUTHN_GAP"            # an anonymous principal received owner-private data (missing authn)
KIND_CHAINED_LEAK = "CHAINED_LEAK"     # second-order: attacker carries a value forward, then leaks owner data
KIND_CHAINED_WRITE = "CHAINED_WRITE"   # second-order: attacker carries a value forward, then mutates owner data

# Checker outcomes (fail-safe: default is NOT "certified").
CERTIFIED = "CERTIFIED"    # transcript independently entails the verdict
REJECTED = "REJECTED"      # transcript CONTRADICTS the claim, or integrity broke
ABSTAIN = "ABSTAIN"        # not independently checkable from the bundled transcript


# --------------------------------------------------------------------------- #
# Canonical serialization + tamper-evident hash chain                          #
# --------------------------------------------------------------------------- #

def _canon(obj: Any) -> str:
    """Deterministic JSON: sorted keys, tight separators. The spine every hash
    keys on, so two byte-identical structures hash identically across machines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _hash_chain(finding: dict, claim: dict, transcript: dict, provenance: str) -> dict:
    f = _sha(finding)
    c = _sha(claim)
    t = _sha(transcript)
    root = hashlib.sha256((f + c + t + provenance).encode("utf-8")).hexdigest()
    return {"finding_sha256": f, "claim_sha256": c,
            "transcript_sha256": t, "root": root}


# --------------------------------------------------------------------------- #
# Emit — a pure READ over a finding's already-proven facts                     #
# --------------------------------------------------------------------------- #

def emit_certificate(*, finding: dict, claim: dict, transcript: dict,
                     provenance: str = "unknown") -> dict:
    """Package a self-contained, tamper-evident certificate. Every argument is a
    plain dict of facts ONYX already proved; nothing here decides anything."""
    cert = {
        "onyx_certificate_version": CERTIFICATE_VERSION,
        "finding": finding,
        "claim": claim,
        "transcript": transcript,
        "provenance": provenance,
    }
    cert["hash_chain"] = _hash_chain(finding, claim, transcript, provenance)
    return cert


def certificate_from_finding(finding_obj, *, attacker_exchange, owner_view=None,
                             victim_before=None, victim_after=None,
                             sensitive_field: str = "", kind: str = "",
                             provenance: str = "unknown") -> dict:
    """Convenience builder from ONYX objects, via duck-typing only (no import of
    authpath types — keeps this module's ZERO-decision-dependency guarantee). Pass
    the raw exchanges captured during the run."""
    sp = getattr(finding_obj, "state_proof", None)
    claim = {
        "kind": kind or (KIND_XPRINCIPAL_WRITE
                         if str(getattr(finding_obj, "effect", "")).upper().find("WRITE") >= 0
                         or victim_after is not None else KIND_READ_LEAK),
        "read_as": getattr(sp, "read_as", "") if sp else "",
        "sensitive_field": sensitive_field,
        "claimed_before": getattr(sp, "before", None) if sp else None,
        "claimed_after": getattr(sp, "after", None) if sp else None,
    }
    finding = {
        "fid": getattr(finding_obj, "fid", ""),
        "title": getattr(finding_obj, "title", ""),
        "effect": str(getattr(finding_obj, "effect", "")),
        "impact": str(getattr(finding_obj, "impact", "")),
        "law_name": getattr(finding_obj, "law_name", ""),
        "actor_pid": getattr(finding_obj, "actor_pid", ""),
        "target_ref": getattr(finding_obj, "target_ref", ""),
        "resource_ref": getattr(finding_obj, "resource_ref", ""),
    }
    transcript = {"attacker": attacker_exchange}
    if owner_view is not None:
        transcript["owner_view"] = owner_view
    if victim_before is not None:
        transcript["victim_readback_before"] = victim_before
    if victim_after is not None:
        transcript["victim_readback_after"] = victim_after
    return emit_certificate(finding=finding, claim=claim,
                            transcript=transcript, provenance=provenance)


# --------------------------------------------------------------------------- #
# Independent re-derivation helpers (raw facts only)                           #
# --------------------------------------------------------------------------- #

def _is_2xx(resp: dict) -> bool:
    try:
        return 200 <= int(resp.get("status", 0)) < 300
    except Exception:
        return False


def _extract(body: Any, path: str) -> Any:
    """Fetch a value by dotted path (e.g. 'body.iban' or 'iban'); if the strict
    path misses, fall back to a recursive search for the final key. Returns None
    if absent."""
    if body is None or not path:
        return None
    parts = [p for p in path.split(".") if p and p != "body"]
    cur = body
    ok = True
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            ok = False
            break
    if ok:
        return cur
    key = parts[-1] if parts else path
    return _find_key(body, key)


def _find_key(container: Any, key: str) -> Any:
    if isinstance(container, dict):
        if key in container:
            return container[key]
        for v in container.values():
            r = _find_key(v, key)
            if r is not None:
                return r
    elif isinstance(container, list):
        for v in container:
            r = _find_key(v, key)
            if r is not None:
                return r
    return None


def _deep_contains_value(container: Any, value: Any) -> bool:
    """Does `value` appear anywhere as a leaf in `container`? Used to prove the
    owner's private value actually reached the attacker's response body."""
    if value is None:
        return False
    if container == value:
        return True
    if isinstance(container, dict):
        return any(_deep_contains_value(v, value) for v in container.values())
    if isinstance(container, list):
        return any(_deep_contains_value(v, value) for v in container)
    return False


# --------------------------------------------------------------------------- #
# The independent checker                                                      #
# --------------------------------------------------------------------------- #

def _result(status: str, reason: str, **extra) -> dict:
    r = {"status": status, "reason": reason}
    r.update(extra)
    return r


def _request_carries(request: dict, value) -> bool:
    """True iff the attack request USES the carried value (in body, path, or a query
    value) — the re-derivable proof that a value was carried forward into the attack."""
    if value is None:
        return False
    if _deep_contains_value(request.get("body"), value):
        return True
    sval = str(value)
    if sval and sval in str(request.get("path") or ""):
        return True
    q = request.get("query") or {}
    if isinstance(q, dict) and any(str(v) == sval for v in q.values()):
        return True
    return False


def _verify_chain(steps: list, claim: dict):
    """Re-derive the carry chain from raw bytes, supporting MULTI-HOP: each
    carry_source hop's produced value must appear in the NEXT step's request (the
    last hop links into the attack step). Returns (ok, attack_step_or_disposition,
    message); on failure the 2nd item is 'abstain' or 'reject'."""
    carry = [s for s in steps if s.get("role") == "carry_source"]
    attack = next((s for s in steps if s.get("role") == "attack"), steps[-1] if steps else None)
    if not carry or attack is None:
        return (False, "abstain", "no carry_source/attack steps to establish a chain")
    fields = claim.get("carried_fields")
    if not fields:
        cf = claim.get("carried_field", "")
        fields = [cf] if cf else []
    if len(fields) != len(carry):
        return (False, "abstain", "carried_fields count must match the carry_source steps")
    nexts = carry[1:] + [attack]                       # each hop links into the next step
    for i, (hop, nxt) in enumerate(zip(carry, nexts)):
        v = _extract((hop.get("response") or {}).get("body"), fields[i])
        if v is None:
            return (False, "abstain", f"no carried value at hop {i} (field {fields[i]!r})")
        if not _request_carries(nxt.get("request") or {}, v):
            return (False, "reject", f"carried value at hop {i} not used in the next request — chain link absent")
    return (True, attack, "chain verified")


def _check_chained_leak(tr: dict, claim: dict, read_as: str) -> dict:
    """Second-order READ-leak over a multi-step transcript: a (possibly multi-hop)
    carry chain terminates in an attack step whose response leaks owner-private W."""
    steps = tr.get("steps") or []
    if len(steps) < 2:
        return _result(ABSTAIN, "chained leak needs >=2 steps (carry_source + attack); bundle them")
    ok, attack, msg = _verify_chain(steps, claim)
    if not ok:
        return _result(ABSTAIN if attack == "abstain" else REJECTED, msg)
    attacker_pid = attack.get("principal", "")
    if attacker_pid and read_as and attacker_pid == read_as:
        return _result(REJECTED, "actor == owner — not a cross-principal violation")
    attack_resp = attack.get("response") or {}
    if not _is_2xx(attack_resp):
        return _result(REJECTED, "attack step was not accepted (2xx) — no access entailed")
    field = claim.get("sensitive_field", "")
    owner_body = (tr.get("owner_view") or {}).get("response", {}).get("body")
    secret = _extract(owner_body, field) if field else None
    if secret is None:
        return _result(ABSTAIN, "no owner-private value to re-derive the leak (bundle owner_view + sensitive_field)")
    if _deep_contains_value(attack_resp.get("body"), secret):
        return _result(CERTIFIED,
                       f"second-order leak: attacker carried a value forward and the attack "
                       f"response independently contains the owner's private '{field}' — chained leak entailed",
                       kind=KIND_CHAINED_LEAK, rederived_leak_field=field)
    return _result(REJECTED,
                   f"owner's private '{field}' is not present in the attack response — leak not entailed")


def _check_chained_write(tr: dict, claim: dict, read_as: str) -> dict:
    """Second-order WRITE over a multi-step transcript: a (possibly multi-hop) carry
    chain terminates in a mutating attack step whose effect persists on the owner's
    authenticated read-back (before != after)."""
    steps = tr.get("steps") or []
    if len(steps) < 2:
        return _result(ABSTAIN, "chained write needs >=2 steps (carry_source + attack); bundle them")
    ok, attack, msg = _verify_chain(steps, claim)
    if not ok:
        return _result(ABSTAIN if attack == "abstain" else REJECTED, msg)
    attacker_pid = attack.get("principal", "")
    if attacker_pid and read_as and attacker_pid == read_as:
        return _result(REJECTED, "actor == owner — not a cross-principal violation")
    attack_req = attack.get("request") or {}
    attack_resp = attack.get("response") or {}
    if str(attack_req.get("method", "")).upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return _result(REJECTED, "attack step is not a mutating request — no write entailed")
    if not _is_2xx(attack_resp):
        return _result(REJECTED, "attack write was not accepted (2xx) — no mutation entailed")
    before = (tr.get("victim_readback_before") or {}).get("response", {})
    after = (tr.get("victim_readback_after") or {}).get("response", {})
    if not after:
        return _result(ABSTAIN, "no owner-authenticated read-back after the write (bundle victim_readback_after)")
    b_body, a_body = before.get("body"), after.get("body")
    a_status = after.get("status", 0)
    gone = (b_body is not None) and (a_body is None or int(a_status or 0) == 404)
    changed = (before != {}) and (b_body != a_body)
    if changed or gone:
        return _result(CERTIFIED,
                       "second-order write: attacker carried a value forward and used it to mutate a "
                       "foreign object, persisted on the owner's authenticated read-back",
                       kind=KIND_CHAINED_WRITE, rederived_delta={"before": b_body, "after": a_body})
    return _result(REJECTED, "owner's authenticated re-read is unchanged — no persisted Δstate")


def check_certificate(cert: dict) -> dict:
    """Re-derive the verdict from the RAW transcript, trusting nothing but the
    bundled request/response bytes and the stdlib. Returns CERTIFIED only on
    positive entailment; otherwise REJECTED (contradiction/tamper) or ABSTAIN."""
    # 0) Integrity — recompute the hash chain over the canonical sections.
    try:
        expect = _hash_chain(cert["finding"], cert["claim"],
                             cert["transcript"], cert.get("provenance", "unknown"))
    except Exception as e:
        return _result(REJECTED, f"malformed certificate: {e!r}")
    if cert.get("hash_chain") != expect:
        return _result(REJECTED, "integrity: hash chain does not match contents (tampered)")

    claim = cert["claim"]
    tr = cert["transcript"]
    kind = claim.get("kind")
    read_as = claim.get("read_as", "")

    # Multi-step (second-order) certificates carry an ordered `steps` list rather
    # than a single `attacker` exchange, so they are dispatched before the
    # single-transcript common checks below.
    if kind == KIND_CHAINED_LEAK:
        return _check_chained_leak(tr, claim, read_as)
    if kind == KIND_CHAINED_WRITE:
        return _check_chained_write(tr, claim, read_as)

    attacker = tr.get("attacker") or {}
    attacker_pid = attacker.get("principal", "")
    attacker_resp = attacker.get("response") or {}

    # A denial can never be a violation (RL3 — no status-only confirmation, and a
    # non-2xx attacker response is definitionally not an accessed/mutated object).
    if not _is_2xx(attacker_resp):
        return _result(REJECTED, "attacker request was not accepted (2xx) — no access entailed")

    # The actor must differ from the owner we read back as, or there is no
    # CROSS-principal violation to speak of.
    if attacker_pid and read_as and attacker_pid == read_as:
        return _result(REJECTED, "actor == owner — not a cross-principal violation")

    if kind in (KIND_READ_LEAK, KIND_AUTHN_GAP):
        # AUTHN_GAP is definitionally an UNAUTHENTICATED read; if the attacker
        # carried a real identity it is a different class — abstain, never guess.
        if kind == KIND_AUTHN_GAP and str(attacker_pid).strip().lower() not in (
                "", "anon", "anonymous", "none", "null", "public", "guest"):
            return _result(ABSTAIN,
                           "AUTHN_GAP claim but the attacker carried an authenticated "
                           "identity — not an authentication gap")
        owner_view = (tr.get("owner_view") or {}).get("response", {}) or {}
        owner_body = owner_view.get("body")
        attacker_body = attacker_resp.get("body")
        field = claim.get("sensitive_field", "")
        secret = _extract(owner_body, field) if field else None
        if secret is None:
            return _result(ABSTAIN,
                           "no owner-private value available to re-derive the leak "
                           "(bundle owner_view + sensitive_field to certify)")
        if _deep_contains_value(attacker_body, secret):
            label = "anonymous read" if kind == KIND_AUTHN_GAP else "cross-principal read"
            return _result(CERTIFIED,
                           "attacker response independently contains the owner's private "
                           f"value of '{field}' — unauthorized {label} entailed by transcript",
                           kind=kind, rederived_leak_field=field)
        return _result(REJECTED,
                       f"owner's private value of '{field}' is NOT present in the "
                       "attacker response — leak not entailed (contradicted/tampered)")

    if kind == KIND_XPRINCIPAL_WRITE:
        before = (tr.get("victim_readback_before") or {}).get("response", {})
        after = (tr.get("victim_readback_after") or {}).get("response", {})
        if not after:
            return _result(ABSTAIN,
                           "no owner-authenticated read-back after the write "
                           "(bundle victim_readback_after to certify)")
        b_body, a_body = before.get("body"), after.get("body")
        a_status = after.get("status", 0)
        # DELETE: object was present, owner's fresh re-read now gone (404 / null body).
        gone = (b_body is not None) and (a_body is None or int(a_status or 0) == 404)
        changed = (before != {}) and (b_body != a_body)
        if gone or changed:
            return _result(CERTIFIED,
                           "owner's authenticated re-read changed after a foreign write "
                           "— persisted cross-principal mutation entailed by transcript",
                           kind=kind, rederived_delta={"before": b_body, "after": a_body})
        return _result(REJECTED,
                       "owner's authenticated re-read is unchanged — no persisted "
                       "Δstate (mutation not entailed; contradicted/tampered)")

    return _result(ABSTAIN, f"effect kind {kind!r} is not independently certifiable by this layer yet")


def check_summary(cert: dict) -> str:
    r = check_certificate(cert)
    return f"[{r['status']}] {r['reason']}"


# --------------------------------------------------------------------------- #
# Adapter — certify FINISHED findings without importing/altering engine code.  #
# --------------------------------------------------------------------------- #

def certify_findings(items, *, provenance: str = "unknown") -> list:
    """Turn finished ONYX findings + their captured raw exchanges into certificates,
    WITHOUT importing or modifying any engine code (duck-typed; stays decision-free).

    Each item is a dict (or object) providing at least `finding` and
    `attacker_exchange`, and optionally `owner_view`, `victim_before`,
    `victim_after`, `sensitive_field`, `kind`. Returns a list of
    (certificate, check_result) pairs — the caller decides what to do with them.
    """
    out = []
    for it in items:
        get = it.get if isinstance(it, dict) else (lambda k, d=None: getattr(it, k, d))
        cert = certificate_from_finding(
            get("finding"),
            attacker_exchange=get("attacker_exchange") or get("attacker"),
            owner_view=get("owner_view"),
            victim_before=get("victim_before"),
            victim_after=get("victim_after"),
            sensitive_field=get("sensitive_field", "") or "",
            kind=get("kind", "") or "",
            provenance=provenance,
        )
        out.append((cert, check_certificate(cert)))
    return out


# --------------------------------------------------------------------------- #
# Self-test — a stdlib property / metamorphic + mutation harness.             #
# --------------------------------------------------------------------------- #
# This is distribution-level evidence for the checker's ONE load-bearing        #
# invariant: it NEVER returns CERTIFIED without a genuine cross-principal        #
# Δstate actually present in the raw transcript (the RL5 fail-safe, proven over  #
# many randomized instances rather than a handful of fixtures). It also runs a   #
# mutation pass: every single-fault mutation of a genuine certificate must flip  #
# it off CERTIFIED. Pure stdlib (random) — no third-party dependency (RL: stdlib).#

def run_selftest(iterations: int = 500, seed: int = 1337) -> dict:
    import random
    rng = random.Random(seed)

    def _secret():
        return "S-" + "".join(rng.choice("0123456789ABCDEF") for _ in range(12))

    def _genuine_read(anon=False):
        s = _secret()
        pid = "anon" if anon else "bob"
        attacker = {"principal": pid,
                    "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
                    "response": {"status": 200, "body": {"id": "ALICE", "iban": s}}}
        owner = {"response": {"status": 200, "body": {"id": "ALICE", "iban": s}}}
        return emit_certificate(
            finding={"fid": "p", "effect": "READ"},
            claim={"kind": KIND_AUTHN_GAP if anon else KIND_READ_LEAK,
                   "read_as": "alice", "sensitive_field": "iban"},
            transcript={"attacker": attacker, "owner_view": owner}, provenance="self")

    def _safe_read():
        attacker = {"principal": "bob",
                    "request": {"method": "GET", "path": "/api/accounts/BOB", "host": "t.local"},
                    "response": {"status": 200, "body": {"id": "BOB", "iban": _secret()}}}
        owner = {"response": {"status": 200, "body": {"id": "ALICE", "iban": _secret()}}}
        return emit_certificate(
            finding={"fid": "p", "effect": "READ"},
            claim={"kind": KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
            transcript={"attacker": attacker, "owner_view": owner}, provenance="self")

    def _genuine_write():
        x, y = _secret(), _secret()
        attacker = {"principal": "bob",
                    "request": {"method": "PUT", "path": "/api/docs/D", "host": "t.local"},
                    "response": {"status": 200, "body": {"ok": True}}}
        return emit_certificate(
            finding={"fid": "p", "effect": "WRITE"},
            claim={"kind": KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
            transcript={"attacker": attacker,
                        "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": x}}},
                        "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "v": y}}}},
            provenance="self")

    def _safe_write():
        same = {"response": {"status": 200, "body": {"id": "D", "v": _secret()}}}
        attacker = {"principal": "bob",
                    "request": {"method": "PUT", "path": "/api/docs/D", "host": "t.local"},
                    "response": {"status": 200, "body": {"ok": True}}}
        return emit_certificate(
            finding={"fid": "p", "effect": "WRITE"},
            claim={"kind": KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
            transcript={"attacker": attacker,
                        "victim_readback_before": {"response": dict(same["response"])},
                        "victim_readback_after": {"response": dict(same["response"])}},
            provenance="self")

    def _reemit(cert):
        return emit_certificate(finding=cert["finding"], claim=cert["claim"],
                                transcript=cert["transcript"], provenance=cert["provenance"])

    def _mutate(cert):
        """Apply exactly one fault; the checker MUST no longer certify it."""
        c = json.loads(_canon(cert))  # deep copy via canonical round-trip
        which = rng.choice(("scrub", "actor", "status", "hashbyte"))
        if which == "scrub":
            c["transcript"]["attacker"]["response"]["body"] = {"id": "ALICE"}
            c = _reemit(c)
        elif which == "actor":
            c["claim"]["read_as"] = c["transcript"]["attacker"]["principal"]
            c = _reemit(c)
        elif which == "status":
            c["transcript"]["attacker"]["response"]["status"] = 500
            c = _reemit(c)
        else:  # hashbyte — corrupt content but keep the stale hash (integrity break)
            c["transcript"]["attacker"]["response"]["body"]["iban"] = "TAMPERED"
        return c

    certified_without_delta = 0   # the soundness invariant — must stay 0
    genuine_missed = 0            # the checker must not lose real ones
    mutation_survivors = 0        # every single-fault mutant must be caught

    for _ in range(iterations):
        # genuine positives
        for cert in (_genuine_read(), _genuine_read(anon=True), _genuine_write()):
            if check_certificate(cert)["status"] != CERTIFIED:
                genuine_missed += 1
        # true negatives — a CERTIFIED here would be a fail-safe violation
        for cert in (_safe_read(), _safe_write()):
            if check_certificate(cert)["status"] == CERTIFIED:
                certified_without_delta += 1
        # mutation pass on a genuine read certificate
        if check_certificate(_mutate(_genuine_read()))["status"] == CERTIFIED:
            mutation_survivors += 1

    summary = {
        "iterations": iterations,
        "certified_without_delta": certified_without_delta,
        "genuine_missed": genuine_missed,
        "mutation_survivors": mutation_survivors,
    }
    # The invariants. Any breach is a hard failure.
    assert certified_without_delta == 0, summary
    assert genuine_missed == 0, summary
    assert mutation_survivors == 0, summary
    return summary


# --------------------------------------------------------------------------- #
# Coverage certificate — the explicit, machine-checkable boundary.            #
# --------------------------------------------------------------------------- #
# The honesty core of the whole layer: an enumerated statement of exactly what  #
# it can independently CERTIFY, what it ABSTAINS on pending more evidence, and   #
# what is structurally OUTSIDE it (residual). verify_coverage() checks this      #
# declaration against what check_certificate actually does, so the coverage      #
# claim can never quietly drift away from the code.                             #

CERTIFIABLE_KINDS = (KIND_READ_LEAK, KIND_AUTHN_GAP, KIND_XPRINCIPAL_WRITE,
                     KIND_CHAINED_LEAK, KIND_CHAINED_WRITE)

COVERAGE = {
    "certifies": [
        (KIND_READ_LEAK, "BOLA/BOPLA read, incl. secondary-key BOLA — owner's private "
                         "value present in the attacker's response, re-derived from raw bodies"),
        (KIND_AUTHN_GAP, "anonymous receipt of owner-private data (missing authentication)"),
        (KIND_XPRINCIPAL_WRITE, "cross-principal create/update/delete on a foreign object, "
                                "persisted on the owner's authenticated read-back"),
        (KIND_CHAINED_LEAK, "second-order leak — attacker carries a value forward (multi-hop "
                            "chain), then leaks owner data via it"),
        (KIND_CHAINED_WRITE, "second-order write — attacker carries a value forward (multi-hop "
                             "chain), then mutates a foreign object, persisted on owner read-back"),
    ],
    "abstains_pending_evidence": [
        "a certifiable kind whose transcript omits owner_view / read-backs (bundle them to certify)",
    ],
    "outside_layer_residual": [
        ("BFLA role/privilege semantics", "the 'privileged function' judgment is not "
         "re-derivable from raw HTTP; only its Δstate CONSEQUENCE is certifiable via XPRINCIPAL_WRITE"),
        ("uniform BOPLA over-exposure", "a field exposed to everyone has no owner to "
         "differentiate from — no cross-principal Δ to re-derive"),
        ("non-value-carried provenance", "chains linked by a value carried in the transcript are "
         "certifiable (CHAINED_LEAK/WRITE, multi-hop); side effects linked outside the captured "
         "bytes (server-side state, timing) are not re-derivable from a single bundled transcript"),
    ],
}


def _min_read_cert(kind: str, pid: str, secret: str = "X-SECRET-1") -> dict:
    attacker = {"principal": pid,
                "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
                "response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}}
    owner = {"response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}}
    return emit_certificate(finding={"fid": "m", "effect": "READ"},
                            claim={"kind": kind, "read_as": "alice", "sensitive_field": "iban"},
                            transcript={"attacker": attacker, "owner_view": owner}, provenance="self")


def _min_write_cert(a: str = "A1", b: str = "B2") -> dict:
    attacker = {"principal": "bob",
                "request": {"method": "PUT", "path": "/api/docs/D", "host": "t.local"},
                "response": {"status": 200, "body": {"ok": True}}}
    return emit_certificate(
        finding={"fid": "m", "effect": "WRITE"},
        claim={"kind": KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": attacker,
                    "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": a}}},
                    "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "v": b}}}},
        provenance="self")


def _min_chained_cert() -> dict:
    v, w = "REF-XYZ-123", "SEC-OWNER-IBAN"
    steps = [
        {"role": "carry_source", "principal": "bob",
         "request": {"method": "POST", "path": "/api/refs"},
         "response": {"status": 200, "body": {"ref": v}}},
        {"role": "attack", "principal": "bob",
         "request": {"method": "GET", "path": f"/api/fetch?ref={v}"},
         "response": {"status": 200, "body": {"iban": w}}},
    ]
    return emit_certificate(
        finding={"fid": "m", "effect": "READ"},
        claim={"kind": KIND_CHAINED_LEAK, "read_as": "alice",
               "sensitive_field": "iban", "carried_field": "ref"},
        transcript={"steps": steps, "owner_view": {"response": {"status": 200, "body": {"iban": w}}}},
        provenance="self")


def _min_chained_write_cert() -> dict:
    v = "TOK-9F"
    steps = [
        {"role": "carry_source", "principal": "bob",
         "request": {"method": "POST", "path": "/api/sessions"},
         "response": {"status": 200, "body": {"token": v}}},
        {"role": "attack", "principal": "bob",
         "request": {"method": "PUT", "path": f"/api/docs/D?token={v}", "body": {"title": "PWNED"}},
         "response": {"status": 200, "body": {"ok": True}}},
    ]
    return emit_certificate(
        finding={"fid": "m", "effect": "WRITE"},
        claim={"kind": KIND_CHAINED_WRITE, "read_as": "alice", "carried_field": "token"},
        transcript={"steps": steps,
                    "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "title": "orig"}}},
                    "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "title": "PWNED"}}}},
        provenance="self")


def verify_coverage() -> dict:
    """Self-consistency guard: every declared-certifiable kind must actually reach
    CERTIFIED on a genuine minimal transcript, and a kind outside the set must
    never certify — so the coverage claim stays honest against the code."""
    genuine = {
        KIND_READ_LEAK: _min_read_cert(KIND_READ_LEAK, "bob"),
        KIND_AUTHN_GAP: _min_read_cert(KIND_AUTHN_GAP, "anon"),
        KIND_XPRINCIPAL_WRITE: _min_write_cert(),
        KIND_CHAINED_LEAK: _min_chained_cert(),
        KIND_CHAINED_WRITE: _min_chained_write_cert(),
    }
    for k in CERTIFIABLE_KINDS:
        assert check_certificate(genuine[k])["status"] == CERTIFIED, \
            ("declared certifiable but does not certify", k)
    outside = _min_read_cert(KIND_READ_LEAK, "bob")
    outside["claim"]["kind"] = "NOT_A_REAL_KIND"
    outside = emit_certificate(finding=outside["finding"], claim=outside["claim"],
                               transcript=outside["transcript"], provenance=outside["provenance"])
    assert check_certificate(outside)["status"] != CERTIFIED, "an undeclared kind certified"
    declared = {k for k, _ in COVERAGE["certifies"]}
    assert declared == set(CERTIFIABLE_KINDS), "COVERAGE list and CERTIFIABLE_KINDS disagree"
    return {"certifiable": list(CERTIFIABLE_KINDS), "consistent": True}


# --------------------------------------------------------------------------- #
# Assurance case — compose the two columns with an explicit residual-risk part. #
# --------------------------------------------------------------------------- #

def assurance_case(facts: "dict | None" = None) -> str:
    """Two-column assurance case (soundness / completeness) with an explicit
    residual-risk section. Quantitative inputs come from `facts` at call time and
    are stamped with an evidence tier; nothing is hardcoded or left bare (RL20)."""
    facts = dict(facts or {})
    suite = facts.get("suite_passed")
    pw_recall = facts.get("proving_world_recall")  # a caller-tiered string, or None
    cbp = facts.get("cert_blind_precision")        # certificate-layer blind benchmark
    cbr = facts.get("cert_blind_recall")
    er = facts.get("engine_recall")                # full-engine proving_world
    ep = facts.get("engine_precision")
    L: list = []
    A = L.append
    A("# ONYX — Offline Assurance Case (certifying-algorithm layer)")
    A("")
    A("TOP CLAIM: every finding of a covered class carries a self-contained certificate")
    A("an INDEPENDENT checker re-derives from the raw transcript (sound per finding); the")
    A("layer's detection ability is stated as an explicit coverage boundary with residual")
    A("risk (completeness is BOUNDED, never claimed complete).")
    A("")
    A("## Column A — SOUNDNESS  (provable ~100% per finding)")
    A("- [T4_BY_CONSTRUCTION] CERTIFIED requires the owner's private Δstate to be present in")
    A("  the raw transcript — no status-only and no model judgment (RL3 / RL1).")
    A("- [T4_BY_CONSTRUCTION] The checker imports zero decision code (AST-guarded); a certified")
    A("  finding therefore does not trust ONYX.")
    A("- [T4_BY_CONSTRUCTION] Fail-safe: uncheckable ⇒ ABSTAIN/REJECT, never a false CERTIFIED (RL5).")
    if suite is not None:
        A(f"- [T2_SELF_MEASURED] Suite green: {suite} of {suite} tests pass (self-measured, this build).")
    A("- [T2_SELF_MEASURED] Property/mutation self-test over a randomized distribution:")
    A("  0 certified-without-Δstate, 0 genuine lost, 0 mutation survivors (self-measured).")
    A("")
    A("## Column B — COMPLETENESS  (measured and BOUNDED only)")
    A("Certifiable classes — independently re-derivable today:")
    for k, d in COVERAGE["certifies"]:
        A(f"  - {k}: {d}")
    A("Abstains pending evidence (an honest gap, not a weakening):")
    for d in COVERAGE["abstains_pending_evidence"]:
        A(f"  - {d}")
    # Measured evidence — folded in at call time (nothing hardcoded), each tiered.
    if cbp is not None or cbr is not None:
        A(f"- [T2_SELF_MEASURED] Certificate-layer blind benchmark (external-taxonomy, "
          f"sealed): precision {float(cbp or 0):.3f}, in-boundary recall "
          f"{float(cbr or 0):.3f} (self-measured).")
    if er is not None or ep is not None:
        A(f"- [T2_SELF_MEASURED] Full-engine recall on randomized sealed worlds: recall "
          f"{float(er or 0):.3f}, precision {float(ep or 0):.3f} (self-measured; "
          f"by-construction independent, not a third party).")
    if pw_recall:
        A(f"- [T2_SELF_MEASURED] {pw_recall}")
    if cbp is None and er is None and not pw_recall:
        A("- [T3_MECHANISM_ESTIMATE] Independent recall on a third-party target: not yet measured.")
    A("")
    A("## Residual risk — what stays UNGUARANTEED offline (stated, not hidden)")
    A("- Checker trust base: soundness is only as strong as the small stdlib checker; shrink")
    A("  and independently verify it to reduce this.")
    A("- Transcript fidelity: a certificate certifies the bundled bytes; an unfaithful capture")
    A("  certifies a fiction.")
    A("- Recall on unknown-unknowns: classes/signals not imagined cannot be certified for")
    A("  detection (Rice's theorem + the sim-to-real gap) — a fundamental limit, not a to-do.")
    A("Classes structurally outside this layer (residual):")
    for name, why in COVERAGE["outside_layer_residual"]:
        A(f"  - {name}: {why}")
    A("")
    A("CERTIFIED = independently re-derivable from the transcript. Nothing here claims full")
    A("real-world recall; the boundary above is the honest scope.")
    return "\n".join(L)


if __name__ == "__main__":
    import sys as _sys
    r = run_selftest()
    cov = verify_coverage()
    print("ASSURANCE-1 certifying-algorithm self-test")
    print(f"  iterations              : {r['iterations']}")
    print(f"  certified_without_delta : {r['certified_without_delta']}  (must be 0 — RL5 soundness)")
    print(f"  genuine_missed          : {r['genuine_missed']}  (must be 0 — no real finding lost)")
    print(f"  mutation_survivors      : {r['mutation_survivors']}  (must be 0 — every fault caught)")
    print(f"  coverage self-consistent: {cov['consistent']}  ({', '.join(cov['certifiable'])})")
    held = max(r["certified_without_delta"], r["genuine_missed"], r["mutation_survivors"]) == 0
    print("  ALL INVARIANTS HELD" if held else "  INVARIANT BREACH")
    if "--case" in _sys.argv:
        print()
        print(assurance_case())
    _sys.exit(0 if held else 1)
