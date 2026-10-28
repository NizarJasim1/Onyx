"""
ASSURANCE-1 — the certifying-algorithm layer.

Proves the independent checker (authpath/certificate.py) is a real certifying
verifier: it CERTIFIES a genuine finding by re-deriving the verdict from the raw
transcript, REJECTS any tampered/forged certificate, and ABSTAINS honestly when the
bundled transcript is insufficient — never emitting a false CERTIFIED (RL5).

The independence of the checker is enforced STRUCTURALLY (an AST guard), mirroring
the proving-world's anti-circularity discipline: the checker must not import any of
ONYX's decision code, or it would merely be trusting the tool it is meant to check.
"""
import ast
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath import certificate as C


# --------------------------------------------------------------------------- #
# Fixtures — raw transcripts, authored like an ordinary HTTP capture.          #
# --------------------------------------------------------------------------- #

def _read_leak_cert():
    """Alice's private IBAN leaks to Bob via GET /api/accounts/ALICE."""
    owner_view = {  # Alice reading her OWN account (owner-authenticated)
        "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
        "response": {"status": 200, "body": {"id": "ALICE", "iban": "DE89-3704-0044-0532-0130-00"}},
    }
    attacker = {  # Bob reading Alice's account and getting it back
        "principal": "bob",
        "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
        "response": {"status": 200, "body": {"id": "ALICE", "iban": "DE89-3704-0044-0532-0130-00"}},
    }
    return C.emit_certificate(
        finding={"fid": "f1", "title": "BOLA read-leak", "effect": "READ",
                 "impact": "PII", "law_name": "OwnershipLaw", "actor_pid": "bob",
                 "target_ref": "account:ALICE"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice",
               "sensitive_field": "iban", "claimed_before": None, "claimed_after": None},
        transcript={"attacker": attacker, "owner_view": owner_view},
        provenance="self",
    )


def _xwrite_cert(delete=False):
    """Bob mutates Alice's object; Alice's fresh re-read confirms the persisted change."""
    if delete:
        before = {"response": {"status": 200, "body": {"id": "DOC9", "title": "Alice memo"}}}
        after = {"response": {"status": 404, "body": None}}
    else:
        before = {"response": {"status": 200, "body": {"id": "DOC9", "title": "Alice memo"}}}
        after = {"response": {"status": 200, "body": {"id": "DOC9", "title": "PWNED"}}}
    attacker = {
        "principal": "bob",
        "request": {"method": "DELETE" if delete else "PUT", "path": "/api/docs/DOC9", "host": "t.local"},
        "response": {"status": 200, "body": {"ok": True}},
    }
    return C.emit_certificate(
        finding={"fid": "f2", "title": "cross-principal write", "effect": "WRITE",
                 "impact": "INTEGRITY", "law_name": "XPrincipalWrite", "actor_pid": "bob"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice", "sensitive_field": ""},
        transcript={"attacker": attacker,
                    "victim_readback_before": before, "victim_readback_after": after},
        provenance="self",
    )


# --------------------------------------------------------------------------- #
# CERTIFIED — genuine findings are independently re-derivable.                 #
# --------------------------------------------------------------------------- #

def test_genuine_read_leak_is_certified():
    r = C.check_certificate(_read_leak_cert())
    assert r["status"] == C.CERTIFIED, r


def test_genuine_xprincipal_write_is_certified():
    r = C.check_certificate(_xwrite_cert(delete=False))
    assert r["status"] == C.CERTIFIED, r


def test_genuine_xprincipal_delete_is_certified():
    r = C.check_certificate(_xwrite_cert(delete=True))
    assert r["status"] == C.CERTIFIED, r


# --------------------------------------------------------------------------- #
# REJECTED — tamper and forgery cannot pass the checker.                       #
# --------------------------------------------------------------------------- #

def test_hash_tamper_is_rejected():
    cert = _read_leak_cert()
    cert["transcript"]["attacker"]["response"]["body"]["iban"] = "AA00-0000"  # change body, keep old hash
    r = C.check_certificate(cert)
    assert r["status"] == C.REJECTED and "integrity" in r["reason"], r


def test_dropped_leak_is_rejected_even_after_rehash():
    # Attacker who removes the leaked value AND recomputes hashes still fails,
    # because the raw transcript no longer ENTAILS the leak.
    cert = _read_leak_cert()
    cert["transcript"]["attacker"]["response"]["body"] = {"id": "ALICE"}  # iban scrubbed
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.REJECTED and "not entailed" in r["reason"].lower() \
        or r["status"] == C.REJECTED and "not present" in r["reason"].lower(), r


def test_forged_write_with_unchanged_readback_is_rejected():
    cert = _xwrite_cert(delete=False)
    # Owner's re-read is actually unchanged → no persisted Δstate → cannot certify.
    same = {"response": {"status": 200, "body": {"id": "DOC9", "title": "Alice memo"}}}
    cert["transcript"]["victim_readback_after"] = copy.deepcopy(same)
    cert["transcript"]["victim_readback_before"] = copy.deepcopy(same)
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.REJECTED, r


def test_non_2xx_attacker_is_rejected():
    cert = _read_leak_cert()
    cert["transcript"]["attacker"]["response"]["status"] = 403
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.REJECTED, r


def test_actor_equals_owner_is_rejected():
    cert = _read_leak_cert()
    cert["claim"]["read_as"] = "bob"  # same as attacker principal
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.REJECTED, r


# --------------------------------------------------------------------------- #
# ABSTAIN — honest coverage gap, never a false CERTIFIED (RL5).                #
# --------------------------------------------------------------------------- #

def test_missing_owner_view_abstains_not_certifies():
    cert = _read_leak_cert()
    del cert["transcript"]["owner_view"]
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.ABSTAIN, r


def test_unknown_kind_abstains():
    cert = _read_leak_cert()
    cert["claim"]["kind"] = "SOME_FUTURE_CLASS"
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    r = C.check_certificate(cert)
    assert r["status"] == C.ABSTAIN, r


# --------------------------------------------------------------------------- #
# INDEPENDENCE — structural guard (anti-circularity), not a promise.          #
# --------------------------------------------------------------------------- #

_DECISION_MODULES = {"confirmer", "eil", "engine", "provenance", "envelope",
                     "contract", "conservation", "nerve_bridge", "broadcast"}


def test_checker_imports_no_decision_code():
    """The certificate module must not import any of ONYX's decision code, or the
    'independent' checker would merely be trusting the tool it checks."""
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "authpath", "certificate.py")
    with open(src, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "")
            if mod.startswith("authpath"):
                tail = mod.split(".")[-1]
                imported.add(tail)
            imported.add(mod.split(".")[0])
    leaked = imported & _DECISION_MODULES
    assert not leaked, f"certificate.py leaked decision-code imports: {leaked}"
    # And it must not import the authpath package at all in its decision path.
    assert "authpath" not in imported, "certificate.py must stay authpath-free (independence)"


# --------------------------------------------------------------------------- #
# Increment 2 — AUTHN_GAP, secondary-key BOLA, and the property harness.       #
# --------------------------------------------------------------------------- #

def _authn_gap_cert(authenticated_attacker=False):
    """An anonymous caller receives Alice's private IBAN (missing authentication)."""
    secret = "GB00-BARC-2000-0055-7799-11"
    owner_view = {"response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}}
    attacker = {"principal": ("mallory" if authenticated_attacker else "anon"),
                "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
                "response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}}
    return C.emit_certificate(
        finding={"fid": "f3", "title": "anon read of private account", "effect": "READ"},
        claim={"kind": C.KIND_AUTHN_GAP, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": attacker, "owner_view": owner_view}, provenance="self")


def test_authn_gap_anonymous_leak_is_certified():
    r = C.check_certificate(_authn_gap_cert())
    assert r["status"] == C.CERTIFIED, r


def test_authn_gap_claim_with_authenticated_attacker_abstains():
    # If the caller actually had an identity, it is not an auth gap — abstain,
    # never silently certify it as one.
    r = C.check_certificate(_authn_gap_cert(authenticated_attacker=True))
    assert r["status"] == C.ABSTAIN, r


def test_secondary_key_bola_read_leak_is_certified():
    # An object addressed by a secondary key (?invoice=) still certifies via the
    # read-leak predicate — the addressing form does not change the entailment.
    secret = "owner@victim.example"
    owner_view = {"response": {"status": 200, "body": {"invoice": "INV-9", "email": secret}}}
    attacker = {"principal": "bob",
                "request": {"method": "GET", "path": "/api/orders?invoice=INV-9", "host": "t.local"},
                "response": {"status": 200, "body": {"invoice": "INV-9", "email": secret}}}
    cert = C.emit_certificate(
        finding={"fid": "f4", "title": "secondary-key BOLA", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "email"},
        transcript={"attacker": attacker, "owner_view": owner_view}, provenance="self")
    assert C.check_certificate(cert)["status"] == C.CERTIFIED


def test_property_and_mutation_selftest_invariants_hold():
    # Distribution-level proof of the RL5 fail-safe: never CERTIFIED without a
    # genuine cross-principal Δstate; every single-fault mutant is caught.
    s = C.run_selftest(iterations=300, seed=7)
    assert s["certified_without_delta"] == 0, s
    assert s["genuine_missed"] == 0, s
    assert s["mutation_survivors"] == 0, s


def test_adapter_certifies_finished_findings():
    # The engine-free adapter turns finished findings + raw exchanges into
    # certificates without importing engine code.
    items = [{
        "finding": {"fid": "a1", "effect": "READ", "title": "x"},
        "attacker": {"principal": "bob",
                     "request": {"method": "GET", "path": "/api/accounts/ALICE", "host": "t.local"},
                     "response": {"status": 200, "body": {"id": "ALICE", "iban": "ZZ-1"}}},
        "owner_view": {"response": {"status": 200, "body": {"id": "ALICE", "iban": "ZZ-1"}}},
        "sensitive_field": "iban", "kind": C.KIND_READ_LEAK,
    }]
    pairs = C.certify_findings(items, provenance="self")
    assert len(pairs) == 1 and pairs[0][1]["status"] == C.CERTIFIED, pairs


# --------------------------------------------------------------------------- #
# Increment 3 — coverage certificate + assurance-case composer.                #
# --------------------------------------------------------------------------- #

def test_coverage_is_self_consistent_with_the_code():
    # Every declared-certifiable kind must actually certify; an undeclared kind
    # must not. Keeps the coverage claim from drifting away from check_certificate.
    v = C.verify_coverage()
    assert v["consistent"] is True, v
    assert set(v["certifiable"]) == {k for k, _ in C.COVERAGE["certifies"]}


def test_assurance_case_has_both_columns_and_residual_risk():
    text = C.assurance_case({"suite_passed": 685})
    assert "SOUNDNESS" in text and "COMPLETENESS" in text, text[:200]
    assert "Residual risk" in text, "the honest residual-risk section must be present"
    # honesty invariant: it must never claim full real-world recall
    assert "full" in text and "real-world recall" in text
    # every certifiable kind is named in the case
    for k, _ in C.COVERAGE["certifies"]:
        assert k in text


def test_assurance_case_tiers_every_metric_no_bare_number():
    # RL20 discipline applied to our own output: any metric carries a tier tag.
    text = C.assurance_case({"suite_passed": 685})
    for line in text.splitlines():
        if "685" in line:
            assert "T2_" in line or "T1_" in line, f"bare metric without tier: {line}"





# --------------------------------------------------------------------------- #
# Increment 7 — evidence-backed assurance case + CRUD coverage clarification.  #
# --------------------------------------------------------------------------- #

def test_assurance_case_folds_measured_facts_with_tiers():
    text = C.assurance_case({"cert_blind_precision": 1.0, "cert_blind_recall": 1.0,
                             "engine_recall": 0.92, "engine_precision": 1.0})
    assert "blind benchmark" in text and "Full-engine recall" in text, text
    for line in text.splitlines():
        if "0.92" in line:
            assert "T2_" in line, f"measured metric without a tier: {line}"


def test_xprincipal_write_covers_create():
    # create (absent -> present, confirmed by owner read-back) is covered by the
    # write predicate — CRUD create/update/delete all reduce to a persisted Δstate.
    attacker = {"principal": "bob",
                "request": {"method": "POST", "path": "/api/docs", "host": "t.local"},
                "response": {"status": 201, "body": {"id": "NEW"}}}
    cert = C.emit_certificate(
        finding={"fid": "c", "effect": "WRITE"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": attacker,
                    "victim_readback_before": {"response": {"status": 404, "body": None}},
                    "victim_readback_after": {"response": {"status": 200, "body": {"id": "NEW", "owner": "bob"}}}},
        provenance="self")
    assert C.check_certificate(cert)["status"] == C.CERTIFIED


def test_assurance_report_measures_real_engine_recall():
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "tools", "assurance_report.py")
    spec = importlib.util.spec_from_file_location("assurance_report", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    facts = mod.measure(cert_seeds=range(1, 4), world_seeds=range(1, 4))
    assert facts.get("cert_selftest_ok") is True, facts
    assert facts.get("coverage_consistent") is True, facts
    er = facts.get("engine_recall")
    assert er is not None and 0.0 <= er <= 1.0, facts
    assert facts.get("engine_precision") == 1.0, facts  # zero-FP core holds on the full engine


# --------------------------------------------------------------------------- #
# Increment 8 — multi-step / chained (second-order) certification.            #
# --------------------------------------------------------------------------- #

def test_chained_genuine_second_order_leak_is_certified():
    assert C.check_certificate(C._min_chained_cert())["status"] == C.CERTIFIED


def test_chained_broken_link_is_rejected():
    # carried value NOT used in the attack request -> the chain link is absent,
    # so even though the owner value is in the response, it is not a proven chain.
    cert = C._min_chained_cert()
    cert["transcript"]["steps"][1]["request"]["path"] = "/api/fetch?ref=UNRELATED"
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.REJECTED


def test_chained_no_leak_is_rejected():
    # carried value IS used, but the attack response does not contain the owner value.
    cert = C._min_chained_cert()
    cert["transcript"]["steps"][1]["response"]["body"] = {"iban": "SOMETHING-ELSE"}
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.REJECTED


def test_chained_actor_equals_owner_is_rejected():
    cert = C._min_chained_cert()
    cert["claim"]["read_as"] = "bob"  # same principal as the attack step
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.REJECTED


def test_chained_missing_steps_abstains():
    cert = C._min_chained_cert()
    cert["transcript"] = {"owner_view": cert["transcript"]["owner_view"]}  # drop steps
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.ABSTAIN


def test_coverage_lists_chained_kind():
    assert C.KIND_CHAINED_LEAK in {k for k, _ in C.COVERAGE["certifies"]}
    assert C.KIND_CHAINED_LEAK in C.CERTIFIABLE_KINDS


# --------------------------------------------------------------------------- #
# Increment 9 — chained WRITE + deeper multi-hop chains.                       #
# --------------------------------------------------------------------------- #

def test_chained_write_genuine_is_certified():
    assert C.check_certificate(C._min_chained_write_cert())["status"] == C.CERTIFIED


def test_chained_write_unchanged_readback_is_rejected():
    cert = C._min_chained_write_cert()
    same = {"response": {"status": 200, "body": {"id": "D", "title": "orig"}}}
    cert["transcript"]["victim_readback_before"] = {"response": dict(same["response"])}
    cert["transcript"]["victim_readback_after"] = {"response": dict(same["response"])}
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.REJECTED


def _multihop_leak(v0="A0", v1="B1", w="SEC-W"):
    steps = [
        {"role": "carry_source", "principal": "bob",
         "request": {"method": "POST", "path": "/s1"}, "response": {"status": 200, "body": {"a": v0}}},
        {"role": "carry_source", "principal": "bob",
         "request": {"method": "GET", "path": f"/s2?a={v0}"}, "response": {"status": 200, "body": {"b": v1}}},
        {"role": "attack", "principal": "bob",
         "request": {"method": "GET", "path": f"/fetch?b={v1}"}, "response": {"status": 200, "body": {"iban": w}}},
    ]
    return C.emit_certificate(
        finding={"fid": "mh", "effect": "READ"},
        claim={"kind": C.KIND_CHAINED_LEAK, "read_as": "alice",
               "sensitive_field": "iban", "carried_fields": ["a", "b"]},
        transcript={"steps": steps, "owner_view": {"response": {"status": 200, "body": {"iban": w}}}},
        provenance="self")


def test_chained_multihop_leak_is_certified():
    assert C.check_certificate(_multihop_leak())["status"] == C.CERTIFIED


def test_chained_multihop_broken_middle_link_is_rejected():
    cert = _multihop_leak()
    # break the SECOND hop: attack request no longer carries v1
    cert["transcript"]["steps"][2]["request"]["path"] = "/fetch?b=UNRELATED"
    cert = C.emit_certificate(finding=cert["finding"], claim=cert["claim"],
                              transcript=cert["transcript"], provenance=cert["provenance"])
    assert C.check_certificate(cert)["status"] == C.REJECTED


def test_coverage_lists_chained_write():
    assert C.KIND_CHAINED_WRITE in {k for k, _ in C.COVERAGE["certifies"]}
    assert C.KIND_CHAINED_WRITE in C.CERTIFIABLE_KINDS


if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    print("\nASSURANCE-1 certifying-algorithm — certificate tests\n" + "-" * 60)
    p = _fail = 0
    for n, f in fns:
        try:
            f(); p += 1; print(f"  [PASS] {n}")
        except Exception:
            _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-" * 60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
