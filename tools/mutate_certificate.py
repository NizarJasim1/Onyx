"""Mutation testing on certificate.py: break each decision the INDEPENDENT checker
depends on; every mutant MUST kill >=1 certificate test. A survivor = a teethless
test (a real gap). This turns "the certificate tests pass" into "the certificate
tests would catch a fault injected into the checker's logic" — the mutation-adequacy
evidence the assurance layer needs about ITSELF. Same idiom as mutate_evidence.py."""
import os
import sys
import subprocess

SRC = "authpath/certificate.py"
TESTS = ["tests/test_certificate_independent.py"]
orig = open(SRC).read()

# (label, find, replace) — each breaks ONE load-bearing decision in check_certificate.
MUTANTS = [
    ("integrity/hash-chain gate disabled (accept tampered certs)",
     '    if cert.get("hash_chain") != expect:',
     '    if False:  # MUTANT: integrity gate disabled'),

    ("non-2xx gate disabled (a denied request could 'leak')",
     "    if not _is_2xx(attacker_resp):",
     "    if False:  # MUTANT: non-2xx gate disabled"),

    ("cross-principal gate disabled (actor==owner could certify)",
     "    if attacker_pid and read_as and attacker_pid == read_as:",
     "    if False:  # MUTANT: cross-principal gate disabled"),

    ("missing owner-value ABSTAIN flipped to CERTIFIED (over-certify)",
     '        if secret is None:\n'
     '            return _result(ABSTAIN,\n'
     '                           "no owner-private value available to re-derive the leak "\n'
     '                           "(bundle owner_view + sensitive_field to certify)")',
     '        if secret is None:\n'
     '            return _result(CERTIFIED, "MUTANT: certified with no owner value")'),

    ("read-leak entailment bypassed (certify without the leak present)",
     "        if _deep_contains_value(attacker_body, secret):",
     "        if True:  # MUTANT: leak entailment bypassed"),

    ("AUTHN_GAP identity guard removed (authenticated caller certifies as anon)",
     '        if kind == KIND_AUTHN_GAP and str(attacker_pid).strip().lower() not in (\n'
     '                "", "anon", "anonymous", "none", "null", "public", "guest"):\n'
     '            return _result(ABSTAIN,\n'
     '                           "AUTHN_GAP claim but the attacker carried an authenticated "\n'
     '                           "identity — not an authentication gap")',
     '        if False:  # MUTANT: authn-gap identity guard removed\n'
     '            return _result(ABSTAIN, "unreachable")'),

    ("write Δstate check bypassed (certify an unchanged read-back)",
     "        if gone or changed:",
     "        if True:  # MUTANT: write delta bypassed"),

    ("chained chain-link check disabled (certify without the carry, any chained kind)",
     '        if not _request_carries(nxt.get("request") or {}, v):',
     "        if False:  # MUTANT: chain-link check disabled"),

    ("chained-leak entailment bypassed (certify without the leak present)",
     '    if _deep_contains_value(attack_resp.get("body"), secret):',
     "    if True:  # MUTANT: chained leak entailment bypassed"),

    ("chained-write Δstate check bypassed (certify an unchanged read-back)",
     "    if changed or gone:",
     "    if True:  # MUTANT: chained write delta bypassed"),
]

FLOOR = 10


def run_tests():
    for t in TESTS:
        r = subprocess.run([sys.executable, t], capture_output=True, text=True, cwd=os.getcwd())
        if r.returncode != 0:
            return False   # a test failed -> mutant killed
    return True


killed = survived = 0
for label, find, repl in MUTANTS:
    if find not in orig:
        print(f"  [SKIP] anchor not found: {label}"); continue
    open(SRC, "w").write(orig.replace(find, repl, 1))
    subprocess.run(["find", ".", "-name", "__pycache__", "-type", "d", "-exec", "rm", "-rf", "{}", "+"],
                   capture_output=True)
    alive = run_tests()   # True = all tests still passed = mutant SURVIVED
    open(SRC, "w").write(orig)
    if alive:
        survived += 1; print(f"  [SURVIVED] {label}  <-- TEETHLESS, gap!")
    else:
        killed += 1; print(f"  [killed]   {label}")

open(SRC, "w").write(orig)
subprocess.run(["find", ".", "-name", "__pycache__", "-type", "d", "-exec", "rm", "-rf", "{}", "+"],
               capture_output=True)
print(f"\nmutation score: {killed}/{killed + survived} killed (floor={FLOOR})")
sys.exit(0 if killed >= FLOOR else 1)
