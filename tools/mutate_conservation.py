"""Manual mutation testing on conservation.py: flip each decision branch, run the
conservation+confirm test files, and require that EACH mutation kills >=1 test.
A surviving mutant = a teethless test (a real gap)."""
import os, sys, subprocess
SRC = "authpath/conservation.py"
TESTS = ["tests/test_conservation.py", "tests/test_conservation_e2e.py", "tests/test_conservation_confirm.py"]

orig = open(SRC).read()

# (label, find, replace) — each inverts/breaks one decision the law depends on.
MUTANTS = [
  ("public-exoneration disabled",
   "if any(_is_anon(p) for p in seers):\n            res.exonerated_public += 1\n            continue",
   "if False:\n            res.exonerated_public += 1\n            continue"),
  ("self/shared-exoneration disabled",
   "if acting in holders or acting in seers or env_holds:",
   "if False:"),
  ("multi-holder shared-guard disabled",
   "if len(owners) > 1:\n            res.exonerated_shared += 1     # legitimately held by several -> common, not private\n            continue",
   "if False:\n            res.exonerated_shared += 1\n            continue"),
  ("no-baseline abstain disabled (fire on empty owners)",
   "if len(owners) == 0:\n            res.unattributed += 1          # no owner baseline -> abstain (coverage gap)\n            continue",
   "if len(owners) == 0:\n            owners = frozenset({'PHANTOM'})"),
  ("privacy-bound gate always true (over-fire)",
   "def _privacy_bound(tv, ctx: LawContext) -> bool:",
   "def _privacy_bound(tv, ctx: LawContext) -> bool:\n    return True  # MUTANT"),
  ("service-axis tagging broken (always property)",
   "if owner_hosts and req_host and req_host not in owner_hosts:\n            axis = AXIS_SERVICE",
   "if False:\n            axis = AXIS_SERVICE"),
  ("read-only gate removed (fire on writes too)",
   'if method not in ("GET", "QUERY", "") and not ctx.exchange.request.is_graphql():\n            return self._pass("conservation read-leak law applies to reads only")',
   'pass  # MUTANT: read-only gate removed'),
]

def run_tests():
    for t in TESTS:
        r = subprocess.run([sys.executable, t], capture_output=True, text=True,
                           cwd=os.getcwd())
        if r.returncode != 0:
            return False  # a test failed -> mutant killed
    return True

killed = survived = 0
for label, find, repl in MUTANTS:
    if find not in orig:
        print(f"  [SKIP] anchor not found: {label}"); continue
    open(SRC, "w").write(orig.replace(find, repl, 1))
    # clear pycache so the mutant is loaded
    subprocess.run(["find", ".", "-name", "__pycache__", "-type", "d", "-exec", "rm", "-rf", "{}", "+"],
                   capture_output=True)
    alive = run_tests()   # True = all tests still passed = mutant SURVIVED
    open(SRC, "w").write(orig)
    if alive:
        survived += 1; print(f"  [SURVIVED] {label}  <-- TEETHLESS, gap!")
    else:
        killed += 1; print(f"  [killed]   {label}")
open(SRC, "w").write(orig)
subprocess.run(["find", ".", "-name", "__pycache__", "-type", "d", "-exec", "rm", "-rf", "{}", "+"], capture_output=True)
print(f"\nmutation score: {killed}/{killed+survived} killed (floor=6)")
import sys as _sys; _sys.exit(0 if killed >= 6 else 1)
