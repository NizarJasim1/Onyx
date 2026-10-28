"""Mutation testing on evidence.py: flip each decision the discipline depends on;
each mutant MUST kill >=1 evidence test. A survivor = a teethless test."""
import os, sys, subprocess
SRC = "authpath/evidence.py"
TESTS = ["tests/test_evidence.py", "tests/test_evidence_integration.py"]
orig = open(SRC).read()

MUTANTS = [
  ("SELF ceiling promoted to T1 (over-claim self target)",
   "TargetProvenance.SELF: EvidenceTier.T2_SELF_MEASURED,",
   "TargetProvenance.SELF: EvidenceTier.T1_INDEPENDENT,"),
  ("UNKNOWN ceiling promoted to T1 (lose humble default)",
   "TargetProvenance.UNKNOWN: EvidenceTier.T2_SELF_MEASURED,  # humble",
   "TargetProvenance.UNKNOWN: EvidenceTier.T1_INDEPENDENT,  # humble"),
  ("unconfirmed graded as confirmed (T3 guard removed)",
   "    if not confirmed:\n        return EvidenceTier.T3_MECHANISM_ESTIMATE\n    return provenance.ceiling",
   "    return provenance.ceiling"),
  ("T2 allowed to say 'proven' (may_say_proven broken)",
   "    def may_say_proven(self) -> bool: return self is EvidenceTier.T1_INDEPENDENT",
   "    def may_say_proven(self) -> bool: return True"),
  ("coerce defaults to THIRD_PARTY instead of UNKNOWN",
   "    except Exception:\n        return TargetProvenance.UNKNOWN",
   "    except Exception:\n        return TargetProvenance.THIRD_PARTY"),
  ("no-bare-metrics gate disabled (accept any number)",
   "        if not _TIER_NEARBY.search(window):\n            raise AssertionError(",
   "        if False:\n            raise AssertionError("),
  ("manifest seal ignores statements (tamper-blind)",
   'body = "\\n".join(f"{c.tier.name}|{c.statement}|{c.detail}"\n                         for c in self.claims)',
   'body = "constant"'),
  ("fp decomposition drops the by-construction T4 piece",
   '        Claim("no finding can be produced without a Δstate delta",\n              grade_structural(), "precision is a construction property, not a rate"),',
   '        Claim("zero false positives", EvidenceTier.T2_SELF_MEASURED),'),
]

def run():
    for t in TESTS:
        if subprocess.run([sys.executable,t],capture_output=True,cwd=os.getcwd()).returncode!=0:
            return False
    return True

killed=survived=0
for label,find,repl in MUTANTS:
    if find not in orig:
        print(f"  [SKIP] anchor not found: {label}"); continue
    open(SRC,"w").write(orig.replace(find,repl,1))
    subprocess.run(["find",".","-name","__pycache__","-type","d","-exec","rm","-rf","{}","+"],capture_output=True)
    alive=run(); open(SRC,"w").write(orig)
    if alive: survived+=1; print(f"  [SURVIVED] {label}  <-- TEETHLESS")
    else: killed+=1; print(f"  [killed]   {label}")
open(SRC,"w").write(orig)
subprocess.run(["find",".","-name","__pycache__","-type","d","-exec","rm","-rf","{}","+"],capture_output=True)
print(f"\nmutation score: {killed}/{killed+survived} killed (floor=8)")
import sys as _sys; _sys.exit(0 if killed >= 8 else 1)
