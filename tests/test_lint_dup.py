"""Ensure the dedup lint stays clean (catches copy-paste duplicate statements)."""
import os, sys, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_no_duplicate_statements():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "lint_dup.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"dedup lint failed:\n{r.stdout}"

if __name__ == "__main__":
    test_no_duplicate_statements(); print("ok test_no_duplicate_statements")
