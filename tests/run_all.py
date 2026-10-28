#!/usr/bin/env python3
"""Canonical, dependency-free test runner (the project is stdlib-only, so its gate
is too). Collects every test_* function from tests/test_*.py, runs it, and exits
non-zero on ANY failure or import error. This is the CI gate; `pytest` also works
(see conftest.py) for anyone who prefers it."""
import os, sys, importlib.util, traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TESTS = os.path.join(ROOT, "tests")

def main() -> int:
    passed = failed = errors = 0
    fails = []
    for fn in sorted(os.listdir(TESTS)):
        if not (fn.startswith("test_") and fn.endswith(".py")):
            continue
        path = os.path.join(TESTS, fn)
        spec = importlib.util.spec_from_file_location(fn[:-3], path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            errors += 1; fails.append((fn, "<import>", repr(e)))
            print(f"  [IMPORT-ERROR] {fn}: {e!r}")
            continue
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            obj = getattr(mod, name)
            if not callable(obj):
                continue
            try:
                obj(); passed += 1
            except Exception as e:
                failed += 1; fails.append((fn, name, repr(e)))
                print(f"  [FAIL] {fn}::{name}: {e!r}")
    total = passed + failed
    print(f"\nTOTAL={total} PASSED={passed} FAILED={failed} IMPORT_ERRORS={errors}")
    if fails:
        print("\nFAILURES:")
        for f, n, e in fails:
            print(f"  - {f}::{n} -> {e}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
