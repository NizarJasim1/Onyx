#!/usr/bin/env python3
"""
Dedup lint — catches the copy-paste defect class (two byte-identical statements
back-to-back within a block), which has bitten this codebase twice (a duplicated
202-exclusion and a duplicated grant check, both from re-applying an edit). Adjacent
identical statements are ~always a paste artifact, never intentional. Runs over the
engine/confirmer/provenance hot files; exits non-zero if any are found.
"""
import ast, sys, os

TARGETS = ["authpath/engine.py", "authpath/confirmer.py", "authpath/provenance.py"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dump(node):
    # structural signature of a statement, ignoring line numbers
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _scan_block(body, path, out):
    prev = None
    for stmt in body:
        sig = _dump(stmt)
        if prev is not None and sig == prev[0] and not isinstance(stmt, (ast.Pass, ast.Import, ast.ImportFrom)):
            out.append((path, getattr(stmt, "lineno", "?"), sig[:70]))
        prev = (sig, stmt)
        # recurse into nested blocks
        for field in ("body", "orelse", "finalbody"):
            sub = getattr(stmt, field, None)
            if isinstance(sub, list):
                _scan_block(sub, path, out)
        for h in getattr(stmt, "handlers", []) or []:
            _scan_block(h.body, path, out)


def main():
    findings = []
    for rel in TARGETS:
        p = os.path.join(ROOT, rel)
        tree = ast.parse(open(p, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _scan_block(node.body, rel, findings)
    if findings:
        print("DUPLICATE-STATEMENT DEFECTS (copy-paste artifacts):")
        for path, line, sig in findings:
            print(f"  {path}:{line}  {sig}...")
        print(f"\n{len(findings)} duplicate(s) found.")
        return 1
    print("dedup lint: clean (no adjacent duplicate statements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
