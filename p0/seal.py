#!/usr/bin/env python3
"""Pre-registration seal for the P0 rig. Computes a sha256 over the oracle (the
ground truth) and the protocol (the scoring rules) BEFORE any live run, and writes
it to oracle.sealed. The scorer refuses to award the independent (T1) tier unless
this seal still verifies at scoring time — so the ground truth cannot be edited
after seeing ONYX's output. This is what makes the measurement game-proof."""
import hashlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.join(HERE, "oracle.json")
PROTOCOL = os.path.join(HERE, "protocol.md")
SEALED = os.path.join(HERE, "oracle.sealed")


def _digest() -> str:
    h = hashlib.sha256()
    for path in (ORACLE, PROTOCOL):
        with open(path, "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()


def seal() -> str:
    d = _digest()
    with open(SEALED, "w", encoding="utf-8") as fh:
        fh.write(d + "\n")
    return d


def verify() -> bool:
    if not os.path.exists(SEALED):
        return False
    with open(SEALED, encoding="utf-8") as fh:
        recorded = fh.read().strip()
    return recorded == _digest()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "seal"
    if cmd == "verify":
        ok = verify()
        print("SEAL OK" if ok else "SEAL MISMATCH")
        sys.exit(0 if ok else 1)
    print("sealed:", seal())
