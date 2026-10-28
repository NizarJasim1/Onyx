"""pytest support. Puts the repo root and tests/ on the import path so `pytest`
works from a fresh clone. The canonical gate is still `python tests/run_all.py`.

A few tests swap in a fake `requests` module or re-import `authpath` to drive the
CLI end to end. The fixture below restores those modules after each test so one
test's stubs can't leak into the next when pytest runs everything in one process."""
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.abspath(__file__))
for p in (_ROOT, os.path.join(_ROOT, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

_ISOLATED = ("authpath", "requests", "curl_cffi")


def _owned(name: str) -> bool:
    return any(name == root or name.startswith(root + ".") for root in _ISOLATED)


@pytest.fixture(autouse=True)
def _isolate_swapped_modules():
    saved = {k: v for k, v in sys.modules.items() if _owned(k)}
    yield
    for k in [k for k in sys.modules if _owned(k)]:
        if k not in saved:
            del sys.modules[k]
    sys.modules.update(saved)
