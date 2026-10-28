"""
AuthPath v3 — a deterministic authorization & business-logic provenance engine.

Public surface. The design discipline lives in docs/design-rationale.md; the load-bearing
invariants (no induction, no LLM in the value path, confirm-by-Δstate, every
finding reportable, Scope-Guard fail-safe) are enforced in the components below.
"""

from .engine import AuthPathEngine, PipelineTrace
from .models import (
    EffectClass,
    Finding,
    HTTPRequest,
    HTTPResponse,
    Principal,
    Severity,
)
from .scope_guard import ScopeConfig, ScopeGuard
from .transport import HTTPTarget, MockTarget, make_exchange

__version__ = "3.2.0"

__all__ = [
    "AuthPathEngine", "PipelineTrace",
    "EffectClass", "Finding", "HTTPRequest", "HTTPResponse", "Principal", "Severity",
    "ScopeConfig", "ScopeGuard",
    "HTTPTarget", "MockTarget", "make_exchange",
    "__version__",
]
