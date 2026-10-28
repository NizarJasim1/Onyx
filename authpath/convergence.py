"""
⑱ Convergence gate (Gap G3) — replica-lag / read-your-writes safety, pure logic.

A real effect may not have propagated to a replica at read time (false negative), or
a transient may look persisted (FP risk). So NEVER judge from a single read: poll
until a control write of ours is visible (read-your-writes reached) or a bounded
window elapses, then confirm ONLY if the effect is present AT a proven convergence
point. Timeout without convergence => abstain.

FP gate: CV-0 bounded window, timeout w/o convergence => abstain; CV-1 confirm only
if effect present at a proven convergence point; CV-2 vanished-after-convergence
(transient/saga rollback) => abstain; CV-3 default-OFF (caller opts in).
"""
from __future__ import annotations
from typing import Callable, Any, Optional


def converged_persisted(read_back: Callable[[], Any], persisted: Callable[[Any], bool],
                        control_visible: Callable[[Any], bool], *, max_polls: int = 5,
                        interval_s: float = 0.0, sleep: Optional[Callable[[float], None]] = None) -> bool:
    """Confirm a persisted effect only at a proven convergence point.
    control_visible(rb): has our control write appeared (read-your-writes reached)?
    persisted(rb): is our effect present? Returns True only if the effect is present
    at the first convergence point; if convergence never reached => False (abstain)."""
    if sleep is None:
        import time
        sleep = time.sleep
    for i in range(max(1, max_polls)):
        rb = read_back()
        if rb is not None and control_visible(rb):     # convergence reached
            return bool(persisted(rb))                 # CV-1/CV-2: effect present now?
        if i < max_polls - 1:
            sleep(interval_s)
    return False                                        # CV-0: never converged => abstain
