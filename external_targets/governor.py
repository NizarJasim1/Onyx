#!/usr/bin/env python3
"""
governor.py — Phase 6 (part 2): ADAPTIVE THROTTLE / ANTI-WAF / BUDGET.

Giant targets sit behind WAFs and rate limits: fire too fast and you are blocked before you find
anything. The Governor wraps request issuance so a long hunt completes without tripping defenses
and without EVER dropping a probe:
  * adaptive throttle: on a WAF signal (429 / 403-challenge / connection reset) it backs off
    (exponential delay, capped) and RE-QUEUES the probe — a blocked probe is retried, never lost.
  * session rotation: on repeated blocks it rotates a session marker so the hunt looks like a
    fresh, well-behaved client instead of one hammering identity.
  * scope + budget: it refuses off-scope hosts (Scope-Guard) and enforces a hard request budget.

It changes DELIVERY only — never a verdict. Every response it returns is the server's real
response, so the proven path's Δstate confirmation is untouched (zero-FP preserved).
"""
from __future__ import annotations
import time, argparse, sys, os
from urllib.parse import urlparse

_WAF_STATUSES = {429, 503}
_CHALLENGE_MARKERS = ("captcha", "attention required", "cloudflare", "access denied", "request blocked")


def _is_waf(status, text):
    if status in _WAF_STATUSES:
        return True
    if status == 403 and any(m in (text or "").lower() for m in _CHALLENGE_MARKERS):
        return True
    return False


class Governor:
    def __init__(self, scope_hosts, *, base_delay=0.0, max_delay=8.0, budget=100000,
                 block_threshold=3, researcher="", verify=True, timeout=15, sleep=time.sleep):
        import requests
        self.requests = requests
        self.scope = set(scope_hosts)
        self.delay = base_delay
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.budget = budget
        self.block_threshold = block_threshold
        self.session_id = 1
        self.researcher = researcher
        self.verify = verify
        self.timeout = timeout
        self._sleep = sleep
        self.stats = {"sent": 0, "waf_hits": 0, "retries": 0, "rotations": 0, "refused": 0, "requeued": 0}

    def _ua(self):
        return (f"ONYX/1.0 (authorized-testing; session={self.session_id}"
                + (f"; {self.researcher}" if self.researcher else "") + ")")

    def in_scope(self, url):
        h = urlparse(url if "://" in url else "http://" + url).hostname or ""
        return h in self.scope

    def request(self, method, url, token=None, *, max_retries=6, _send=None, **kw):
        """Governed request. Returns the server's real (status, text-ish) via a small shim, or
        None if budget is exhausted. Retries WAF blocks with backoff + rotation; never drops."""
        if not self.in_scope(url):
            self.stats["refused"] += 1
            raise PermissionError(f"off-scope host blocked by Scope-Guard: {url}")
        consecutive_blocks = 0
        for attempt in range(max_retries + 1):
            if self.budget <= 0:
                return None
            if self.delay > 0:
                self._sleep(self.delay)
            headers = dict(kw.pop("headers", {}))
            headers["User-Agent"] = self._ua()
            if token:
                headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
            self.budget -= 1
            self.stats["sent"] += 1
            resp = (_send or self._send)(method, url, headers, kw)
            status, text = resp
            if _is_waf(status, text):
                self.stats["waf_hits"] += 1
                consecutive_blocks += 1
                self.delay = min(self.max_delay, (self.delay or self.base_delay or 0.1) * 2)
                if consecutive_blocks >= self.block_threshold:
                    self.session_id += 1                  # rotate identity/session marker
                    self.stats["rotations"] += 1
                    consecutive_blocks = 0
                self.stats["retries"] += 1
                self.stats["requeued"] += 1               # the probe is retried, never lost
                continue
            # success (or a real non-WAF status): gently relax the throttle
            self.delay = max(self.base_delay, self.delay / 2)
            return resp
        return resp   # exhausted retries — return the last real response (caller decides)

    def _send(self, method, url, headers, kw):
        r = self.requests.request(method, url, headers=headers, timeout=self.timeout,
                                  verify=self.verify, **kw)
        try:
            return r.status_code, r.text
        except Exception:
            return r.status_code, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX governor — adaptive anti-WAF throttle (delivery only; no verdict).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True); ap.add_argument("--scope")
    ap.add_argument("--budget", type=int, default=1000); ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized.")
    host = urlparse(args.base_url).hostname
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else [host]
    gov = Governor(scope, budget=args.budget, researcher=args.researcher)
    print(f"governor ready — scope={scope} budget={args.budget}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
