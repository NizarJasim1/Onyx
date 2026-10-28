#!/usr/bin/env python3
"""measure_ws.py — MEASURED proof for Phase 3 (part 2): WebSocket ingestion feeds the
anatomy. A WS-only object (an id that appears ONLY over the socket, never in REST) must enter
the site model so it becomes visible to the analyst's dissection — something a REST-only capture
cannot show.

GROUND TRUTH: three principals receive order objects over a WS /orders channel. inv ids appear
only in WS payloads. Assert:
  1. ingestion produces HAR entries under /__ws__/…
  2. the WS-carried object ids appear in the Layer-1 site model (offline, no network).
  3. merge_captures fuses a REST HAR + the WS HAR into one capture.

Run:  python3 external_targets/measure_ws.py   (exit 0 = pass)
"""
import json, sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import ws_ingest as WS
import sitemodel as SM

def main():
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    ws_log = [
        {"principal": "A", "dir": "recv", "channel": "/orders", "data": {"id": "o-A", "owner": "a@x.com", "total": 100}},
        {"principal": "B", "dir": "recv", "channel": "/orders", "data": {"id": "o-B", "owner": "b@x.com", "total": 200}},
        {"principal": "C", "dir": "recv", "channel": "/orders", "data": {"id": "o-C", "owner": "c@x.com", "total": 300}},
    ]
    har = WS.ingest(ws_log, token_map=token_map)
    entries = har["log"]["entries"]
    under_ws = all("/__ws__/" in e["request"]["url"] for e in entries)

    # build the Layer-1 model from the WS-derived capture (offline)
    model = SM.from_sources(har=har, openapi=None, token_map=token_map)
    rep = model.report()
    # the WS object ids must now be known to the model
    seen_ids = set(getattr(model, "_id_index", {}).keys())
    ws_ids_present = {"o-A", "o-B", "o-C"} <= seen_ids

    # fuse with a REST capture
    rest = {"log": {"entries": [{"request": {"method": "GET", "url": "http://t/api/ping",
            "headers": [{"name": "Authorization", "value": "Bearer tokA"}]},
            "response": {"status": 200, "content": {"text": "{}"}}}]}}
    fused = WS.merge_captures(rest, har)
    fused_ok = len(fused["log"]["entries"]) == len(entries) + 1

    print(f"  ws entries               : {len(entries)}  (all under /__ws__: {under_ws})")
    print(f"  WS object ids in L1 model : {sorted(seen_ids & {'o-A','o-B','o-C'})}")
    print(f"  merge REST+WS captures    : {len(fused['log']['entries'])} entries")
    print()
    print(f"  ingestion namespaced      : {under_ws}")
    print(f"  WS-only ids reach anatomy : {ws_ids_present}")
    print(f"  captures fuse cleanly     : {fused_ok}")
    if under_ws and ws_ids_present and fused_ok:
        print("\nMEASURE-WS: PASS — WebSocket-carried objects enter the site model (visible to the analyst's "
              "dissection) and fuse with REST/GraphQL captures. Ingestion only; the engine still judges.")
        return 0
    print("\nMEASURE-WS: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
