#!/usr/bin/env python3
"""
ws_ingest.py — Phase 3 (part 2): WebSocket surface INGESTION.

Real-time surfaces (WebSocket / socket.io / GraphQL subscriptions) carry objects that never
appear in REST, so REST-only recon is blind to them. This module converts a captured WS
message log into HAR-shaped entries the Conductor's existing layers consume — so WS-carried
objects, ids and cross-owner references enter the ANATOMY and HYPOTHESES for the analyst, and any
that map onto an addressable REST/GraphQL door become confirmable by the proven path.

It is INGESTION ONLY — it invents nothing and confirms nothing. Each synthetic entry mirrors a
real observed message: a message a principal RECEIVED becomes a GET-shaped observation of the
object it carried; a message a principal SENT with an id becomes a request observation. The
Δstate verdict stays the engine's job over an addressable door.

WS log entry shape (what a proxy/devtools export gives):
  {"principal": "A", "dir": "recv"|"send", "channel": "/orders", "data": {...json...}}
"""
from __future__ import annotations
import json, argparse, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitemodel as SM


def _channel_to_path(channel):
    """A WS channel/topic → a stable pseudo-path under /__ws__ so it is namespaced and never
    confused with a real HTTP door."""
    c = (channel or "stream").strip().strip("/")
    return "/__ws__/" + c


def ingest(ws_log, base_url="http://ws.local", token_map=None):
    """WS message log → HAR {log:{entries}}. token_map maps principal→token so the synthetic
    Authorization header lets sitemodel attribute each observation to its principal."""
    token_map = token_map or {}
    pid_tok = {p: t for t, p in token_map.items()} if token_map else {}
    entries = []
    for msg in ws_log:
        pid = msg.get("principal")
        data = msg.get("data")
        if data is None:
            continue
        path = _channel_to_path(msg.get("channel"))
        # a received message → the principal OBSERVED this object on the channel (a read)
        # a sent message with an id → the principal addressed an object (also a read-shaped obs)
        tok = pid_tok.get(pid, f"tok{pid}")
        # if the payload carries an id, expose it as an item pseudo-path so id-linkage/harvest
        # can see it; otherwise keep the channel path (a collection-shaped observation).
        oid = _first_id(data)
        p = path + ("/" + str(oid) if oid else "")
        entries.append({
            "request": {"method": "GET", "url": base_url.rstrip("/") + p,
                        "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
            "response": {"status": 200, "content": {"text": json.dumps(data)}},
        })
    return {"log": {"entries": entries}}


def _first_id(data):
    if isinstance(data, dict):
        for k, v in data.items():
            if (k.lower() == "id" or k.lower().endswith("id")) and isinstance(v, (str, int)):
                return v
    return None


def merge_captures(*hars):
    """Fold several HAR captures (REST + GraphQL + WS) into one for the Conductor."""
    out = {"log": {"entries": []}}
    for h in hars:
        out["log"]["entries"].extend(((h or {}).get("log") or {}).get("entries") or [])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX WebSocket ingester — WS message log → HAR capture (ingestion only; confirms nothing).")
    ap.add_argument("--ws-log", required=True, help="JSON file: list of {principal,dir,channel,data}")
    ap.add_argument("--tokens", help='JSON token→principal map')
    ap.add_argument("--base-url", default="http://ws.local")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    ws_log = json.load(open(args.ws_log))
    token_map = json.loads(args.tokens) if args.tokens else {}
    har = ingest(ws_log, base_url=args.base_url, token_map=token_map)
    json.dump(har, open(args.out, "w"), indent=2)
    print(f"ws-ingest: {len(har['log']['entries'])} entries → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
