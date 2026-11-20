"""Derives chat.json here from ../chat-v1/chat.json: the same format-1 store
with alice's ChatContact removed, as a JMAP client's ChatContact/set
destroy leaves it. Nothing else changes. See PROVENANCE.

Run: python3 -I derive.py ../chat-v1/chat.json chat.json
"""

import json
import sys

ALICE = "mimi://a.example/u/alice"

source, target = sys.argv[1], sys.argv[2]
with open(source, "rb") as f:
    original = f.read()
store = json.loads(original)
# serde_json's compact form; the derivation is checked to reproduce the
# source octets before anything is removed.
dump = lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode()
assert dump(store) == original, "the source does not re-encode to itself"
contacts = store["objects"]["ChatContact"]
kept = [c for c in contacts if c["identity"] != ALICE]
assert len(kept) == len(contacts) - 1, "alice's ChatContact is not there once"
store["objects"]["ChatContact"] = kept
with open(target, "wb") as f:
    f.write(dump(store))
