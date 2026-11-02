#!/usr/bin/env bash
# Runs inside the namespace (./run.sh ./b4.sh). Bead mimid-1wgh.46.1.6.
set -uo pipefail
H=https://haven.localhost
enc() { python3 -I -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
ALICE=mimi://b.example/u/alice; CAROL=mimi://b.example/u/carol
BOB=mimi://haven.localhost/u/bob; ROOM=mimi://haven.localhost/r/live1
st() { curl -sS -o "$WORK/resp.bin" -w '%{http_code}' "$@"; }
echo "SETUP publish Haven-minted KeyPackage for $BOB: $(st -X POST --data-binary @"$KP" "$H/mimi/v1/keyMaterial/ingest?user=$(enc $BOB)") $(head -c 200 "$WORK/resp.bin")"
echo "SETUP grant consent $ALICE -> $BOB: $(st -X POST -H 'content-type: application/json' -d "{\"operation\":2,\"requester_uri\":\"$ALICE\",\"target_uri\":\"$BOB\"}" "$H/mimi/v1/updateConsent")"
echo "SETUP addParticipant $ALICE to $ROOM: $(st -X POST "$H/mimi/v1/addParticipant?room=$(enc $ROOM)&member=$(enc $ALICE)") $(head -c 200 "$WORK/resp.bin")"
"$DRIVER"; rc=$?
mkdir -p "$(dirname "$0")/out"
cp -f "$WORK/update_commit.bin" "$(dirname "$0")/out/update_commit.bin"
echo "CHECK 3 fetch stored message for routing key $ROOM: $(st "$H/mimi/v1/message?user=$(enc $ROOM)")"
if cmp -s "$WORK/resp.bin" "$WORK/submitted_app_message.bin"; then echo "  stored bytes identical to the submitted appMessage"; else echo "  stored bytes DIFFER: $(xxd -p "$WORK/resp.bin" | tr -d '\n' | head -c 200)"; fi
echo "CHECK 4 is carol a participant now (authorizeSender): $(st -X POST "$H/mimi/v1/authorizeSender?room=$(enc $ROOM)&sender=$(enc $CAROL)") $(head -c 200 "$WORK/resp.bin")"
echo "DIAG 4 bare mimid Commit (no UpdateRequest wrapper) to Haven update: $(st -X POST --data-binary @"$WORK/update_commit.bin" "$H/mimi/pl/update/$(enc $ROOM)") $(head -c 200 "$WORK/resp.bin")"
exit $rc
