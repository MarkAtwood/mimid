#!/usr/bin/env bash
# Runs inside the namespace (./run.sh ./b4.sh). Beads mimid-1wgh.46.1.6 and
# mimid-1wgh.46.6. Seeds mimi-hubd over its JSON lane (and its store for the
# one thing no route seeds: an enrolled handle), runs the driver, then checks
# what the hub stored. Copies the driver's Commits and proposal to out/.
set -uo pipefail
H=https://haven.localhost
OUT="$(cd "$(dirname "$0")" && pwd)/out"
enc() { python3 -I -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
db() { python3 -I -c 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);r=c.execute(sys.argv[2]).fetchall();c.commit();print(r)' "$WORK/hub.db" "$1"; }
ALICE=mimi://b.example/u/alice; CAROL=mimi://b.example/u/carol; DAVE=mimi://b.example/u/dave
ERIN=mimi://b.example/u/erin; FRANK=mimi://b.example/u/frank
BOB=mimi://haven.localhost/u/bob; GRACE=mimi://haven.localhost/u/grace; ROOM=mimi://haven.localhost/r/live1
st() { curl -sS -o "$WORK/resp.bin" -w '%{http_code}' "$@"; }
body() { head -c 300 "$WORK/resp.bin" | tr -d '\0'; }
"$DRIVER" make-kp "$GRACE" "$WORK/grace_kp.bin"
echo "SETUP publish Haven-minted KeyPackage for $BOB: $(st -X POST --data-binary @"$KP" "$H/mimi/v1/keyMaterial/ingest?user=$(enc $BOB)") $(body)"
echo "SETUP publish mimid-minted KeyPackage for $GRACE: $(st -X POST --data-binary @"$WORK/grace_kp.bin" "$H/mimi/v1/keyMaterial/ingest?user=$(enc $GRACE)") $(body)"
for target in "$BOB" "$GRACE"; do
  echo "SETUP grant consent $ALICE -> $target: $(st -X POST -H 'content-type: application/json' -d "{\"operation\":2,\"requester_uri\":\"$ALICE\",\"target_uri\":\"$target\"}" "$H/mimi/v1/updateConsent")"
done
echo "SETUP addParticipant $ALICE to $ROOM: $(st -X POST "$H/mimi/v1/addParticipant?room=$(enc $ROOM)&member=$(enc $ALICE)") $(body)"
echo "SETUP enroll handle bob (no route; written to the hub's store): $(db "INSERT OR IGNORE INTO enrolled (username) VALUES ('bob')")"
"$DRIVER"; rc=$?
mkdir -p "$OUT"
for f in update_commit.bin update_commit_add.bin update_commit_two_changes.bin update_commit_without_held.bin update_commit_by_reference.bin leave_proposal.bin; do
  [ -f "$WORK/$f" ] && cp -f "$WORK/$f" "$OUT/$f"
done
echo "CHECK 3 fetch stored message for routing key $ROOM: $(st "$H/mimi/v1/message?user=$(enc $ROOM)")"
if cmp -s "$WORK/resp.bin" "$WORK/submitted_app_message.bin"; then echo "  stored bytes identical to the submitted appMessage"; else echo "  stored bytes DIFFER: $(od -An -tx1 "$WORK/resp.bin" | tr -d ' \n' | head -c 200)"; fi
echo "CHECK 4 room participants in join order: $(db "SELECT member_uri, seq FROM room_participants WHERE room_uri='$ROOM' ORDER BY seq")"
echo "CHECK 4 room epoch the hub learned: $(db "SELECT epoch FROM room_epoch WHERE room_uri='$ROOM'")"
echo "CHECK 4 held proposals: $(db "SELECT epoch, hex(reference) FROM pending_proposals")"
for who in "$DAVE" "$CAROL" "$ERIN" "$FRANK"; do
  echo "CHECK 4 authorizeSender $who: $(st -X POST "$H/mimi/v1/authorizeSender?room=$(enc $ROOM)&sender=$(enc $who)") $(body)"
done
echo "CHECK 5 notify bodies the hub kept: $(db "SELECT count(*) FROM notify_seen")"
echo "CHECK 6 consent rows: $(db "SELECT requester, target, room_key, state FROM consent ORDER BY requester, target")"
echo "CHECK 8 abuse reports: $(db "SELECT room_uri, reporting_user, alleged_abuser_uri, reason_code, note FROM abuse_reports")"
# Response media type (protocol-07 §10.6) and request media type, by hand.
printf '\x00\x01\x00\x01\x00' > "$WORK/junk.bin"
for ct in application/mimi-protocol application/octet-stream; do
  code=$(curl -sS -o "$WORK/resp.bin" -D "$WORK/hdr.txt" -w '%{http_code}' -X POST -H "Content-Type: $ct" -H 'From: mimi@b.example' \
    --data-binary @"$WORK/update_commit.bin" "$H/mimi/pl/update/$(enc $ROOM)")
  echo "DIAG update with request Content-Type $ct (body: a bare Commit, not an UpdateRequest): $code, response $(grep -i '^content-type' "$WORK/hdr.txt" | tr -d '\r') $(body)"
done
echo "DIAG From header naming another domain: $(st -X POST -H 'Content-Type: application/mimi-protocol' -H 'From: mimi@c.example' --data-binary @"$WORK/junk.bin" "$H/mimi/pl/update/$(enc $ROOM)")"
exit $rc
