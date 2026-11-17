#!/usr/bin/env bash
# Runs inside the namespace (./run.sh ./b4.sh), or on a host whose outbound
# proxy adds the mTLS client certificate (public.sh). Beads mimid-1wgh.46.1.6
# and mimid-1wgh.46.6. Seeds mimi-hubd over its JSON lane (and its store for
# the one thing no route seeds: an enrolled handle), runs the driver, then
# checks what the hub stored. Copies the driver's Commits and proposal to out/.
#
# Environment (defaults are the namespace run's):
#   HAVEN_DOMAIN, OWN_DOMAIN, RUN_TAG   as for the driver (driver/src/main.rs)
#   HAVEN_LANE   base URL of the hub's mTLS lanes (default https://HAVEN_DOMAIN)
#   HAVEN_ADMIN  base URL of the hub's operator listener, which serves
#                addParticipant (default http://127.0.0.1:9090, as up.sh sets)
#   CURL_OPTS    extra curl options, word-split (e.g. --cacert FILE)
#   HUB_DB_CMD   a command that runs the SQL on its stdin against the hub's
#                store and prints the rows (default: python3 on $WORK/hub.db)
#   OUT          where the driver's Commits are copied (default ./out)
set -uo pipefail
HAVEN_DOMAIN=${HAVEN_DOMAIN:-haven.localhost}; OWN_DOMAIN=${OWN_DOMAIN:-b.example}; RUN_TAG=${RUN_TAG:-}
export HAVEN_DOMAIN OWN_DOMAIN RUN_TAG
H=${HAVEN_LANE:-https://$HAVEN_DOMAIN}
ADMIN=${HAVEN_ADMIN:-http://127.0.0.1:9090}
read -r -a CURL_X <<<"${CURL_OPTS:-}"
OUT=${OUT:-"$(cd "$(dirname "$0")" && pwd)/out"}
enc() { python3 -I -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
db() {
  if [ -n "${HUB_DB_CMD:-}" ]; then printf '%s;\n' "$1" | $HUB_DB_CMD | tr '\n' ' '; echo
  else python3 -I -c 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);r=c.execute(sys.argv[2]).fetchall();c.commit();print(r)' "$WORK/hub.db" "$1"; fi
}
u() { echo "mimi://$1/u/$2$RUN_TAG"; }
ALICE=$(u "$OWN_DOMAIN" alice); CAROL=$(u "$OWN_DOMAIN" carol); DAVE=$(u "$OWN_DOMAIN" dave)
ERIN=$(u "$OWN_DOMAIN" erin); FRANK=$(u "$OWN_DOMAIN" frank)
BOB=$(u "$HAVEN_DOMAIN" bob); GRACE=$(u "$HAVEN_DOMAIN" grace); ROOM=mimi://$HAVEN_DOMAIN/r/live1$RUN_TAG
echo "RUN haven=$HAVEN_DOMAIN own=$OWN_DOMAIN lane=$H room=$ROOM tag='$RUN_TAG' at $(date -u +%FT%TZ)"
# mimi-hubd requires From on its JSON lane too, since d750a8d (DIV-16).
st() { curl "${CURL_X[@]}" -sS -o "$WORK/resp.bin" -w '%{http_code}' -H "From: mimi@$OWN_DOMAIN" "$@"; }
body() { head -c 300 "$WORK/resp.bin" | tr -d '\0'; }
"$DRIVER" make-kp "$GRACE" "$WORK/grace_kp.bin"
echo "SETUP publish Haven-minted KeyPackage for $BOB: $(st -X POST --data-binary @"$KP" "$H/mimi/v1/keyMaterial/ingest?user=$(enc $BOB)") $(body)"
echo "SETUP publish mimid-minted KeyPackage for $GRACE: $(st -X POST --data-binary @"$WORK/grace_kp.bin" "$H/mimi/v1/keyMaterial/ingest?user=$(enc $GRACE)") $(body)"
for target in "$BOB" "$GRACE"; do
  echo "SETUP grant consent $ALICE -> $target: $(st -X POST -H 'content-type: application/json' -d "{\"operation\":2,\"requester_uri\":\"$ALICE\",\"target_uri\":\"$target\"}" "$H/mimi/v1/updateConsent")"
done
echo "SETUP addParticipant $ALICE to $ROOM: $(st -X POST "$ADMIN/mimi/v1/addParticipant?room=$(enc $ROOM)&member=$(enc $ALICE)") $(body)"
echo "SETUP enroll handle bob (no route; written to the hub's store): $(db "INSERT OR IGNORE INTO enrolled (username) VALUES ('bob$RUN_TAG')")"
"$DRIVER"; rc=$?
mkdir -p "$OUT"
for f in update_commit.bin update_commit_add.bin update_commit_two_changes.bin update_commit_without_held.bin update_commit_by_reference.bin leave_proposal.bin; do
  [ -f "$WORK/$f" ] && cp -f "$WORK/$f" "$OUT/$f"
done
echo "CHECK 3 fetch stored message for routing key $ROOM: $(st "$H/mimi/v1/message?user=$(enc $ROOM)")"
if cmp -s "$WORK/resp.bin" "$WORK/submitted_app_message.bin"; then echo "  stored bytes identical to the submitted appMessage"; else echo "  stored bytes DIFFER: $(od -An -tx1 "$WORK/resp.bin" | tr -d ' \n' | head -c 200)"; fi
echo "CHECK 4 room participants in join order: $(db "SELECT member_uri, seq FROM room_participants WHERE room_uri='$ROOM' ORDER BY seq")"
echo "CHECK 4 room epoch the hub learned: $(db "SELECT epoch FROM room_epoch WHERE room_uri='$ROOM'")"
echo "CHECK 4 held proposals: $(db "SELECT epoch, hex(reference) FROM pending_proposals WHERE room_uri='$ROOM'")"
for who in "$DAVE" "$CAROL" "$ERIN" "$FRANK"; do
  echo "CHECK 4 authorizeSender $who: $(st -X POST "$H/mimi/v1/authorizeSender?room=$(enc $ROOM)&sender=$(enc $who)") $(body)"
done
echo "CHECK 5 notify bodies the hub kept (whole hub, all runs): $(db "SELECT count(*) FROM notify_seen")"
echo "CHECK 6 consent rows: $(db "SELECT requester, target, room_key, state FROM consent WHERE requester LIKE '%$RUN_TAG' OR target LIKE '%$RUN_TAG' ORDER BY requester, target")"
echo "CHECK 8 abuse reports: $(db "SELECT room_uri, reporting_user, alleged_abuser_uri, reason_code, note FROM abuse_reports WHERE room_uri='$ROOM'")"
# Response media type (protocol-07 §10.6) and request media type, by hand.
printf '\x00\x01\x00\x01\x00' > "$WORK/junk.bin"
for ct in application/mimi-protocol application/octet-stream; do
  code=$(curl "${CURL_X[@]}" -sS -o "$WORK/resp.bin" -D "$WORK/hdr.txt" -w '%{http_code}' -X POST -H "Content-Type: $ct" -H "From: mimi@$OWN_DOMAIN" \
    --data-binary @"$WORK/update_commit.bin" "$H/mimi/pl/update/$(enc $ROOM)")
  echo "DIAG update with request Content-Type $ct (body: a bare Commit, not an UpdateRequest): $code, response $(grep -i '^content-type' "$WORK/hdr.txt" | tr -d '\r') $(body)"
done
fromdiag() { curl "${CURL_X[@]}" -sS -o "$WORK/resp.bin" -w '%{http_code}' -X POST -H 'Content-Type: application/mimi-protocol' "$@" --data-binary @"$WORK/junk.bin" "$H/mimi/pl/update/$(enc $ROOM)"; }
echo "DIAG From header naming another domain: $(fromdiag -H 'From: mimi@c.example')"
echo "DIAG two From headers, ours then another domain's: $(fromdiag -H "From: mimi@$OWN_DOMAIN" -H 'From: mimi@c.example')"
echo "DIAG two From headers, another domain's then ours: $(fromdiag -H 'From: mimi@c.example' -H "From: mimi@$OWN_DOMAIN")"
exit $rc
