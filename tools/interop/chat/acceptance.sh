#!/usr/bin/env bash
# The mimid-chat acceptance test (bead mimid-1wgh.46.14), run from this dev
# box on the mimid hackathon host against the hub. Two users chat end to end;
# both processes are driven by --script files and restarted between phases:
#   phase 1  A creates a room, C grants consent, A invites C, C joins, each
#            sends a message and sees the other's
#   phase 2  both restart from their state directories, exchange a message
#            each, C's bad commands are refused, A leaves (protocol-07 §3.5)
#            and C commits the leave
# Copies the binary to the host first. Nothing else on the host changes.
#
# Usage: BIN=.../release/mimid-chat ./acceptance.sh [A C ROOM]
#   defaults: alice-TAG carol-TAG table-TAG, TAG=t<UTC timestamp>, so a rerun
#   against a hub that keeps state starts fresh
set -euo pipefail
BIN=${BIN:?release build of mimid-chat}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/mimid-hackathon.pem}
MIMID_HOST=${MIMID_HOST:-admin@172.31.40.235}
REMOTE=${REMOTE:-/home/admin/interop/chat}
TAG=${TAG:-t$(date -u +%Y%m%d%H%M%S)}
A=${1:-alice-$TAG} C=${2:-carol-$TAG} R=${3:-table-$TAG}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/a1.script" <<EOF
/create $R
# give $C time to /allow $A
/sleep 8
/invite $C
hello $C, this is $A
/expect hi $A 90
/who
/quit
EOF
cat >"$WORK/c1.script" <<EOF
/allow $A
/expect invite # 60
/join
/expect hello $C 30
hi $A, $C here
/quit
EOF
cat >"$WORK/a2.script" <<EOF
/rooms
/sleep 4
still here after a restart
/expect back too 90
/leave
/expect you have left 90
/rooms
/quit
EOF
cat >"$WORK/c2.script" <<EOF
/rooms
/bogus
/invite
/join
/create Bad_Name
/room nosuch
/expect still here after a restart 60
back too
/expect committed the leave 90
/who
/quit
EOF
cat >"$WORK/run.sh" <<'EOF'
set -u
cd "$1"; A=$2 C=$3; rc=0
export SSL_CERT_FILE=/home/admin/interop/trust.pem RUST_LOG=${RUST_LOG:-warn}
for phase in 1 2; do
  ./mimid-chat --user "$C" --state-dir "state-$C" --script "acc/c$phase.script" >"acc/$C.$phase.out" 2>&1 &
  cpid=$!
  sleep 1
  ./mimid-chat --user "$A" --state-dir "state-$A" --script "acc/a$phase.script" >"acc/$A.$phase.out" 2>&1 || rc=1
  wait "$cpid" || rc=1
  echo "=== phase $phase: $A"; cat "acc/$A.$phase.out"
  echo "=== phase $phase: $C"; cat "acc/$C.$phase.out"
done
exit $rc
EOF

Q=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes)
ssh "${Q[@]}" "$MIMID_HOST" "mkdir -p -m 0700 $REMOTE/acc"
scp -q "${Q[@]}" "$BIN" "$MIMID_HOST:$REMOTE/mimid-chat"
scp -q "${Q[@]}" "$WORK"/a1.script "$WORK"/c1.script "$WORK"/a2.script "$WORK"/c2.script "$MIMID_HOST:$REMOTE/acc/"
ssh "${Q[@]}" "$MIMID_HOST" bash -s -- "$REMOTE" "$A" "$C" <"$WORK/run.sh"
