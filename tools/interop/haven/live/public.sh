#!/usr/bin/env bash
# B4 against a public mimi-hubd (bead mimid-1wgh.46.6), run from this dev
# box: copies the driver, b4.sh and a Haven-minted KeyPackage to the mimid
# host, runs b4.sh there (its outbound proxy adds mimid's mTLS client
# certificate for HAVEN_DOMAIN), and reaches the hub's store directly over
# SSH from the mimid host with a key the hub host restricts to one forced
# command (authorized_keys: from=<mimid host>,restrict,command="sudo -u
# mimi-hubd sqlite3 -batch <hub db>"; SQL goes on stdin) and a pinned host
# key. No agent is forwarded. Then collects the hub's journal and the
# proxy's wire log for the run. Nothing on either host is configured or
# restarted.
#
# Usage: DRIVER=... KP=... ./public.sh [log dir]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
DRIVER=${DRIVER:?release build of driver/ (mimid-haven-live)}
KP=${KP:?haven_default_key_package.bin from the harness make-kp-default}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/mimid-hackathon.pem}
MIMID_HOST=${MIMID_HOST:-admin@172.31.40.235}
HUB_HOST=${HUB_HOST:-172.31.40.164}
HAVEN_DOMAIN=${HAVEN_DOMAIN:-haven.reviewcommit.com}
OWN_DOMAIN=${OWN_DOMAIN:-mimid.reviewcommit.com}
WIRE_LOG=${WIRE_LOG:-/var/log/mimid/ourhaven-8443.wire.log}
REMOTE=/home/admin/interop
# On the mimid host: the restricted key and the hub host's pinned host key.
HUB_DB_KEY=${HUB_DB_KEY:-$REMOTE/hubdb_ed25519}
HUB_KNOWN_HOSTS=${HUB_KNOWN_HOSTS:-$REMOTE/known_hosts_hub}
RUN_TAG=${RUN_TAG:-t$(date -u +%Y%m%d%H%M%S)}
LOGS=${1:-$HERE/out/public-$RUN_TAG}
mkdir -p "$LOGS"

Q=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10)
HUB_SSH="-i $HUB_DB_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$HUB_KNOWN_HOSTS"

ssh "${Q[@]}" "$MIMID_HOST" "mkdir -p $REMOTE/work-$RUN_TAG && sudo install -o admin -g admin -m 0644 /etc/mimid/outbound/trust.pem $REMOTE/trust.pem"
scp -q -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$DRIVER" "$HERE/b4.sh" "$KP" "$MIMID_HOST:$REMOTE/"
wire_start=$(ssh "${Q[@]}" "$MIMID_HOST" "sudo cat $WIRE_LOG | wc -l")
since=$(date -u '+%Y-%m-%d %H:%M:%S')

set +e
ssh "${Q[@]}" "$MIMID_HOST" \
  "cd $REMOTE && env SSL_CERT_FILE=$REMOTE/trust.pem WORK=$REMOTE/work-$RUN_TAG OUT=$REMOTE/work-$RUN_TAG/out \
   DRIVER=$REMOTE/$(basename "$DRIVER") KP=$REMOTE/$(basename "$KP") \
   HAVEN_DOMAIN=$HAVEN_DOMAIN OWN_DOMAIN=$OWN_DOMAIN RUN_TAG=$RUN_TAG \
   HAVEN_LANE=https://$HAVEN_DOMAIN:8443 CURL_OPTS='--cacert $REMOTE/trust.pem' \
   HUB_DB_CMD='ssh $HUB_SSH admin@$HUB_HOST sqlite3' \
   ./b4.sh" 2>&1 | tee "$LOGS/b4.log"
rc=${PIPESTATUS[0]}
set -e

ssh "${Q[@]}" "admin@$HUB_HOST" "sudo journalctl -u mimi-hubd --since '$since' --no-pager -o short-iso-precise" >"$LOGS/mimi-hubd.journal" || true
ssh "${Q[@]}" "$MIMID_HOST" "sudo tail -n +$((wire_start + 1)) $WIRE_LOG" >"$LOGS/ourhaven-8443.wire.log" || true
echo "rc=$rc tag=$RUN_TAG logs=$LOGS (journal $(wc -l <"$LOGS/mimi-hubd.journal") lines, wire $(wc -l <"$LOGS/ourhaven-8443.wire.log") lines)"
exit "$rc"
