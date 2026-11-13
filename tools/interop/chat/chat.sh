#!/usr/bin/env bash
# Runs mimid-chat interactively on the mimid hackathon host as USER (bead
# mimid-1wgh.46.14). The host's outbound proxy adds mimid's mTLS client
# certificate for the hub; SSL_CERT_FILE trusts the hub's certificate. State
# stays on the host in /home/admin/interop/chat/state-USER.
#
# Usage: ./chat.sh USER [mimid-chat options...]
#   e.g. ./chat.sh alice
#        RUST_LOG=mimid_chat=debug ./chat.sh carol --poll-ms 1000
set -euo pipefail
USER_NAME=${1:?usage: ./chat.sh USER [mimid-chat options...]}
shift
SSH_KEY=${SSH_KEY:-$HOME/.ssh/mimid-hackathon.pem}
MIMID_HOST=${MIMID_HOST:-admin@172.31.40.235}
REMOTE=${REMOTE:-/home/admin/interop/chat}
q() { [ $# -eq 0 ] || printf '%q ' "$@"; }
exec ssh -t -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$MIMID_HOST" \
  "SSL_CERT_FILE=/home/admin/interop/trust.pem RUST_LOG=$(q "${RUST_LOG:-warn}") \
   $REMOTE/mimid-chat --user $(q "$USER_NAME") --state-dir $REMOTE/state-$(q "$USER_NAME") $(q "$@")"
