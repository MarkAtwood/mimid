#!/usr/bin/env bash
# Runs inside the private namespace started by run.sh.
set -euo pipefail
C="$WORK/certs"
ip link set lo up
MIMI_PROVIDER_DOMAIN=haven.localhost MIMI_BIND_ADDR=127.0.0.1:8443 \
MIMI_DB_PATH="$WORK/hub.db" MIMI_SERVER_CERT="$C/hub.pem" MIMI_SERVER_KEY="$C/hub-key.pem" \
MIMI_CLIENT_CA="$C/ca.pem" "$HUBD" >"$WORK/hubd.log" 2>&1 &
HUB=$!
socat OPENSSL-LISTEN:443,pf=ip6,ipv6only=0,reuseaddr,fork,cert="$C/proxy.pem",key="$C/proxy-key.pem",verify=0 \
  OPENSSL:127.0.0.1:8443,cert="$C/client.pem",key="$C/client-key.pem",cafile="$C/ca.pem",verify=1,commonname=localhost,snihost=localhost \
  2>"$WORK/socat.log" &
PROXY=$!
trap 'kill $HUB $PROXY 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  grep -q 'listening (mTLS)' "$WORK/hubd.log" 2>/dev/null && break
  kill -0 $HUB 2>/dev/null || { echo "mimi-hubd exited:"; cat "$WORK/hubd.log"; exit 1; }
  sleep 0.1
done
grep -q 'listening (mTLS)' "$WORK/hubd.log" || { echo "mimi-hubd not ready:"; cat "$WORK/hubd.log"; exit 1; }
export SSL_CERT_FILE="$C/ca.pem"   # mimid (rustls native roots) and curl trust the throwaway CA
set +e; "$@"; rc=$?; set -e
[ $rc -eq 0 ] || { echo "--- hubd.log"; tail -20 "$WORK/hubd.log"; echo "--- socat.log"; tail -20 "$WORK/socat.log"; }
exit $rc
