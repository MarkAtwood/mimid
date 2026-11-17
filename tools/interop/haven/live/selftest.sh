#!/usr/bin/env bash
# Proves the proxy path works without a client cert and the hub refuses direct access.
set -uo pipefail
dir=$(curl -sS --fail https://haven.localhost/.well-known/mimi-protocol-directory) || { echo "FAIL: directory via proxy"; exit 1; }
echo "$dir" | grep -q '"keyMaterial": *"https://haven.localhost/mimi/pl/keyMaterial/{targetUser}"' \
  || { echo "FAIL: unexpected directory: $dir"; exit 1; }
echo "ok: directory via proxy, URLs point at https://haven.localhost"
# Since d750a8d mimi-hubd completes TLS without a client certificate (a
# request may carry a signature instead) and serves the directory to
# anyone; every other route needs a proof of the provider From names.
code=$(curl -sS --cacert "$SSL_CERT_FILE" -o /dev/null -w '%{http_code}' -X POST -H 'From: mimi@b.example' \
  --data-binary x https://localhost:8443/mimi/pl/update/x 2>/dev/null)
[ "$code" = 403 ] || { echo "FAIL: hub answered $code to an update without a client certificate"; exit 1; }
echo "ok: hub refuses an update without a client certificate (403)"
