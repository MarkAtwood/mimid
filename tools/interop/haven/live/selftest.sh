#!/usr/bin/env bash
# Proves the proxy path works without a client cert and the hub refuses direct access.
set -uo pipefail
dir=$(curl -sS --fail https://haven.localhost/.well-known/mimi-protocol-directory) || { echo "FAIL: directory via proxy"; exit 1; }
echo "$dir" | grep -q '"keyMaterial": *"https://haven.localhost/mimi/pl/keyMaterial/{targetUser}"' \
  || { echo "FAIL: unexpected directory: $dir"; exit 1; }
echo "ok: directory via proxy, URLs point at https://haven.localhost"
if curl -sS --cacert "$SSL_CERT_FILE" https://localhost:8443/.well-known/mimi-protocol-directory >/dev/null 2>&1; then
  echo "FAIL: hub accepted a request without a client certificate"; exit 1
fi
echo "ok: hub refuses a request without a client certificate"
