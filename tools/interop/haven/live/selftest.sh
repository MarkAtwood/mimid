#!/usr/bin/env bash
# Proves the proxy path works without a client cert and the hub refuses direct access.
set -uo pipefail
dir=$(curl -sS --fail https://haven.localhost/.well-known/mimi-protocol-directory) || { echo "FAIL: directory via proxy"; exit 1; }
echo "$dir" | grep -q '"keyMaterial": *"https://haven.localhost/mimi/pl/keyMaterial/{targetUser}"' \
  || { echo "FAIL: unexpected directory: $dir"; exit 1; }
echo "ok: directory via proxy, URLs point at https://haven.localhost"
# The hub must not take an update from a peer that proved nothing. Two
# shapes are both acceptable, and which one Haven does has changed:
#
#   403  it completes TLS and refuses at the HTTP layer. This is what
#        d750a8d did, when a request could carry a signature instead.
#   000  it requires a client certificate in the handshake, so there is
#        no HTTP answer at all. This is what 34eae7e does (checked
#        2026-11-22, bead mimid-1wgh.46.6).
#
# Accept either, and say which, because the difference matters to a peer:
# a handshake refusal carries no reason, so a misconfigured peer learns
# nothing (compare mimid's own 403, which names a reason since
# mimid-75nk.12). Anything else is a real failure.
code=$(curl -sS --cacert "$SSL_CERT_FILE" -o /dev/null -w '%{http_code}' -X POST -H 'From: mimi@b.example' \
  --data-binary x https://localhost:8443/mimi/pl/update/x 2>/dev/null)
case "$code" in
  403) echo "ok: hub completes TLS and refuses the update (403)" ;;
  000) echo "ok: hub requires a client certificate in the handshake (no HTTP answer)" ;;
  *) echo "FAIL: hub answered $code to an update without a client certificate"; exit 1 ;;
esac
