#!/usr/bin/env bash
# Throwaway CA and certificates, regenerated every run; never committed.
set -euo pipefail
C=$1; mkdir -p "$C"; cd "$C"
q() { "$@" >/dev/null 2>&1; }
q openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout ca-key.pem -out ca.pem -subj "/CN=mimid-haven-harness-ca"
leaf() { # name CN SAN
  q openssl req -newkey rsa:2048 -nodes -keyout "$1-key.pem" -out "$1.csr" -subj "/CN=$2"
  q openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 \
    -out "$1.pem" -extfile <(printf 'subjectAltName=%s\n' "$3")
}
leaf hub localhost "DNS:localhost,IP:127.0.0.1"
leaf proxy haven.localhost "DNS:haven.localhost"
leaf client mimid-harness-proxy "DNS:mimid-harness-proxy"
