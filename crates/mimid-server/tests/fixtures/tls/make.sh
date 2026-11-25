#!/bin/sh
# Test certificates for mimid's TLS listener (bead mimid-75nk.4). Not
# secret: test-only keys. Regenerate with `sh make.sh` in this directory.
# P-256 ECDSA, valid for 100 years so tests do not expire.
set -eu
days=36500
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days $days \
  -subj "/CN=mimid test CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
issue() { # name subjectAltName extendedKeyUsage
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
    -keyout "$1.key" -out "$1.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\nbasicConstraints=critical,CA:false\n' "$2" "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days $days \
    -extfile "$1.ext" -out "$1.pem"
  rm "$1.csr" "$1.ext"
}
# A second root that signs nothing here, so a verifier anchored to it
# refuses the client certificate above. It is how tests/peer_client_tls.rs
# reproduces the failure of bead mimid-75nk.14: a peer that asks for a
# client certificate, does not require one, and does not trust our issuer.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days $days \
  -subj "/CN=mimid test CA (other)" -keyout other-ca.key -out other-ca.pem \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
issue server "DNS:localhost,IP:127.0.0.1" serverAuth
issue client "DNS:a.example" clientAuth
# An asset server under the peer domain b.example (proxyDownload tests).
issue assets "DNS:assets.b.example" serverAuth
rm -f ca.srl
