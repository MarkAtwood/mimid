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
issue server "DNS:localhost,IP:127.0.0.1" serverAuth
issue client "DNS:a.example" clientAuth
rm -f ca.srl
