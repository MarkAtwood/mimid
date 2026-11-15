#!/bin/sh
# Test certificates for PKIX provider authentication (bead mimid-75nk.5),
# issued by the TLS test CA in ../tls, whose key is test-only, not
# secret. Regenerate with `sh make.sh` in this directory. Valid for 100
# years; the tests move the clock to test expiry. No private keys are kept:
# the mechanism checks certificates, and the TLS handshake (tested in
# tls_listener.rs) is what proves possession.
#
# haven-root.pem and haven-client.pem are not made here: they are Haven's
# real certificates (see PROVENANCE).
set -eu
days=36500
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256"
issue() { # name "newkey options" extensions...
  name=$1; newkey=$2; shift 2
  : > "$name.ext"
  for ext in "$@"; do printf '%s\n' "$ext" >> "$name.ext"; done
  # shellcheck disable=SC2086
  openssl req $newkey -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ../tls/ca.pem -CAkey ../tls/ca.key -CAcreateserial \
    -days $days -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  rm "$name.csr" "$name.ext" "$name.key"
}
leaf="basicConstraints=critical,CA:false"
# A dNSName and no extended key usage: accepted (draft §6).
issue noeku "$ec" "subjectAltName=DNS:a.example" "$leaf"
# The domain only in the common name: refused (RFC 9525 does not use CN).
issue a.example "$ec" "extendedKeyUsage=clientAuth" "$leaf"
# Wildcard dNSNames: one over b.example, and one over a single-label
# suffix, which pkix-identity does not honor.
issue wildcard "$ec" "subjectAltName=DNS:*.b.example,DNS:*.example" "extendedKeyUsage=clientAuth" "$leaf"
# An RSA key below 2048 bits.
issue rsa1024 "-newkey rsa:1024" "subjectAltName=DNS:a.example" "extendedKeyUsage=clientAuth" "$leaf"
# Another CA, which issued nothing here: an anchor that does not match.
openssl req -x509 $ec -nodes -days $days -subj "/CN=other test CA" \
  -keyout other-ca.key -out other-ca.pem \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
rm other-ca.key
rm -f ../tls/ca.srl
