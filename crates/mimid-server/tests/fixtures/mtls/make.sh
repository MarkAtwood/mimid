#!/bin/sh
# Client certificates for the two-binary mTLS tests (bead mimid-6x2f,
# tests/mtls_binaries.rs). Not secret: test-only keys. Regenerate with
# `sh make.sh` in this directory. P-256 ECDSA. a.example's client
# certificate is ../tls/client.pem; the test CA is ../tls/ca.pem.
set -eu
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256"
leaf="basicConstraints=critical,CA:false"
# issue name ca-cert ca-key subjectAltName [openssl ca date options]
issue() {
  name=$1; ca=$2; cakey=$3; san=$4; shift 4
  # shellcheck disable=SC2086
  openssl req $ec -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  printf '%s\nextendedKeyUsage=clientAuth\nsubjectAltName=%s\n' "$leaf" "$san" > "$name.ext"
  if [ $# -eq 0 ]; then
    openssl x509 -req -in "$name.csr" -CA "$ca" -CAkey "$cakey" -CAcreateserial \
      -days 36500 -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  else
    # openssl ca, for a validity period in the past.
    dir=$(mktemp -d)
    : > "$dir/index.txt"
    echo 01 > "$dir/serial"
    cat > "$dir/ca.cnf" <<CNF
[ca]
default_ca = test
[test]
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
default_md = sha256
policy = any
copy_extensions = none
[any]
commonName = supplied
CNF
    openssl ca -batch -config "$dir/ca.cnf" -cert "$ca" -keyfile "$cakey" \
      -in "$name.csr" -extfile "$name.ext" -notext -out "$name.pem" "$@" 2>/dev/null
    rm -r "$dir"
  fi
  rm "$name.csr" "$name.ext"
}
# b.example's client certificate, from the test CA.
issue b-client ../tls/ca.pem ../tls/ca.key DNS:b.example
# The same name, from a CA nobody configures.
openssl req -x509 $ec -nodes -days 36500 -subj "/CN=untrusted test CA" \
  -keyout untrusted-ca.key -out untrusted-ca.pem \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
issue b-untrusted untrusted-ca.pem untrusted-ca.key DNS:b.example
rm untrusted-ca.key untrusted-ca.srl
# The same name, from the test CA, expired since 2021.
issue b-expired ../tls/ca.pem ../tls/ca.key DNS:b.example \
  -startdate 20200101000000Z -enddate 20210101000000Z
rm -f ../tls/ca.srl
