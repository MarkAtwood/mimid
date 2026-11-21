#!/bin/sh
# Makes the TLS fixtures of mimid-agent's tests: a CA, and a server
# certificate from it for localhost, 127.0.0.1 and host.tailnet.ts.net,
# valid for 100 years. Run in this directory; needs OpenSSL 3.
set -eu
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 36500 -subj "/CN=mimid-agent test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 36500 \
  -extfile /dev/stdin <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:host.tailnet.ts.net
EXT
rm -f server.csr ca.srl ca.key
