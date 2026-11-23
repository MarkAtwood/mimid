# mTLS interop test plan

For testing mimid's client-certificate provider authentication with an
external peer (Haven, Rohan Mahy, Konrad Kohbrok) on the interop day.
Bead mimid-6x2f. The local half, two mimid binaries on loopback, is in
`crates/mimid-server/tests/mtls_binaries.rs`.

**Tested against a non-mimid peer, 2026-11-22.** Our own instance of
mimi-hubd at 34eae7e, run by `tools/interop/haven/live/run.sh`, with the
driver pointed straight at it and socat out of the path:

| mimid presents | Result |
|---|---|
| nothing | `received fatal alert: CertificateRequired` |
| `[peer_tls.identity]` | TLS completes; identifierQuery 200, reportAbuse 200 |

Set `MIMID_CLIENT_CERT`, `MIMID_CLIENT_KEY` and `MIMID_PEER_ROOTS` on the
driver to make mimid present its own certificate; without them the
harness's socat holds one instead, which tests the proxy rather than
mimid. Still untested: the inbound direction, a non-mimid peer presenting
a certificate to mimid, which needs the peer's cooperation. No
conformance claim is made for protocol-07 §4.1.

## What mimid does

Inbound, every `/v1/` request is authenticated against the domain in its
`From` header (`mimi@<domain>`). The mechanisms run in this order, and the
first one that succeeds is used:

1. RFC 9421 signature, key configured for the peer
   (`[provider_auth.peers."<domain>"] keys`).
2. RFC 9421 signature, key in DNS at `<selector>._mimi.<domain>`
   (`dns_keys`, on by default).
3. DANE: the client certificate against TLSA records at
   `_mimi._client.<domain>` (`dane`, on by default).
4. PKIX: the client certificate against configured anchors
   (`pkix_anchors`, on when any are set).

mimid signs every outbound request. A peer that checks signatures may
authenticate mimid by its signature before it looks at the certificate,
and mimid may do the same to the peer. **To test a certificate mechanism,
turn the signature mechanisms off on the receiving side for the test**
(mimid: `dns_keys = false` and no `keys` for the peer), and check the
`mechanism` field in the log.

The certificate checks:

- **PKIX**: the path validates (RFC 5280) to an anchor configured for
  every peer or for this peer only; RSA keys are at least 2048 bits; the
  chain has at most 5 certificates; the leaf has no extended key usage,
  or one that includes `clientAuth`; a subjectAltName dNSName matches
  the `From` domain (a wildcard covers one label). The subject CN is
  ignored. No revocation checking.
- **DANE**: only DNSSEC-secure answers count. Usage 3 (DANE-EE) matches
  the leaf or its key; names and dates are not checked. Usage 2 (DANE-TA)
  matches a certificate the client sent above the leaf, then the path to
  it, `clientAuth` and the dNSName are checked as for PKIX. Usages 0 and
  1 are not used. Selectors 0 and 1, matching types 0, 1 and 2.

The TLS layer asks for a client certificate but does not require one and
sends no list of acceptable CAs. It checks only that the client holds the
key. A connection without a certificate still works; its requests are
refused in enforce mode.

Outbound, mimid presents `[peer_tls.identity]` to every peer, and
trusts the system roots plus `[peer_tls] roots` for peers' server
certificates.

## What each side sets up

### Certificates

| Item | Value |
|---|---|
| Client certificate SAN | dNSName = the MIMI provider domain used in `From` (Haven's current one is `mimi.havenmessenger.com`) |
| Client certificate EKU | `clientAuth`, or none |
| Key | ECDSA P-256, Ed25519, or RSA of at least 2048 bits |
| Validity | Current; mimid uses its system clock |
| Chain sent | Leaf first. For DANE-TA, include the CA the TLSA record names |

### For PKIX: exchange CA certificates

Each side sends the other the CA certificate that issued its client
certificate, out of band (Zulip, mail), with its SHA-256 fingerprint:
`openssl x509 -in ca.pem -noout -fingerprint -sha256`. Haven's root is
already in `tools/interop/haven/certs/haven-root.pem`.

On mimid, anchor it for that peer only:

```toml
[provider_auth.peers."mimi.havenmessenger.com"]
pkix_anchors = ["/etc/mimid/peers/haven-root.pem"]
```

### For DANE: TLSA records and DNSSEC

The sender publishes a TLSA record at `_mimi._client.<its domain>` in a
DNSSEC-signed zone. For its own key (DANE-EE, SPKI, SHA-256):

```sh
openssl x509 -in client.pem -pubkey -noout \
  | openssl pkey -pubin -outform der | sha256sum
# _mimi._client.example.com. IN TLSA 3 1 1 <hex>
```

Check the answer is secure through a validating resolver:
`delv @1.1.1.1 _mimi._client.example.com TLSA` must say
`fully validated`. mimid's own zone (reviewcommit.com, at Epik) must be
DNSSEC-signed before a peer can test DANE against mimid; check this
first.

On mimid, `dane` is on by default. `dns_servers`, if set, must be
resolvers that pass DNSSEC records through. At start mimid logs
`provider_auth_dnssec_ok` when validation works, and
`provider_auth_dnssec_unavailable` or `provider_auth_dnssec_unproven`
when it does not.

### mimid configuration

Inbound, one of:

```toml
# mimid terminates TLS itself and asks for client certificates.
[tls]
cert = "/etc/mimid/tls/fullchain.pem"
key = "/etc/mimid/tls/key.pem"
```

```toml
# Caddy terminates TLS and forwards the leaf certificate.
[trusted_proxy]
addresses = ["127.0.0.1"]
header = "X-Client-Cert"
```

with, in the Caddyfile:

```
tls { client_auth { mode request } }
reverse_proxy 127.0.0.1:8080 {
    header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}
}
```

Through Caddy only the leaf arrives: DANE-TA does not work, and an
intermediate CA must be configured as an anchor itself.

Outbound and the test settings:

```toml
[peer_tls.identity]
cert = "/etc/mimid/client/chain.pem"   # leaf first
key = "/etc/mimid/client/key.pem"

[provider_auth]
mode = "enforce"
dns_keys = false   # for the test only: see above
dane = true

[provider_auth.peers."mimi.havenmessenger.com"]
pkix_anchors = ["/etc/mimid/peers/haven-root.pem"]
# mode = "observe"   # start here if the peer is not ready
```

mimid reads its configuration at start only: restart after each change.

### Observe and enforce

`enforce` (the default) answers an unauthenticated request with `403`, an
RFC 9457 problem of type `provider-authentication` and an
`Accept-Signature` field. `observe` lets it through and logs the first
failure per peer at INFO (`provider_auth_observed`), the rest at DEBUG.
Start each peer in observe, check the log shows the expected mechanism,
then switch it to enforce.

## Logging

Run mimid with:

```sh
RUST_LOG=info,mimid_server::provider_auth=debug MIMID_LOG_FORMAT=json mimid mimid.toml
```

| Message | Fields |
|---|---|
| `provider authenticated` | `peer`, `endpoint`, `mechanism` (`pkix`, `dane`, `dns_key`, `trust_list`), `key_id`, `dnssec` |
| `request refused: provider not authenticated` | `peer`, `endpoint`, `reason`, `status` |
| `provider_auth_observed` (INFO) | `peer`, `endpoint`, `reason` |

`key_id` for a certificate is `sha256:` and the SHA-256 of the leaf's
DER, so it can be compared with
`openssl x509 -in client.pem -outform der | sha256sum`.

Each side captures, per test row: the time, the request, the status, the
log lines above, and the peer's own log. For handshake problems, also
`openssl s_client -connect <host>:443 -cert client.pem -key key.pem
-servername <host>`, which shows whether the server requested a
certificate.

## Test matrix

Run each row in both directions. "Inbound" is the peer sending to mimid;
"outbound" is mimid sending to the peer, checked in the peer's log.
Requests that make traffic each way:

| Direction | Requests | Made by |
|---|---|---|
| peer room, mimid user | keyMaterial, notify to mimid; submitMessage, update, groupInfo, updateConsent from mimid | the peer's users adding a mimid user, sending; the mimid user replying |
| mimid room, peer user | keyMaterial, notify to the peer; submitMessage, update, groupInfo from the peer | the reverse |

| # | Mechanism | Client sends | Receiver's mode | Expected |
|---|---|---|---|---|
| 1 | PKIX | right certificate, anchor configured | observe | accepted; `mechanism = pkix`, right `key_id` |
| 2 | PKIX | right certificate | enforce | accepted, normal responses (`200`, `201`, `202`) |
| 3 | PKIX | no certificate | enforce | `403`, reason `no credentials` |
| 4 | PKIX | certificate for another domain | enforce | `403`, `no dNSName for the domain` |
| 5 | PKIX | certificate from a CA not configured | enforce | `403`, `certificate path refused` |
| 6 | PKIX | expired certificate (if the sender can make one) | enforce | `403`, `certificate path refused` |
| 7 | DANE-EE | certificate matching `3 1 1`, zone signed | enforce | accepted; `mechanism = dane`, `dnssec = secure` |
| 8 | DANE-TA | chain with the CA matching `2 0 1` | enforce | accepted; `mechanism = dane` |
| 9 | DANE | TLSA record for another key | enforce | `403`, `no TLSA record matches` |
| 10 | DANE | unsigned zone | enforce | `403`, `the key record is not DNSSEC-secure` (no PKIX anchor set) |
| 11 | none | signatures back on (`dns_keys = true`) | enforce | accepted; `mechanism = dns_key`: confirms the order |

Rows 3 to 6 and 9 to 10 need no cooperation beyond a client the sender
can point at the receiver (curl with `--cert`/`--key`, or a second
configuration).

## Rollback

Keep the previous configuration file and restart with it. In order of
how much they undo:

- One peer misbehaving: set `mode = "observe"` for it and restart.
- mimid's certificate causing trouble at a peer: remove
  `[peer_tls.identity]` and restart; mimid still signs its requests.
- Signatures turned off for the test: set `dns_keys = true` again (and
  restore any `keys`).
- Behind Caddy: restore the previous Caddyfile and `caddy reload`.

A peer that enforces on mimid without a working mechanism will refuse
every request from mimid; agree the order (observe first) before
switching to enforce.

## Proven locally

`tests/mtls_binaries.rs`, two `mimid` binaries on loopback, enforce mode:

- PKIX, mimid terminating TLS, both directions: updateConsent,
  submitMessage, groupInfo and update b → a; keyMaterial and notify
  a → b; each authenticated as `pkix` with the sender's key id.
- PKIX refusals: no certificate, wrong domain, unknown CA, expired.
- Trusted proxy: the forwarded certificate is accepted from the proxy's
  address only.
- DANE b → a, against a stub resolver standing in for DNSSEC (the
  binary's resolver validates from the real root): DANE-EE and DANE-TA
  accepted; a record for another key, an insecure answer and no records
  refused.

Not proven: interop with another implementation's TLS stack and
certificates, DANE through real DNSSEC, and DANE toward a mimid binary.
