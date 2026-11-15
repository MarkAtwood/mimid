# mimid

A Rust reference implementation of IETF MIMI (More Instant Messaging Interoperability) over MLS (RFC 9420). It implements the latest MIMI drafts as written, with enough product around them to be a usable chat system. It's a work in progress, not ready for production use.

## Specifications

mimid targets the latest revision of each draft. Where the drafts are ambiguous, the chosen reading is recorded as a decision and cited in the code.

| Draft | Target | Notes |
|---|---|---|
| draft-ietf-mimi-protocol | -07 | catching up from -06 |
| draft-ietf-mimi-content | -10 | |
| draft-ietf-mimi-room-policy | -04 | |
| draft-ietf-mimi-arch | -03 | |
| draft-ietf-mls-extensions | -10 | |
| draft-ietf-mls-ratchet-tree-options | -02 | |

## Known weaknesses

These are deliberate in the current version:

- **Provider authentication is partial.** Providers prove who they are with RFC 9421 request signatures, with keys configured per peer or published in DNS at `<selector>._mimi.<domain>` (draft-atwood-mimi-provider-auth-00; `[provider_auth]` in the configuration; `mimid admin <config> provider-key` prints this server's key and its DNS record). DNS keys are looked up with DNSSEC validation, so the resolvers in `dns_servers` must pass DNSSEC records through. A peer's TLS client certificate authenticates it when its path validates against a CA configured in `pkix_anchors` and it names the peer's domain as a SAN dNSName; the certificate reaches mimid from its own TLS listener (`[tls]`) or from a trusted proxy (`[trusted_proxy]`). mimid presents its own client certificate to peers when `[peer_tls.identity]` is set. A peer set to `observe` is let through unauthenticated. protocol-07 requires mutually authenticated TLS; mimid has both halves, but they haven't been deployed or tested with a peer yet, so it doesn't claim conformance.
- **BasicCredential only.** A provider can claim any identity for its own users, so mimid offers no protection against a malicious provider.
- **Peers come from configuration**, not DNS discovery.

Each crate documents its own limitations in the `# Limitations` section of its rustdoc.

## Crates

| Crate | Contents |
|---|---|
| `mimi-mls` | All OpenMLS usage, MLS wire newtypes, label helpers |
| `mimi-content` | mimi-content CBOR message format and MessageId |
| `mimi-room-policy` | room-policy codecs and policy evaluation |
| `mimi-protocol` | protocol wire types and franking |
| `mimid-server` | The `mimid` provider server: hub and follower roles, and a JMAP Chat endpoint (partial) |

The four `mimi-*` crates are synchronous and do no I/O. Planned but not yet written: an admin CLI, and a client-side agent that bridges standard JMAP Chat clients to MIMI. mimid ships no UI of its own.

mimid builds against a fork of OpenMLS ([MarkAtwood/openmls](https://github.com/MarkAtwood/openmls)) carrying fixes that are not yet in an OpenMLS release.

## Build and test

mimid supports the latest stable Rust only.

```bash
cargo build --workspace
cargo test --workspace --all-features
```

The full set of checks CI runs is in `.github/workflows/ci.yml`. Tests are fully offline.

To run the server: `mimid <config.toml>`. The config format is documented in `mimid_server::config`.

## Interoperability

Wire-format fixtures come from sources outside mimid: draft examples, working group files, hand-encoded bytes, and other implementations (OpenMLS, mls-rs, Haven's mimi-core), each with a `PROVENANCE` file. Spec errata found along the way go back to the working groups.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Versions before the commit that made this change were published under AGPL-3.0-only.
