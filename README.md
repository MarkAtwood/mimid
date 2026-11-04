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

- **No authentication between providers.** protocol-07 requires mutually authenticated TLS between providers; mimid doesn't implement it and doesn't claim conformance to it.
- **BasicCredential only.** Combined with the point above, mimid offers no protection against a malicious or impersonated provider.
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

AGPL-3.0-only. See [LICENSE](LICENSE).
