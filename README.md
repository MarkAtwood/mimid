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
| draft-ietf-mls-extensions | -11 | |
| draft-ietf-mls-ratchet-tree-options | -02 | |

## Provisional codepoints

These are values the drafts suggest or request but IANA has not assigned, because the registries or the documents are not yet published. mimid uses them as written and will follow any change at assignment.

| Value | What | Source |
|---|---|---|
| extension types 0x0006–0x0008 | `app_data_dictionary`, `supported_wire_formats`, `required_wire_formats` | mls-extensions-11 §7.1, "(suggested)" |
| proposal types 0x0008–0x000a | `app_data_update`, `app_ephemeral`, `self_remove` | mls-extensions-11 §7.2, "(suggested)" |
| components 0x0001–0x0005 | `app_components`, `safe_aad`, `content_media_types`, `last_resort_key_package`, `app_ack` | mls-extensions-11 §7.5, initial contents of a registry not yet created |
| components 0x0020–0x0023 | `frank_aad`, `franking_agent`, `participant_list`, `room_metadata` | protocol-07 §10, requested in that registry |

mimid also uses values of its own from the private-use range of the MLS Component Types registry (0x8000–0xFFFF, mls-extensions-11 §7.5). No draft defines them, and other implementations ignore them:

| Value | What | Decision |
|---|---|---|
| component 0xF013 | the did:webvh heads record (configurable as `heads_component`) | mimid-1wgh.4.81.35 |
| component 0xF020 | `unverified_abusive_messages`: unfranked messages in an AbuseReport's `abuse_extensions`, which only a mimid hub reads and records as unverified | mimid-1wgh.60 |

## Known weaknesses

These are deliberate in the current version:

- **Provider authentication is partial.** Providers prove who they are with RFC 9421 request signatures, with keys configured per peer or published in DNS at `<selector>._mimi.<domain>` (draft-atwood-mimi-provider-auth-00; `[provider_auth]` in the configuration; `mimid admin <config> provider-key` prints this server's key and its DNS record). DNS keys are looked up with DNSSEC validation, so the resolvers in `dns_servers` must pass DNSSEC records through. A peer's TLS client certificate authenticates it when its path validates against a CA configured in `pkix_anchors` and it names the peer's domain as a SAN dNSName, or when it matches DNSSEC-secure TLSA records the peer publishes at `_mimi._client.<domain>` (DANE; on unless `dane = false`; usages DANE-EE and DANE-TA only); the certificate reaches mimid from its own TLS listener (`[tls]`) or from a trusted proxy (`[trusted_proxy]`). mimid presents its own client certificate to peers when `[peer_tls.identity]` is set. A peer set to `observe` is let through unauthenticated. protocol-07 requires mutually authenticated TLS; mimid has both halves, but they haven't been deployed or tested with a peer yet, so it doesn't claim conformance.
- **BasicCredential by default.** A client's credential is a BasicCredential holding its user's MIMI URI, so the user's provider can claim any identity for its own users, and mimid offers no protection against a malicious provider for them. In the terms of draft-barnes-mimi-identity-arch-04 §6: the end-to-end protocol is MLS (RFC 9420); there is no revocation; and the only authority behind such a leaf is, implicitly, the provider of the URI's domain. The credential-to-domain rule is open in mimi-protocol#159. A user can instead use a did:webvh credential (draft-atwood-mls-didwebvh-credential; `[did_webvh]` in the agent's configuration): the user's own keys sign the log that authorizes each device, members pin the user's DID on first sight and flag a change, and a revoked device is removed from every room. That protects against the provider only from first contact on.
- **Peers come from configuration**, not DNS discovery.

## Known gaps

Not deliberate; each is being fixed:

- A room's creator holds `canKick`, bans and role changes in the default room policy, but mimid-agent has no operation that uses them yet, so removing another user from a mimid-agent room needs another client or the operator (`mimid admin remove|ban`). Bead mimid-90cd.
- A user's new device is not added to rooms the user is already in. Bead mimid-d464.
- Two devices of one user can't share a group with stock mls-rs, which refuses two leaves with the same BasicCredential. Epic mimid-4lp4.
- Received edits and retractions are skipped. Bead mimid-kmhd.

Each crate documents its own limitations in the `# Limitations` section of its rustdoc.

## Crates

| Crate | Contents |
|---|---|
| `mimi-mls` | All OpenMLS usage, MLS wire newtypes, label helpers |
| `mimi-content` | mimi-content CBOR message format and MessageId |
| `mimi-room-policy` | room-policy codecs and policy evaluation |
| `mimi-protocol` | protocol wire types and franking |
| `mimid-server` | The `mimid` provider server: hub and follower roles, and a JMAP Chat endpoint (partial) |
| `mimid-agent-core` | The client engine: one user's MLS keys and rooms, through their mimid server's JMAP API |
| `mimid-agent-jmap` | JMAP Chat over `mimid-agent-core`: the user's rooms as Chats and Messages |
| `mimid-agent` | The `mimid-agent` daemon: serves `mimid-agent-jmap` as a local JMAP Chat endpoint on loopback |

The four `mimi-*` crates are synchronous and do no I/O. Planned but not yet written: an admin CLI. mimid ships no UI of its own.

mimid builds against a fork of OpenMLS ([MarkAtwood/openmls](https://github.com/MarkAtwood/openmls)) carrying fixes that are not yet in an OpenMLS release.

## Build and test

mimid supports the latest stable Rust only.

```bash
cargo build --workspace
cargo test --workspace --all-features
```

The full set of checks CI runs is in `.github/workflows/ci.yml`. Tests are fully offline.

To run the server: `mimid <config.toml>`. The config format is documented in `mimid_server::config`.

To run the agent for one user: `mimid-agent <config.toml>`. The config format is documented in `mimid_agent::config`; a JMAP Chat client authenticates with the token in `<state_dir>/agent-token`.

## Interoperability

Wire-format fixtures come from sources outside mimid: draft examples, working group files, hand-encoded bytes, and other implementations (OpenMLS, mls-rs, Haven's mimi-core), each with a `PROVENANCE` file. Spec errata found along the way go back to the working groups.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Versions before the commit that made this change were published under AGPL-3.0-only.
