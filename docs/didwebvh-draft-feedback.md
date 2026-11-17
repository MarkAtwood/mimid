# Feedback on draft-atwood-mls-didwebvh-credential-00 from implementing it in mimid

mimid is the first implementation of draft-atwood-mls-didwebvh-credential-00.
This file lists what implementing it showed to be ambiguous, underspecified or
wrong, for -01 (IETF-xgzc). Each item gives the draft section, what is unclear,
the reading mimid chose and why, and the decision bead that records it.

The did:webvh method used is v1.0, `spec-v1.0/` of
decentralized-identity/didwebvh at 91f3cba, the commit the draft cites.
`spec-v1.0/` is byte-identical at deef9cf and at main bf3d9b4 (2026-11-02).

Code: `crates/mls-didwebvh` (the credential, log verification, the heads
extension and the group rules, with no MLS library) and `crates/mimi-mls` (the
same rules applied to OpenMLS groups).

## Wire format

### 1. The credential cannot be carried by OpenMLS or mls-rs as written

**§The did:webvh Credential.** The draft puts `DIDWebVHCredential did_webvh;`,
a struct of two `opaque<V>` fields, directly in the `select` arm of RFC 9420's
`Credential`.

Both OpenMLS 0.9 and mls-rs encode every credential type they do not know as
`credential_type` followed by one `opaque<V>`. OpenMLS's source says so ("The
implementation only works with credentials that are encoded as variable-sized
vectors"). Given the draft's encoding, either library reads `did_log` as the
whole credential and then parses `witness_file` as the next LeafNode field. RFC
9420's own two types (`basic`, `x509`) are both one vector, so nothing in RFC
9420 forced this assumption to be tested before.

**mimid:** carries the TLS encoding of `DIDWebVHCredential` inside one
`opaque<V>`, so that the wire is `credential_type || varint(len) ||
did_log<V> || witness_file<V>`. This is not what -00 says; it is marked
INVENTED, NOT FROM SPEC in the code. Decision mimid-1wgh.4.81.8.

**For -01:** write the arm as `opaque did_webvh<V>;` whose content is a
`DIDWebVHCredential`, or say in prose that the structure is carried inside an
`opaque<V>`. Consider a sentence noting that new credential types need this
shape to be carried by existing stacks. This also bears on the encoding
question (item 7 of Open Issues; see below).

## Log verification and the profile

### 2. Missing final LF: two of six did:webvh implementations fail the profile

**§did:webvh Profile, Encoding:** "each line ending in a single LF (0x0A),
with no blank lines and nothing after the last LF".

In the DIF did:webvh test suite (commit 703f97f), the logs written by the
dart and java implementations have no final LF. Python, Rust, TypeScript and
java-eecc conform. Under -00, every log the dart and java implementations
produce is invalid as a credential, although those logs are valid did:webvh.

**mimid:** refuses them, as written. Decision mimid-1wgh.4.81.11.

**For -01:** either accept a missing final LF (entries are delimited by LF
anyway, so this costs nothing and loses no determinism), or keep the rule and
say that a controller must add the LF before putting a log in a credential.

### 3. CR LF and whitespace inside lines

**§did:webvh Profile, Encoding.** JSON Lines (jsonlines.org) tolerates `\r\n`
because whitespace around a value is ignored; "a single LF" suggests not. JSON
whitespace between tokens inside a line is not mentioned; did:webvh says
entries have "all extra whitespace removed", but hashes over JCS, so
whitespace never changes validity under v1.0.

**mimid:** refuses a line ending in CR; accepts other JSON whitespace inside a
line; refuses an empty `did_log`. Decision mimid-1wgh.4.81.11.

**For -01:** say both explicitly.

### 4. "MUST be I-JSON" and numbers

**§did:webvh Profile, Encoding:** "Each log entry, and `witness_file`, MUST be
I-JSON [RFC7493]". RFC 7493 §2.2 on numbers is a SHOULD NOT ("SHOULD NOT
include numbers that express greater magnitude or precision than an IEEE 754
double"). Does "MUST be I-JSON" make it a MUST NOT?

This matters for determinism: the entry hash is over JCS, which serializes
numbers as doubles. A member whose JSON parser keeps `9007199254740993`
exactly and one that rounds it to a double compute different hashes, so they
disagree about validity. RFC 7493 also requires no noncharacters, which many
JSON parsers accept silently.

**mimid:** refuses any number whose value is integral with magnitude above
2^53 - 1, however written (`9007199254740993`, `1e20`); accepts non-integral
numbers as its parser reads them, so it cannot detect excess precision in
`3.141592653589793238`; refuses noncharacters in strings and member names;
compares member names after unescaping (`"a"` and `"a"` are duplicates).
Decision mimid-1wgh.4.81.9.

**For -01:** say which numbers are allowed. The simplest deterministic rule
is integers within ±(2^53 - 1) only: did:webvh's own parameters need nothing
else, and DID documents rarely carry numbers.

### 5. No JSON nesting limit

The draft fixes byte limits "so that every member applies the same limit",
but JSON parsers also differ in nesting depth (serde_json stops at 128). A
1 MiB log can nest far deeper than that, and members with different parsers
then disagree.

**mimid:** refuses nesting deeper than 128 (serde_json's limit). Decision
mimid-1wgh.4.81.9.

**For -01:** give a nesting limit, by the same argument as the byte limits.

### 6. The ASCII domain rule

**§did:webvh Profile, Domain:** "The DID string MUST match the
method-specific identifier syntax of [DIDWEBVH] using only ASCII letters,
digits, hyphens and dots."

- Literally the whole DID string has colons, the SCID and path segments, so
  the rule must mean the domain component.
- did:webvh writes a port as `%3A<port>` in the domain component; `%` is not
  allowed, so ports are forbidden. Intended?
- Which DID string: the head's, or every entry's `state.id`? They differ after
  a portable move.
- "No internationalized domain name processing is performed", but `xn--`
  labels are ASCII. A did:webvh verifier that runs IDNA (as mimid's inherited
  one does) refuses a malformed `xn--` label; one that does no IDNA processing
  accepts it.

**mimid:** applies the rule to the domain component of every entry's
`state.id`, which must be non-empty `[A-Za-z0-9.-]`, so ports and
percent-encoded IDNs are refused; path segments follow did:webvh; malformed
`xn--` labels are refused (documented limitation). Decision
mimid-1wgh.4.81.12.

**For -01:** say "domain component", say whether ports are allowed, and say
whether `xn--` labels are validated.

### 7. `ttl` "has no effect on validation"

**§Log Verification, change 3.** Read strictly, even a malformed `ttl`
(negative, above 2^31) would not affect validation, but did:webvh's "Allowed
Values" rule makes a log with an invalid parameter value invalid.

**mimid:** an invalid `ttl` value still makes the log invalid (did:webvh's
parameter rules apply); only its caching meaning is ignored.

**For -01:** say "the value of `ttl` is not used" rather than "has no effect
on validation".

### 8. Future `versionTime` in the DIF suite

The DIF negative scenario `negative-versiontime-future` (entries at
2000-01-01, 9999-06-15, 2000-01-03) is rejected by a v1.0 resolver at entry 2
for being in the future. Under change 3 mimid rejects it at entry 3 instead,
for going backwards. Worth a sentence in -01 that change 3 can change *where*
a log fails, not only whether, and that a log valid under change 3 may be
refused by every ordinary resolver.

### 9. Authorized keys: three gaps

**§Conventions, "Authorized key".**

1. "a 32-byte public key in the format of [RFC8032]": must the bytes decode
   as a valid Ed25519 point? If some members check and others do not, they
   compute different `authorized_keys`, the extension differs, and members
   disagree. **mimid:** no point check.
2. "A relative reference is resolved against the document's `id` as
   [DID-CORE] specifies": DID Core points to RFC 3986 §5.2, under which only
   a fragment-only reference has an obvious result against a `did:` base.
   **mimid:** `#frag` resolves to `id#frag`; absolute `did:` references are
   used as is; other relative forms resolve to nothing. Verification method
   `id`s are resolved the same way before comparing.
3. Where a reference resolves: **mimid:** only to objects in the top-level
   `verificationMethod` array; two methods sharing an `id` resolve to nothing.

Decision mimid-1wgh.4.81.10. **For -01:** say all three. A vector
(`dave-authorized-keys` in `crates/mls-didwebvh/tests/vectors/vectors.json`)
exercises each case.

### 10. `witness_file` and pruning

**§The did:webvh Credential:** `witness_file` holds "the witness proofs for
the carried entries". did:webvh says a witness proof approves all earlier
entries, and that controllers SHOULD prune the published `did-witness.json` to
the latest proof per witness. So a device whose credential carries an older
head cannot use the current published witness file: its proofs are for
versionIds beyond that device's head, which "are ignored". Each device must
keep the witness file as it was when its head was current, or the controller
must keep unpruned proofs.

**For -01:** say so in §Adding a Device or in the field description.

## Group rules

### 11. Ties for the newest log

**§Expected Heads:** "Let L be the newest log among the resulting tree's
credentials with SCID S", and "Newest log: the one whose head has the highest
version number". Two forks can have heads with the same version number; L is
then unspecified, and so is the expected extension.

**mimid:** ties go to the greatest head `versionId` bytes; a tie between
different heads always fails the consistency rule anyway, so mimid checks
consistency before the extension match and reports the fork. Decision
mimid-1wgh.4.81.14.

**For -01:** state that heads with the same version number and different
`versionId`s make the Commit invalid, before computing the expected entry.

### 12. Consistency when there is no reference entry

**§Rules, Consistency with the reference entry:** "Every credential with SCID
S whose head is newer than R's is a prefix of L." When R does not exist (a
new user) this is undefined. Read as "no check", two forked credentials of a
new SCID are both admitted: the extension records one, the other leaf is
judged only by authorization against L's keys.

**mimid:** with no R, every credential of S must be a prefix of L. Decision
mimid-1wgh.4.81.14. Vector `new-scid-two-forks`.

**For -01:** say so.

### 13. Malformed or oversized `did_webvh_heads`

**§The Heads Extension** gives no limits and does not say what a member does
with a malformed extension (unsorted, duplicates, keys not 32 bytes). Dropping
a malformed extension, as is usual for unknown extensions, would forget
revocations.

**mimid:** a malformed extension fails closed (the Commit, Welcome or
GroupInfo is refused). It caps entries at 65,536 (invented; the record grows
forever, Open Issue 6) and keys per entry at 1,048,576/48 (derived: each
distinct key needs a 48-byte `publicKeyMultibase` string in a 1 MiB
document). Decision mimid-1wgh.4.81.13.

**For -01:** say that a malformed extension means rejection, and either set a
limit on entries or say none is intended.

## Section 7, item 7: the encoding question

To be completed once the OpenMLS integration is done; see the end of this file.
