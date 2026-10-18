#!/usr/bin/env python3
"""Independent oracle for protocol-06 franking (mimid-1wgh.5.4, .5.6).

Computes, from the text of draft-ietf-mimi-protocol-06 alone:

  §5.4.1.1  franking_tag = HMAC_SHA256(salt, application_data)
  §5.4.1.2  server_frank = HMAC_SHA256(hub_key, franking_tag || context)

where context is the TLS encoding of

  struct {
      IdentifierUri sender_uri;   /* struct { opaque uri<V>; } (§5.2) */
      IdentifierUri room_uri;
      uint64 accepted_timestamp;
  } ServerFrankingContext;

<V> is the RFC 9420 §2.1.2 variable-length integer prefix, uint64 is
big-endian (RFC 8446 §3.3), and "||" is the raw 32-byte tag followed by the
encoded context (decision mimid-1wgh.5.28). application_data is opaque here
(decision mimid-1wgh.5.29).

It also computes the hub's integrity signature (§5.4.1.2):

  struct {
      opaque server_frank[32];
      CipherSuite franking_signature_ciphersuite;   /* uint16 */
      ServerFrankingContext context;
  } FrankingIntegrityTBS;

  franking_integrity_signature = SignWithLabel(franking_private_key,
      "FrankingIntegrityTBS", FrankingIntegrityTBS)

with RFC 9420 §5.1.2 SignWithLabel over Ed25519, which is deterministic
(RFC 8032 §5.1.6). Before printing anything it self-checks SignWithLabel
against the suite 1 entry of the mlswg crypto-basics.json vectors.

Standard library (hmac, hashlib, struct, json) plus pyca/cryptography for
Ed25519. It does not call or read any mimid code. Regenerate (from this
directory):

  python3 -I franking_gen.py \\
    ../../../../mimi-mls/tests/fixtures/crypto-basics/crypto-basics.json \\
    > franking_gen.out
"""

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def varint(n):
    """RFC 9420 §2.1.2 minimal variable-length integer."""
    if n < 1 << 6:
        return struct.pack(">B", n)
    if n < 1 << 14:
        return struct.pack(">H", 0x4000 | n)
    if n < 1 << 30:
        return struct.pack(">I", 0x80000000 | n)
    raise ValueError("too long for an MLS vector")


def opaque_v(b):
    return varint(len(b)) + b


def server_franking_context(sender_uri, room_uri, accepted_timestamp):
    return (
        opaque_v(sender_uri.encode("ascii"))
        + opaque_v(room_uri.encode("ascii"))
        + struct.pack(">Q", accepted_timestamp)
    )


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def pattern(n):
    """Deterministic filler: byte i is i mod 251."""
    return bytes(i % 251 for i in range(n))


def cbor_tstr(s):
    """CBOR text string (RFC 8949 §3.1, major type 3), lengths < 2^16."""
    b = s.encode("utf-8")
    if len(b) < 24:
        return bytes([0x60 | len(b)]) + b
    if len(b) < 256:
        return bytes([0x78, len(b)]) + b
    return bytes([0x79]) + struct.pack(">H", len(b)) + b


def extensions_map(sender_uri, room_uri):
    """CBOR map {1: sender_uri, 2: room_uri}, as in protocol-06 §5.4.1.1.

    Realistic application_data bytes only; franking_tag treats them as
    opaque.
    """
    return bytes([0xA2, 0x01]) + cbor_tstr(sender_uri) + bytes([0x02]) + cbor_tstr(room_uri)


def sign_with_label(seed, label, content):
    """RFC 9420 §5.1.2: sign SignContent { "MLS 1.0 " + label, content }."""
    sign_content = opaque_v(b"MLS 1.0 " + label) + opaque_v(content)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(sign_content)


def ed25519_pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def self_check_sign(crypto_basics_path):
    """mlswg crypto-basics.json, cipher_suite 1, sign_with_label."""
    with open(crypto_basics_path, encoding="utf-8") as f:
        entry = next(e for e in json.load(f) if e["cipher_suite"] == 1)
    v = entry["sign_with_label"]
    seed = bytes.fromhex(v["priv"])
    assert ed25519_pub(seed).hex() == v["pub"], "Ed25519 public key self-check failed"
    sig = sign_with_label(seed, v["label"].encode(), bytes.fromhex(v["content"]))
    assert sig.hex() == v["signature"], "SignWithLabel self-check failed"


def self_check():
    # RFC 9420 §2.1.2 worked examples.
    assert varint(37) == bytes.fromhex("25")
    assert varint(15293) == bytes.fromhex("7bbd")
    assert varint(494878333) == bytes.fromhex("9d7f3e7d")
    # RFC 4231 §4.2 and §4.3 (HMAC-SHA-256 test cases 1 and 2).
    assert hmac_sha256(b"\x0b" * 20, b"Hi There").hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    assert hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


SALT_A = bytes(range(16))
SALT_FF = b"\xff" * 16
ALICE = "mimi://b.example/u/alice"
ROOM = "mimi://hub.example/r/Rl33FWLCYWOwxHrYnpWDQg"

TAG_CASES = [
    # (name, salt, application_data, description of application_data)
    ("spec_example", SALT_A, extensions_map(ALICE, ROOM), "extensions_map(ALICE, ROOM)"),
    ("empty_application_data", SALT_A, b"", "empty"),
    (
        "non_ascii_room_uri",
        SALT_A,
        extensions_map(ALICE, "mimi://hub.example/r/café-☃-\U0001f600"),
        "extensions_map(ALICE, mimi://hub.example/r/caf\\u00e9-\\u2603-\\U0001f600)",
    ),
    ("long_application_data", SALT_A, pattern(100000), "pattern(100000)"),
    ("salt_ff_one_zero_byte", SALT_FF, b"\x00", "00"),
]

HUB_KEY_A = bytes(range(0x20, 0x40))
HUB_KEY_FF = b"\xff" * 32
LONG_ROOM = "mimi://hub.example/r/" + "a" * (16384 - len("mimi://hub.example/r/"))
URI_64 = "mimi://b.example/u/" + "b" * (64 - len("mimi://b.example/u/"))
URI_63 = URI_64[:63]


def frank_cases():
    tag_spec = hmac_sha256(SALT_A, extensions_map(ALICE, ROOM))
    return [
        # (name, hub_key, franking_tag, sender_uri, room_uri, accepted_timestamp)
        ("basic", HUB_KEY_A, tag_spec, ALICE, ROOM, 1700000000000),
        ("empty_uris_zero_timestamp", HUB_KEY_A, b"\x00" * 32, "", "", 0),
        ("max_timestamp", HUB_KEY_FF, tag_spec, ALICE, ROOM, 2**64 - 1),
        ("prefix_boundary_63_64", HUB_KEY_A, tag_spec, URI_63, URI_64, 1),
        ("long_room_uri_4byte_prefix", HUB_KEY_A, tag_spec, ALICE, LONG_ROOM, 1700000000000),
        (
            "percent_encoded_non_ascii_room_uri",
            HUB_KEY_A,
            tag_spec,
            ALICE,
            "mimi://hub.example/r/caf%C3%A9-%E2%98%83",
            1700000000000,
        ),
    ]


def show(label, b):
    """Full hex up to 256 bytes; beyond that, length, SHA-256 and first 8 bytes."""
    if not b:
        print(f"  {label} = (zero bytes)")
    elif len(b) <= 256:
        print(f"  {label} = {b.hex()}")
    else:
        print(f"  {label} = len {len(b)} sha256 {hashlib.sha256(b).hexdigest()} head {b[:8].hex()}")


FRANKING_SEED = bytes([0x55] * 32)
SUITE_1 = 0x0001
SUITE_3 = 0x0003  # MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519


def integrity_cases():
    """Each case signs the server_frank and context of a frank_cases entry."""
    return [
        # (name, frank_cases name, franking_signature_ciphersuite)
        ("basic", "basic", SUITE_1),
        ("empty_uris_zero_timestamp", "empty_uris_zero_timestamp", SUITE_1),
        ("max_timestamp", "max_timestamp", SUITE_1),
        ("long_room_uri_4byte_prefix", "long_room_uri_4byte_prefix", SUITE_1),
        ("suite_3", "basic", SUITE_3),
    ]


def main():
    self_check()
    self_check_sign(sys.argv[1])
    print("# franking_gen.py output: see PROVENANCE. Hex is lowercase.")
    for name, salt, data, desc in TAG_CASES:
        print(f"franking_tag {name}")
        print(f"  salt = {salt.hex()}")
        print(f"  application_data = {desc}")
        show("application_data_bytes", data)
        print(f"  franking_tag = {hmac_sha256(salt, data).hex()}")
    for name, key, tag, sender, room, ts in frank_cases():
        ctx = server_franking_context(sender, room, ts)
        print(f"server_frank {name}")
        print(f"  hub_key = {key.hex()}")
        print(f"  franking_tag = {tag.hex()}")
        print(f"  sender_uri len {len(sender)}, room_uri len {len(room)}, accepted_timestamp = {ts}")
        show("context", ctx)
        print(f"  server_frank = {hmac_sha256(key, tag + ctx).hex()}")
    franks = {}
    for name, key, tag, sender, room, ts in frank_cases():
        ctx = server_franking_context(sender, room, ts)
        franks[name] = (hmac_sha256(key, tag + ctx), ctx)
    print("franking_key")
    print(f"  seed = {FRANKING_SEED.hex()}")
    print(f"  franking_signature_key = {ed25519_pub(FRANKING_SEED).hex()}")
    for name, frank_case, suite in integrity_cases():
        frank, ctx = franks[frank_case]
        tbs = frank + struct.pack(">H", suite) + ctx
        print(f"franking_integrity {name}")
        print(f"  server_frank = {frank.hex()} (server_frank {frank_case})")
        print(f"  franking_signature_ciphersuite = {suite:#06x}")
        show("tbs", tbs)
        sig = sign_with_label(FRANKING_SEED, b"FrankingIntegrityTBS", tbs)
        print(f"  franking_integrity_signature = {sig.hex()}")


if __name__ == "__main__":
    main()
