#!/usr/bin/env python3
"""Independent oracle for protocol-06 franking HMACs (mimid-1wgh.5.4).

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

Standard library only (hmac, hashlib, struct). It does not call or read any
mimid code. Regenerate:

  python3 -I franking_gen.py > franking_gen.out
"""

import hashlib
import hmac
import struct


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


def main():
    self_check()
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


if __name__ == "__main__":
    main()
