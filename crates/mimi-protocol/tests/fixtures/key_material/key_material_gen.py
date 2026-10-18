#!/usr/bin/env python3
"""Independent oracle for the protocol-06 §5.2 keyMaterial signature (mimid-1wgh.5.8).

Computes, from the text of draft-ietf-mimi-protocol-06 §5.2 and RFC 9420
§5.1.2 alone:

  key_material_request_signature = SignWithLabel(requesterSignatureKey,
      "KeyMaterialRequestTBS", KeyMaterialRequestTBS)

with Ed25519, the signature scheme of ciphersuite 1, for two requests: one
with a roomId and one with a zero-length roomId (absent, decision
mimid-1wgh.5.27).

Before printing anything it self-checks SignWithLabel against the mlswg
crypto-basics.json suite 1 vector. It does not call or read any mimid code.
Regenerate (from this directory):

  python3 -I key_material_gen.py \\
    ../../../../mimi-mls/tests/fixtures/crypto-basics/crypto-basics.json \\
    > key_material_gen.out
"""

import json
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RAW = serialization.Encoding.Raw
RAW_PUB = serialization.PublicFormat.Raw


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


def sign_with_label(seed, label, content):
    """RFC 9420 §5.1.2 SignWithLabel."""
    sign_content = opaque_v(b"MLS 1.0 " + label) + opaque_v(content)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(sign_content)


def self_check(crypto_basics_path):
    with open(crypto_basics_path, encoding="utf-8") as f:
        entry = next(e for e in json.load(f) if e["cipher_suite"] == 1)
    s = entry["sign_with_label"]
    sig = sign_with_label(
        bytes.fromhex(s["priv"]), s["label"].encode(), bytes.fromhex(s["content"])
    )
    assert sig.hex() == s["signature"], "SignWithLabel self-check failed"


def ed25519_pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        RAW, RAW_PUB
    )


def request_tbs(requester_pub, room_id):
    """protocol-06 §5.2 KeyMaterialRequestTBS, protocol mls10."""
    suites = struct.pack(">HH", 0x0001, 0x0003)
    required_capabilities = (
        opaque_v(b"")  # extension_types<V>
        + opaque_v(b"")  # proposal_types<V>
        + opaque_v(struct.pack(">H", 0x0001))  # credential_types<V>: basic
    )
    credential = struct.pack(">H", 0x0001) + opaque_v(b"alice")  # basic
    return (
        b"\x01"  # protocol: mls10
        + opaque_v(b"mimi://a.example/u/alice")  # requestingUser
        + opaque_v(b"mimi://b.example/u/bob")  # targetUser
        + opaque_v(room_id)  # roomId
        + opaque_v(suites)  # acceptableCiphersuites<V>
        + required_capabilities
        + opaque_v(requester_pub)  # requesterSignatureKey
        + credential  # requesterCredential
    )


def main():
    (crypto_basics,) = sys.argv[1:2]
    self_check(crypto_basics)

    requester_seed = bytes([0x11] * 32)
    requester_pub = ed25519_pub(requester_seed)
    label = b"KeyMaterialRequestTBS"

    tbs_room = request_tbs(requester_pub, b"mimi://a.example/r/clubhouse")
    tbs_no_room = request_tbs(requester_pub, b"")

    out = {
        "requester_seed": requester_seed,
        "requester_pub": requester_pub,
        "request_tbs": tbs_room,
        "request_signature": sign_with_label(requester_seed, label, tbs_room),
        "request_tbs_no_room": tbs_no_room,
        "request_signature_no_room": sign_with_label(
            requester_seed, label, tbs_no_room
        ),
    }
    for name, value in out.items():
        print(f"{name} = {value.hex()}")


if __name__ == "__main__":
    main()
