#!/usr/bin/env python3
"""Independent oracle for protocol-06 §5.6 groupInfo crypto (mimid-1wgh.5.11).

Computes, from the text of draft-ietf-mimi-protocol-06 §5.6 and RFC 9420
§5.1.2/§5.1.3 alone:

  signature = SignWithLabel(requestingSignatureKey,
                            "GroupInfoRequestTBS", GroupInfoRequestTBS)
  encrypted_groupinfo_and_tree = EncryptWithLabel(groupInfoPublicKey,
      "GroupInfo and ratchet_tree encryption", room_id,
      group_info_ratchet_tree_tbe)
  signature = SignWithLabel(hub_sender.signature_key,
                            "GroupInfoResponseTBS", GroupInfoResponseTBS)

for ciphersuite 1 (Ed25519; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM). HPKE base mode (RFC 9180 §4.1, §5.1, §5.2) is written out
here because the installed pyca/cryptography (41) has no HPKE module; the
ephemeral key is fixed so the output is reproducible.

Decisions applied: joiningCode is optional in both TBS and request
(mimid-1wgh.5.22); the response TBS exists only on success and carries
status success(1) (mimid-1wgh.5.26); the room_id context is the raw URI
bytes, no length prefix (mimid-1wgh.5.30); "Protocol version" is the
Protocol field, mls10(1) (mimid-1wgh.5.23).

Before printing anything it self-checks SignWithLabel and DecryptWithLabel
against the mlswg crypto-basics.json suite 1 vectors. It does not call or
read any mimid code. Regenerate (from this directory):

  python3 -I group_info_gen.py \\
    ../../../../mimi-mls/tests/fixtures/crypto-basics/crypto-basics.json \\
    ../../../../mimi-mls/tests/fixtures/mlswg/messages-000-mls_group_info.bin \\
    ../../../../mimi-mls/tests/fixtures/mlswg/messages-000-public_message_proposal.bin \\
    > group_info_gen.out
"""

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


# RFC 9420 §5.1.2 / §5.1.3


def sign_with_label(seed, label, content):
    sign_content = opaque_v(b"MLS 1.0 " + label) + opaque_v(content)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(sign_content)


def encrypt_context(label, context):
    return opaque_v(b"MLS 1.0 " + label) + opaque_v(context)


# RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM

KEM_SUITE = b"KEM" + struct.pack(">H", 0x0020)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x0020, 0x0001, 0x0001)


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(
        prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length
    )


def shared_secret(dh, enc, pk_rm):
    eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", enc + pk_rm, 32)


def key_schedule(secret_in, info):
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash  # mode_base
    secret = labeled_extract(HPKE_SUITE, secret_in, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, secret, b"key", context, 16)
    nonce = labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    return key, nonce


def seal_base(pk_r, info, plaintext, sk_e):
    eph = X25519PrivateKey.from_private_bytes(sk_e)
    enc = eph.public_key().public_bytes(RAW, RAW_PUB)
    dh = eph.exchange(X25519PublicKey.from_public_bytes(pk_r))
    key, nonce = key_schedule(shared_secret(dh, enc, pk_r), info)
    return enc, AESGCM(key).encrypt(nonce, plaintext, b"")


def open_base(sk_r, info, enc, ciphertext):
    sk = X25519PrivateKey.from_private_bytes(sk_r)
    pk_r = sk.public_key().public_bytes(RAW, RAW_PUB)
    dh = sk.exchange(X25519PublicKey.from_public_bytes(enc))
    key, nonce = key_schedule(shared_secret(dh, enc, pk_r), info)
    return AESGCM(key).decrypt(nonce, ciphertext, b"")


def self_check(crypto_basics_path):
    with open(crypto_basics_path, encoding="utf-8") as f:
        entry = next(e for e in json.load(f) if e["cipher_suite"] == 1)
    s = entry["sign_with_label"]
    sig = sign_with_label(
        bytes.fromhex(s["priv"]), s["label"].encode(), bytes.fromhex(s["content"])
    )
    assert sig.hex() == s["signature"], "SignWithLabel self-check failed"
    e = entry["encrypt_with_label"]
    info = encrypt_context(e["label"].encode(), bytes.fromhex(e["context"]))
    pt = open_base(
        bytes.fromhex(e["priv"]),
        info,
        bytes.fromhex(e["kem_output"]),
        bytes.fromhex(e["ciphertext"]),
    )
    assert pt.hex() == e["plaintext"], "DecryptWithLabel self-check failed"


def ed25519_pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        RAW, RAW_PUB
    )


def x25519_pub(sk):
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(
        RAW, RAW_PUB
    )


def basic_credential(identity):
    """RFC 9420 §5.3 Credential, credential_type basic(1)."""
    return struct.pack(">H", 0x0001) + opaque_v(identity)


def main():
    crypto_basics, group_info_message, proposal = sys.argv[1:4]
    self_check(crypto_basics)

    with open(group_info_message, "rb") as f:
        group_info = f.read()[4:]  # drop RFC 9420 §6 version, wire_format
    with open(proposal, "rb") as f:
        proposal_message = f.read()

    requester_seed = bytes([0x11] * 32)
    hub_seed = bytes([0x22] * 32)
    group_info_sk = bytes([0x33] * 32)
    ephemeral_sk = bytes([0x44] * 32)
    room_id = b"mimi://a.example/r/clubhouse"
    cipher_suite = struct.pack(">H", 0x0001)
    mls10 = b"\x01"

    # protocol-06 §5.6 GroupInfoRequestTBS, joiningCode present
    request_tbs = (
        mls10
        + cipher_suite
        + opaque_v(ed25519_pub(requester_seed))  # requestingSignatureKey
        + basic_credential(b"alice")  # requestingCredential
        + opaque_v(x25519_pub(group_info_sk))  # groupInfoPublicKey
        + b"\x01"
        + opaque_v(b"code")  # optional joiningCode
    )
    request_sig = sign_with_label(requester_seed, b"GroupInfoRequestTBS", request_tbs)

    # GroupInfoRatchetTreeTBE
    pending = proposal_message + struct.pack(">Q", 1_700_000_000_000)
    tbe = group_info + b"\x04" + opaque_v(pending)  # distributionService(4)
    info = encrypt_context(b"GroupInfo and ratchet_tree encryption", room_id)
    kem_output, ciphertext = seal_base(
        x25519_pub(group_info_sk), info, tbe, ephemeral_sk
    )
    hpke_ciphertext = opaque_v(kem_output) + opaque_v(ciphertext)

    # GroupInfoResponseTBS (success only)
    hub_sender = opaque_v(ed25519_pub(hub_seed)) + basic_credential(b"hub.example")
    response_tbs = (
        mls10
        + opaque_v(room_id)
        + b"\x01"  # status: success
        + cipher_suite
        + hub_sender
        + hpke_ciphertext
    )
    response_sig = sign_with_label(hub_seed, b"GroupInfoResponseTBS", response_tbs)

    out = {
        "requester_seed": requester_seed,
        "requester_pub": ed25519_pub(requester_seed),
        "hub_seed": hub_seed,
        "hub_pub": ed25519_pub(hub_seed),
        "group_info_sk": group_info_sk,
        "group_info_pk": x25519_pub(group_info_sk),
        "ephemeral_sk": ephemeral_sk,
        "room_id": room_id,
        "request_tbs": request_tbs,
        "request_signature": request_sig,
        "tbe": tbe,
        "kem_output": kem_output,
        "ciphertext": ciphertext,
        "response_tbs": response_tbs,
        "response_signature": response_sig,
    }
    for name, value in out.items():
        print(f"{name} = {value.hex()}")


if __name__ == "__main__":
    main()
