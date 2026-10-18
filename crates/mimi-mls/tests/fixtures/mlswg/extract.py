"""Extract fixtures from the mlswg test vectors.

Usage: python3 -I extract.py <path/to/test-vectors> <output directory>

From messages.json, writes one file per (entry, field), named
messages-<entry>-<field>.bin, holding the hex-decoded bytes of that field.

From each passive-client-*.json, writes <name>-suite1.json holding only the
test cases with cipher_suite 1, otherwise unchanged.
"""

import json
import pathlib
import sys

# One entry per ciphersuite: 0 is suite 0x0001, 100 is 0x0003, 200 is 0x0002.
ENTRIES = (0, 100, 200)

FIELDS = (
    "mls_welcome",
    "mls_group_info",
    "mls_key_package",
    "ratchet_tree",
    "public_message_application",
    "public_message_proposal",
    "public_message_commit",
    "private_message",
)

PASSIVE_CLIENT = (
    "passive-client-handling-commit",
    "passive-client-random",
    "passive-client-welcome",
)


def main() -> None:
    source, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    vectors = json.loads((source / "messages.json").read_text())
    for entry in ENTRIES:
        for field in FIELDS:
            data = bytes.fromhex(vectors[entry][field])
            (out_dir / f"messages-{entry:03}-{field}.bin").write_bytes(data)
    for name in PASSIVE_CLIENT:
        cases = json.loads((source / f"{name}.json").read_text())
        suite1 = [case for case in cases if case["cipher_suite"] == 1]
        (out_dir / f"{name}-suite1.json").write_text(json.dumps(suite1, indent=1) + "\n")


if __name__ == "__main__":
    main()
