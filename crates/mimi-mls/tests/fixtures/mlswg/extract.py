"""Extract binary fixtures from the mlswg messages.json test vector.

Usage: python3 -I extract.py <path/to/messages.json> <output directory>

Writes one file per (entry, field), named messages-<entry>-<field>.bin,
holding the hex-decoded bytes of that field. Nothing else is changed.
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


def main() -> None:
    source, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    vectors = json.loads(source.read_text())
    for entry in ENTRIES:
        for field in FIELDS:
            data = bytes.fromhex(vectors[entry][field])
            (out_dir / f"messages-{entry:03}-{field}.bin").write_bytes(data)


if __name__ == "__main__":
    main()
