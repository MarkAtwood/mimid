"""Cross-check the hand-encoded fixtures with Python cbor2.

For each ../fixtures/*.hex: strip comments (from ';'), read the hex,
decode with cbor2, require that cbor2's canonical encoding of the value
gives the same bytes (RFC 8949 §4.2.1 order, shortest forms), and print
the value. Run with an interpreter that has cbor2, in isolated mode:

    python3 -I cbor2_check.py > cbor2_check.out
"""

import pathlib
import sys

import cbor2


def fixture_bytes(path):
    hex_text = "".join(line.split(";", 1)[0] for line in path.read_text().splitlines())
    return bytes.fromhex("".join(hex_text.split()))


def show(value):
    if isinstance(value, dict):
        return "{" + ", ".join(f"{show(k)}: {show(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(show(v) for v in value) + "]"
    if isinstance(value, bytes):
        return "h'" + value.hex() + "'"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return '"' + value + '"'
    return str(value)


def main():
    here = pathlib.Path(__file__).resolve().parent
    failed = False
    for path in sorted((here.parent / "fixtures").glob("*.hex")):
        data = fixture_bytes(path)
        value = cbor2.loads(data)
        again = cbor2.dumps(value, canonical=True)
        status = "ok" if again == data else "MISMATCH " + again.hex()
        failed |= again != data
        print(f"{path.name}: {status}")
        print(f"  {show(value)}")
    print("cbor2", getattr(cbor2, "__version__", "6.3.0"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
