#!/usr/bin/env python3
"""Independent oracle for URI fields under decision mimid-1wgh.36.

Rule: a field value is accepted if it is empty (decisions mimid-1wgh.5.27 and
mimid-1wgh.3.18: zero length means absent) or if it matches the RFC 3986 `URI`
production.

The regex below is transcribed by hand, rule by rule, from RFC 3986
Appendix A (Collected ABNF for URI), with core rules from RFC 5234 Appendix
B.1. It is not derived from iri-string or any other implementation. Every
case also carries a verdict written by hand from the RFC text; the script
fails if the regex disagrees with it.

Usage: python3 -I rfc3986_check.py > rfc3986_check.out
Output: one line per case, "ACCEPT<TAB><hex>" or "REJECT<TAB><hex>", where
<hex> is the lowercase hex of the case's UTF-8 bytes. The Rust tests in
mimi-protocol and mimi-room-policy read the committed output file.

Standard library only; offline.
"""

import re
import sys

# RFC 5234 B.1 core rules. ABNF quoted strings are case-insensitive, so
# HEXDIG's "A"-"F" also match "a"-"f".
ALPHA = r"[A-Za-z]"
DIGIT = r"[0-9]"
HEXDIG = r"[0-9A-Fa-f]"

# RFC 3986 Appendix A.
unreserved = r"[A-Za-z0-9\-._~]"
sub_delims = r"[!$&'()*+,;=]"
pct_encoded = r"%" + HEXDIG + HEXDIG
pchar = rf"(?:{unreserved}|{pct_encoded}|{sub_delims}|[:@])"

scheme = rf"{ALPHA}(?:{ALPHA}|{DIGIT}|[+\-.])*"

userinfo = rf"(?:{unreserved}|{pct_encoded}|{sub_delims}|:)*"

dec_octet = (
    rf"(?:{DIGIT}"  # 0-9
    rf"|[1-9]{DIGIT}"  # 10-99
    rf"|1{DIGIT}{DIGIT}"  # 100-199
    rf"|2[0-4]{DIGIT}"  # 200-249
    r"|25[0-5])"  # 250-255
)
IPv4address = rf"{dec_octet}\.{dec_octet}\.{dec_octet}\.{dec_octet}"

h16 = rf"{HEXDIG}{{1,4}}"
ls32 = rf"(?:{h16}:{h16}|{IPv4address})"


def upto(n):
    """[ *n( h16 ":" ) h16 ]"""
    return rf"(?:(?:{h16}:){{0,{n}}}{h16})?"


IPv6address = "(?:" + "|".join(
    [
        rf"(?:{h16}:){{6}}{ls32}",
        rf"::(?:{h16}:){{5}}{ls32}",
        rf"(?:{h16})?::(?:{h16}:){{4}}{ls32}",
        rf"{upto(1)}::(?:{h16}:){{3}}{ls32}",
        rf"{upto(2)}::(?:{h16}:){{2}}{ls32}",
        rf"{upto(3)}::{h16}:{ls32}",
        rf"{upto(4)}::{ls32}",
        rf"{upto(5)}::{h16}",
        rf"{upto(6)}::",
    ]
) + ")"

# "v" is an ABNF quoted string, so case-insensitive.
IPvFuture = rf"[vV]{HEXDIG}+\.(?:{unreserved}|{sub_delims}|:)+"
IP_literal = rf"\[(?:{IPv6address}|{IPvFuture})\]"
reg_name = rf"(?:{unreserved}|{pct_encoded}|{sub_delims})*"
host = rf"(?:{IP_literal}|{IPv4address}|{reg_name})"
port = rf"{DIGIT}*"
authority = rf"(?:{userinfo}@)?{host}(?::{port})?"

segment = rf"{pchar}*"
segment_nz = rf"{pchar}+"
path_abempty = rf"(?:/{segment})*"
path_absolute = rf"/(?:{segment_nz}(?:/{segment})*)?"
path_rootless = rf"{segment_nz}(?:/{segment})*"
path_empty = r""

hier_part = (
    rf"(?://{authority}{path_abempty}"
    rf"|{path_absolute}"
    rf"|{path_rootless}"
    rf"|{path_empty})"
)
query = rf"(?:{pchar}|[/?])*"
fragment = rf"(?:{pchar}|[/?])*"

URI = re.compile(rf"{scheme}:{hier_part}(?:\?{query})?(?:#{fragment})?", re.ASCII)


def field_accepts(value):
    return value == "" or URI.fullmatch(value) is not None


# (value, hand verdict from the RFC text, reason)
CASES = [
    ("mimi://a.example/u/alice", True, "authority + path-abempty"),
    ("https://a.example/x?y#z", True, "query and fragment"),
    ("urn:ietf:params:mimi", True, "path-rootless"),
    ("", True, "empty means absent (decisions mimid-1wgh.5.27, .3.18)"),
    ("http://[2001:db8::1]:8080/p", True, "IP-literal IPv6 with port"),
    ("mimi://a.example/u/al%20ice", True, "pct-encoded"),
    ("m:", True, "scheme + path-empty"),
    ("mimi://a.example", True, "authority, empty path-abempty"),
    ("file:///etc", True, "empty authority"),
    ("http://192.0.2.1/", True, "IPv4address"),
    ("http://[::1]/", True, "IPv6 ::1"),
    ("http://[::ffff:192.0.2.1]/", True, "IPv6 with ls32 IPv4"),
    ("http://[v1.x]/", True, "IPvFuture"),
    ("http://a.example:/", True, "port = *DIGIT may be empty"),
    ("http://u:p@a.example/", True, "userinfo"),
    ("HTTPS://A.EXAMPLE/%7e", True, "upper-case scheme, lower-case hex"),
    ("mailto:alice@a.example", True, "path-rootless with @"),
    ("a:b:c", True, "colons in path-rootless"),
    ("m:/x?a/b?c#d/e?f", True, "/ and ? in query and fragment"),
    ("m:" + "x" * 62, True, "64 bytes, path-rootless"),
    ("https://a.examp", True, "reg-name need not be a DNS name"),
    ("m:a", True, "path-rootless"),
    ("x" * 64, False, "no scheme"),
    ("//a.example", False, "relative-ref: no scheme"),
    ("/path", False, "relative-ref: path-absolute"),
    ("a.example", False, "relative-ref: path-noscheme"),
    ("mimi://a.example/u/al ice", False, "space is not a pchar"),
    ("mimi://a.example/u/\u00e9", False, "raw non-ASCII"),
    ("mimi://a.example/\u202e", False, "U+202E RIGHT-TO-LEFT OVERRIDE"),
    ("mimi://a.example/\u200b", False, "U+200B ZERO WIDTH SPACE"),
    ("mimi://a.example/%G1", False, "G is not HEXDIG"),
    ("mimi://a.example/%4", False, "truncated pct-encoded"),
    ("1abc://x", False, "scheme starts with DIGIT"),
    ("http://2001:db8::1/", False, "unbracketed IPv6: port must be DIGITs"),
    ("mimi://a.example/\x00", False, "null byte"),
    ("mimi:x\n", False, "trailing LF"),
    ("mimi://a.example/u/alice ", False, "trailing space"),
    (":foo", False, "empty scheme"),
    ("mimi://a.example/#a#b", False, "# inside fragment"),
    ("mimi://a.example/<x>", False, "< and > are not allowed"),
    ("mimi://a.example/a\\b", False, "backslash is not allowed"),
    ("http://[2001:db8::1/", False, "unterminated IP-literal"),
    ("http://[2001:db8:::1]/", False, "::: is not IPv6"),
    ("http://[1:2:3:4:5:6:7:8:9]/", False, "nine IPv6 groups"),
    ("http://a.example:80a/", False, "non-digit port"),
    ("mimi://a.example/\x7f", False, "DEL"),
]


def main():
    out = [
        "# Generated by rfc3986_check.py; do not edit by hand.",
        "# Format: ACCEPT|REJECT <TAB> lowercase hex of the UTF-8 bytes.",
    ]
    mismatches = 0
    for value, expected, reason in CASES:
        got = field_accepts(value)
        if got != expected:
            mismatches += 1
            print(f"MISMATCH {value!r}: regex {got}, hand {expected} ({reason})", file=sys.stderr)
        verdict = "ACCEPT" if got else "REJECT"
        out.append(f"{verdict}\t{value.encode('utf-8').hex()}")
    if mismatches:
        sys.exit(1)
    print("\n".join(out))


if __name__ == "__main__":
    main()
