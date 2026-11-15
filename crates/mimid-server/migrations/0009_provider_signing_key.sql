-- This server's Ed25519 key for signing requests to other providers with
-- RFC 9421 (bead mimid-75nk.1). Separate from the hub's MLS key in
-- hub_secret: an HTTP signature and an MLS signature must not share a key.
CREATE TABLE provider_signing_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- The 32-byte Ed25519 private key (RFC 8032 seed).
    seed BLOB NOT NULL CHECK (length(seed) = 32)
) STRICT;
