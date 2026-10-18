-- Hub role tables (plan of mimid-1wgh.6). All are created at once, so that
-- later hub beads add code, not schema.

-- The hub's secrets: one Ed25519 key pair, used both as the external sender
-- and as the franking agent (decision mimid-1wgh.6.18), and the franking
-- HMAC key `hub_key` (protocol-06 §5.4.1.2; decision mimid-1wgh.5.53).
-- Generated on first start. Stored unencrypted: the database file must be
-- readable by its owner only (mode 0600), which the store enforces.
CREATE TABLE hub_secret (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- The 32-byte Ed25519 private key (RFC 8032 seed).
    signature_private_key BLOB NOT NULL CHECK (length(signature_private_key) = 32),
    -- The 32-byte Ed25519 public key.
    signature_public_key BLOB NOT NULL CHECK (length(signature_public_key) = 32),
    hub_key BLOB NOT NULL CHECK (length(hub_key) = 32)
) STRICT;

-- One row per hosted room: the snapshot its Observer is rebuilt from at
-- startup (decision mimid-1wgh.6.6). Replaced after every merged Commit.
CREATE TABLE room (
    -- The full room URI, as decoded from the request path (decision
    -- mimid-1wgh.5.18), e.g. mimi://a.example/r/clubhouse.
    room_id TEXT PRIMARY KEY,
    group_id BLOB NOT NULL UNIQUE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    -- The current epoch's GroupInfo as a TLS-encoded MLSMessage, without a
    -- ratchet_tree extension (decision mimid-1wgh.6.11).
    group_info BLOB NOT NULL,
    -- The current epoch's TLS-encoded ratchet tree (RFC 9420 §12.4.3.3).
    ratchet_tree BLOB NOT NULL,
    -- Milliseconds since the UNIX epoch.
    created_at INTEGER NOT NULL
) STRICT;

-- Every accepted handshake and application message, in hub order.
CREATE TABLE room_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL REFERENCES room (room_id),
    -- The epoch the message was accepted in.
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    -- Hub acceptance time, milliseconds since the UNIX epoch.
    accepted_at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('commit', 'proposal', 'application')),
    -- The message exactly as received.
    bytes BLOB NOT NULL,
    -- Hash of the request as received, for retry deduplication.
    hash BLOB NOT NULL UNIQUE
) STRICT;

-- Proposals accepted in the current epoch and not yet committed, in hub
-- order. Replayed into the rebuilt Observer at startup (decision
-- mimid-1wgh.6.6) and dropped when the epoch ends.
CREATE TABLE pending_proposal (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL REFERENCES room (room_id),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    -- The proposal MLSMessage exactly as received.
    proposal BLOB NOT NULL,
    -- protocol-06 §5.6 hub_accepted_time, milliseconds since the UNIX epoch.
    hub_accepted_time INTEGER NOT NULL
) STRICT;

CREATE INDEX pending_proposal_by_room ON pending_proposal (room_id, epoch, seq);

-- Fanout requests not yet delivered, FIFO per (room_id, domain) in id order
-- and retried indefinitely (decision mimid-1wgh.6.19).
CREATE TABLE outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL REFERENCES room (room_id),
    -- The destination provider domain.
    domain TEXT NOT NULL,
    -- The request body to send.
    body BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- Earliest time of the next attempt, milliseconds since the UNIX epoch.
    next_attempt_at INTEGER NOT NULL
) STRICT;

CREATE INDEX outbox_by_destination ON outbox (room_id, domain, id);
