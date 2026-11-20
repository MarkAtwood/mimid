-- The findings of the live stream's second binding (epic mimid-e64f,
-- docs/design/binary-live-stream-findings.md), as Mark decided them on
-- 2026-11-20.

-- F15: unbinding a Chat moves the account's Chat state. Each leaving of a
-- followed room takes the next number of this provider-wide counter; the
-- Chat state names the account's highest.
ALTER TABLE follower_member ADD COLUMN left_mod INTEGER
    CHECK (left_mod IS NULL OR left_mod > 0);

-- F9: KeyPackage/changes. Every KeyPackage stored or removed (uploaded,
-- destroyed, replaced by a new last-resort one, or handed out to a
-- keyMaterial request) takes the next number of this log, with its owner
-- at that time. The KeyPackage state of an account is the highest number
-- among its owner's rows. The triggers cover every path that writes
-- `key_package`, so none can forget it.
CREATE TABLE key_package_change (
    modseq INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uri TEXT NOT NULL,
    -- The KeyPackageRef (RFC 9420 §5.2).
    ref BLOB NOT NULL,
    -- 0 when the KeyPackage was stored, 1 when it was removed.
    destroyed INTEGER NOT NULL CHECK (destroyed IN (0, 1))
) STRICT;

CREATE INDEX key_package_change_by_user ON key_package_change (user_uri, modseq);

CREATE TRIGGER key_package_created AFTER INSERT ON key_package
BEGIN
    INSERT INTO key_package_change (user_uri, ref, destroyed)
    SELECT user_uri, NEW.ref, 0 FROM client WHERE client_id = NEW.client_id;
END;

CREATE TRIGGER key_package_destroyed AFTER DELETE ON key_package
BEGIN
    INSERT INTO key_package_change (user_uri, ref, destroyed)
    SELECT user_uri, OLD.ref, 1 FROM client WHERE client_id = OLD.client_id;
END;

-- F11: a request the hub accepted, so that the same bytes sent again by
-- the same user for the same room are answered with the hub's response
-- instead of being submitted twice. Kept for a bounded time
-- (store::accepted::ACCEPTED_RETENTION_MS, INVENTED, NOT FROM SPEC).
CREATE TABLE accepted_request (
    user_uri TEXT NOT NULL,
    room_id TEXT NOT NULL,
    -- 'send' for Room/send (a SubmitMessageRequest), 'update' for
    -- Room/update (an UpdateRequest).
    kind TEXT NOT NULL CHECK (kind IN ('send', 'update')),
    -- SHA-256 of the request relayed to the hub, exactly as relayed.
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    -- The hub's response, exactly as received.
    response BLOB NOT NULL,
    -- When it was recorded, milliseconds since the UNIX epoch.
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    PRIMARY KEY (user_uri, room_id, kind, hash)
) STRICT;

CREATE INDEX accepted_request_by_time ON accepted_request (recorded_at);
