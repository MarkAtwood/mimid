-- Follower role tables (plan of mimid-1wgh.7). All are created at once, so
-- that later follower beads add code, not schema.

-- One row per room this provider follows. A room is created on its first
-- /notify, even before the relay response that caused it (decision
-- mimid-1wgh.7.4).
CREATE TABLE follower_room (
    -- The full room URI, as decoded from the request path (decision
    -- mimid-1wgh.5.18).
    room_id TEXT PRIMARY KEY,
    -- The room's hub: the room URI's authority (decision mimid-1wgh.7.5).
    hub_domain TEXT NOT NULL,
    -- The MLS group ID, once a message has revealed it.
    group_id BLOB,
    -- Milliseconds since the UNIX epoch.
    first_seen INTEGER NOT NULL
) STRICT;

-- Every FanoutMessage received for a followed room, in arrival order
-- (decision mimid-1wgh.7.17).
CREATE TABLE follower_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL REFERENCES follower_room (room_id),
    -- Arrival time, milliseconds since the UNIX epoch.
    received_at INTEGER NOT NULL,
    -- The FanoutMessage `timestamp`: hub acceptance time, milliseconds since
    -- the UNIX epoch (protocol-06 §5.5).
    hub_timestamp INTEGER NOT NULL CHECK (hub_timestamp >= 0),
    -- The FanoutMessage arm (protocol-06 §5.5).
    kind TEXT NOT NULL CHECK (kind IN ('application', 'welcome', 'proposal', 'commit')),
    -- One FanoutMessage exactly as received.
    bytes BLOB NOT NULL,
    -- SHA-256 of `bytes`, for deduplication (decision mimid-1wgh.7.3).
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    UNIQUE (room_id, hash)
) STRICT;

CREATE INDEX follower_event_by_room ON follower_event (room_id, seq);

-- The KeyPackageRefs of the new members a Welcome event names, used to show
-- the Welcome only to the users it is for.
CREATE TABLE welcome_ref (
    event_seq INTEGER NOT NULL REFERENCES follower_event (seq),
    key_package_ref BLOB NOT NULL,
    PRIMARY KEY (event_seq, key_package_ref)
) STRICT;

CREATE INDEX welcome_ref_by_ref ON welcome_ref (key_package_ref);

-- Local users' membership of followed rooms (decision mimid-1wgh.7.7). A
-- user who leaves and rejoins gets a new row.
CREATE TABLE follower_member (
    room_id TEXT NOT NULL REFERENCES follower_room (room_id),
    user_uri TEXT NOT NULL,
    -- The first follower_event seq the user may see.
    since_seq INTEGER NOT NULL CHECK (since_seq >= 0),
    -- Milliseconds since the UNIX epoch; NULL while the user is a member.
    left_at INTEGER
) STRICT;

-- At most one current membership per user and room.
CREATE UNIQUE INDEX follower_member_current ON follower_member (room_id, user_uri)
    WHERE left_at IS NULL;
CREATE INDEX follower_member_by_user ON follower_member (user_uri, room_id);

-- Local users' clients. The client ID is derived from the client's leaf
-- signature key (decision mimid-1wgh.7.8).
CREATE TABLE client (
    client_id TEXT PRIMARY KEY,
    user_uri TEXT NOT NULL
) STRICT;

CREATE INDEX client_by_user ON client (user_uri);

-- KeyPackages uploaded by local clients, served through keyMaterial
-- (protocol-06 §5.2).
CREATE TABLE key_package (
    -- The KeyPackageRef (RFC 9420 §5.2).
    ref BLOB PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES client (client_id),
    -- The TLS-encoded KeyPackage exactly as uploaded.
    bytes BLOB NOT NULL,
    -- 1 if the KeyPackage has the last_resort extension: served without
    -- being consumed (decision mimid-1wgh.7.14).
    last_resort INTEGER NOT NULL CHECK (last_resort IN (0, 1)),
    -- The lifetime's not_after, seconds since the UNIX epoch (RFC 9420
    -- §7.2).
    not_after INTEGER NOT NULL CHECK (not_after >= 0)
) STRICT;

CREATE INDEX key_package_by_client ON key_package (client_id, not_after);
-- At most one last-resort KeyPackage per client.
CREATE UNIQUE INDEX key_package_last_resort ON key_package (client_id)
    WHERE last_resort = 1;

-- KeyPackages handed out through keyMaterial, kept until a Welcome matches
-- or the KeyPackage expires (decision mimid-1wgh.7.15). A claimed single-use
-- KeyPackage leaves `key_package`, so `ref` is not a foreign key, and a
-- last-resort one can be claimed many times, so it is not unique.
CREATE TABLE key_package_claim (
    ref BLOB NOT NULL,
    -- The local user and client the KeyPackage belongs to.
    user_uri TEXT NOT NULL,
    client_id TEXT NOT NULL,
    -- The keyMaterial requestingUser.
    requester TEXT NOT NULL,
    -- The keyMaterial roomId.
    room_id TEXT NOT NULL,
    -- Milliseconds since the UNIX epoch.
    claimed_at INTEGER NOT NULL
) STRICT;

CREATE INDEX key_package_claim_by_ref ON key_package_claim (ref);
