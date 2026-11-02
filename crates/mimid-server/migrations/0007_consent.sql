-- Consent entries received on the protocol-06 §5.7 endpoints (bead
-- mimid-1wgh.7.32). They are stored for a later JMAP surface to show users,
-- not enforced (decision mimid-1wgh.7.35).
--
-- Both tables are keyed by the entry's ConsentScope. `room_id` is '' when
-- the scope is any room: a present but empty roomId is refused on decode
-- (decision mimid-1wgh.5.69), so '' cannot collide with a real room.

-- One row per pending requestConsent `request` for a local target user. A
-- `cancel` with the same scope deletes it (§5.7).
CREATE TABLE consent_request (
    -- `requesterUri`, as received.
    requester_uri TEXT NOT NULL CHECK (length(requester_uri) > 0),
    -- `targetUri`, as received: a user of this provider.
    target_uri TEXT NOT NULL CHECK (length(target_uri) > 0),
    -- `roomId`, as received, or '' for any room.
    room_id TEXT NOT NULL,
    -- The ConsentEntry exactly as received.
    entry BLOB NOT NULL,
    -- The sending provider, from the `From` header (decision mimid-1wgh.6.9).
    from_domain TEXT NOT NULL,
    -- Milliseconds since the UNIX epoch.
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    PRIMARY KEY (requester_uri, target_uri, room_id)
) STRICT;

-- The latest updateConsent `grant` or `revoke` for a local requester user,
-- per scope. A later entry for the same scope replaces it.
CREATE TABLE consent_update (
    -- `requesterUri`, as received: a user of this provider.
    requester_uri TEXT NOT NULL CHECK (length(requester_uri) > 0),
    -- `targetUri`, as received.
    target_uri TEXT NOT NULL CHECK (length(target_uri) > 0),
    -- `roomId`, as received, or '' for any room.
    room_id TEXT NOT NULL,
    -- The ConsentEntry's `consentOperation`.
    operation TEXT NOT NULL CHECK (operation IN ('grant', 'revoke')),
    -- The ConsentEntry exactly as received, including any KeyPackages of a
    -- grant, which are not otherwise used.
    entry BLOB NOT NULL,
    -- The sending provider, from the `From` header (decision mimid-1wgh.6.9).
    from_domain TEXT NOT NULL,
    -- Milliseconds since the UNIX epoch.
    received_at INTEGER NOT NULL CHECK (received_at >= 0),
    PRIMARY KEY (requester_uri, target_uri, room_id)
) STRICT;
