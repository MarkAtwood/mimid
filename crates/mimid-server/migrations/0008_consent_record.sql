-- JMAP Consent records (draft-atwood-jmap-chat-mimi-00 §Consent; bead
-- mimid-1wgh.12.43). One row per account owner and ConsentScope in which
-- the owner is the requester or the target. The URIs are in RFC 3986
-- §6.2.2 normal form, as in migration 0007's tables; `room_id` is '' for
-- any room.
CREATE TABLE consent_record (
    -- The record's JMAP id: a ULID.
    id TEXT PRIMARY KEY NOT NULL,
    -- The local user whose account holds the record.
    owner_uri TEXT NOT NULL CHECK (length(owner_uri) > 0),
    requester_uri TEXT NOT NULL CHECK (length(requester_uri) > 0),
    target_uri TEXT NOT NULL CHECK (length(target_uri) > 0),
    room_id TEXT NOT NULL,
    requested INTEGER NOT NULL CHECK (requested IN (0, 1)),
    decision TEXT CHECK (decision IN ('grant', 'revoke')),
    -- Milliseconds since the UNIX epoch.
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= 0),
    -- The modseq when the row was created, and when it last changed: the
    -- record's place in Consent/changes.
    created_modseq INTEGER NOT NULL CHECK (created_modseq > 0),
    modseq INTEGER NOT NULL CHECK (modseq >= created_modseq),
    CHECK (owner_uri = requester_uri OR owner_uri = target_uri),
    CHECK (requester_uri <> target_uri),
    UNIQUE (owner_uri, requester_uri, target_uri, room_id)
) STRICT;

CREATE INDEX consent_record_owner_modseq ON consent_record (owner_uri, modseq);

-- Destroyed records, for Consent/changes. Never pruned in v1.
CREATE TABLE consent_destroyed (
    id TEXT PRIMARY KEY NOT NULL,
    owner_uri TEXT NOT NULL,
    created_modseq INTEGER NOT NULL,
    modseq INTEGER NOT NULL
) STRICT;

CREATE INDEX consent_destroyed_owner_modseq ON consent_destroyed (owner_uri, modseq);

-- The last modseq given out, shared by every account.
CREATE TABLE consent_modseq (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    modseq INTEGER NOT NULL
) STRICT;

INSERT INTO consent_modseq (one, modseq) VALUES (1, 0);
