-- Membership history, Chat ids and Message ids for the JMAP read
-- projection (bead mimid-1wgh.11.3; decisions mimid-1wgh.12.31,
-- mimid-1wgh.12.35, mimid-1wgh.12.38).
--
-- Rows stored before this migration get ids built here from what is
-- stored: the ULID time is a stored time, and the 80-bit random part is
-- a row number, not random (INVENTED, NOT FROM SPEC). New rows get random
-- parts from the store code.

-- follower_member is rebuilt with an explicit INTEGER PRIMARY KEY, so its
-- ids, which JMAP state strings carry, survive VACUUM (decision
-- mimid-1wgh.12.38). Each row keeps its old rowid as its id.
CREATE TABLE follower_member_new (
    id INTEGER PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES follower_room (room_id),
    user_uri TEXT NOT NULL,
    -- The first follower_event seq the user may see.
    since_seq INTEGER NOT NULL CHECK (since_seq >= 0),
    -- Milliseconds since the UNIX epoch; NULL while the user is a member.
    left_at INTEGER,
    -- The first follower_event seq the user may no longer see; NULL while
    -- the user is a member. Events of a past membership stay visible.
    left_seq INTEGER CHECK (left_seq >= 0),
    -- Milliseconds since the UNIX epoch.
    joined_at INTEGER NOT NULL CHECK (joined_at >= 0),
    CHECK ((left_at IS NULL) = (left_seq IS NULL))
) STRICT;

-- A past membership ends before the first event received after it ended
-- (INVENTED, NOT FROM SPEC: the leaving seq was not recorded). Its joining
-- time was not recorded either; the room's first-seen time stands in.
INSERT INTO follower_member_new
    (id, room_id, user_uri, since_seq, left_at, left_seq, joined_at)
SELECT m.rowid, m.room_id, m.user_uri, m.since_seq, m.left_at,
       CASE WHEN m.left_at IS NULL THEN NULL ELSE COALESCE(
           (SELECT MIN(e.seq) FROM follower_event e
            WHERE e.room_id = m.room_id AND e.received_at > m.left_at),
           (SELECT COALESCE(MAX(seq), 0) + 1 FROM follower_event)) END,
       r.first_seen
FROM follower_member m JOIN follower_room r ON r.room_id = m.room_id
ORDER BY m.rowid;

DROP TABLE follower_member;
ALTER TABLE follower_member_new RENAME TO follower_member;

CREATE UNIQUE INDEX follower_member_current ON follower_member (room_id, user_uri)
    WHERE left_at IS NULL;
CREATE INDEX follower_member_by_user ON follower_member (user_uri, room_id);

-- One JMAP Chat per user and room the user was ever a member of, with a
-- ULID minted once (draft-atwood-jmap-chat-00 §Chat ID Assignment), so a
-- rejoined room finds the same Chat.
CREATE TABLE follower_chat (
    chat_id TEXT PRIMARY KEY CHECK (length(chat_id) = 26),
    user_uri TEXT NOT NULL,
    room_id TEXT NOT NULL REFERENCES follower_room (room_id),
    -- Milliseconds since the UNIX epoch: the Chat's createdAt.
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (user_uri, room_id)
) STRICT;

-- The Message id: a ULID assigned at storage time, increasing with seq
-- (draft-atwood-jmap-chat-00 §Message IDs; decision mimid-1wgh.12.31).
ALTER TABLE follower_event ADD COLUMN message_id TEXT
    CHECK (message_id IS NULL OR length(message_id) = 26);

-- ULIDs from (k, t, r): t is the 48-bit time, r the 80-bit random part,
-- in Crockford base32 (the ULID spec).
CREATE TEMP TABLE ulid_source (k TEXT PRIMARY KEY, t INTEGER NOT NULL, r INTEGER NOT NULL);

-- Chats: the first membership's joining time, and its id.
INSERT INTO ulid_source (k, t, r)
SELECT 'c' || MIN(id), MIN(joined_at), MIN(id) FROM follower_member
GROUP BY user_uri, room_id;

-- Messages: the running maximum of the arrival times, so ids increase
-- with seq, and the seq.
INSERT INTO ulid_source (k, t, r)
SELECT 'm' || seq, MAX(received_at) OVER (ORDER BY seq), seq FROM follower_event;

CREATE TEMP TABLE ulid_encoded AS
WITH RECURSIVE encode (k, t, r, pos, out) AS (
    SELECT k, t, r, 0, '' FROM ulid_source
    UNION ALL
    SELECT k, t, r, pos + 1, out || substr('0123456789ABCDEFGHJKMNPQRSTVWXYZ',
        ((CASE WHEN pos < 10 THEN t >> (45 - 5 * pos) ELSE r >> (125 - 5 * pos) END) & 31) + 1,
        1)
    FROM encode WHERE pos < 26
)
SELECT k, out AS ulid FROM encode WHERE pos = 26;

INSERT INTO follower_chat (chat_id, user_uri, room_id, created_at)
SELECT u.ulid, m.user_uri, m.room_id, m.joined_at
FROM follower_member m JOIN ulid_encoded u ON u.k = 'c' || m.id
ORDER BY m.id;

UPDATE follower_event
SET message_id = (SELECT ulid FROM ulid_encoded WHERE k = 'm' || follower_event.seq);

DROP TABLE ulid_encoded;
DROP TABLE ulid_source;

CREATE UNIQUE INDEX follower_event_message_id ON follower_event (message_id);
