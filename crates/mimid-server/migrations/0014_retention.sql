-- Message retention (decision mimid-1wgh.82) and deletion out of band
-- (decision mimid-1wgh.83): the follower log and the hub log may lose old
-- rows, to the server's own sweep or to an operator with the sqlite3 CLI,
-- in any amount and order. The triggers below run for either, so what
-- depends on a deleted row learns of it.

-- How many events of the room were ever deleted. The JMAP Message and Chat
-- states carry the sum over a user's rooms, so a state from before a
-- deletion is told apart from the current one (cannotCalculateChanges).
ALTER TABLE follower_room ADD COLUMN gone INTEGER NOT NULL DEFAULT 0 CHECK (gone >= 0);

-- The highest Message id ever deleted, so that a new id still sorts after
-- every id handed out before (draft-atwood-jmap-chat-00 §Message IDs).
CREATE TABLE follower_gone (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_message_id TEXT CHECK (max_message_id IS NULL OR length(max_message_id) = 26)
) STRICT;

INSERT INTO follower_gone (id, max_message_id) VALUES (1, NULL);

-- A Welcome's refs go with it. BEFORE, so that the delete also passes the
-- foreign key when foreign keys are on.
CREATE TRIGGER follower_event_refs_gone BEFORE DELETE ON follower_event
BEGIN
    DELETE FROM welcome_ref WHERE event_seq = OLD.seq;
END;

CREATE TRIGGER follower_event_gone AFTER DELETE ON follower_event
BEGIN
    UPDATE follower_room SET gone = gone + 1 WHERE room_id = OLD.room_id;
    UPDATE follower_gone SET max_message_id = OLD.message_id
    WHERE id = 1 AND OLD.message_id IS NOT NULL
      AND (max_message_id IS NULL OR OLD.message_id > max_message_id);
END;

-- The sweep finds expired rows by hub acceptance time.
CREATE INDEX follower_event_by_hub_time ON follower_event (hub_timestamp);
CREATE INDEX room_event_by_time ON room_event (accepted_at);
