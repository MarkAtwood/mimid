-- The fanouts a hub delivered, which is what a catch-up answer is made
-- of (docs/design/mimi-catchup.md §5; decision on bead
-- mimid-1wgh.37.104.7, Mark 2026-11-25).
--
-- Per DESTINATION, not per event, because a handshake's fanout differs
-- by who gets it: the joiner of a room receives a Welcome and the other
-- providers receive the Commit, one event, different bytes
-- (hub::update builds accepted.outbox as (domain, body) pairs). An
-- application message is identical for every destination, so those rows
-- hold the same bytes; that is the cost of answering handshake catch-up
-- at all.
--
-- The bytes are the fanout EXACTLY AS DELIVERED. Catch-up can then only
-- return what was really sent, which is the same property the
-- participation ranges of bead mimid-1wgh.37.104.2 give, and no
-- re-encoding sits between a follower and the frank it checks.
CREATE TABLE room_fanout (
    room_id TEXT NOT NULL REFERENCES room (room_id),
    -- The room's fanout sequence (0018_fanout_sequence.sql).
    fanout_seq INTEGER NOT NULL CHECK (fanout_seq >= 1),
    -- The destination provider's domain.
    domain TEXT NOT NULL,
    -- One FanoutMessage as it was sent to that domain.
    bytes BLOB NOT NULL,
    PRIMARY KEY (room_id, fanout_seq, domain)
) STRICT;

-- Catch-up reaches exactly as far back as the hub log does, with nothing
-- to keep in step: a fanout goes when its event goes. The sweep of
-- 0014_retention.sql deletes room_event by acceptance time, and an
-- operator with the sqlite3 CLI may delete rows too (decision
-- mimid-1wgh.83), so this is a trigger rather than a second sweep.
CREATE TRIGGER room_event_fanout_gone AFTER DELETE ON room_event
BEGIN
    DELETE FROM room_fanout
    WHERE room_id = OLD.room_id AND fanout_seq = OLD.fanout_seq;
END;
