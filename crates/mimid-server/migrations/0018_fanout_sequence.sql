-- The hub's per-room fanout sequence (docs/design/mimi-catchup.md §4;
-- decision mimid-1wgh.104, bead mimid-1wgh.37.104.1).
--
-- Monotonic per room, from 1, one per fanout, covering handshakes as well
-- as application messages, never reused or renumbered. It is not
-- room_event.seq, which is a global AUTOINCREMENT and so skips within a
-- room, and it is not accepted_at, which is milliseconds and collides.

-- The next sequence to hand out for the room. The counter lives here, not
-- in MAX(room_event.fanout_seq), because retention deletes event rows
-- (0014_retention.sql) and a prune must not let a delivered number be
-- handed out again.
ALTER TABLE room ADD COLUMN next_fanout_seq INTEGER NOT NULL DEFAULT 1
    CHECK (next_fanout_seq >= 1);

-- The sequence this event was fanned out at, so catch-up can serve by it.
-- 0 for an event accepted before this migration: those were delivered
-- without a sequence and catch-up cannot name them.
ALTER TABLE room_event ADD COLUMN fanout_seq INTEGER NOT NULL DEFAULT 0
    CHECK (fanout_seq >= 0);

CREATE UNIQUE INDEX room_event_by_fanout_seq
    ON room_event (room_id, fanout_seq) WHERE fanout_seq > 0;

-- Carried on the row rather than looked up from it, so a delivery after a
-- restart sends the same number without having to match a body back to an
-- event. 0 for a row enqueued before this migration.
ALTER TABLE outbox ADD COLUMN fanout_seq INTEGER NOT NULL DEFAULT 0
    CHECK (fanout_seq >= 0);
