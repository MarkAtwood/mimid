-- What a follower holds of a room's fanout, and what it knows is missing
-- (docs/design/mimi-catchup.md §10; bead mimid-1wgh.37.104.4).
--
-- A follower that misses a /notify loses that ciphertext for good today,
-- and nobody is told. Knowing its own position is what lets it notice.
--
-- All three columns land together rather than one per stage: they are
-- one piece of state, and a room is either current, behind by a known
-- amount, or behind by an amount nobody can supply.

-- The highest fanout sequence this follower holds for the room. 0 means
-- none has been seen, which is also what a hub that does not number its
-- fanout leaves, so a 0 here is "nothing to compare against" and never
-- "the hub is at zero".
ALTER TABLE follower_room ADD COLUMN highest_fanout_seq INTEGER NOT NULL DEFAULT 0
    CHECK (highest_fanout_seq >= 0);

-- The first sequence known to be missing, when a gap has been noticed
-- and not yet filled; NULL when there is no known gap. Set when live
-- fanout arrives above highest_fanout_seq + 1, which is the only way a
-- follower can detect a gap from its own state: at startup it knows its
-- own highest and not the hub's.
ALTER TABLE follower_room ADD COLUMN gap_from INTEGER
    CHECK (gap_from IS NULL OR gap_from >= 1);

-- Whether the hub has said that gap cannot be filled (§5.1): the range
-- is older than it holds. This is the thing the whole design exists to
-- remove -- silent loss -- so it is recorded against the room and
-- surfaced rather than retried, because retrying cannot help.
ALTER TABLE follower_room ADD COLUMN gap_unfillable INTEGER NOT NULL DEFAULT 0
    CHECK (gap_unfillable IN (0, 1));
