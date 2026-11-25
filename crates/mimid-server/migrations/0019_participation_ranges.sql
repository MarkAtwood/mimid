-- Per-room, per-provider participation ranges in fanout sequences
-- (docs/design/mimi-catchup.md §8; bead mimid-1wgh.37.104.2), so a
-- catch-up answer can be bounded by what the requester was there for.
--
-- A range records WHAT WAS FANNED OUT, not what the participant list
-- says. A provider is a destination of a fanout exactly when it had a
-- member in the room (hub::submit::destinations), so the ranges and the
-- deliveries cannot disagree: catch-up can never serve a provider a
-- sequence it was not originally sent. Re-deriving the window from
-- membership changes would be a second answer to the same question.
--
-- Contiguous by construction: between joining and leaving, every fanout
-- of the room goes to the provider, so its presence is runs of
-- consecutive sequences. A provider that leaves and rejoins gets two
-- rows and not the gap between them.
--
-- Separate from room_event, so retention (0014_retention.sql) pruning
-- the events does not lose the window.
CREATE TABLE room_provider_range (
    room_id TEXT NOT NULL REFERENCES room (room_id),
    -- The destination provider's domain.
    domain TEXT NOT NULL,
    -- The first and last fanout sequence of one unbroken run, inclusive.
    first_seq INTEGER NOT NULL CHECK (first_seq >= 1),
    last_seq INTEGER NOT NULL CHECK (last_seq >= first_seq),
    PRIMARY KEY (room_id, domain, first_seq)
) STRICT;

-- The extend-or-open lookup: the run whose last sequence is the one
-- before the fanout being recorded.
CREATE INDEX room_provider_range_by_last
    ON room_provider_range (room_id, domain, last_seq);
