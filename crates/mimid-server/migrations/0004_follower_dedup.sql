-- FanoutMessage deduplication by inner message and by senderMsgId
-- (bead mimid-1wgh.7.31; decisions mimid-1wgh.7.30, mimid-1wgh.12.24).
-- The `UNIQUE (room_id, hash)` of 0003 stays: two identical FanoutMessages
-- have identical inner messages, so the new rules already refuse what it
-- refuses.
--
-- Rows stored before this migration have NULL in both columns, since
-- SQLite cannot hash or decode them, and are not deduplicated against.

-- SHA-256 of the FanoutMessage's inner `message` octets: no two events of
-- a room carry byte-identical messages (decision mimid-1wgh.7.30).
ALTER TABLE follower_event ADD COLUMN message_hash BLOB
    CHECK (message_hash IS NULL OR length(message_hash) = 32);

-- The draft-atwood-jmap-chat-mimi-00 senderMsgId, as a 16-byte binary
-- ULID: the 48-bit `timestamp`, big-endian, then the first 10 octets of
-- `hash`.
ALTER TABLE follower_event ADD COLUMN sender_msg_id BLOB
    CHECK (sender_msg_id IS NULL OR length(sender_msg_id) = 16);

CREATE UNIQUE INDEX follower_event_message ON follower_event (room_id, message_hash);
CREATE UNIQUE INDEX follower_event_sender_msg_id ON follower_event (room_id, sender_msg_id);
