-- The privateMetadata property of a Chat (draft-ietf-jmap-metadata-05 §2;
-- decision mimid-1wgh.63): the account owner's own JSON object, keyed by
-- namespace. A Chat with no row has privateMetadata {}.
CREATE TABLE chat_private_metadata (
    chat_id TEXT PRIMARY KEY REFERENCES follower_chat (chat_id),
    -- The privateMetadata object, as JSON text.
    value TEXT NOT NULL CHECK (json_valid(value) AND json_type(value) = 'object'),
    -- Increases with every write, over every Chat: the Chat changed after
    -- Chat state part p if modseq > p.
    modseq INTEGER NOT NULL UNIQUE CHECK (modseq > 0)
) STRICT;
