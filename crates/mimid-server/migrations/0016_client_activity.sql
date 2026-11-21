-- Idle Client records (draft-atwood-jmap-chat-mimi-00 §Clients,
-- jmap-chat-spec 735503c; clean-room finding C6): when the server last
-- saw a signature key act through the mimi capability, in milliseconds
-- since the UNIX epoch. The idle sweep unbinds a key with no KeyPackage
-- record and no activity for the configured period. Rows from before this
-- migration have none and count as idle since their KeyPackages expired
-- (nothing runs in production).
ALTER TABLE client ADD COLUMN last_active_ms INTEGER;
