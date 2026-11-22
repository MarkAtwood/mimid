-- Provider tokens that can be listed and revoked one by one (bead
-- mimid-v9co; purple-mimi decision PQ7): each token gets an opaque id,
-- 16 random bytes as 32 lowercase hex characters, which `mimid admin`
-- shows and revokes by; an optional name the operator gives it; and when
-- it last authenticated a request, in milliseconds since the UNIX epoch,
-- kept to the minute. Tokens from before this migration get a random id
-- and no name or last use (nothing runs in production).
ALTER TABLE jmap_token ADD COLUMN token_id TEXT;
ALTER TABLE jmap_token ADD COLUMN name TEXT;
ALTER TABLE jmap_token ADD COLUMN last_used_at INTEGER CHECK (last_used_at >= 0);
UPDATE jmap_token SET token_id = lower(hex(randomblob(16))) WHERE token_id IS NULL;
CREATE UNIQUE INDEX jmap_token_id ON jmap_token (token_id);
CREATE INDEX jmap_token_account ON jmap_token (account_id);
