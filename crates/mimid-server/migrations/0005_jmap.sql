-- JMAP accounts and bearer tokens (mimid-1wgh.11.1; plan of mimid-1wgh.12,
-- section 3).

-- One JMAP account per local user.
CREATE TABLE jmap_account (
    -- A ULID, used as the RFC 8620 section 1.2 Id of the account.
    account_id TEXT PRIMARY KEY CHECK (length(account_id) = 26),
    -- The user URI, under this provider's domain.
    user_uri TEXT NOT NULL UNIQUE,
    -- Milliseconds since the UNIX epoch.
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

-- Bearer tokens. Only SHA-256 of each token's 32 bytes is stored.
CREATE TABLE jmap_token (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    account_id TEXT NOT NULL REFERENCES jmap_account (account_id),
    -- Milliseconds since the UNIX epoch.
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    -- Milliseconds since the UNIX epoch; NULL while the token is valid.
    revoked_at INTEGER CHECK (revoked_at >= 0)
) STRICT;
