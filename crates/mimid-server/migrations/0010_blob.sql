-- JMAP blobs (RFC 8620 §6; bead mimid-1wgh.14, stage 1): opaque bytes a
-- user uploaded, by a random id. Clients upload ciphertext, so the server
-- never interprets them.
CREATE TABLE blob (
    -- 16 random octets, unpadded base64url: 22 characters.
    blob_id TEXT PRIMARY KEY CHECK (length(blob_id) = 22),
    -- The uploader. Only this account may download the blob over JMAP.
    account_id TEXT NOT NULL REFERENCES jmap_account (account_id),
    -- The Content-Type of the upload request (RFC 8620 §6.1 `type`).
    media_type TEXT NOT NULL,
    -- The octets, as uploaded.
    bytes BLOB NOT NULL,
    -- Milliseconds since the UNIX epoch.
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE INDEX blob_by_account ON blob (account_id);
