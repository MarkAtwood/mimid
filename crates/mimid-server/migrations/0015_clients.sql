-- Client records (draft-atwood-jmap-chat-mimi-00 §Clients, jmap-chat-spec
-- bde5330; bead mimid-e64f.22): each row of `client` is one signature key
-- bound to an account. The key itself is kept, as the record's
-- `signatureKey`; rows from before this migration have none and are not
-- listed (nothing runs in production).
ALTER TABLE client ADD COLUMN signature_key BLOB;

-- Client/changes: every binding and unbinding takes the next number of
-- this log, with its owner. The Client state of an account is the highest
-- number among its owner's rows.
CREATE TABLE client_change (
    modseq INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uri TEXT NOT NULL,
    client_id TEXT NOT NULL,
    -- 0 when the key was bound, 1 when it was unbound.
    destroyed INTEGER NOT NULL CHECK (destroyed IN (0, 1))
) STRICT;

CREATE INDEX client_change_by_user ON client_change (user_uri, modseq);

CREATE TRIGGER client_bound AFTER INSERT ON client
BEGIN
    INSERT INTO client_change (user_uri, client_id, destroyed)
    VALUES (NEW.user_uri, NEW.client_id, 0);
END;

CREATE TRIGGER client_unbound AFTER DELETE ON client
BEGIN
    INSERT INTO client_change (user_uri, client_id, destroyed)
    VALUES (OLD.user_uri, OLD.client_id, 1);
END;
