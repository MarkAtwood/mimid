-- The hub's HPKE key pair, for reading SemiPrivateMessage handshakes as an
-- external receiver (draft-mahy-mls-semiprivatemessage-08 §3; bead
-- mimid-1wgh.4.79.2).
--
-- One pair for the whole hub, beside the signature key and the franking
-- key, rather than one per room (decision mimid-1wgh.4.79.7): the hub is
-- one party with one Credential, and every private key here is already
-- unencrypted in this one file, so per-room keys would be compartments
-- inside one box.
--
-- Nullable because the row may predate this migration. It is filled on
-- first use, as the other secrets are.
ALTER TABLE hub_secret ADD COLUMN hpke_private_key BLOB;
ALTER TABLE hub_secret ADD COLUMN hpke_public_key BLOB;
