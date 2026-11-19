-- Blob expiry (bead mimid-1wgh.14.2; decision mimid-1wgh.67): the sweep
-- deletes blobs by upload time. Without the index it would scan the
-- table, reading every blob's octets to reach created_at.
CREATE INDEX blob_by_created_at ON blob (created_at);
