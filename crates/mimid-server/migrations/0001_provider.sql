-- The provider domain this database belongs to. A single row, written on
-- first open and checked on every later open, so a database cannot be
-- served under a different domain by mistake.
CREATE TABLE provider (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    domain TEXT NOT NULL
) STRICT;
