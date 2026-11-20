//! Durable MLS key and group state (decision mimid-1wgh.4.14).

use std::path::Path;

use openmls::prelude::OpenMlsProvider;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};

use crate::Error;

/// Serializes OpenMLS storage entities as JSON.
#[derive(Default)]
pub(crate) struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The OpenMLS provider: RustCrypto for crypto and randomness, SQLite for
/// storage. Kept private so OpenMLS traits stay out of the public API.
///
/// It borrows the [`Store`]'s connection and is made for each use
/// ([`Store::provider`]), so the connection stays the `Store`'s own and the
/// caller can run its own statements and transactions on it
/// ([`Store::connection`]): openmls_sqlite_storage opens no transaction of
/// its own, so OpenMLS's writes join the caller's. A `&Connection` is not
/// `Send` (`Connection` is not `Sync`); the provider never outlives the
/// synchronous call that made it.
pub(crate) struct Provider<'a> {
    crypto: &'a RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
}

impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}

/// An SQLite database holding a client's MLS private state.
///
/// The database holds private keys in the clear; see the crate-level
/// `# Limitations`. The caller may keep its own tables in the same
/// database and wrap OpenMLS's writes in its own transactions
/// ([`Store::connection`]).
pub struct Store {
    connection: Connection,
    crypto: RustCrypto,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and applies the
    /// OpenMLS schema migrations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreOpen`] if the file cannot be opened as an SQLite
    /// database or the migrations fail.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let connection = Connection::open(path).map_err(|e| Error::StoreOpen(e.into()))?;
        Self::from_connection(connection)
    }

    /// Opens a fresh database that lives only in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StoreOpen`] if SQLite cannot create the database or
    /// the migrations fail.
    pub fn open_in_memory() -> Result<Self, Error> {
        let connection = Connection::open_in_memory().map_err(|e| Error::StoreOpen(e.into()))?;
        Self::from_connection(connection)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, Error> {
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut connection)
            .run_migrations()
            .map_err(|e| Error::StoreOpen(e.into()))?;
        Ok(Self {
            connection,
            crypto: RustCrypto::default(),
        })
    }

    /// The database connection OpenMLS writes through, for the caller's
    /// own tables and transactions in the same database (bead
    /// mimid-1vul.10). OpenMLS runs each statement on it as it comes and
    /// opens no transaction of its own, so a transaction the caller has
    /// open takes in OpenMLS's writes too, and a rollback undoes them.
    /// Leave OpenMLS's tables (`openmls_*`, `vc_*` and the migration
    /// history) to it.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn provider(&self) -> Provider<'_> {
        Provider {
            crypto: &self.crypto,
            storage: SqliteStorageProvider::new(&self.connection),
        }
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn signature_keys(store: &Store) -> i64 {
        store
            .connection()
            .query_row("SELECT count(*) FROM openmls_signature_keys", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    /// OpenMLS's writes join a transaction the caller opened on
    /// [`Store::connection`]: a rollback undoes them, a commit keeps them.
    #[test]
    fn openmls_writes_join_the_callers_transaction() {
        for (end, kept) in [("ROLLBACK", 0), ("COMMIT", 1)] {
            let store = Store::open_in_memory().unwrap();
            store.connection().execute_batch("BEGIN IMMEDIATE").unwrap();
            let identity = Identity::generate(b"alice", store).unwrap();
            assert!(!identity.store().connection().is_autocommit());
            identity.store().connection().execute_batch(end).unwrap();
            assert_eq!(signature_keys(identity.store()), kept, "{end}");
        }
    }
}
