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
pub(crate) struct Provider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// An SQLite database holding a client's MLS private state.
///
/// The database holds private keys in the clear; see the crate-level
/// `# Limitations`.
pub struct Store {
    provider: Provider,
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

    fn from_connection(connection: Connection) -> Result<Self, Error> {
        let mut storage = SqliteStorageProvider::new(connection);
        storage
            .run_migrations()
            .map_err(|e| Error::StoreOpen(e.into()))?;
        Ok(Self {
            provider: Provider {
                crypto: RustCrypto::default(),
                storage,
            },
        })
    }

    pub(crate) fn provider(&self) -> &Provider {
        &self.provider
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}
