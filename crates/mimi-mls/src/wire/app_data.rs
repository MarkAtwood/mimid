//! mls-extensions-10 §4.6 `AppDataDictionary`.

use std::io::Read;

use openmls::component::ComponentData;
use tls_codec::{Deserialize, Serialize, VLBytes};

use super::{decode_canonical, impl_encoding_from_bytes};

/// mls-extensions-10 §4.6: `AppDataDictionary`, the content of an
/// app_data_dictionary extension.
///
/// Its `component_data` entries are strictly sorted by `component_id`
/// (sorted, and at most one per `component_id`); decoding and
/// [`AppDataDictionary::new`] reject anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppDataDictionary {
    bytes: Vec<u8>,
    dictionary: openmls::extensions::AppDataDictionary,
}

impl_encoding_from_bytes!(AppDataDictionary);

impl AppDataDictionary {
    /// Builds a dictionary from `(component_id, data)` entries, which must
    /// already be strictly sorted by `component_id`.
    ///
    /// # Errors
    ///
    /// Returns [`tls_codec::Error::DecodingError`] if the entries are out of
    /// order or repeat a `component_id`, and a tls_codec error if an entry
    /// is too large to encode.
    pub fn new(entries: &[(u16, &[u8])]) -> Result<Self, tls_codec::Error> {
        let component_data: Vec<ComponentData> = entries
            .iter()
            .map(|&(component_id, data)| {
                ComponentData::from_parts(component_id, VLBytes::new(data.to_vec()))
            })
            .collect();
        Self::tls_deserialize_exact(component_data.tls_serialize_detached()?)
    }

    /// Returns the `data` of the entry for `component_id`, if present.
    pub fn get(&self, component_id: u16) -> Option<&[u8]> {
        self.dictionary.get(&component_id)
    }

    /// Returns the `(component_id, data)` entries in order.
    pub fn entries(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.dictionary
            .entries()
            .map(|entry| (entry.id(), entry.data()))
    }
}

impl Deserialize for AppDataDictionary {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (dictionary, bytes) =
            decode_canonical::<openmls::extensions::AppDataDictionary, R>(bytes)?;
        Ok(Self { bytes, dictionary })
    }
}
