//! The `logging_policy` component of room-policy-04 §6.5.

use std::io::Read;

use tls_codec::{Deserialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{OptionalitySelect, PolicyError, Uri};

/// The fields of the room-policy-04 §6.5 `LoggingPolicy` that follow a
/// `logging` value of `required` or `optional`. The draft gives this arm
/// no name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct LoggingSettings {
    /// `Uri logging_clients<V>`: the logging clients' URIs.
    pub logging_clients: Vec<Uri>,
    /// `Uri machine_readable_policy`: the owning provider's machine-readable
    /// logging policy; a zero-length value means absent (decision
    /// mimid-1wgh.3.18).
    pub machine_readable_policy: Uri,
    /// `Uri human_readable_policy`: the owning provider's human-readable
    /// logging policy; a zero-length value means absent (decision
    /// mimid-1wgh.3.18).
    pub human_readable_policy: Uri,
}

/// The `LoggingPolicy` struct of room-policy-04 §6.5: whether calls and
/// messages in the room are logged, and the data of the `logging_policy`
/// component.
///
/// If `logging` is optional and there is at least one logging client,
/// logging is active for the room (§6.5).
///
/// Decoding checks the wire format and [`LoggingPolicy::validate`]. A value
/// built in code is not checked until `validate` is called; encoding does
/// not check it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct LoggingPolicy {
    /// `Optionality logging` and the fields it selects.
    pub logging: OptionalitySelect<LoggingSettings>,
}

/// `LoggingPolicy LoggingPolicyData` of room-policy-04 §6.5.
pub type LoggingPolicyData = LoggingPolicy;

/// `LoggingPolicy LoggingPolicyUpdate` of room-policy-04 §6.5: an
/// `AppDataUpdate` that replaces the whole `logging_policy` (decision
/// mimid-1wgh.3.20).
pub type LoggingPolicyUpdate = LoggingPolicy;

impl LoggingPolicy {
    /// Checks the structural rule room-policy-04 §6.5 states for this
    /// component.
    ///
    /// "If logging is required, the list of logging_clients needs to
    /// contain at least one logging URI": `logging_clients` then holds at
    /// least one non-empty [`Uri`], since a zero-length one means absent
    /// (decisions mimid-1wgh.3.18, mimid-1wgh.3.61). Further entries, empty
    /// or not, are kept. Whether each provider has at most one logging
    /// client (§6.5 "should") is not checked (decision mimid-1wgh.3.64).
    ///
    /// # Errors
    ///
    /// [`PolicyError::MissingLoggingClient`] if the rule is broken.
    pub fn validate(&self) -> Result<(), PolicyError> {
        // room-policy-04 §6.5; decision mimid-1wgh.3.61
        match &self.logging {
            OptionalitySelect::Required(settings)
                if settings.logging_clients.iter().all(Uri::is_empty) =>
            {
                Err(PolicyError::MissingLoggingClient)
            }
            _ => Ok(()),
        }
    }
}

impl Deserialize for LoggingPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            logging: OptionalitySelect::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
