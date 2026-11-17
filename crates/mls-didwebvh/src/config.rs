//! The code points this credential uses, which IANA has not assigned.

/// The credential type and GroupContext extension type a deployment uses
/// for `did_webvh` and `did_webvh_heads`.
///
/// draft-atwood-mls-didwebvh-credential-00 §IANA Considerations asks for
/// "TBD1 (suggested value 0x0008)" in the MLS Credential Types registry and
/// "TBD2 (suggested value 0x0013)" in the MLS Extension Types registry.
/// Until IANA assigns them, both are settings (bead mimid-1wgh.4.81).
/// Every member of a group must use the same values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodePoints {
    credential_type: u16,
    heads_extension_type: u16,
    /// `Some` when the record travels as an `app_data_dictionary` component
    /// instead of the `did_webvh_heads` GroupContext extension (spike bead
    /// mimid-1wgh.4.81.32).
    heads_component: Option<u16>,
}

/// Why a [`CodePoints`] value is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodePointError {
    /// The credential type is reserved (0x0000), already assigned by
    /// RFC 9420 (`basic` 0x0001, `x509` 0x0002), or a GREASE value
    /// (RFC 9420 §13.5).
    #[error("credential type {0:#06x} is reserved, assigned or GREASE")]
    CredentialType(u16),
    /// The extension type is reserved (0x0000), one OpenMLS gives a meaning
    /// to (0x0001 to 0x0006 and 0x000a), or a GREASE value.
    #[error("extension type {0:#06x} is reserved, assigned or GREASE")]
    ExtensionType(u16),
    /// The component ID is reserved (0x0000), one mls-extensions-11 §5
    /// defines (`app_components` 0x0001, `safe_aad` 0x0002), or a GREASE
    /// value.
    #[error("component id {0:#06x} is reserved, assigned or GREASE")]
    ComponentId(u16),
}

/// RFC 9420 §13.5: the GREASE values are 0x0A0A, 0x1A1A, ..., 0xEAEA.
fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

impl CodePoints {
    /// The values the draft suggests: credential type 0x0008 and extension
    /// type 0x0013.
    pub const SUGGESTED: Self = Self {
        credential_type: 0x0008,
        heads_extension_type: 0x0013,
        heads_component: None,
    };

    /// Code points other than the suggested ones, for a deployment that
    /// must avoid them.
    ///
    /// # Errors
    ///
    /// Returns [`CodePointError`] for a value that would collide with one
    /// RFC 9420 or OpenMLS already gives a meaning to.
    pub fn new(credential_type: u16, heads_extension_type: u16) -> Result<Self, CodePointError> {
        if matches!(credential_type, 0x0000..=0x0002) || is_grease(credential_type) {
            return Err(CodePointError::CredentialType(credential_type));
        }
        if matches!(heads_extension_type, 0x0000..=0x0006 | 0x000a)
            || is_grease(heads_extension_type)
        {
            return Err(CodePointError::ExtensionType(heads_extension_type));
        }
        Ok(Self {
            credential_type,
            heads_extension_type,
            heads_component: None,
        })
    }

    /// The same code points, with the record carried as the entry
    /// `component_id` of the GroupContext `app_data_dictionary` and changed
    /// by AppDataUpdate proposals (mls-extensions-11 §4.6, §4.7), instead
    /// of as the `did_webvh_heads` GroupContext extension changed by
    /// GroupContextExtensions proposals.
    ///
    /// INVENTED, NOT FROM SPEC: a prototype of a possible -01 carriage
    /// (spike bead mimid-1wgh.4.81.32, decision mimid-1wgh.4.81.33,
    /// `docs/didwebvh-appdata-spike.md`). The component's `update` is a `DIDWebVHHeads` whose entries replace
    /// or add the entries of the same SCIDs; a `remove` is invalid. Every
    /// member of a group must use the same setting.
    ///
    /// # Errors
    ///
    /// Returns [`CodePointError::ComponentId`] for 0x0000, `app_components`
    /// (0x0001), `safe_aad` (0x0002) or a GREASE value.
    pub fn with_heads_component(self, component_id: u16) -> Result<Self, CodePointError> {
        // mls-extensions-11 §7.5: the component GREASE values are 0x0A0A
        // to 0x7A7A; 0x8000 and up is private use.
        if matches!(component_id, 0x0000..=0x0002)
            || (is_grease(component_id) && component_id < 0x8000)
        {
            return Err(CodePointError::ComponentId(component_id));
        }
        Ok(Self {
            heads_component: Some(component_id),
            ..self
        })
    }

    /// The `app_data_dictionary` component that carries the record, or
    /// `None` when the record is the `did_webvh_heads` GroupContext
    /// extension (the draft's form, and the default).
    pub fn heads_component(&self) -> Option<u16> {
        self.heads_component
    }

    /// The `did_webvh` credential type.
    pub fn credential_type(&self) -> u16 {
        self.credential_type
    }

    /// The `did_webvh_heads` GroupContext extension type.
    pub fn heads_extension_type(&self) -> u16 {
        self.heads_extension_type
    }
}

impl Default for CodePoints {
    fn default() -> Self {
        Self::SUGGESTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_values_are_the_drafts() {
        assert_eq!(CodePoints::SUGGESTED.credential_type(), 0x0008);
        assert_eq!(CodePoints::SUGGESTED.heads_extension_type(), 0x0013);
        assert_eq!(CodePoints::new(0x0008, 0x0013), Ok(CodePoints::SUGGESTED));
    }

    #[test]
    fn colliding_values_are_refused() {
        for credential_type in [0x0000, 0x0001, 0x0002, 0x0a0a, 0xeaea] {
            assert_eq!(
                CodePoints::new(credential_type, 0x0013),
                Err(CodePointError::CredentialType(credential_type))
            );
        }
        for extension_type in [0x0000, 0x0002, 0x0006, 0x000a, 0x3a3a] {
            assert_eq!(
                CodePoints::new(0x0008, extension_type),
                Err(CodePointError::ExtensionType(extension_type))
            );
        }
        assert!(CodePoints::new(0xf008, 0xf013).is_ok());
        for component_id in [0x0000, 0x0001, 0x0002, 0x7a7a] {
            assert_eq!(
                CodePoints::SUGGESTED.with_heads_component(component_id),
                Err(CodePointError::ComponentId(component_id))
            );
        }
        let component = CodePoints::SUGGESTED
            .with_heads_component(0xf013)
            .expect("private-use id");
        assert_eq!(component.heads_component(), Some(0xf013));
        assert!(CodePoints::SUGGESTED.with_heads_component(0x8a8a).is_ok());
        assert_eq!(CodePoints::SUGGESTED.heads_component(), None);
        assert_ne!(component, CodePoints::SUGGESTED);
    }
}
