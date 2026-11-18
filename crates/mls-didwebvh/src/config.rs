//! The code points this credential uses, which IANA has not assigned.

/// The credential type and `app_data_dictionary` component ID a deployment
/// uses for `did_webvh` and the `did_webvh_heads` record.
///
/// draft-atwood-mls-didwebvh-credential-00 §IANA Considerations asks for
/// "TBD1 (suggested value 0x0008)" in the MLS Credential Types registry.
/// It defines the record as a GroupContext extension ("TBD2 (suggested
/// value 0x0013)" in the MLS Extension Types registry); mimid carries it
/// instead as a component of the GroupContext `app_data_dictionary`
/// extension, changed by AppDataUpdate proposals (mls-extensions-11 §4.6,
/// §4.7), which the draft names no value for (decisions mimid-1wgh.4.81.33
/// and mimid-1wgh.4.81.35). Until IANA assigns them, both are settings
/// (bead mimid-1wgh.4.81). Every member of a group must use the same
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodePoints {
    credential_type: u16,
    heads_component: u16,
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
    /// The component ID is reserved (0x0000), one mls-extensions-11 §7.5
    /// assigns (0x0001 `app_components` to 0x0005 `app_ack`), or a GREASE
    /// value (0x0A0A to 0x7A7A).
    #[error("component id {0:#06x} is reserved, assigned or GREASE")]
    ComponentId(u16),
}

/// RFC 9420 §13.5: the GREASE values are 0x0A0A, 0x1A1A, ..., 0xEAEA.
fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

impl CodePoints {
    /// The default values: the draft's suggested credential type 0x0008,
    /// and the record as component 0xF013.
    ///
    /// INVENTED, NOT FROM SPEC: 0xF013 is in the private-use range of the
    /// MLS Component Types registry (mls-extensions-11 §7.5: 0x8000 to
    /// 0xFFFF), chosen because the draft names no component value
    /// (decision mimid-1wgh.4.81.35). It is mimid's, not an interoperable
    /// assignment.
    pub const DEFAULT: Self = Self {
        credential_type: 0x0008,
        heads_component: 0xf013,
    };

    /// Code points other than the default ones, for a deployment that must
    /// avoid them or match a peer's.
    ///
    /// # Errors
    ///
    /// Returns [`CodePointError`] for a value that would collide with one
    /// RFC 9420 or mls-extensions-11 already gives a meaning to.
    pub fn new(credential_type: u16, heads_component: u16) -> Result<Self, CodePointError> {
        if matches!(credential_type, 0x0000..=0x0002) || is_grease(credential_type) {
            return Err(CodePointError::CredentialType(credential_type));
        }
        // mls-extensions-11 §7.5: 0x0000 is reserved, 0x0001 to 0x0005 are
        // assigned, and the component GREASE values are 0x0A0A to 0x7A7A;
        // 0x8000 and up is private use.
        if matches!(heads_component, 0x0000..=0x0005)
            || (is_grease(heads_component) && heads_component < 0x8000)
        {
            return Err(CodePointError::ComponentId(heads_component));
        }
        Ok(Self {
            credential_type,
            heads_component,
        })
    }

    /// The `did_webvh` credential type.
    pub fn credential_type(&self) -> u16 {
        self.credential_type
    }

    /// The `app_data_dictionary` component that carries the
    /// `did_webvh_heads` record.
    pub fn heads_component(&self) -> u16 {
        self.heads_component
    }
}

impl Default for CodePoints {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_the_drafts_credential_type_and_a_private_use_component() {
        assert_eq!(CodePoints::DEFAULT.credential_type(), 0x0008);
        assert_eq!(CodePoints::DEFAULT.heads_component(), 0xf013);
        assert_eq!(CodePoints::new(0x0008, 0xf013), Ok(CodePoints::DEFAULT));
        assert_eq!(CodePoints::default(), CodePoints::DEFAULT);
    }

    #[test]
    fn colliding_values_are_refused() {
        for credential_type in [0x0000, 0x0001, 0x0002, 0x0a0a, 0xeaea] {
            assert_eq!(
                CodePoints::new(credential_type, 0xf013),
                Err(CodePointError::CredentialType(credential_type))
            );
        }
        for component_id in [
            0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0a0a, 0x7a7a,
        ] {
            assert_eq!(
                CodePoints::new(0x0008, component_id),
                Err(CodePointError::ComponentId(component_id))
            );
        }
        // Unassigned, and private use, including the private-use values
        // shaped like GREASE (§7.5 lists GREASE only below 0x8000).
        for component_id in [0x0006, 0x0013, 0x8000, 0x8a8a, 0xffff] {
            assert!(CodePoints::new(0x0008, component_id).is_ok());
        }
        assert!(CodePoints::new(0xf008, 0xf014).is_ok());
    }
}
