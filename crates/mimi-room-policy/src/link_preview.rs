//! The `link_preview_policy` component of room-policy-04 §6.3.

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size};

use crate::{Optionality, PolicyError, Uri};

/// The `link_preview_proxy_use` selector of the room-policy-04 §6.3
/// `LinkPreviewPolicy`, together with the `link_preview_proxy` field it
/// selects.
///
/// It is encoded as the [`Optionality`] byte followed, unless
/// `forbidden`, by `Uri link_preview_proxy<V>`. The draft's `case
/// mandatory` arm is [`LinkPreviewProxyUse::Required`] (decision
/// mimid-1wgh.3.13).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkPreviewProxyUse {
    /// `optional(0)`: clients may use a link preview proxy.
    Optional {
        /// `Uri link_preview_proxy<V>`.
        link_preview_proxy: Vec<Uri>,
    },
    /// `required(1)`: clients must use a link preview proxy.
    Required {
        /// `Uri link_preview_proxy<V>`.
        link_preview_proxy: Vec<Uri>,
    },
    /// `forbidden(2)`: clients must not use a link preview proxy.
    Forbidden,
}

impl LinkPreviewProxyUse {
    /// The `link_preview_proxy_use` value.
    pub fn optionality(&self) -> Optionality {
        match self {
            Self::Optional { .. } => Optionality::Optional,
            Self::Required { .. } => Optionality::Required,
            Self::Forbidden => Optionality::Forbidden,
        }
    }

    /// The `link_preview_proxy` field, or `None` when `forbidden`.
    pub fn link_preview_proxy(&self) -> Option<&[Uri]> {
        match self {
            Self::Optional { link_preview_proxy } | Self::Required { link_preview_proxy } => {
                Some(link_preview_proxy)
            }
            Self::Forbidden => None,
        }
    }
}

impl Size for LinkPreviewProxyUse {
    fn tls_serialized_len(&self) -> usize {
        self.optionality().tls_serialized_len()
            + self
                .link_preview_proxy()
                .map_or(0, |proxy| proxy.tls_serialized_len())
    }
}

impl Serialize for LinkPreviewProxyUse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.optionality().tls_serialize(writer)?;
        if let Some(proxy) = self.link_preview_proxy() {
            written += proxy.tls_serialize(writer)?;
        }
        Ok(written)
    }
}

impl Deserialize for LinkPreviewProxyUse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(match Optionality::tls_deserialize(bytes)? {
            Optionality::Optional => Self::Optional {
                link_preview_proxy: Vec::tls_deserialize(bytes)?,
            },
            Optionality::Required => Self::Required {
                link_preview_proxy: Vec::tls_deserialize(bytes)?,
            },
            Optionality::Forbidden => Self::Forbidden,
        })
    }
}

/// The `LinkPreviewPolicy` struct of room-policy-04 §6.3: how clients
/// detect hyperlinks and generate link previews, and the data of the
/// `link_preview_policy` component.
///
/// Decoding checks the wire format and [`LinkPreviewPolicy::validate`]. A
/// value built in code is not checked until `validate` is called; encoding
/// does not check it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkPreviewPolicy {
    /// `Optionality autodetect_hyperlinks_in_text`: whether a message
    /// composer detects hyperlinks in text that resembles links. Never
    /// `required`.
    pub autodetect_hyperlinks_in_text: Optionality,
    /// `Optionality send_link_previews`: whether a sender includes a link
    /// preview.
    pub send_link_previews: Optionality,
    /// `Optionality automatic_link_previews`: whether a receiver generates
    /// link previews.
    pub automatic_link_previews: Optionality,
    /// `Optionality link_preview_proxy_use` and the `link_preview_proxy`
    /// it selects.
    pub link_preview_proxy_use: LinkPreviewProxyUse,
}

/// `LinkPreviewPolicy LinkPreviewPolicyData` of room-policy-04 §6.3.
pub type LinkPreviewPolicyData = LinkPreviewPolicy;

/// `LinkPreviewPolicy LinkPreviewPolicyUpdate` of room-policy-04 §6.3: an
/// `AppDataUpdate` that replaces the whole `link_preview_policy` (decision
/// mimid-1wgh.3.20).
pub type LinkPreviewPolicyUpdate = LinkPreviewPolicy;

impl LinkPreviewPolicy {
    /// Checks the two rules room-policy-04 §6.3 states for this component.
    ///
    /// - "The value of autodetect_hyperlinks_in_text MUST NOT be
    ///   mandatory", read as `required` (decision mimid-1wgh.3.13); such a
    ///   value is rejected at decode (decision mimid-1wgh.3.59).
    /// - "The link_preview_proxy setting MUST include the URI of a link
    ///   preview proxy if link_preview_proxy_use is mandatory or
    ///   optional": `link_preview_proxy` holds at least one non-empty
    ///   [`Uri`], since a zero-length one means absent (decisions
    ///   mimid-1wgh.3.18, mimid-1wgh.3.57). Further entries, empty or not,
    ///   are kept.
    ///
    /// # Errors
    ///
    /// [`PolicyError::AutodetectHyperlinksRequired`] or
    /// [`PolicyError::MissingLinkPreviewProxy`] if a rule is broken.
    pub fn validate(&self) -> Result<(), PolicyError> {
        // room-policy-04 §6.3; decision mimid-1wgh.3.59
        if self.autodetect_hyperlinks_in_text == Optionality::Required {
            return Err(PolicyError::AutodetectHyperlinksRequired);
        }
        // room-policy-04 §6.3; decision mimid-1wgh.3.57
        match self.link_preview_proxy_use.link_preview_proxy() {
            Some(proxy) if !proxy.iter().any(|uri| !uri.is_empty()) => {
                Err(PolicyError::MissingLinkPreviewProxy)
            }
            _ => Ok(()),
        }
    }
}

impl Size for LinkPreviewPolicy {
    fn tls_serialized_len(&self) -> usize {
        self.autodetect_hyperlinks_in_text.tls_serialized_len()
            + self.send_link_previews.tls_serialized_len()
            + self.automatic_link_previews.tls_serialized_len()
            + self.link_preview_proxy_use.tls_serialized_len()
    }
}

impl Serialize for LinkPreviewPolicy {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.autodetect_hyperlinks_in_text.tls_serialize(writer)?
            + self.send_link_previews.tls_serialize(writer)?
            + self.automatic_link_previews.tls_serialize(writer)?
            + self.link_preview_proxy_use.tls_serialize(writer)?)
    }
}

impl Deserialize for LinkPreviewPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            autodetect_hyperlinks_in_text: Optionality::tls_deserialize(bytes)?,
            send_link_previews: Optionality::tls_deserialize(bytes)?,
            automatic_link_previews: Optionality::tls_deserialize(bytes)?,
            link_preview_proxy_use: LinkPreviewProxyUse::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
