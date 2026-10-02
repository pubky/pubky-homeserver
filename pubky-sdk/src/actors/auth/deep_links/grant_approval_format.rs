use pubky_common::capabilities::{Action, Capabilities};

/// Relay payload format understood by a grant client.
///
/// V1 delivers keys only for explicit `e` permissions, independently of storage
/// read/write permissions. Bare-grant requests cannot ask for keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GrantApprovalFormat {
    /// A bare grant JWS for clients that predate scoped encryption keys.
    #[default]
    Grant,
    /// A signed approval with keys only for approved `e` scopes.
    ///
    /// Encoded as `approval=v1` in the deep link. Both formats use the
    /// existing shared-secret relay encryption.
    V1,
}

impl GrantApprovalFormat {
    pub(crate) fn validate_capabilities(self, capabilities: &Capabilities) -> crate::Result<()> {
        if self == Self::Grant
            && capabilities
                .iter()
                .any(|cap| cap.actions().contains(&Action::EncryptionKeys))
        {
            return Err(crate::errors::AuthError::Validation(
                "encryption key permission requires approval=v1".into(),
            )
            .into());
        }
        Ok(())
    }
}
