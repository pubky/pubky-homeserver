use pubky_common::capabilities::{Action, Capabilities};

/// Relay payload format understood by a grant client.
///
/// Signed approvals (V1) deliver keys only for explicit `e` permissions,
/// independently of storage read/write permissions. Bare grants cannot ask
/// for keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GrantApprovalFormat {
    /// A signed grant JWS without an approval envelope or encryption-key bundle.
    #[default]
    BareGrant,
    /// A V1 signed approval containing a grant and an encryption-key bundle.
    /// The bundle contains keys only for approved `e` scopes and may be empty.
    ///
    /// Encoded as `approval=v1` in the deep link. Both formats use the
    /// existing shared-secret relay encryption.
    SignedApprovalV1,
}

impl GrantApprovalFormat {
    pub(crate) fn validate_capabilities(self, capabilities: &Capabilities) -> crate::Result<()> {
        if self == Self::BareGrant
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
