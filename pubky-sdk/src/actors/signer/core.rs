use crate::{BuildError, Keypair, PubkyHttpClient, PublicKey};

/// Holds a private key and proves identity.
///
/// Use a `PubkySigner` to:
/// - **Sign up** for a homeserver ([`signup`](crate::PubkySigner::signup)).
/// - **Sign in** locally to get a [`PubkySession`](crate::PubkySession)
///   ([`signin`](crate::PubkySigner::signin)).
/// - **Approve auth** requests from other apps via QR / deep link
///   ([`approve_auth`](crate::PubkySigner::approve_auth),
///   [`handle_deeplink`](crate::PubkySigner::handle_deeplink)).
/// - **Publish PKDNS** records so others can discover your homeserver
///   ([`pkdns()`](crate::PubkySigner::pkdns)).
///
/// # Creating a signer
///
/// Prefer [`Pubky::signer`](crate::Pubky::signer) to share the same HTTP
/// client. Use [`PubkySigner::new`] only when you don't have a [`Pubky`](crate::Pubky) facade.
///
/// # Quick start
///
/// ```no_run
/// use pubky::{Pubky, Keypair, ClientId};
///
/// # async fn run() -> pubky::Result<()> {
/// let signer = Pubky::testnet()?.signer(Keypair::random());
///
/// // See signup() and signin() for full examples
/// let session = signer.signin(ClientId::new("my.app").unwrap()).await?;
/// session.storage().put("/pub/my.app/hello.txt", "world").await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct PubkySigner {
    pub(crate) client: PubkyHttpClient,
    pub(crate) keypair: Keypair,
}

impl PubkySigner {
    /// Construct a standalone `PubkySigner` with its own HTTP client.
    ///
    /// If you already have a [`Pubky`](crate::Pubky) facade, prefer
    /// [`Pubky::signer`](crate::Pubky::signer) to share the connection pool.
    ///
    /// # Examples
    /// ```
    /// # use pubky::{PubkySigner, Keypair};
    /// let signer = PubkySigner::new(Keypair::random())?;
    /// # Ok::<_, pubky::BuildError>(())
    /// ```
    ///
    /// # Errors
    /// - Returns [`crate::BuildError`] if the underlying [`PubkyHttpClient`] cannot be constructed.
    pub fn new(keypair: Keypair) -> std::result::Result<Self, BuildError> {
        Ok(Self {
            client: PubkyHttpClient::new()?,
            keypair,
        })
    }

    /// Public key of this signer.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Borrow the signer's keypair.
    #[inline]
    #[must_use]
    pub const fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}
