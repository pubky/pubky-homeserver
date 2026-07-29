use anyhow::Result;
use pubky::{PubkySigner, PublicKey};

pub const TESTNET_HOMESERVER: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";

#[allow(dead_code)]
pub async fn ensure_signup(signer: &PubkySigner, homeserver: &PublicKey) -> Result<()> {
    match signer.signup(homeserver, None).await {
        Ok(()) => println!("Signed up to the testnet homeserver."),
        Err(pubky::Error::Request(pubky::errors::RequestError::Server { status, .. }))
            if status == reqwest::StatusCode::CONFLICT =>
        {
            println!("Testnet user already exists, continuing...");
            signer
                .pkdns()
                .publish_homeserver_force(Some(homeserver))
                .await?;
            println!("Published testnet homeserver record.");
        }
        Err(err) => return Err(err.into()),
    }

    Ok(())
}
