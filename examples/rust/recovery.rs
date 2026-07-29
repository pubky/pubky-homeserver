use anyhow::Result;
use pubky::Keypair;
use std::path::{Path, PathBuf};

pub const SAMPLE_RECOVERY_FILE: &str = "sample_recovery.key";

pub fn sample_recovery_file(is_testnet: bool) -> PathBuf {
    if !is_testnet {
        panic!("Sample recovery file is only available for testnet");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(SAMPLE_RECOVERY_FILE)
}

pub fn decrypt_recovery_file(path: &Path, prompt: &str) -> Result<Keypair> {
    let recovery_file = std::fs::read(path)?;

    if let Ok(keypair) = pubky::recovery_file::decrypt_recovery_file(&recovery_file, "") {
        return Ok(keypair);
    }

    println!("{prompt}");
    let passphrase = rpassword::read_password()?;
    Ok(pubky::recovery_file::decrypt_recovery_file(
        &recovery_file,
        &passphrase,
    )?)
}
