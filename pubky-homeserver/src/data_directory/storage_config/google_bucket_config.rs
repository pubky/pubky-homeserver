use serde::Deserialize;
use std::{path::PathBuf, str::FromStr};

/// Google service account key config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoogleServiceAccountKeyConfig {
    /// The path to the credential file.
    Path(PathBuf),
    /// The inline service account key.
    Inline(String),
}

impl GoogleServiceAccountKeyConfig {
    /// Get the credentials. Reads if necessary.
    pub fn get_base64_content(&self) -> Result<String, std::io::Error> {
        let plain_text = match self {
            GoogleServiceAccountKeyConfig::Path(path) => std::fs::read_to_string(path)?,
            GoogleServiceAccountKeyConfig::Inline(inline) => inline.clone(),
        };

        let base64_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plain_text.as_bytes(),
        );
        Ok(base64_encoded)
    }
}

impl FromStr for GoogleServiceAccountKeyConfig {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_p12 = s.contains("-----BEGIN CERTIFICATE-----");
        let is_json =
            s.contains("\"service_account\"") && s.contains("\"auth_provider_x509_cert_url\"");
        let is_path = !(is_p12 || is_json);
        if is_path {
            Ok(GoogleServiceAccountKeyConfig::Path(PathBuf::from(s)))
        } else {
            Ok(GoogleServiceAccountKeyConfig::Inline(s.to_string()))
        }
    }
}

impl std::fmt::Display for GoogleServiceAccountKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleServiceAccountKeyConfig::Path(path) => write!(f, "{}", path.display()),
            GoogleServiceAccountKeyConfig::Inline(inline) => write!(f, "{}", inline),
        }
    }
}

impl serde::Serialize for GoogleServiceAccountKeyConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> serde::Deserialize<'de> for GoogleServiceAccountKeyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let config = GoogleServiceAccountKeyConfig::from_str(&s)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        if let GoogleServiceAccountKeyConfig::Path(path) = &config {
            if !path.exists() || !path.is_file() {
                return Err(serde::de::Error::custom(format!(
                    "File does not exist or is not a file: {}",
                    path.display()
                )));
            }
        }
        Ok(config)
    }
}

/// Google Cloud Storage config.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GoogleBucketConfig {
    /// The name of the bucket to use. Deserialization rejects empty names.
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub bucket_name: String,
    /// The credential to use. Inline service account key or path to the credential file.
    pub credential: GoogleServiceAccountKeyConfig,
}

fn deserialize_nonempty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("string must not be empty"));
    }
    Ok(value)
}

impl GoogleBucketConfig {
    /// Returns the builder.
    pub fn to_builder(&self) -> Result<opendal::services::Gcs, std::io::Error> {
        let credential = self.credential.get_base64_content()?;
        let builder = opendal::services::Gcs::default()
            .bucket(&self.bucket_name)
            .credential(&credential);
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_google_credentials_p12() {
        let p12 = "-----BEGIN CERTIFICATE-----
MIIDdjCCAl6gAwIBAgIU1234567890ABCDEF1234567890ABCDEFwDQYJKoZIhvcN
AQELBQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJjAkBgNV
BAMTHUdvb2dsZSBDbG91ZCBTZXJ2aWNlIEFjY291bnQgQ0EwHhcNMjUwMTAxMDAw
MDAwWhcNMjYwMTAxMDAwMDAwWjCBhTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdv
b2dsZSBJbmMxMTAvBgNVBAMTKHlvdXItc2VydmljZS1hY2NvdW50QHlvdXItcHJv
amVjdC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABN... (truncated) ...==
-----END CERTIFICATE-----";
        let config = GoogleServiceAccountKeyConfig::from_str(p12).unwrap();
        assert_eq!(
            config,
            GoogleServiceAccountKeyConfig::Inline(p12.to_string())
        );
    }

    #[test]
    fn test_validate_google_credentials_json() {
        let json = "{\"type\": \"service_account\", \"project_id\": \"my-project\", \"auth_provider_x509_cert_url\": \"\" \"private_key_id\": \"1234567890\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIE... (truncated) ...\\n-----END PRIVATE KEY-----\\n\"}";
        let config = GoogleServiceAccountKeyConfig::from_str(json).unwrap();
        assert_eq!(
            config,
            GoogleServiceAccountKeyConfig::Inline(json.to_string())
        );
    }

    #[test]
    fn test_validate_google_credentials_path() {
        let path = "/folder/service_file_account.json";
        let config = GoogleServiceAccountKeyConfig::from_str(path).unwrap();
        assert_eq!(
            config,
            GoogleServiceAccountKeyConfig::Path(PathBuf::from(path))
        );
    }
}
