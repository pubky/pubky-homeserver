use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use pubky_common::crypto::PublicKey;

/// The key to limit the quota on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimitKey {
    /// Limit on the user pubkey
    User(PublicKey),
    /// Limit on the ip address
    Ip(IpAddr),
}

impl LimitKey {
    /// Get the type of the limit key.
    pub fn get_type(&self) -> LimitKeyType {
        match self {
            LimitKey::User(_) => LimitKeyType::User,
            LimitKey::Ip(_) => LimitKeyType::Ip,
        }
    }
}

impl FromStr for LimitKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pubkey_parse_error = match s.parse::<PublicKey>() {
            Ok(user_pubkey) => return Ok(LimitKey::User(user_pubkey)),
            Err(e) => e,
        };

        let ip_parse_error = match s.parse::<IpAddr>() {
            Ok(ip_addr) => return Ok(LimitKey::Ip(ip_addr)),
            Err(e) => e,
        };

        anyhow::bail!("Invalid limit key. Can't be parsed as a public key or ip address:\n- Public key error: {pubkey_parse_error}\n- Ip address error: {ip_parse_error}")
    }
}

impl fmt::Display for LimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LimitKey::User(user_pubkey) => user_pubkey.z32(),
                LimitKey::Ip(ip_addr) => ip_addr.to_string(),
            }
        )
    }
}

impl serde::Serialize for LimitKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for LimitKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        LimitKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// The key type to limit the quota on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimitKeyType {
    /// Limit on the user id    
    User,
    /// Limit on the ip address
    Ip,
}

impl fmt::Display for LimitKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LimitKeyType::User => "user",
                LimitKeyType::Ip => "ip",
            }
        )
    }
}

impl FromStr for LimitKeyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(LimitKeyType::User),
            "ip" => Ok(LimitKeyType::Ip),
            _ => Err(format!("Invalid limit key: {}", s)),
        }
    }
}

impl serde::Serialize for LimitKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for LimitKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        LimitKeyType::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pubky_common::crypto::Keypair;

    use super::*;

    #[test]
    fn test_limit_key_pubkey() {
        let keypair = Keypair::from_secret(&[0u8; 32]);
        let pubkey = keypair.public_key();

        let limit_key = LimitKey::User(pubkey);
        assert_eq!(limit_key.get_type(), LimitKeyType::User);
        let string = limit_key.to_string();
        assert_eq!(
            string,
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
        );

        let limit_key_from_str = LimitKey::from_str(&string).unwrap();
        assert_eq!(limit_key, limit_key_from_str);
    }

    #[test]
    fn test_limit_key_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let limit_key = LimitKey::Ip(ip);
        assert_eq!(limit_key.get_type(), LimitKeyType::Ip);
        let string = limit_key.to_string();
        assert_eq!(string, "127.0.0.1");

        let limit_key_from_str = LimitKey::from_str(&string).unwrap();
        assert_eq!(limit_key, limit_key_from_str);
    }

    #[test]
    fn test_limit_key_parse_error() {
        let string = "invalid";
        let result = LimitKey::from_str(string);
        assert!(result.is_err());
    }
}
