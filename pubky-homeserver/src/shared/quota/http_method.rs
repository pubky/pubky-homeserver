use std::{fmt::Display, str::FromStr};

use axum::http::Method;
use serde::{Deserialize, Serialize};

/// A wrapper around http::Method to implement serde traits
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpMethod(pub Method);

impl From<Method> for HttpMethod {
    fn from(method: Method) -> Self {
        HttpMethod(method)
    }
}

impl From<HttpMethod> for Method {
    fn from(method: HttpMethod) -> Self {
        method.0
    }
}

impl FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Method::from_str(s.to_uppercase().as_str())
            .map(HttpMethod)
            .map_err(|_| format!("Invalid method: {}", s))
    }
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for HttpMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HttpMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        HttpMethod::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_serde() {
        let method = Method::GET;
        let http_method = HttpMethod(method);
        assert_eq!(http_method.to_string(), "GET");

        let deserialized: HttpMethod = "GET".parse().unwrap();
        assert_eq!(deserialized, http_method);
    }
}
