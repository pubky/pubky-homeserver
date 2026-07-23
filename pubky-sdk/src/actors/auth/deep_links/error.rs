/// Errors that can occur when parsing a deep link.
#[derive(Debug, thiserror::Error)]
pub enum DeepLinkParseError {
    /// Failed to parse the URL.
    #[error("Failed to parse URL")]
    UrlParseError(#[from] url::ParseError),
    /// Invalid schema.
    #[error("Invalid schema. Expected {0}")]
    InvalidSchema(&'static str),
    /// Missing query parameter aka parameter missing in the URL.
    #[error("Missing query parameter {0}")]
    MissingQueryParameter(&'static str),
    /// Invalid query parameter aka parameter with an invalid value in the URL.
    #[error("Invalid query parameter {0}: {1}")]
    InvalidQueryParameter(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync>,
    ),
    /// Invalid intent. Expected a valid intent.
    #[error("Invalid intent. Expected {0}")]
    InvalidIntent(&'static str),
}
