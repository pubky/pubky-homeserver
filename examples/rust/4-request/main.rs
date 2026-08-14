use anyhow::{Context, Result};
use clap::Parser;
use reqwest::header::{HeaderName, HeaderValue};
use std::env;
use url::Url;

use pubky::{Method, PubkyHttpClient};

#[derive(Parser, Debug)]
#[command(version, about = "Raw Pubky/HTTPS request tool using PubkyHttpClient")]
struct Cli {
    /// HTTP method to use (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
    method: Method,
    /// Pubky or HTTPS URL (e.g. pubky<user>/pub/my-cool-app/file, pubky://<user>/..., or https://example.com)
    url: Url,
    /// Use testnet endpoints
    #[arg(long)]
    testnet: bool,
    /// Repeatable header in "Name: value" form
    #[arg(short = 'H', long = "header")]
    header: Vec<String>,
    /// Request body (use with POST/PUT/PATCH)
    #[arg(short = 'd', long = "data")]
    data: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(env::var("TRACING").unwrap_or_else(|_| "info".to_string()))
        .init();

    let client = if args.testnet {
        PubkyHttpClient::testnet()?
    } else {
        PubkyHttpClient::new()?
    };

    let mut rb = client.request(args.method.clone(), &args.url);

    // Apply headers
    for h in &args.header {
        let (name, value) = h
            .split_once(':')
            .context("header must be in the form \"Name: value\"")?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).context("invalid header name")?;
        let value = HeaderValue::from_str(value.trim()).context("invalid header value")?;
        rb = rb.header(name, value);
    }

    // Optional body
    if let Some(body) = args.data {
        rb = rb.body(body);
    }

    let response = rb.send().await?;

    println!("< Response:");
    println!("< {:?} {}", response.version(), response.status());
    for (name, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            println!("< {name}: {v}");
        }
    }

    let bytes = response.bytes().await?;
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => println!("<\n{text}"),
        Err(_) => println!("<\n{:?}", bytes),
    }

    Ok(())
}
