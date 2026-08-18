use crate::helpers::errors::HttpStatusError;
use anyhow::{Context, Error, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::Method;
use serde::Serialize;
use std::time::Duration;
use url::Url;

pub enum Auth {
    #[allow(dead_code)] // used by unauthenticated commands (upcoming)
    None,
    AdminPassword(String),
}

pub struct HttpClient {
    http: Client,
    base_url: Url,
    auth: Auth,
}

pub fn http_status(err: &Error) -> Option<u16> {
    err.downcast_ref::<HttpStatusError>().map(|e| e.status)
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::None => write!(f, "None"),
            Auth::AdminPassword(_) => write!(f, "AdminPassword(***)"),
        }
    }
}

impl HttpClient {
    pub fn new(mut base_url: Url, auth: Auth) -> Result<Self> {
        if !base_url.path().ends_with('/') {
            log::warn!(
                "base URL '{}' has no trailing slash — appending one. Add a trailing slash to silence this warning.",
                base_url
            );
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            base_url,
            auth,
        })
    }

    pub fn get(&self, path: &str) -> Result<Response> {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: &str) -> Result<Response> {
        self.request(Method::POST, path)
    }

    pub fn post_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
        self.request_json(Method::POST, path, body)
    }

    pub fn patch_json<B: Serialize>(&self, path: &str, body: &B) -> Result<Response> {
        self.request_json(Method::PATCH, path, body)
    }

    fn request(&self, method: Method, path: &str) -> Result<Response> {
        let url = self.url(path)?;
        self.send(self.http.request(method, url.clone()), &url)
    }

    fn request_json<B: Serialize>(&self, method: Method, path: &str, body: &B) -> Result<Response> {
        let url = self.url(path)?;
        self.send(self.http.request(method, url.clone()).json(body), &url)
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .with_context(|| format!("invalid path: {path}"))
    }

    fn send(&self, request: RequestBuilder, url: &Url) -> Result<Response> {
        let response = self
            .apply_auth(request)
            .send()
            .with_context(|| format!("request to {url} failed"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(HttpStatusError {
                status: status.as_u16(),
                url: url.clone(),
            }
            .into());
        }
        Ok(response)
    }

    fn apply_auth(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Auth::None => request,
            Auth::AdminPassword(password) => request.header("X-Admin-Password", password),
        }
    }
}
