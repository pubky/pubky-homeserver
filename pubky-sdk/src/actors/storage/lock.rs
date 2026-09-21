use std::time::Duration;

use reqwest::{Method, header::HeaderMap};

use super::core::SessionStorage;
use super::resource::{IntoResourcePath, ResourcePath};
use crate::{Result, cross_log, errors::RequestError};

const LOCK_TOKEN_SCHEME: &str = "opaquelocktoken:";

/// An exclusive write lock on one file path, granted by the homeserver.
///
/// While the lock lives, only writes that present it are accepted on the path;
/// every other write, and every other `LOCK`, gets `423 Locked`. The lock ends
/// when it is [unlocked](SessionStorage::unlock) or when its
/// [`timeout`](Self::timeout) runs out without a
/// [refresh](SessionStorage::refresh), so a client that disappears never blocks
/// a path for long.
///
/// The lock is a bearer token: whoever holds this value, and may write the
/// path, can use and release the lock.
///
/// # Example
///
/// ```no_run
/// # use std::time::Duration;
/// # async fn example(session: pubky::PubkySession) -> pubky::Result<()> {
/// let storage = session.storage();
/// let lock = storage.lock("/pub/my.app/state.json", Duration::from_secs(30)).await?;
/// // ... read, then write presenting `lock.if_header()` ...
/// storage.unlock(&lock).await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageLock {
    path: ResourcePath,
    token: String,
    timeout: Duration,
}

impl StorageLock {
    /// The locked path.
    #[must_use]
    pub const fn path(&self) -> &ResourcePath {
        &self.path
    }

    /// The lock token URL, `opaquelocktoken:<uuid>`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Lifetime the homeserver granted at the last `lock` or `refresh`. It may
    /// be shorter than what was asked for.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Value of the `If` header that presents this lock on a write.
    #[must_use]
    pub fn if_header(&self) -> String {
        format!("(<{}>)", self.token)
    }

    /// Value of the `Lock-Token` header that names this lock on `UNLOCK`.
    fn lock_token_header(&self) -> String {
        format!("<{}>", self.token)
    }
}

impl SessionStorage {
    /// Take an exclusive write lock on a file at an **absolute path**.
    ///
    /// The file need not exist; locking a free path reserves it. `timeout` is
    /// the lifetime asked for; the homeserver caps it, and
    /// [`StorageLock::timeout`] tells what was granted.
    ///
    /// # Errors
    /// A path that is already locked, or that a write is still writing, returns
    /// 423. Directory targets return 400. A homeserver without lock support
    /// returns 405. See [`SessionStorage`] for shared errors.
    pub async fn lock<P: IntoResourcePath>(
        &self,
        path: P,
        timeout: Duration,
    ) -> Result<StorageLock> {
        let path = path.into_abs_path()?;
        let rb = self
            .request(lock_method(), &path)
            .await?
            .header("Timeout", timeout_header(timeout));
        let resp = self.client.check_http_status(rb.send().await?).await?;

        let token = granted_token(resp.headers()).ok_or_else(|| RequestError::Validation {
            message: "homeserver granted a lock without a Lock-Token".into(),
        })?;
        let timeout = granted_timeout(resp.headers()).unwrap_or(timeout);
        cross_log!(debug, "Locked {} for {:?}", path, timeout);
        Ok(StorageLock {
            path,
            token,
            timeout,
        })
    }

    /// Restart the lifetime of a lock this client holds.
    ///
    /// On success `lock` carries the newly granted [`StorageLock::timeout`].
    ///
    /// # Errors
    /// A lock that has expired or was unlocked returns 412; take a new one and
    /// read the file again. See [`SessionStorage`] for shared errors.
    pub async fn refresh(&self, lock: &mut StorageLock, timeout: Duration) -> Result<()> {
        let rb = self
            .request(lock_method(), &lock.path)
            .await?
            .header("If", lock.if_header())
            .header("Timeout", timeout_header(timeout));
        let resp = self.client.check_http_status(rb.send().await?).await?;
        lock.timeout = granted_timeout(resp.headers()).unwrap_or(timeout);
        Ok(())
    }

    /// Release a lock this client holds.
    ///
    /// # Errors
    /// A lock that no longer exists returns 409. See [`SessionStorage`] for
    /// shared errors.
    pub async fn unlock(&self, lock: &StorageLock) -> Result<()> {
        let rb = self
            .request(unlock_method(), &lock.path)
            .await?
            .header("Lock-Token", lock.lock_token_header());
        self.client.check_http_status(rb.send().await?).await?;
        Ok(())
    }
}

fn lock_method() -> Method {
    Method::from_bytes(b"LOCK").expect("LOCK is a valid HTTP method")
}

fn unlock_method() -> Method {
    Method::from_bytes(b"UNLOCK").expect("UNLOCK is a valid HTTP method")
}

/// `Second-N`, at least one second: the homeserver counts in whole seconds.
fn timeout_header(timeout: Duration) -> String {
    format!("Second-{}", timeout.as_secs().max(1))
}

/// The token URL from `Lock-Token: <opaquelocktoken:...>`.
fn granted_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("lock-token")?.to_str().ok()?.trim();
    let token = value.strip_prefix('<')?.strip_suffix('>')?;
    token
        .starts_with(LOCK_TOKEN_SCHEME)
        .then(|| token.to_owned())
}

/// The lifetime from `Timeout: Second-N`.
fn granted_timeout(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get("timeout")?.to_str().ok()?.trim();
    let seconds = value.strip_prefix("Second-")?.parse().ok()?;
    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    fn headers_with(name: &'static str, value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn granted_token_needs_a_bracketed_lock_token_url() {
        let granted = headers_with("lock-token", " <opaquelocktoken:abc> ");
        assert_eq!(
            granted_token(&granted).as_deref(),
            Some("opaquelocktoken:abc")
        );
        for malformed in ["opaquelocktoken:abc", "<urn:uuid:abc>", ""] {
            assert_eq!(granted_token(&headers_with("lock-token", malformed)), None);
        }
        assert_eq!(granted_token(&HeaderMap::new()), None);
    }

    #[test]
    fn granted_timeout_reads_whole_seconds() {
        let granted = headers_with("timeout", "Second-30");
        assert_eq!(granted_timeout(&granted), Some(Duration::from_secs(30)));
        for malformed in ["Infinite", "Second-", "30"] {
            assert_eq!(granted_timeout(&headers_with("timeout", malformed)), None);
        }
        assert_eq!(granted_timeout(&HeaderMap::new()), None);
    }

    #[test]
    fn timeout_header_rounds_up_to_one_second() {
        assert_eq!(timeout_header(Duration::from_secs(45)), "Second-45");
        assert_eq!(timeout_header(Duration::from_millis(200)), "Second-1");
    }

    #[test]
    fn lock_presents_its_token_in_both_header_forms() {
        let lock = StorageLock {
            path: ResourcePath::parse("/pub/state.json").unwrap(),
            token: "opaquelocktoken:abc".into(),
            timeout: Duration::from_secs(30),
        };
        assert_eq!(lock.if_header(), "(<opaquelocktoken:abc>)");
        assert_eq!(lock.lock_token_header(), "<opaquelocktoken:abc>");
    }
}
