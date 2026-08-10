//! Docker-based PostgreSQL for running tests without external Postgres.
//!
//! This module provides a containerized PostgreSQL instance (via testcontainers)
//! that can be used for integration tests without requiring a separate Postgres
//! installation. Containers are cleaned up:
//! - On drop (via testcontainers)
//! - On SIGINT/SIGTERM (via the testcontainers watchdog)
//! - On normal process exit (via an `atexit` hook for the shared instance)
//!
//! Note: `kill -9` will still leave containers orphaned.

use pubky_homeserver::ConnectionString;
use std::sync::OnceLock;
use testcontainers::{runners::AsyncRunner, ContainerAsync};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;

/// Shared Docker postgres instance, initialized once per process.
static SHARED_PG: OnceCell<DockerPostgres> = OnceCell::const_new();

/// Container ID of the shared instance, used by the `atexit` handler.
static SHARED_CONTAINER_ID: OnceLock<String> = OnceLock::new();

/// `atexit` handler: forcefully removes the shared container on normal process exit.
///
/// This is necessary because Rust never drops statics, so the `ContainerAsync`
/// destructor won't run for `SHARED_PG`. We shell out to `docker rm -f`
/// synchronously since async is not available in atexit handlers.
extern "C" fn cleanup_shared_container() {
    if let Some(id) = SHARED_CONTAINER_ID.get() {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", id])
            .output();
    }
}

/// A containerized PostgreSQL instance for testing.
///
/// The container is automatically cleaned up on drop, on Ctrl+C/SIGTERM,
/// and (for the shared instance) on normal process exit via an `atexit` hook.
///
/// Multiple testnets can safely share one container — each gets its own
/// isolated database. See [`Self::connection_string()`] for details.
pub struct DockerPostgres {
    _container: ContainerAsync<Postgres>,
    host: String,
    port: u16,
}

/// Deprecated alias for [`DockerPostgres`].
#[deprecated(since = "0.9.0", note = "Renamed to `DockerPostgres`")]
pub type EmbeddedPostgres = DockerPostgres;

impl DockerPostgres {
    /// Return a shared Docker PostgreSQL container, starting it on first call.
    ///
    /// Avoids the overhead of starting a separate container per test.
    /// Each testnet still gets its own isolated database.
    ///
    /// # Panics
    ///
    /// Panics if the container fails to start (e.g., Docker is not running).
    pub async fn shared() -> &'static DockerPostgres {
        SHARED_PG
            .get_or_init(|| async {
                let pg = DockerPostgres::start()
                    .await
                    .expect("Failed to start shared Docker postgres. Is Docker running?");

                // Register atexit cleanup (idempotent — only the first call matters).
                SHARED_CONTAINER_ID.get_or_init(|| {
                    // SAFETY: `cleanup_shared_container` only calls
                    // `std::process::Command::new("docker")`, which is safe to invoke
                    // from an atexit handler on all supported platforms. The handler
                    // runs after `main` returns but before the process exits, so the
                    // allocator and standard library are still available.
                    let ret = unsafe { libc::atexit(cleanup_shared_container) };
                    if ret != 0 {
                        eprintln!("warning: failed to register atexit handler for Docker cleanup (returned {ret})");
                    }
                    pg.container_id().to_string()
                });

                pg
            })
            .await
    }

    /// Start a new Docker PostgreSQL container.
    ///
    /// Requires Docker to be running on the host.
    pub async fn start() -> anyhow::Result<Self> {
        let container = Postgres::default().start().await.map_err(|e| {
            anyhow::anyhow!("Failed to start Postgres container. Is Docker running? Error: {e}")
        })?;

        let host = container.get_host().await?.to_string();
        let port = container.get_host_port_ipv4(5432).await?;

        Ok(Self {
            _container: container,
            host,
            port,
        })
    }

    /// Get the connection string for this Docker PostgreSQL instance.
    ///
    /// The returned connection string includes `?pubky-test=true` so that
    /// each homeserver creates its own ephemeral `pubky_test_{uuid}` database.
    /// This is what makes `DockerPostgres::shared()` safe: multiple testnets
    /// share the same Postgres **server** but each gets an isolated database.
    pub fn connection_string(&self) -> anyhow::Result<ConnectionString> {
        let url = format!(
            "postgres://postgres:postgres@{}:{}/postgres?pubky-test=true",
            self.host, self.port
        );
        ConnectionString::new(&url).map_err(|e| anyhow::anyhow!("Invalid connection string: {e}"))
    }

    /// Get the Docker container ID (for diagnostics / verification).
    pub fn container_id(&self) -> &str {
        self._container.id()
    }
}

#[cfg(test)]
mod tests {
    use super::DockerPostgres;
    use crate::EphemeralTestnet;
    use pubky::Keypair;

    const CONTAINER_ID_PREFIX: &str = "CONTAINER_ID=";

    /// Poll `docker inspect` until the container no longer exists, or panic
    /// after `max_attempts` tries (each separated by 1 second).
    async fn wait_for_container_removal(container_id: &str, max_attempts: u32) {
        for i in 0..max_attempts {
            let output = std::process::Command::new("docker")
                .args(["inspect", container_id])
                .output()
                .expect("docker inspect failed");
            if !output.status.success() {
                return; // container is gone
            }
            if i + 1 < max_attempts {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        panic!("Container {container_id} still exists after {max_attempts} attempts");
    }

    /// Extract the container ID printed by the subprocess using the
    /// `CONTAINER_ID=<id>` delimiter, so we don't accidentally match
    /// other hex in the test harness output.
    fn extract_container_id(s: &str) -> Option<String> {
        s.lines()
            .find_map(|line| line.trim().strip_prefix(CONTAINER_ID_PREFIX))
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
    }

    /// Basic integration test: start a testnet with docker postgres + http relay,
    /// signup a user, store and retrieve data.
    #[tokio::test]
    async fn test_docker_postgres_with_testnet() {
        let testnet = EphemeralTestnet::builder()
            .with_docker_postgres()
            .with_http_relay()
            .build()
            .await
            .expect("Failed to start testnet with docker postgres");

        // Verify the homeserver is running
        assert!(!testnet.homeserver_app().public_key().to_string().is_empty());

        // Verify HTTP relay is running
        let _ = testnet.http_relay();

        // Test user operations
        let pubky = testnet.sdk().expect("Failed to create SDK");
        let keypair = Keypair::random();
        let signer = pubky.signer(keypair);

        let session = signer
            .signup_cookie(&testnet.homeserver_app().public_key(), None)
            .await
            .expect("Failed to signup user");

        // Store and retrieve data
        let path = "/pub/test.txt";
        let data = b"Hello from docker postgres test!";
        session
            .storage()
            .put(path, data.as_slice())
            .await
            .expect("Failed to store data");

        let response = session
            .storage()
            .get(path)
            .await
            .expect("Failed to get data");
        let bytes = response.bytes().await.expect("Failed to read bytes");
        assert_eq!(bytes.as_ref(), data);
    }

    /// Verify that dropping a DockerPostgres removes the Docker container.
    #[tokio::test]
    async fn test_container_cleaned_up_on_drop() {
        let pg = DockerPostgres::start()
            .await
            .expect("Failed to start docker postgres");
        let container_id = pg.container_id().to_string();

        // Verify the container is running.
        let output = std::process::Command::new("docker")
            .args(["inspect", "--format", "{{.State.Running}}", &container_id])
            .output()
            .expect("docker inspect failed");
        let running = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(running, "true", "Container should be running before drop");

        // Drop it — testcontainers should stop and remove the container.
        drop(pg);

        // Poll until Docker confirms the container is gone.
        wait_for_container_removal(&container_id, 15).await;
    }

    /// Verify that the shared instance's container is cleaned up on normal process exit.
    ///
    /// This re-executes the test binary as a subprocess with a sentinel env var.
    /// The subprocess starts a shared `DockerPostgres`, prints its container ID,
    /// and exits normally. The parent then verifies the container was removed by
    /// the `atexit` hook.
    #[tokio::test]
    async fn test_shared_container_cleaned_up_on_normal_exit() {
        const SENTINEL: &str = "__DOCKER_PG_PRINT_CONTAINER_ID";

        // When invoked as the subprocess, start shared postgres, print ID, and exit.
        if std::env::var(SENTINEL).is_ok() {
            let pg = DockerPostgres::shared().await;
            println!("{}{}", CONTAINER_ID_PREFIX, pg.container_id());
            return;
        }

        // Spawn ourselves as a subprocess with the sentinel set.
        let exe = std::env::current_exe().expect("failed to get current exe");
        let output = std::process::Command::new(exe)
            .env(SENTINEL, "1")
            .arg("docker_postgres::tests::test_shared_container_cleaned_up_on_normal_exit")
            .arg("--exact")
            .arg("--nocapture")
            .output()
            .expect("Failed to run child process");

        assert!(
            output.status.success(),
            "Child process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let container_id = extract_container_id(&stdout)
            .unwrap_or_else(|| panic!("Child did not print a container ID. stdout: {stdout}"));

        // Poll until Docker confirms the container is gone.
        wait_for_container_removal(&container_id, 15).await;
    }

    /// Verify that `shared()` returns the same instance (same container) on repeated calls.
    #[tokio::test]
    async fn test_shared_returns_same_instance() {
        let pg1 = DockerPostgres::shared().await;
        let pg2 = DockerPostgres::shared().await;
        assert_eq!(
            pg1.container_id(),
            pg2.container_id(),
            "shared() should return the same container on repeated calls"
        );
    }

    /// Verify that two testnets sharing a `DockerPostgres` get isolated databases.
    ///
    /// Signs up a user on testnet A, then verifies that same keypair can sign up
    /// on testnet B (proving it has a separate, empty database).
    #[tokio::test]
    async fn test_shared_docker_postgres_provides_db_isolation() {
        let pg = DockerPostgres::start()
            .await
            .expect("Failed to start docker postgres");

        let keypair = Keypair::random();

        // Build two independent testnets sharing the same Postgres container.
        let testnet_a = EphemeralTestnet::builder()
            .postgres(pg.connection_string().unwrap())
            .build()
            .await
            .expect("Failed to start testnet A");

        let testnet_b = EphemeralTestnet::builder()
            .postgres(pg.connection_string().unwrap())
            .keypair(Keypair::random()) // different homeserver identity
            .build()
            .await
            .expect("Failed to start testnet B");

        // Sign up the user on testnet A.
        let sdk_a = testnet_a.sdk().expect("Failed to create SDK A");
        let signer_a = sdk_a.signer(keypair.clone());
        signer_a
            .signup_cookie(&testnet_a.homeserver_app().public_key(), None)
            .await
            .expect("Signup on testnet A should succeed");

        // The same keypair should be able to sign up on testnet B,
        // proving it has its own isolated database.
        let sdk_b = testnet_b.sdk().expect("Failed to create SDK B");
        let signer_b = sdk_b.signer(keypair);
        signer_b
            .signup_cookie(&testnet_b.homeserver_app().public_key(), None)
            .await
            .expect("Signup on testnet B should succeed (proves DB isolation)");
    }

    /// Test that specifying both docker postgres and a custom connection string fails.
    #[tokio::test]
    async fn test_docker_postgres_and_custom_connection_string_fails() {
        use pubky_homeserver::ConnectionString;

        let connection = ConnectionString::new("postgres://localhost:5432/test").unwrap();

        let result = EphemeralTestnet::builder()
            .postgres(connection)
            .with_docker_postgres()
            .build()
            .await;

        let err = result
            .err()
            .expect("Should fail when both postgres options are set")
            .to_string();
        assert!(
            err.contains("Cannot use both docker postgres and a custom connection string"),
            "Expected error about conflicting postgres options, got: {err}"
        );
    }
}
