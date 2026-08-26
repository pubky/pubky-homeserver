use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use pubky_testnet::pubky::Keypair;
use pubky_testnet::{
    pubky_homeserver::{ConfigToml, MockDataDir},
    Testnet,
};

fn cli_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        escargot::CargoBuild::new()
            .bin("homeservercli")
            .manifest_path(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../homeservercli/Cargo.toml"
            ))
            .run()
            .expect("failed to build homeservercli")
            .path()
            .to_path_buf()
    })
    .as_path()
}

fn write_config(dir: &Path, admin_endpoint: &str, admin_password: &str) {
    std::fs::write(
        dir.join("config.toml"),
        format!(
            "[admin]\nadmin_password = \"{admin_password}\"\nlisten_socket = \"{admin_endpoint}\"\n"
        ),
    )
    .unwrap();
}

async fn run_cli(data_dir: &Path, args: &[&str]) -> Output {
    let data_dir = data_dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::new(cli_bin())
            .arg("--data-dir")
            .arg(&data_dir)
            .args(&args)
            .output()
            .expect("failed to run homeservercli")
    })
    .await
    .unwrap()
}

/// Run `users quota-get` and return the parsed `effective` quota object.
async fn get_effective(data_dir: &Path, pk: &str) -> serde_json::Value {
    let out = run_cli(data_dir, &["users", "quota-get", pk]).await;
    assert!(
        out.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "quota-get did not emit valid json ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    value["effective"].clone()
}

/// Start a homeserver, sign up a fresh user, and return the running testnet plus
/// the admin endpoint, admin password, and the new user's public key.
///
/// The testnet owns the homeserver, so the caller must keep it alive for the
/// duration of the test.
async fn spawn_homeserver_with_user() -> (Testnet, String, String, String) {
    spawn_homeserver_with_user_config(ConfigToml::default_test_config()).await
}

/// Same as [`spawn_homeserver_with_user`], but with a caller-provided config so
/// tests can set system-wide default quotas.
async fn spawn_homeserver_with_user_config(
    config: ConfigToml,
) -> (Testnet, String, String, String) {
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let mock_dir = MockDataDir::new(config, Some(Keypair::random())).unwrap();

    let (endpoint, server_pk) = {
        let server = testnet
            .create_homeserver_app_with_mock(mock_dir)
            .await
            .unwrap();
        let admin_socket = server
            .admin_server()
            .expect("admin server should be enabled")
            .listen_socket();
        (format!("http://{admin_socket}/"), server.public_key())
    };

    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    signer.signup_cookie(&server_pk, None).await.unwrap();
    let pk = signer.public_key().z32();

    (testnet, endpoint, admin_password, pk)
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_quota_set_then_get_roundtrip() {
    let (_testnet, endpoint, admin_password, pk) = spawn_homeserver_with_user().await;

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "users",
            "quota-set",
            "--storage-quota-mb",
            "500",
            "--rate-read",
            "100mb/s",
            "--rate-read-burst",
            "50",
            "--allowed-write-paths",
            "/pub/tokens/",
            "--allowed-write-paths",
            "/pub/paykit/",
            &pk,
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let effective = get_effective(data_dir.path(), &pk).await;
    assert_eq!(effective["storage_quota_mb"], 500, "{effective}");
    assert_eq!(effective["rate_read"], "100mb/s", "{effective}");
    assert_eq!(effective["rate_read_burst"], 50, "{effective}");
    assert_eq!(
        effective["allowed_write_paths"],
        serde_json::json!(["/pub/tokens/", "/pub/paykit/"]),
        "{effective}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_allowed_write_paths_repeat_keeps_positional_pubkey() {
    let (_testnet, endpoint, admin_password, pk) = spawn_homeserver_with_user().await;

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "users",
            "quota-set",
            "--allowed-write-paths",
            "/pub/tokens/",
            "--allowed-write-paths",
            "/pub/paykit/",
            &pk,
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "set failed (pubkey likely swallowed): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let effective = get_effective(data_dir.path(), &pk).await;
    assert_eq!(
        effective["allowed_write_paths"],
        serde_json::json!(["/pub/tokens/", "/pub/paykit/"]),
        "{effective}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_unlimited_roundtrips() {
    let (_testnet, endpoint, admin_password, pk) = spawn_homeserver_with_user().await;

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "users",
            "quota-set",
            "--storage-quota-mb",
            "unlimited",
            "--rate-read",
            "unlimited",
            &pk,
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let effective = get_effective(data_dir.path(), &pk).await;
    assert_eq!(effective["storage_quota_mb"], "unlimited", "{effective}");
    assert_eq!(effective["rate_read"], "unlimited", "{effective}");
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_reset_to_default_restores_system_default() {
    let mut config = ConfigToml::default_test_config();
    config.storage.default_quota_mb = Some(100);
    config.default_quotas.rate_read = Some("10mb/s".parse().unwrap());
    let (_testnet, endpoint, admin_password, pk) = spawn_homeserver_with_user_config(config).await;

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    // Override the system defaults with custom values.
    let out = run_cli(
        data_dir.path(),
        &[
            "users",
            "quota-set",
            "--storage-quota-mb",
            "500",
            "--rate-read",
            "5mb/s",
            &pk,
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let effective = get_effective(data_dir.path(), &pk).await;
    assert_eq!(effective["storage_quota_mb"], 500, "{effective}");
    assert_eq!(effective["rate_read"], "5mb/s", "{effective}");

    // Reset the overrides back to the inherited system defaults.
    let out = run_cli(
        data_dir.path(),
        &[
            "users",
            "quota-set",
            "--storage-quota-mb",
            "default",
            "--rate-read",
            "default",
            &pk,
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "reset failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let effective = get_effective(data_dir.path(), &pk).await;
    assert_eq!(effective["storage_quota_mb"], 100, "{effective}");
    assert_eq!(effective["rate_read"], "10mb/s", "{effective}");
}

#[tokio::test]
async fn cli_rejects_invalid_rate_without_calling_server() {
    let pk = Keypair::random().public_key().z32();
    let data_dir = tempfile::tempdir().unwrap();

    for bad_rate in ["0mb/s", "rubbish"] {
        let out = run_cli(
            data_dir.path(),
            &["users", "quota-set", "--rate-read", bad_rate, &pk],
        )
        .await;
        assert!(
            !out.status.success(),
            "expected failure for rate '{bad_rate}'"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("invalid rate"),
            "stderr for '{bad_rate}': {stderr}"
        );
    }
}
