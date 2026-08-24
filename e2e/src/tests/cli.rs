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
            "[admin]\nadmin_password = \"{admin_password}\"\nadmin_endpoint = \"{admin_endpoint}\"\n"
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

fn field(stdout: &str, label: &str) -> String {
    let needle = format!("{label}:");
    stdout
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_quota_set_then_get_roundtrip() {
    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let mock_dir = MockDataDir::new(config, Some(Keypair::random())).unwrap();
    let server = testnet
        .create_homeserver_app_with_mock(mock_dir)
        .await
        .unwrap();
    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let endpoint = format!("http://{admin_socket}/");

    let signer = pubky.signer(Keypair::random());
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pk = signer.public_key().z32();

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "quota",
            "set",
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

    let out = run_cli(data_dir.path(), &["quota", "get", &pk]).await;
    assert!(
        out.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(field(&stdout, "storage_quota_mb"), "500", "{stdout}");
    assert_eq!(field(&stdout, "rate_read"), "100mb/s", "{stdout}");
    assert_eq!(field(&stdout, "rate_read_burst"), "50", "{stdout}");
    assert_eq!(
        field(&stdout, "allowed_write_paths"),
        "/pub/tokens/, /pub/paykit/",
        "{stdout}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_allowed_write_paths_repeat_keeps_positional_pubkey() {
    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let mock_dir = MockDataDir::new(config, Some(Keypair::random())).unwrap();
    let server = testnet
        .create_homeserver_app_with_mock(mock_dir)
        .await
        .unwrap();
    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let endpoint = format!("http://{admin_socket}/");

    let signer = pubky.signer(Keypair::random());
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pk = signer.public_key().z32();

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "quota",
            "set",
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

    let out = run_cli(data_dir.path(), &["quota", "get", &pk]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        field(&stdout, "allowed_write_paths"),
        "/pub/tokens/, /pub/paykit/",
        "{stdout}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn cli_unlimited_roundtrips() {
    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let mock_dir = MockDataDir::new(config, Some(Keypair::random())).unwrap();
    let server = testnet
        .create_homeserver_app_with_mock(mock_dir)
        .await
        .unwrap();
    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let endpoint = format!("http://{admin_socket}/");

    let signer = pubky.signer(Keypair::random());
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pk = signer.public_key().z32();

    let data_dir = tempfile::tempdir().unwrap();
    write_config(data_dir.path(), &endpoint, &admin_password);

    let out = run_cli(
        data_dir.path(),
        &[
            "quota",
            "set",
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

    let out = run_cli(data_dir.path(), &["quota", "get", &pk]).await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(field(&stdout, "storage_quota_mb"), "unlimited", "{stdout}");
    assert_eq!(field(&stdout, "rate_read"), "unlimited", "{stdout}");
}

#[tokio::test]
async fn cli_rejects_invalid_rate_without_calling_server() {
    let pk = Keypair::random().public_key().z32();
    let data_dir = tempfile::tempdir().unwrap();

    for bad_rate in ["0mb/s", "rubbish"] {
        let out = run_cli(
            data_dir.path(),
            &["quota", "set", "--rate-read", bad_rate, &pk],
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
