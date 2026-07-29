use super::*;

// This test verifies that when a signin happens immediately after signup,
// the record is not republished on signin (its timestamp remains unchanged)
// but when a signin happens after the record is "old" (in test, after 1 second),
// the record is republished (its timestamp increases).
#[tokio::test]
#[pubky_testnet::test]
async fn republish_if_stale_triggers_timestamp_bump() {
    use std::time::Duration;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let client = testnet.client().unwrap();

    // Sign up a brand-new user (initial publish happens on signup)
    let signer = pubky.signer(Keypair::random());
    let pubky = signer.public_key().clone();
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Capture initial record timestamp
    let ts1 = client
        .pkarr()
        .resolve(&pubky, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    // Make conditional publish consider the record stale after just 1ms,
    // then wait long enough to cross a whole second (pkarr timestamps are second-resolution).
    let pkdns = signer.pkdns().set_stale_after(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Conditional republish should now occur
    pkdns.publish_homeserver_if_stale(None).await.unwrap();

    let ts2 = client
        .pkarr()
        .resolve(&pubky, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    assert_ne!(ts1, ts2, "record should be republished when stale");
}

// This test verifies that when a signin happens immediately after signup,
// the record is not republished on signin (its timestamp remains unchanged)
// but when a signin happens after the record is “old” (in test, after 1 second),
// the record is republished (its timestamp increases).
#[tokio::test]
#[pubky_testnet::test]
async fn conditional_publish_skips_when_fresh() {
    use std::time::Duration;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let client = testnet.client().unwrap();

    let signer = pubky.signer(Keypair::random());
    let pubky = signer.public_key().clone();
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let ts1 = client
        .pkarr()
        .resolve(&pubky, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    // Set a very large staleness window so the record is definitively "fresh"
    // Default is 3600 seconds, we set it again just for sanity.
    let pkdns = signer.pkdns().set_stale_after(Duration::from_secs(3600));
    pkdns.publish_homeserver_if_stale(None).await.unwrap();

    let ts2 = client
        .pkarr()
        .resolve(&pubky, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    assert_eq!(ts1, ts2, "fresh record must not be republished");
}

#[tokio::test]
#[pubky_testnet::test]
async fn test_republish_homeserver() {
    use std::time::Duration;

    // Setup testnet + a homeserver.
    let mut testnet = Testnet::new().await.unwrap();
    let max_record_age = Duration::from_secs(5);
    let pubky = testnet.sdk().unwrap();
    let server = testnet.create_homeserver().await.unwrap();

    // Create user and publish initial record via signup.
    let signer = pubky.signer(Keypair::random());
    let public_key = signer.public_key().clone();
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Initial timestamp.
    let ts1 = pubky
        .client()
        .pkarr()
        .resolve(&public_key, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    // Conditional publish with a "fresh" record should NO-OP.
    let pkdns = signer.pkdns().set_stale_after(max_record_age);
    pkdns.publish_homeserver_if_stale(None).await.unwrap();

    let ts2 = pubky
        .client()
        .pkarr()
        .resolve(&public_key, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();
    assert_eq!(ts1, ts2, "fresh record must not be republished");

    // Wait until the record is stale (add 1s to cross second-resolution).
    tokio::time::sleep(max_record_age + Duration::from_secs(1)).await;

    // Now the conditional publish should republish and bump the timestamp.
    pkdns.publish_homeserver_if_stale(None).await.unwrap();

    let ts3 = pubky
        .client()
        .pkarr()
        .resolve(&public_key, pkarr::ResolvePolicy::NetworkOnly)
        .await
        .unwrap()
        .timestamp()
        .as_u64();

    assert!(ts3 > ts2, "record should be republished when stale");
}
