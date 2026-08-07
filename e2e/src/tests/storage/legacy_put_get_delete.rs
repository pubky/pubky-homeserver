use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn put_get_delete() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let cookie_secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (cookie_name, cookie_value) = cookie_secret.split_once(':').unwrap();
    let cookie = format!("{cookie_name}={cookie_value}");
    let url = format!(
        "{}pub/foo.txt?pubky-host={}",
        server.icann_http_url(),
        session.public_key().z32()
    );

    let response = session
        .client()
        .request(Method::PUT, &url)
        .header("Host", "non.pubky.host")
        .header("Cookie", &cookie)
        .body(vec![0, 1, 2, 3, 4])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = session
        .client()
        .request(Method::GET, &url)
        .header("Host", "non.pubky.host")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from(vec![0, 1, 2, 3, 4])
    );

    let response = session
        .client()
        .request(Method::DELETE, &url)
        .header("Host", "non.pubky.host")
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = session
        .client()
        .request(Method::GET, &url)
        .header("Host", "non.pubky.host")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
