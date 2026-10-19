use super::build_full_testnet;
use pubky_testnet::pubky::{ClientId, Keypair, Method, StatusCode};

/// A site uploaded through the SDK is served by `Host` over plain HTTP.
#[tokio::test]
#[pubky_testnet::test]
async fn serves_a_site_uploaded_through_the_sdk() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin(ClientId::new("website.test").unwrap())
        .await
        .unwrap();
    let storage = session.storage();
    storage
        .put("/pub/website/_/index.html", "<h1>home</h1>")
        .await
        .unwrap();
    storage
        .put("/pub/website/blog/index.html", "<h1>blog</h1>")
        .await
        .unwrap();

    let owner = signer.public_key().z32();
    for (host, body) in [
        (owner.clone(), "<h1>home</h1>"),
        (format!("blog.{owner}"), "<h1>blog</h1>"),
    ] {
        let response = pubky
            .client()
            .request(Method::GET, &server.icann_http_url().to_string())
            .header("Host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/html");
        assert_eq!(response.text().await.unwrap(), body);
    }
}
