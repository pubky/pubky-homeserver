use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn list_events() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Create a user/session
    let signer = pubky.signer(Keypair::random());
    let public_key = signer.public_key();
    let public_key_z32 = public_key.z32();
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Write + delete a bunch of files to populate the event feed
    let paths = vec![
        "/pub/a.com/a.txt",
        "/pub/example.com/a.txt",
        "/pub/example.com/b.txt",
        "/pub/example.com/c.txt",
        "/pub/example.com/d.txt",
        "/pub/example.xyz/d.txt",
        "/pub/example.xyz", // file (not dir)
        "/pub/file",
        "/pub/file2",
        "/pub/z.com/a.txt",
    ];
    for p in &paths {
        session.storage().put(p.to_string(), vec![0]).await.unwrap();
        session.storage().delete(p.to_string()).await.unwrap();
    }

    // Feed is exposed under the public-key host
    let feed_url = format!("https://{}/events/", server.public_key().z32());

    // Page 1
    let cursor: String = {
        let page1_url = format!("{feed_url}?limit=10");
        let resp = session
            .client()
            .request(Method::GET, &page1_url)
            .send()
            .await
            .unwrap();

        let text = resp.text().await.unwrap();
        let lines = text.split('\n').collect::<Vec<_>>();

        // last line is "cursor: <id>"
        let cursor = lines
            .last()
            .unwrap()
            .split(' ')
            .next_back()
            .unwrap()
            .to_string();

        assert_eq!(
            lines,
            vec![
                format!("PUT pubky://{public_key_z32}/pub/a.com/a.txt"),
                format!("DEL pubky://{public_key_z32}/pub/a.com/a.txt"),
                format!("PUT pubky://{public_key_z32}/pub/example.com/a.txt"),
                format!("DEL pubky://{public_key_z32}/pub/example.com/a.txt"),
                format!("PUT pubky://{public_key_z32}/pub/example.com/b.txt"),
                format!("DEL pubky://{public_key_z32}/pub/example.com/b.txt"),
                format!("PUT pubky://{public_key_z32}/pub/example.com/c.txt"),
                format!("DEL pubky://{public_key_z32}/pub/example.com/c.txt"),
                format!("PUT pubky://{public_key_z32}/pub/example.com/d.txt"),
                format!("DEL pubky://{public_key_z32}/pub/example.com/d.txt"),
                format!("cursor: {cursor}"),
            ]
        );

        cursor
    };

    // Page 2 (using cursor)
    {
        let page2_url = format!("{feed_url}?limit=10&cursor={cursor}");
        let resp = session
            .client()
            .request(Method::GET, &page2_url)
            .send()
            .await
            .unwrap();

        let text = resp.text().await.unwrap();
        let lines = text.split('\n').collect::<Vec<_>>();

        assert_eq!(
            lines,
            vec![
                format!("PUT pubky://{public_key_z32}/pub/example.xyz/d.txt"),
                format!("DEL pubky://{public_key_z32}/pub/example.xyz/d.txt"),
                format!("PUT pubky://{public_key_z32}/pub/example.xyz"),
                format!("DEL pubky://{public_key_z32}/pub/example.xyz"),
                format!("PUT pubky://{public_key_z32}/pub/file"),
                format!("DEL pubky://{public_key_z32}/pub/file"),
                format!("PUT pubky://{public_key_z32}/pub/file2"),
                format!("DEL pubky://{public_key_z32}/pub/file2"),
                format!("PUT pubky://{public_key_z32}/pub/z.com/a.txt"),
                format!("DEL pubky://{public_key_z32}/pub/z.com/a.txt"),
                lines.last().unwrap().to_string(),
            ]
        );
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn read_after_event() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // User + session
    let signer = pubky.signer(Keypair::random());
    let public_key = signer.public_key();
    let public_key_z32 = public_key.z32();
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Write one file
    let url = format!("pubky://{public_key_z32}/pub/a.com/a.txt");
    session
        .storage()
        .put("/pub/a.com/a.txt", vec![0])
        .await
        .unwrap();

    // Events page 1
    let feed_url = format!("https://{}/events/", server.public_key().z32());
    {
        let page_url = format!("{feed_url}?limit=10");
        let resp = pubky
            .client()
            .request(Method::GET, &page_url)
            .send()
            .await
            .unwrap();

        let text = resp.text().await.unwrap();
        let lines = text.split('\n').collect::<Vec<_>>();
        let cursor = lines
            .last()
            .unwrap()
            .split(' ')
            .next_back()
            .unwrap()
            .to_string();

        assert_eq!(
            lines,
            vec![format!("PUT {url}"), format!("cursor: {cursor}")]
        );
    }

    // Now the file should exist
    pubky.public_storage().exists(url.clone()).await.unwrap();
    // Provide metadata
    pubky.public_storage().stats(url.clone()).await.unwrap();
    // And be fetchable
    let resp = pubky.public_storage().get(url).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &[0]);
}

#[tokio::test]
#[pubky_testnet::test]
async fn feed_excludes_private_paths() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Interleave public and private writes.
    session.storage().put("/pub/a.txt", vec![1]).await.unwrap();
    session
        .storage()
        .put("/priv/app/secret.txt", vec![2])
        .await
        .unwrap();
    session.storage().put("/pub/b.txt", vec![3]).await.unwrap();

    // The anonymous public feed must never surface a private path.
    let feed_url = format!("https://{}/events/?limit=100", server.public_key().z32());
    let text = pubky
        .client()
        .request(Method::GET, &feed_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        !text.contains("/priv/"),
        "public feed leaked a private path:\n{text}"
    );
    assert!(
        text.contains("/pub/a.txt") && text.contains("/pub/b.txt"),
        "public events should be present:\n{text}"
    );
}
