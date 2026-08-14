use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn list_deep() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Owner user
    let owner = pubky.signer(Keypair::random());
    let owner_session = owner
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let public_key = owner_session.public_key();
    // Write files to the server
    let mut paths = vec![
        format!("/pub/a.wrong/a.txt"),
        format!("/pub/example.com/a.txt"),
        format!("/pub/example.com/b.txt"),
        format!("/pub/example.com/cc-nested/z.txt"),
        format!("/pub/example.wrong/a.txt"),
        format!("/pub/example.com/c.txt"),
        format!("/pub/example.com/d.txt"),
        format!("/pub/z.wrong/a.txt"),
    ];
    paths.shuffle(&mut rng()); // Shuffle randomly to test the order of the list
    for url in paths {
        owner_session.storage().put(url, vec![0]).await.unwrap();
    }

    // List all files with no cursor, no limit
    let url = "/pub/example.com/".to_string();
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/example.com/a.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/b.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/c.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/cc-nested/z.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/d.txt")
                    .parse()
                    .unwrap(),
            ],
            "normal list with no limit or cursor"
        );
    }

    // List files with limit of 2
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .limit(2)
            .send()
            .await
            .unwrap();
        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/example.com/a.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/b.txt")
                    .parse()
                    .unwrap(),
            ],
            "normal list with limit but no cursor"
        );
    }

    // List files with limit of 2 and a file cursor
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .limit(2)
            .cursor(format!("{}/pub/example.com/a.txt", public_key.z32()).as_str())
            .send()
            .await
            .unwrap();

        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/example.com/b.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/c.txt")
                    .parse()
                    .unwrap(),
            ],
            "normal list with limit and a file cursor"
        );
    }

    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .limit(2)
            .cursor(&format!("{}/pub/example.com/a.txt", public_key.z32()))
            .send()
            .await
            .unwrap();

        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/example.com/b.txt")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.com/c.txt")
                    .parse()
                    .unwrap(),
            ],
            "normal list with limit and a full url cursor"
        );
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn list_shallow() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Owner user
    let owner = pubky.signer(Keypair::random());
    let owner_session = owner
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let public_key = owner_session.public_key();

    // Write files to the server
    let mut urls = vec![
        format!("/pub/a.com/a.txt"),
        format!("/pub/example.com/a.txt"),
        format!("/pub/example.com/b.txt"),
        format!("/pub/example.com/c.txt"),
        format!("/pub/example.com/d.txt"),
        format!("/pub/example.con/d.txt"),
        format!("/pub/example.con-file"),
        format!("/pub/file"),
        format!("/pub/file2"),
        format!("/pub/z.com/a.txt"),
    ];
    urls.shuffle(&mut rng()); // Shuffle randomly to test the order of the list
    for url in urls {
        owner_session.storage().put(url, vec![0]).await.unwrap();
    }

    // List all files with no cursor, no limit
    let url = "/pub/".to_string();
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .shallow(true)
            .send()
            .await
            .unwrap();

        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/a.com/").parse().unwrap(),
                format!("{public_key}/pub/example.com/").parse().unwrap(),
                format!("{public_key}/pub/example.con-file")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.con/").parse().unwrap(),
                format!("{public_key}/pub/file").parse().unwrap(),
                format!("{public_key}/pub/file2").parse().unwrap(),
                format!("{public_key}/pub/z.com/").parse().unwrap(),
            ],
            "normal list shallow"
        );
    }

    // List files with limit of 2
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .shallow(true)
            .limit(2)
            .send()
            .await
            .unwrap();

        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/a.com/").parse().unwrap(),
                format!("{public_key}/pub/example.com/").parse().unwrap(),
            ],
            "normal list shallow with limit but no cursor"
        );
    }

    // List files with limit of 2 and a file cursor
    let list1 = owner_session
        .storage()
        .list(&url)
        .unwrap()
        .shallow(true)
        .limit(2)
        .cursor(format!("{}/pub/example.com/", public_key.z32()).as_str())
        .send()
        .await
        .unwrap();

    assert_eq!(
        list1,
        vec![
            format!("{public_key}/pub/example.con-file")
                .parse()
                .unwrap(),
            format!("{public_key}/pub/example.con/").parse().unwrap(),
        ],
        "normal list shallow with limit and a file cursor"
    );
    // Do the same again but without the pubky:// prefix
    let list2 = owner_session
        .storage()
        .list(&url)
        .unwrap()
        .shallow(true)
        .limit(2)
        .cursor(format!("{}/pub/example.com/a.txt", public_key.z32()).as_str())
        .send()
        .await
        .unwrap();

    assert_eq!(
        list2, list1,
        "normal list shallow with limit and a file cursor without the pubky:// prefix"
    );

    // List files with limit of 3 and a directory cursor
    {
        let list = owner_session
            .storage()
            .list(&url)
            .unwrap()
            .shallow(true)
            .limit(3)
            .cursor(format!("{}/pub/example.com/", public_key.z32()).as_str())
            .send()
            .await
            .unwrap();

        assert_eq!(
            list,
            vec![
                format!("{public_key}/pub/example.con-file")
                    .parse()
                    .unwrap(),
                format!("{public_key}/pub/example.con/").parse().unwrap(),
                format!("{public_key}/pub/file").parse().unwrap(),
            ],
            "normal list shallow with limit and a directory cursor"
        );
    }
}
