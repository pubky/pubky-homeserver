use super::*;
use futures::StreamExt;
use pubky_testnet::pubky::{EventType, PubkyResource};
use pubky_testnet::pubky_common::storage_path::StoragePath;
use tokio::time::{timeout, Duration};

#[tokio::test]
#[pubky_testnet::test]
async fn encoded_paths_round_trip_through_listings_and_events() {
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
    let owner = signer.public_key();
    let directory = "/pub/encoded %20 ü/";
    let names = [
        "a b.txt",
        "a%20b.txt",
        "#?.txt",
        "ü.txt",
        "%%2E%%2E/file.txt",
    ];
    let mut resources = Vec::new();
    let mut urls = Vec::new();
    let mut storage_urls = Vec::new();
    for name in names {
        let path = format!("{directory}{name}");
        let encoded_path = StoragePath::new(&path).unwrap().url_encode();
        let storage_url = format!(
            "{}storage/{}{encoded_path}",
            server.icann_http_url(),
            owner.z32()
        );
        // Write directly so the separate SDK session-path encoding bug cannot
        // change the filename used to exercise listings and event feeds.
        session
            .client()
            .request(Method::PUT, &storage_url)
            .header("Cookie", &cookie)
            .body(name.as_bytes().to_vec())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let resource = PubkyResource::new(owner.clone(), &path).unwrap();
        let url = format!("pubky://{}{encoded_path}", owner.z32());
        resources.push(resource);
        urls.push(url);
        storage_urls.push(storage_url);
    }

    let directory_resource = PubkyResource::new(owner.clone(), directory).unwrap();
    let full = pubky
        .public_storage()
        .list(&directory_resource)
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(full.len(), resources.len());
    for resource in &resources {
        assert!(full.contains(resource));
    }

    // Direct HTTP callers may still use decoded storage keys as cursors.
    // Query escaping must not cause a literal %20 in the key to become a space.
    for (name, resource) in names.iter().zip(&resources) {
        let cursor = format!("{}{directory}{name}", owner.z32());
        let mut url = directory_resource.to_transport_url().unwrap();
        url.query_pairs_mut().append_pair("cursor", &cursor);
        let listing = session
            .client()
            .request(Method::GET, &url)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap();
        let entries = listing
            .lines()
            .map(|line| PubkyResource::from_pubky_url(line).unwrap())
            .collect::<Vec<_>>();
        let position = full.iter().position(|entry| entry == resource).unwrap();
        assert_eq!(entries, full[position + 1..]);
    }

    // Both shallow directory cursors and deep file cursors must decode once.
    for shallow in [false, true] {
        for reverse in [false, true] {
            let expected = pubky
                .public_storage()
                .list(&directory_resource)
                .unwrap()
                .shallow(shallow)
                .reverse(reverse)
                .send()
                .await
                .unwrap();
            let mut paginated = Vec::new();
            let mut cursor: Option<String> = None;
            let public_storage = pubky.public_storage();
            for _ in 0..=expected.len() {
                let mut builder = public_storage
                    .list(&directory_resource)
                    .unwrap()
                    .shallow(shallow)
                    .reverse(reverse)
                    .limit(1);
                if let Some(value) = &cursor {
                    builder = builder.cursor(value);
                }
                let page = builder.send().await.unwrap();
                let Some(entry) = page.first() else {
                    break;
                };
                assert_eq!(page.len(), 1, "listing must honor limit=1");
                cursor = Some(entry.to_pubky_url());
                paginated.extend(page);
            }
            assert_eq!(paginated, expected);
        }
    }

    let mut events = pubky
        .event_stream_for_user(&owner, None)
        .subscribe()
        .await
        .unwrap();
    for (resource, name) in resources.iter().zip(names) {
        let event = timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&event.resource, resource);
        assert!(matches!(event.event_type, EventType::Put { .. }));
        let content = pubky
            .public_storage()
            .get(event.resource)
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(content, name, "event must resolve to the original file");
    }
    assert!(timeout(Duration::from_secs(5), events.next())
        .await
        .expect("non-live event stream must close")
        .is_none());

    for storage_url in &storage_urls {
        session
            .client()
            .request(Method::DELETE, storage_url)
            .header("Cookie", &cookie)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    let feed = session
        .client()
        .request(
            Method::GET,
            &format!("https://{}/events/", server.public_key().z32()),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    let expected = urls
        .iter()
        .map(|url| format!("PUT {url}"))
        .chain(urls.iter().map(|url| format!("DEL {url}")))
        .collect::<Vec<_>>();
    let lines = feed.lines().collect::<Vec<_>>();
    let (cursor, event_lines) = lines.split_last().expect("feed must contain a cursor");
    assert_eq!(event_lines, expected);
    cursor
        .strip_prefix("cursor: ")
        .expect("last feed line must be a cursor")
        .parse::<u64>()
        .expect("feed cursor must be a valid event ID");

    let mut deleted = pubky
        .event_stream_for_user(&owner, None)
        .reverse()
        .limit(names.len() as u16)
        .subscribe()
        .await
        .unwrap();
    for resource in resources.iter().rev() {
        let event = timeout(Duration::from_secs(5), deleted.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&event.resource, resource);
        assert!(matches!(event.event_type, EventType::Delete));
    }
    assert!(timeout(Duration::from_secs(5), deleted.next())
        .await
        .expect("limited delete stream must close")
        .is_none());
}
