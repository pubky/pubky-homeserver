//! Synthetic pubky.app social content for a demo drive.
//!
//! Written to `/pub/pubky.app/`, the path the pubky.app clients read, so a demo
//! user's drive holds a plausible social profile as well as ordinary files. The
//! shapes follow [pubky-app-specs](https://github.com/pubky/pubky-app-specs)
//! v0.7.0; the content is invented, so no real person's posts are shipped.
//!
//! Identifiers cannot be baked in as constants, because both kinds depend on
//! values only known once the demo user exists:
//!
//! - **Timestamp IDs** (posts, files) are Crockford base32 of an 8-byte
//!   big-endian microsecond timestamp, and the spec rejects any that predate
//!   October 2024 or sit more than two hours in the future. Deriving them from
//!   the current clock keeps them valid however long this code lives.
//! - **Hash IDs** (tags, bookmarks, feeds, blobs) are the first half of a
//!   Blake3 digest, and what is hashed embeds the drive owner's public key.
//!
//! So the whole tree is generated per user rather than stored as fixtures.
use base32::{encode, Alphabet};
use pubky_common::crypto::{hash, PublicKey};
use serde_json::{json, Value};

/// A file to write into the drive: storage path and body.
pub(super) struct SeedFile {
    pub path: String,
    pub body: Vec<u8>,
}

/// Images reused from the drive's own `pub/photos/` folder, so the social
/// content and the file-manager content are the same bytes.
const IMAGES: [(&str, &[u8]); 2] = [
    (
        "harbour.png",
        include_bytes!("../../../../assets/demo/harbour.png"),
    ),
    (
        "ridge.png",
        include_bytes!("../../../../assets/demo/ridge.png"),
    ),
];

/// Two other pubkys to follow and one to mute. Real-looking keys that belong to
/// nobody, so a demo drive never points at a real account.
const OTHER_PUBKYS: [&str; 3] = [
    "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo",
    "5f4e1b8t9wnqbwoyzsjnkjycxbhq1nqp7dpc4unxsy1w9gsy1hzy",
    "pfytg6fmz6trfqfwqe7hgmpqmxstnrfxdi6mzcx7qfsfrpx8ffno",
];

/// Build the whole `/pub/pubky.app/` tree for `owner`.
pub(super) fn seed_files(owner: &PublicKey) -> Vec<SeedFile> {
    let owner = owner.z32();
    // Every id is a timestamp, so each item gets its own slot in the past week.
    // Slots must not repeat: two items sharing a slot would share an id, and a
    // post and a file colliding is confusing even though they live in separate
    // directories.
    let now = now_micros();
    let slot = |n: i64| now - n * 6 * 60 * 60 * 1_000_000;

    let mut files = Vec::new();
    let mut push = |path: String, body: Vec<u8>| files.push(SeedFile { path, body });

    push(
        "/pub/pubky.app/profile.json".to_string(),
        json_body(&profile()),
    );

    // Files are blobs plus metadata, and a post attaches the metadata rather
    // than the bytes. Build the chain blob -> file -> post.
    let mut attachments = Vec::new();
    for (index, (name, bytes)) in IMAGES.iter().enumerate() {
        let blob_id = hash_id_bytes(bytes);
        let created_at = slot(26 - index as i64);
        let file_id = timestamp_id(created_at);

        push(format!("/pub/pubky.app/blobs/{blob_id}"), bytes.to_vec());
        push(
            format!("/pub/pubky.app/files/{file_id}"),
            json_body(&json!({
                "name": name,
                "created_at": created_at,
                "src": format!("pubky://{owner}/pub/pubky.app/blobs/{blob_id}"),
                "content_type": "image/png",
                "size": bytes.len(),
            })),
        );
        attachments.push(format!("pubky://{owner}/pub/pubky.app/files/{file_id}"));
    }

    // Posts, oldest first. The reply and the repost point at earlier ones, so
    // a client has a thread to render rather than a flat list.
    let root_id = timestamp_id(slot(20));
    let image_id = timestamp_id(slot(16));
    let link_id = timestamp_id(slot(12));
    let long_id = timestamp_id(slot(8));
    let reply_id = timestamp_id(slot(4));
    let repost_id = timestamp_id(slot(1));

    let root_uri = format!("pubky://{owner}/pub/pubky.app/posts/{root_id}");
    let image_uri = format!("pubky://{owner}/pub/pubky.app/posts/{image_id}");

    for (id, post) in [
        (
            &root_id,
            post(
                "Moved my drive onto a homeserver I actually control. Same files, \
                  mounted in Finder, and the public half is on the web.",
                "short",
                None,
                None,
                None,
            ),
        ),
        (
            &image_id,
            post(
                "Low tide, early light.",
                "image",
                None,
                None,
                Some(attachments.clone()),
            ),
        ),
        (
            &link_id,
            post(
                "WebDAV turns out to be the quiet win here: your drive is just a \
                  folder. https://github.com/pubky/pubky-homeserver",
                "link",
                None,
                None,
                None,
            ),
        ),
        (
            &long_id,
            post(
                "Credible exit only means something if the data moves with you.\n\n\
                  A homeserver you can leave is worth more than one you cannot, which \
                  is why the storage layer is boring on purpose: files and folders, \
                  reachable over HTTP and WebDAV, addressed by a key you hold.\n\n\
                  Nothing here is a proprietary sync protocol. Point another client \
                  at the same drive and it sees the same bytes.",
                "long",
                None,
                None,
                None,
            ),
        ),
        (
            &reply_id,
            post(
                "Replying to my own post, mostly to prove threads work.",
                "short",
                Some(root_uri.clone()),
                None,
                None,
            ),
        ),
        (
            &repost_id,
            post(
                "Still true a week later.",
                "short",
                None,
                Some(json!({ "kind": "image", "uri": image_uri.clone() })),
                None,
            ),
        ),
    ] {
        push(format!("/pub/pubky.app/posts/{id}"), json_body(&post));
    }

    // Tags and bookmarks are hash-addressed by what they point at, so their
    // ids fall out of the URIs built above.
    for (uri, label) in [
        (&root_uri, "pubky"),
        (&root_uri, "selfhosting"),
        (&image_uri, "photography"),
    ] {
        let created_at = slot(6);
        push(
            format!("/pub/pubky.app/tags/{}", hash_id(&format!("{uri}:{label}"))),
            json_body(&json!({ "uri": uri, "label": label, "created_at": created_at })),
        );
    }

    push(
        format!("/pub/pubky.app/bookmarks/{}", hash_id(&image_uri)),
        json_body(&json!({ "uri": image_uri, "created_at": slot(3) })),
    );

    for pubky in &OTHER_PUBKYS[..2] {
        push(
            format!("/pub/pubky.app/follows/{pubky}"),
            json_body(&json!({ "created_at": slot(27) })),
        );
    }
    push(
        format!("/pub/pubky.app/mutes/{}", OTHER_PUBKYS[2]),
        json_body(&json!({ "created_at": slot(24) })),
    );

    // A feed's id hashes the filter object only, so renaming it later does not
    // orphan the file.
    let feed_config = json!({
        "tags": ["pubky", "selfhosting"],
        "reach": "following",
        "layout": "columns",
        "sort": "recent",
    });
    push(
        format!(
            "/pub/pubky.app/feeds/{}",
            hash_id(&serde_json::to_string(&feed_config).unwrap_or_default())
        ),
        json_body(&json!({
            "feed": feed_config,
            "name": "Self-hosting",
            "icon": "server",
            "created_at": slot(27),
        })),
    );

    push(
        "/pub/pubky.app/last_read".to_string(),
        // Milliseconds here, unlike `created_at` elsewhere.
        json_body(&json!({ "timestamp": now / 1_000 })),
    );

    files
}

fn profile() -> Value {
    json!({
        "name": "Demo Drive",
        "bio": "A throwaway account on a Pubky test homeserver. \
                Everything here is generated, including the photos.",
        "status": "Mounted over WebDAV",
        "links": [
            { "title": "Homeserver", "url": "https://github.com/pubky/pubky-homeserver" },
            { "title": "Pubky", "url": "https://pubky.org" },
        ],
    })
}

fn post(
    content: &str,
    kind: &str,
    parent: Option<String>,
    embed: Option<Value>,
    attachments: Option<Vec<String>>,
) -> Value {
    json!({
        "content": squash(content),
        "kind": kind,
        "parent": parent,
        "embed": embed,
        "attachments": attachments,
    })
}

/// Collapse the runs of whitespace that Rust's string continuations leave in
/// the literals above, without touching deliberate blank lines.
fn squash(text: &str) -> String {
    text.split('\n')
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join("\n")
        .replace("  ", " ")
}

fn json_body(value: &Value) -> Vec<u8> {
    let mut body = serde_json::to_vec_pretty(value).unwrap_or_default();
    body.push(b'\n');
    body
}

fn now_micros() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

/// Crockford base32 of the 8-byte big-endian microsecond timestamp: 13 chars.
fn timestamp_id(micros: i64) -> String {
    encode(Alphabet::Crockford, &micros.to_be_bytes())
}

/// Crockford base32 of the first half of the Blake3 digest of `data`: 26 chars.
fn hash_id(data: &str) -> String {
    hash_id_bytes(data.as_bytes())
}

fn hash_id_bytes(data: &[u8]) -> String {
    let digest = hash(data);
    let bytes = digest.as_bytes();
    encode(Alphabet::Crockford, &bytes[..bytes.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use base32::decode;
    use pubky_common::crypto::Keypair;
    use serde_json::Value;
    use std::collections::HashMap;

    /// The spec rejects timestamp ids from before this date.
    const OCT_2024_MICROS: i64 = 1_727_740_800_000_000;

    fn seeded() -> (String, HashMap<String, Value>, HashMap<String, Vec<u8>>) {
        let owner = Keypair::random().public_key();
        let mut json = HashMap::new();
        let mut raw = HashMap::new();

        for file in seed_files(&owner) {
            match serde_json::from_slice::<Value>(&file.body) {
                Ok(value) => {
                    json.insert(file.path.clone(), value);
                }
                Err(_) => {
                    raw.insert(file.path.clone(), file.body.clone());
                }
            }
        }
        (owner.z32(), json, raw)
    }

    fn ids_under<'a>(paths: impl Iterator<Item = &'a String>, prefix: &str) -> Vec<String> {
        paths
            .filter_map(|p| p.strip_prefix(prefix))
            .map(|id| id.to_string())
            .collect()
    }

    #[test]
    fn every_file_lives_under_the_pubky_app_directory_or_is_a_plain_file() {
        let (_, json, raw) = seeded();
        for path in json.keys().chain(raw.keys()) {
            assert!(
                path.starts_with("/pub/pubky.app/"),
                "{path} is not pubky.app content"
            );
            StoragePathCheck::assert_valid(path);
        }
    }

    /// The homeserver must be able to parse every path we hand it.
    struct StoragePathCheck;
    impl StoragePathCheck {
        fn assert_valid(path: &str) {
            crate::shared::webdav::StoragePath::new(path)
                .unwrap_or_else(|e| panic!("{path} is not a valid storage path: {e}"));
        }
    }

    #[test]
    fn timestamp_ids_decode_to_a_plausible_time() {
        let (_, json, _) = seeded();
        let now = now_micros();
        let ids: Vec<String> = ids_under(json.keys(), "/pub/pubky.app/posts/")
            .into_iter()
            .chain(ids_under(json.keys(), "/pub/pubky.app/files/"))
            .collect();
        assert!(
            ids.len() >= 8,
            "expected posts and files, got {}",
            ids.len()
        );

        for id in ids {
            assert_eq!(id.len(), 13, "{id} is not a 13-char timestamp id");
            let bytes = decode(Alphabet::Crockford, &id)
                .unwrap_or_else(|| panic!("{id} is not Crockford base32"));
            assert_eq!(bytes.len(), 8, "{id} did not decode to 8 bytes");

            let micros = i64::from_be_bytes(bytes.try_into().unwrap());
            assert!(micros > OCT_2024_MICROS, "{id} predates the spec's floor");
            assert!(
                micros <= now + 2 * 60 * 60 * 1_000_000,
                "{id} is too far in the future"
            );
        }
    }

    #[test]
    fn tag_ids_are_the_blake3_of_uri_and_label() {
        let (_, json, _) = seeded();
        let tags: Vec<_> = json
            .iter()
            .filter(|(path, _)| path.starts_with("/pub/pubky.app/tags/"))
            .collect();
        assert_eq!(tags.len(), 3);

        for (path, value) in tags {
            let id = path.strip_prefix("/pub/pubky.app/tags/").unwrap();
            let uri = value["uri"].as_str().expect("tag needs a uri");
            let label = value["label"].as_str().expect("tag needs a label");

            assert_eq!(
                id,
                hash_id(&format!("{uri}:{label}")),
                "wrong id for {path}"
            );
            assert_eq!(id.len(), 26);
            assert_eq!(label, &label.to_lowercase(), "labels are lowercased");
            assert!(label.len() <= 20, "label over the 20-char cap");
        }
    }

    #[test]
    fn bookmark_and_blob_ids_hash_what_they_address() {
        let (_, json, raw) = seeded();

        let (path, value) = json
            .iter()
            .find(|(p, _)| p.starts_with("/pub/pubky.app/bookmarks/"))
            .expect("a bookmark");
        let id = path.strip_prefix("/pub/pubky.app/bookmarks/").unwrap();
        assert_eq!(id, hash_id(value["uri"].as_str().unwrap()));

        // Blobs are raw bytes, hashed whole, so they land in `raw` not `json`.
        assert!(!raw.is_empty(), "expected image blobs");
        for (path, bytes) in &raw {
            let id = path
                .strip_prefix("/pub/pubky.app/blobs/")
                .unwrap_or_else(|| panic!("{path} is not a blob"));
            assert_eq!(id, hash_id_bytes(bytes), "wrong blob id for {path}");
            assert!(bytes.starts_with(b"\x89PNG"), "blob should be a PNG");
        }
    }

    #[test]
    fn files_point_at_blobs_that_exist_and_report_their_real_size() {
        let (owner, json, raw) = seeded();
        let files: Vec<_> = json
            .iter()
            .filter(|(p, _)| p.starts_with("/pub/pubky.app/files/"))
            .collect();
        assert_eq!(files.len(), raw.len(), "one file record per blob");

        for (path, value) in files {
            let src = value["src"].as_str().expect("file needs src");
            let blob_path = src
                .strip_prefix(&format!("pubky://{owner}"))
                .unwrap_or_else(|| panic!("{path} src does not address the owner: {src}"));
            let bytes = raw
                .get(blob_path)
                .unwrap_or_else(|| panic!("{path} points at a missing blob: {blob_path}"));

            assert_eq!(value["size"].as_u64().unwrap() as usize, bytes.len());
            assert_eq!(value["content_type"], "image/png");
            assert!(!value["name"].as_str().unwrap().is_empty());
        }
    }

    #[test]
    fn posts_are_well_formed_and_their_references_resolve() {
        let (owner, json, _) = seeded();
        let posts: HashMap<&String, &Value> = json
            .iter()
            .filter(|(p, _)| p.starts_with("/pub/pubky.app/posts/"))
            .collect();
        assert_eq!(posts.len(), 6);

        let kinds = [
            "short",
            "long",
            "image",
            "video",
            "link",
            "file",
            "collection",
        ];
        let mut replies = 0;
        let mut embeds = 0;

        for (path, value) in &posts {
            let kind = value["kind"].as_str().expect("post needs a kind");
            assert!(kinds.contains(&kind), "{path} has unknown kind {kind}");

            let content = value["content"].as_str().expect("post needs content");
            assert!(!content.is_empty() && content != "[DELETED]");
            let cap = if kind == "long" { 50_000 } else { 2_000 };
            assert!(content.chars().count() <= cap, "{path} content too long");

            // Every reference must point into this drive and at a post we wrote.
            for uri in [value["parent"].as_str(), value["embed"]["uri"].as_str()]
                .into_iter()
                .flatten()
            {
                let local = uri
                    .strip_prefix(&format!("pubky://{owner}"))
                    .unwrap_or_else(|| panic!("{path} references another drive: {uri}"));
                assert!(
                    json.contains_key(local),
                    "{path} references missing {local}"
                );
            }
            replies += usize::from(value["parent"].is_string());
            embeds += usize::from(value["embed"]["uri"].is_string());
        }

        assert_eq!(replies, 1, "expected one reply so threads render");
        assert_eq!(embeds, 1, "expected one repost");
    }

    #[test]
    fn profile_follows_and_mutes_respect_their_limits() {
        let (owner, json, _) = seeded();

        let profile = &json["/pub/pubky.app/profile.json"];
        let name = profile["name"].as_str().unwrap();
        assert!((3..=50).contains(&name.chars().count()));
        assert_ne!(name, "[DELETED]");
        assert!(profile["bio"].as_str().unwrap().chars().count() <= 160);
        assert!(profile["status"].as_str().unwrap().chars().count() <= 50);
        assert!(profile["links"].as_array().unwrap().len() <= 5);

        // Follows and mutes are keyed by another user's pubky, never the owner's.
        let others = ids_under(json.keys(), "/pub/pubky.app/follows/")
            .into_iter()
            .chain(ids_under(json.keys(), "/pub/pubky.app/mutes/"));
        let mut count = 0;
        for id in others {
            assert_eq!(id.len(), 52, "{id} is not a z32 pubky");
            assert_ne!(id, owner, "the demo user should not follow or mute itself");
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn feed_id_hashes_only_the_filter_so_renaming_is_safe() {
        let (_, json, _) = seeded();
        let (path, value) = json
            .iter()
            .find(|(p, _)| p.starts_with("/pub/pubky.app/feeds/"))
            .expect("a feed");
        let id = path.strip_prefix("/pub/pubky.app/feeds/").unwrap();

        assert_eq!(id, hash_id(&serde_json::to_string(&value["feed"]).unwrap()));
        assert!(["following", "followers", "friends", "all", "wot", "me"]
            .contains(&value["feed"]["reach"].as_str().unwrap()));
        assert!(["columns", "wide", "visual", "list"]
            .contains(&value["feed"]["layout"].as_str().unwrap()));
        assert!(["recent", "popularity"].contains(&value["feed"]["sort"].as_str().unwrap()));
        assert!(value["feed"]["tags"].as_array().unwrap().len() <= 5);
        assert!(!value["icon"].as_str().unwrap().is_empty());
    }

    #[test]
    fn last_read_is_milliseconds_not_microseconds() {
        let (_, json, _) = seeded();
        let timestamp = json["/pub/pubky.app/last_read"]["timestamp"]
            .as_i64()
            .expect("last_read needs a timestamp");
        // Milliseconds since epoch is ~1e12 right now; microseconds would be ~1e15.
        assert!(
            (1_000_000_000_000..100_000_000_000_000).contains(&timestamp),
            "{timestamp} does not look like epoch milliseconds"
        );
    }

    #[test]
    fn no_two_items_share_a_timestamp_id() {
        let (_, json, _) = seeded();
        let ids: Vec<String> = ids_under(json.keys(), "/pub/pubky.app/posts/")
            .into_iter()
            .chain(ids_under(json.keys(), "/pub/pubky.app/files/"))
            .collect();

        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "a post and a file were minted in the same slot: {ids:?}"
        );
    }

    #[test]
    fn two_demo_users_get_distinct_ids() {
        let (_, a, _) = seeded();
        let (_, b, _) = seeded();
        // Hash ids embed the owner's key, so no tag or bookmark path may repeat.
        for prefix in ["/pub/pubky.app/tags/", "/pub/pubky.app/bookmarks/"] {
            let shared: Vec<_> = ids_under(a.keys(), prefix)
                .into_iter()
                .filter(|id| ids_under(b.keys(), prefix).contains(id))
                .collect();
            assert!(shared.is_empty(), "{prefix} ids collided: {shared:?}");
        }
    }
}
