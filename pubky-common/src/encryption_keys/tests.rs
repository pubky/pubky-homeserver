use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn path(value: &str) -> StoragePath {
    StoragePath::new(value).unwrap()
}

fn issue(scopes: &[StoragePath]) -> ScopedEncryptionKeyBundle {
    ScopedEncryptionKeyBundle::from_identity_secret(
        &std::array::from_fn(|index| index as u8),
        scopes,
    )
}

fn root() -> ScopedEncryptionKeyBundle {
    issue(&[StoragePath::root()])
}

fn decode_entry(entry: serde_json::Value) -> Result<ScopedEncryptionKeyBundle, serde_json::Error> {
    serde_json::from_value(serde_json::json!({ "version": "v1", "keys": [entry] }))
}

fn hex_bytes(hex: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

#[test]
fn v1_keys_match_shared_vectors() {
    #[derive(Deserialize)]
    struct Fixture {
        version: String,
        identity_secret_hex: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        path: StoragePath,
        key_hex: String,
    }

    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../tests/fixtures/hierarchical-keys-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture.version, DERIVATION_VERSION);
    let identity_secret = hex_bytes(&fixture.identity_secret_hex);
    let root =
        ScopedEncryptionKeyBundle::from_identity_secret(&identity_secret, &[StoragePath::root()]);
    for vector in fixture.vectors {
        let expected = hex_bytes(&vector.key_hex);
        assert_eq!(
            *root.derive_scoped_path(&vector.path).unwrap(),
            expected,
            "{}",
            vector.path
        );
        if vector.path.is_file() {
            // A delegated parent seed must reproduce the identity-derived key.
            let parent = &vector.path.as_str()[..=vector.path.as_str().rfind('/').unwrap()];
            let delegated =
                ScopedEncryptionKeyBundle::from_identity_secret(&identity_secret, &[path(parent)]);
            assert_eq!(*delegated.derive_for_path(&vector.path).unwrap(), expected);
        }
    }
}

#[test]
fn public_api_rejects_directory_seeds_even_with_covering_scopes() {
    for bundle in [root(), issue(&[path("/pub/app/")]), issue(&[])] {
        for directory in ["/", "/pub/app/", "/pub/app/sub/"] {
            let requested = path(directory);
            assert_eq!(
                bundle.derive_for_path(&requested).unwrap_err(),
                KeyDerivationError::DirectoryPath { requested },
            );
        }
    }
    // A file and directory with the same name remain distinct.
    assert!(root().derive_for_path(&path("/pub/app")).is_ok());
    assert!(issue(&[path("/pub/app/")])
        .derive_for_path(&path("/pub/app/sub/file"))
        .is_ok());
}

#[test]
fn delegated_app_derives_the_same_keys_as_the_signer() {
    let root = root();
    let issued = issue(&[path("/pub/app/")]);
    let payload = postcard::to_allocvec(&issued).unwrap();
    let app: ScopedEncryptionKeyBundle = postcard::from_bytes(&payload).unwrap();

    for target in ["/pub/app/file", "/pub/app/sub/file"] {
        let target = path(target);
        let expected = root.derive_for_path(&target).unwrap();
        let actual = app.derive_for_path(&target).unwrap();
        assert_eq!(*actual, *expected);
    }
}

#[test]
fn directory_key_rejects_ancestors_siblings_and_same_named_file() {
    let app = issue(&[path("/pub/app/")]);
    for target in [
        "/",
        "/pub/",
        "/pub/app",
        "/pub/other/file",
        "/pub/app-evil/file",
    ] {
        let target = path(target);
        assert_eq!(
            app.derive_for_path(&target).unwrap_err(),
            if target.is_directory() {
                KeyDerivationError::DirectoryPath { requested: target }
            } else {
                KeyDerivationError::OutsideScope { requested: target }
            }
        );
    }
}

#[test]
fn file_key_covers_only_its_exact_path() {
    let scope = path("/pub/app/file");
    let file = issue(std::slice::from_ref(&scope));
    assert_eq!(
        *file.derive_for_path(&scope).unwrap(),
        *root().derive_for_path(&scope).unwrap()
    );
    for target in [
        "/pub/app/",
        "/pub/app/file/",
        "/pub/app/file/child",
        "/pub/app/file-other",
    ] {
        assert!(matches!(
            file.derive_for_path(&path(target)),
            Err(KeyDerivationError::DirectoryPath { .. } | KeyDerivationError::OutsideScope { .. })
        ));
    }
}

#[test]
fn identities_roles_segments_and_literal_percent_paths_are_separated() {
    let root = root();
    let other_identity =
        ScopedEncryptionKeyBundle::from_identity_secret(&[42; 32], &[StoragePath::root()]);
    let file = path("/pub/app/file");
    assert_ne!(
        *root.derive_for_path(&file).unwrap(),
        *other_identity.derive_for_path(&file).unwrap()
    );
    for (left, right) in [
        ("/pub/app", "/pub/app/"),
        ("/pub/app/file", "/pub/app/file/"),
        ("/pub/app/file", "/pub/app/renamed"),
        ("/pub/ab/c", "/pub/a/bc"),
        ("/pub/app/a%2Fb", "/pub/app/a/b"),
        ("/pub/app/über", "/pub/app/%C3%BCber"),
    ] {
        assert_ne!(
            *root.derive_scoped_path(&path(left)).unwrap(),
            *root.derive_scoped_path(&path(right)).unwrap(),
            "{left} and {right}"
        );
    }
}

#[test]
fn normalized_aliases_derive_the_same_key() {
    let root = root();
    let alias = StoragePath::normalize("/pub//app/./sub/../file").unwrap();
    let canonical = path("/pub/app/file");
    assert_eq!(
        *root.derive_for_path(&alias).unwrap(),
        *root.derive_for_path(&canonical).unwrap()
    );
}

#[test]
fn bundle_json_round_trip_preserves_path_and_secret() {
    let scope = path("/priv/My File/über%20.json");
    let bundle = issue(std::slice::from_ref(&scope));
    let expected = root().derive_for_path(&scope).unwrap();
    let encoded = serde_json::to_value(&bundle).unwrap();
    assert_eq!(
        encoded,
        serde_json::json!({
            "version": "v1",
            "keys": [{ "scope": scope.as_str(), "secret": URL_SAFE_NO_PAD.encode(expected.as_ref()) }],
        })
    );

    let decoded: ScopedEncryptionKeyBundle = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.scopes().collect::<Vec<_>>(), vec![&scope]);
    assert_eq!(*decoded.derive_for_path(&scope).unwrap(), *expected);
}

#[test]
fn bundle_decode_rejects_noncanonical_paths_and_wrong_key_lengths() {
    for scope in ["relative", "/pub//app/", "/pub/../priv/file", "/priv/a\\b"] {
        let value =
            serde_json::json!({ "scope": scope, "secret": URL_SAFE_NO_PAD.encode([0; 32]) });
        assert!(decode_entry(value).is_err());
    }

    for length in [0, 31, 33] {
        let value = serde_json::json!({ "scope": "/pub/app/", "secret": URL_SAFE_NO_PAD.encode(vec![0; length]) });
        assert!(decode_entry(value).is_err());
    }
}

#[test]
fn bundle_decode_rejects_missing_entry_fields_unknown_fields_and_invalid_secrets() {
    let valid =
        serde_json::json!({ "scope": "/pub/app/", "secret": URL_SAFE_NO_PAD.encode([0; 32]) });
    for field in ["scope", "secret"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode_entry(missing).is_err());
    }

    let mut unknown = valid.clone();
    unknown["purpose"] = serde_json::json!("encryption");
    assert!(decode_entry(unknown).is_err());

    for invalid in [
        serde_json::json!(vec![0; 32]),
        serde_json::json!("0"),
        serde_json::json!(format!("{}=", URL_SAFE_NO_PAD.encode([0; 32]))),
        serde_json::json!("+".repeat(43)),
        serde_json::json!("/".repeat(43)),
        serde_json::json!(format!("{}B", "A".repeat(42))),
        serde_json::json!(format!("{} ", "A".repeat(42))),
    ] {
        let mut value = valid.clone();
        value["secret"] = invalid;
        assert!(decode_entry(value).is_err());
    }
}

#[test]
fn multiple_scopes_round_trip_in_json_and_postcard() {
    let scopes = [
        path("/pub/app/"),
        path("/priv/chat/"),
        path("/priv/settings"),
    ];
    let root = root();
    let bundle = issue(&scopes);
    let json = serde_json::to_value(&bundle).unwrap();
    assert_eq!(json["version"], DERIVATION_VERSION);
    assert_eq!(json["keys"].as_array().unwrap().len(), scopes.len());

    let binary = postcard::to_allocvec(&bundle).unwrap();
    let decoded_bundles = [
        serde_json::from_value::<ScopedEncryptionKeyBundle>(json).unwrap(),
        postcard::from_bytes::<ScopedEncryptionKeyBundle>(&binary).unwrap(),
    ];
    for decoded in decoded_bundles {
        assert!(matches!(decoded.version, DerivationVersion::V1));
        assert_eq!(decoded.scopes().len(), scopes.len());
        for (actual, scope) in decoded.scopes().zip(&scopes) {
            assert_eq!(actual, scope);
            assert_eq!(
                *decoded.derive_scoped_path(scope).unwrap(),
                *root.derive_scoped_path(scope).unwrap()
            );
        }

        let chat_file = path("/priv/chat/messages.json");
        assert_eq!(
            *decoded.derive_for_path(&chat_file).unwrap(),
            *root.derive_for_path(&chat_file).unwrap()
        );
        assert!(decoded
            .derive_for_path(&path("/priv/settings/child"))
            .is_err());
    }
}

#[test]
fn imported_secrets_stay_in_place_when_the_entry_vector_moves() {
    let scopes = (0..10)
        .map(|index| path(&format!("/priv/app-{index}/")))
        .collect::<Vec<_>>();
    let issued = issue(&scopes);
    let json = Zeroizing::new(serde_json::to_string(&issued).unwrap());
    let binary = Zeroizing::new(postcard::to_allocvec(&issued).unwrap());
    for mut decoded in [
        serde_json::from_str::<ScopedEncryptionKeyBundle>(&json).unwrap(),
        postcard::from_bytes::<ScopedEncryptionKeyBundle>(&binary).unwrap(),
    ] {
        let addresses = decoded
            .keys
            .iter()
            .map(|entry| entry.secret.as_ptr())
            .collect::<Vec<_>>();

        // Allocate while the original vector is alive to force relocation,
        // even if the allocator could otherwise grow it in place.
        let entries = std::mem::take(&mut decoded.keys);
        let mut relocated = Vec::with_capacity(entries.capacity() + 1);
        relocated.extend(entries);
        decoded.keys = relocated;

        for ((entry, address), scope) in decoded.keys.iter().zip(addresses).zip(&scopes) {
            assert_eq!(entry.secret.as_ptr(), address);
            assert_eq!(&entry.scope, scope);
            assert_eq!(
                *decoded.derive_scoped_path(scope).unwrap(),
                *issued.derive_scoped_path(scope).unwrap()
            );
        }
    }
}

#[test]
fn bundle_decode_rejects_unsupported_versions_and_missing_fields() {
    for version in ["v2", "", "V1"] {
        let value = serde_json::json!({ "version": version, "keys": [] });
        assert!(serde_json::from_value::<ScopedEncryptionKeyBundle>(value).is_err());
    }
    for value in [
        serde_json::json!({ "keys": [] }),
        serde_json::json!({ "version": "v1" }),
        serde_json::json!({ "version": "v1", "keys": [], "extra": true }),
        serde_json::json!({ "version": "v1", "keys": [{ "scope": "/pub//app/", "secret": URL_SAFE_NO_PAD.encode([0; 32]) }] }),
    ] {
        assert!(serde_json::from_value::<ScopedEncryptionKeyBundle>(value).is_err());
    }

    // Postcard encodes this closed version enum as a variant index.
    assert!(postcard::from_bytes::<ScopedEncryptionKeyBundle>(&[1, 0]).is_err());
}

#[test]
fn empty_bundle_round_trips() {
    let bundle = issue(&[]);
    let json = serde_json::to_string(&bundle).unwrap();
    assert_eq!(json, r#"{"version":"v1","keys":[]}"#);
    assert_eq!(
        serde_json::from_str::<ScopedEncryptionKeyBundle>(&json)
            .unwrap()
            .scopes()
            .len(),
        0
    );

    let binary = postcard::to_allocvec(&bundle).unwrap();
    assert_eq!(
        postcard::from_bytes::<ScopedEncryptionKeyBundle>(&binary)
            .unwrap()
            .scopes()
            .len(),
        0
    );
}

#[test]
fn postcard_wire_format_is_unchanged() {
    let bundle = decode_entry(serde_json::json!({
        "scope": "/pub/app/", "secret": URL_SAFE_NO_PAD.encode([171; 32]),
    }))
    .unwrap();
    // Version variant, entry count, UTF-8 path length/path, 32 secret bytes.
    let mut expected = vec![0, 1, 9];
    expected.extend_from_slice(b"/pub/app/");
    expected.extend_from_slice(&[171; 32]);
    assert_eq!(postcard::to_allocvec(&bundle).unwrap(), expected);
}

#[test]
fn bundle_debug_output_redacts_every_secret() {
    let bundle: ScopedEncryptionKeyBundle = serde_json::from_value(serde_json::json!({
        "version": "v1", "keys": [
            { "scope": "/pub/app/", "secret": URL_SAFE_NO_PAD.encode([171; 32]) },
            { "scope": "/priv/file", "secret": URL_SAFE_NO_PAD.encode([205; 32]) },
        ],
    }))
    .unwrap();
    let debug = format!("{bundle:?}");
    assert!(debug.contains("/pub/app/"));
    assert!(debug.contains("/priv/file"));
    assert_eq!(debug.matches("<redacted>").count(), 2);
    assert!(!debug.contains("171"));
    assert!(!debug.contains("205"));
}

#[test]
fn bundle_derives_paths_across_multiple_scopes() {
    let root = root();
    let bundle = issue(&[
        path("/pub/app/"),
        path("/priv/chat/"),
        path("/priv/settings"),
    ]);

    for target in [
        "/pub/app/",
        "/pub/app/file",
        "/priv/chat/sub/",
        "/priv/chat/sub/file",
        "/priv/settings",
    ] {
        let target = path(target);
        if target.is_directory() {
            assert_eq!(
                bundle.derive_for_path(&target).unwrap_err(),
                KeyDerivationError::DirectoryPath { requested: target },
            );
        } else {
            let actual = bundle.derive_for_path(&target).unwrap();
            assert_eq!(*actual, *root.derive_for_path(&target).unwrap());
        }
    }
}

#[test]
fn overlapping_directory_entries_agree_regardless_of_order() {
    let broad = path("/priv/chat/");
    let narrow = path("/priv/chat/sub/");
    let file = path("/priv/chat/sub/file");
    let expected = root().derive_for_path(&file).unwrap();

    for scopes in [
        vec![broad.clone(), narrow.clone()],
        vec![narrow.clone(), broad.clone()],
    ] {
        let bundle = issue(&scopes);
        assert_eq!(*bundle.derive_for_path(&file).unwrap(), *expected);
    }
}

#[test]
fn exact_file_and_parent_entries_agree_without_shadowing_same_named_directory() {
    let directory = path("/priv/chat/");
    let file = path("/priv/chat/file");
    for scopes in [
        vec![directory.clone(), file.clone()],
        vec![file.clone(), directory.clone()],
    ] {
        let bundle = issue(&scopes);
        assert_eq!(
            *bundle.derive_for_path(&file).unwrap(),
            *root().derive_for_path(&file).unwrap()
        );

        // The file entry must not shadow a directory with the same name.
        let child = path("/priv/chat/file/child");
        assert_eq!(
            *bundle.derive_for_path(&child).unwrap(),
            *root().derive_for_path(&child).unwrap()
        );
    }
}

#[test]
fn repeated_and_overlapping_requests_preserve_order_and_round_trip() {
    let root = root();
    let scopes = [
        path("/priv/chat/"),
        path("/priv/chat/sub/"),
        path("/priv/chat/sub/file"),
        path("/priv/chat/"),
    ];
    let bundle = issue(&scopes);
    let json = serde_json::to_value(&bundle).unwrap();
    let binary = postcard::to_allocvec(&bundle).unwrap();
    for decoded in [
        serde_json::from_value::<ScopedEncryptionKeyBundle>(json).unwrap(),
        postcard::from_bytes::<ScopedEncryptionKeyBundle>(&binary).unwrap(),
    ] {
        assert_eq!(decoded.scopes().len(), scopes.len());
        for (actual, scope) in decoded.scopes().zip(&scopes) {
            assert_eq!(actual, scope);
            assert_eq!(
                *decoded.derive_scoped_path(scope).unwrap(),
                *root.derive_scoped_path(scope).unwrap()
            );
        }
    }
}

#[test]
fn inconsistent_overlaps_are_rejected_during_decoding() {
    // Include duplicate scopes, directories, terminal files, and the root.
    for (covering_scope, covered_scope) in [
        ("/priv/chat/", "/priv/chat/"),
        ("/priv/chat/file", "/priv/chat/file"),
        ("/priv/chat/", "/priv/chat/sub/"),
        ("/priv/chat/", "/priv/chat/sub/file"),
        ("/", "/pub/app/"),
    ] {
        let covering = KeyEntry {
            scope: path(covering_scope),
            secret: Box::new(root().derive_scoped_path(&path(covering_scope)).unwrap()),
        };
        let covered = KeyEntry {
            scope: path(covered_scope),
            secret: Box::new(Zeroizing::new([0; 32])),
        };
        for keys in [
            vec![covering.clone(), covered.clone()],
            vec![covered.clone(), covering.clone()],
            vec![
                covering.clone(),
                KeyEntry {
                    scope: path("/unrelated/"),
                    secret: Box::new(root().derive_scoped_path(&path("/unrelated/")).unwrap()),
                },
                covered.clone(),
            ],
        ] {
            let json = serde_json::json!({ "version": "v1", "keys": &keys });
            let error = serde_json::from_value::<ScopedEncryptionKeyBundle>(json).unwrap_err();
            let expected_error = format!(
                "inconsistent keys for overlapping scopes {} and {}",
                covering_scope, covered_scope,
            );
            assert_eq!(error.to_string(), expected_error);

            // A tuple has the same field encoding as the bundle in Postcard.
            let binary = postcard::to_allocvec(&(DerivationVersion::V1, &keys)).unwrap();
            assert!(postcard::from_bytes::<ScopedEncryptionKeyBundle>(&binary).is_err());
        }
    }
}

#[test]
fn unrelated_scopes_and_file_directory_pairs_need_not_share_an_ancestor() {
    // File and same-named directory keys are separate, non-overlapping scopes.
    let scopes = [
        path("/pub/app/file"),
        path("/pub/app/file/"),
        path("/pub/app-evil/"),
        path("/priv/chat/"),
    ];
    let keys = scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| {
            serde_json::json!({ "scope": scope.as_str(), "secret": URL_SAFE_NO_PAD.encode([index as u8; 32]) })
        })
        .collect::<Vec<_>>();
    let bundle: ScopedEncryptionKeyBundle = serde_json::from_value(serde_json::json!({
        "version": "v1", "keys": keys,
    }))
    .unwrap();
    for (index, scope) in scopes.iter().enumerate() {
        assert_eq!(
            &*bundle.derive_scoped_path(scope).unwrap(),
            &[index as u8; 32]
        );
    }
}

#[test]
fn bundle_rejects_paths_outside_all_entries() {
    let bundle = issue(&[path("/pub/app/"), path("/priv/settings")]);
    for target in [
        "/",
        "/pub/",
        "/pub/app",
        "/pub/app-evil/file",
        "/pub/other/file",
        "/priv/settings/",
        "/priv/settings/child",
        "/priv/settings-other",
    ] {
        let target = path(target);
        assert_eq!(
            bundle.derive_for_path(&target).unwrap_err(),
            if target.is_directory() {
                KeyDerivationError::DirectoryPath { requested: target }
            } else {
                KeyDerivationError::OutsideScope { requested: target }
            }
        );
    }

    let empty = issue(&[]);
    let target = path("/pub/file");
    assert_eq!(
        empty.derive_for_path(&target).unwrap_err(),
        KeyDerivationError::OutsideScope { requested: target }
    );
}
