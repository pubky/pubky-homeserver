use crate::persistence::sql::entry::EntryRepository;
use crate::services::file_service::{
    cleanup::STALE_GARBAGE_CLAIM_SECONDS, reads::READ_LEASE_SECONDS,
    upload_heartbeat::UploadHeartbeat,
};
use crate::{
    services::user_service::FILE_METADATA_SIZE,
    shared::{quota::UserQuota, webdav::StoragePath},
    storage_config::StorageConfigToml,
};
use futures_lite::StreamExt;
use std::time::Duration;

use super::*;

async fn filesystem_context() -> std::sync::Arc<AppContext> {
    AppContext::test_with_config(|config| {
        config.storage.backend = StorageConfigToml::FileSystem;
    })
    .await
}

async fn fail_all_event_inserts(context: &AppContext) {
    sqlx::query(
        r#"
            CREATE FUNCTION fail_event_insert() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced event insert failure';
            END;
            $$ LANGUAGE plpgsql
            "#,
    )
    .execute(context.sql_db.pool())
    .await
    .unwrap();
    sqlx::query(
        r#"
            CREATE TRIGGER fail_event_insert_trigger
            BEFORE INSERT ON events
            FOR EACH ROW EXECUTE FUNCTION fail_event_insert()
            "#,
    )
    .execute(context.sql_db.pool())
    .await
    .unwrap();
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_write_get_delete_db_and_opendal() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();

    let user = user_service.create(&pubkey).await.unwrap();

    // User should not have any data usage yet
    assert_eq!(user.used_bytes, 0);

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

    // Test getting a non-existent file
    match file_service.get_stream(&path).await {
        Ok(_) => panic!("Should error for non-existent file"),
        Err(FileIoError::NotFound) => {}
        Err(e) => panic!("Should error for non-existent file: {}", e),
    };

    // Test data
    let test_data = b"Hello, world! This is test data for the get method.";
    let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
    let stream = futures_util::stream::iter(chunks);

    file_service.write_stream(&path, stream).await.unwrap();
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(
        user.used_bytes,
        test_data.len() as u64 + FILE_METADATA_SIZE,
        "Data usage should be the size of the file"
    );

    // Get the file content and verify
    let mut stream = file_service
        .get_stream(&path)
        .await
        .expect("File should exist");
    let mut collected_data = Vec::new();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.unwrap();
        collected_data.extend_from_slice(&chunk);
    }

    assert_eq!(
        collected_data,
        test_data.to_vec(),
        "Content should match original data"
    );

    file_service.delete(&path).await.unwrap();
    let result = file_service.get_stream(&path).await;
    assert!(result.is_err(), "Should error for deleted file");
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(
        user.used_bytes, 0,
        "Data usage should be 0 after deleting file"
    );

    // Test OpenDal location
    let path = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/test_opendal.txt").unwrap(),
    );
    let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
    let stream = futures_util::stream::iter(chunks);
    file_service.write_stream(&path, stream).await.unwrap();
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(
        user.used_bytes,
        test_data.len() as u64 + FILE_METADATA_SIZE,
        "Data usage should be the size of the file"
    );

    // Get the file content and verify
    let mut stream = file_service
        .get_stream(&path)
        .await
        .expect("File should exist");
    let mut collected_data = Vec::new();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.unwrap();
        collected_data.extend_from_slice(&chunk);
    }

    assert_eq!(
        collected_data,
        test_data.to_vec(),
        "Content should match original data for OpenDal location"
    );

    // Clean up
    file_service.delete(&path).await.unwrap();
    let result = file_service.get_stream(&path).await;
    assert!(result.is_err(), "Should error for deleted file");
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(
        user.used_bytes, 0,
        "Data usage should be 0 after deleting file"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_write_get_basic() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create(&pubkey).await.unwrap();

    let test_data = b"Hello, world!";
    let buffer = Buffer::from(test_data.as_slice());

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    file_service.write(&path, buffer.clone()).await.unwrap();
    let content = file_service.get(&path).await.unwrap();
    assert_eq!(content.as_ref(), test_data);

    // Test OpenDal
    let opendal_path = EntryPath::new(pubkey, StoragePath::new("/test_opendal.txt").unwrap());
    file_service.write(&opendal_path, buffer).await.unwrap();
    let content = file_service.get(&opendal_path).await.unwrap();
    assert_eq!(content.as_ref(), test_data);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_data_usage_update_basic() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create_with_quota_mb(&pubkey, 1).await;

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    let test_data = vec![1u8; 1024];
    let buffer = Buffer::from(test_data.clone());

    file_service.write(&path, buffer).await.unwrap();
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(user.used_bytes, test_data.len() as u64 + FILE_METADATA_SIZE);

    // Delete the file and check if the data usage is updated correctly.
    file_service.delete(&path).await.unwrap();
    let user = user_service.get(&pubkey).await.unwrap();
    assert_eq!(user.used_bytes, 0);
}

/// Override and existing entry and check if the data usage is updated correctly.
#[tokio::test]
#[pubky_test_utils::test]
async fn test_data_usage_override_existing_entry() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create_with_quota_mb(&pubkey, 1).await;

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    let test_data = vec![1u8; 1024];
    let buffer = Buffer::from(test_data.clone());

    file_service.write(&path, buffer).await.unwrap();

    let test_data2 = vec![2u8; 1024];
    let buffer2 = Buffer::from(test_data2.clone());
    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

    file_service.write(&path, buffer2).await.unwrap();

    assert_eq!(
        user_service.get(&pubkey).await.unwrap().used_bytes,
        test_data2.len() as u64 + FILE_METADATA_SIZE
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_rejects_descendant_when_exact_file_exists() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let db = context.sql_db.clone();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create(&pubkey).await.unwrap();

    let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
    let descendant_path = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/app/foo/bar.json").unwrap(),
    );

    file_service
        .write(&exact_path, Buffer::from(vec![1; 10]))
        .await
        .unwrap();
    let err = file_service
        .write(&descendant_path, Buffer::from(vec![2; 10]))
        .await
        .expect_err("descendant write should be rejected");

    assert!(matches!(err, FileIoError::PathCollision));
    file_service
        .get_info(&descendant_path, &mut db.pool().into())
        .await
        .expect_err("Rejected descendant should not create metadata");
    file_service
        .get(&descendant_path)
        .await
        .expect_err("Rejected descendant should not create a blob");
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_rejects_exact_file_when_descendant_exists() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let db = context.sql_db.clone();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create(&pubkey).await.unwrap();

    let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
    let descendant_path =
        EntryPath::new(pubkey, StoragePath::new("/pub/app/foo/bar.json").unwrap());

    file_service
        .write(&descendant_path, Buffer::from(vec![1; 10]))
        .await
        .unwrap();
    let err = file_service
        .write(&exact_path, Buffer::from(vec![2; 10]))
        .await
        .expect_err("exact-file write should be rejected");

    assert!(matches!(err, FileIoError::PathCollision));
    file_service
        .get_info(&exact_path, &mut db.pool().into())
        .await
        .expect_err("Rejected exact file should not create metadata");
    file_service
        .get(&exact_path)
        .await
        .expect_err("Rejected exact file should not create a blob");
}

/// Write a file that is exactly at the quota and check if the data usage is updated correctly.
#[tokio::test]
#[pubky_test_utils::test]
async fn test_data_usage_exactly_to_quota() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create_with_quota_mb(&pubkey, 1).await;

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    let test_data = vec![1u8; 1024 * 1024 - FILE_METADATA_SIZE as usize];
    let buffer = Buffer::from(test_data.clone());

    file_service.write(&path, buffer).await.unwrap();

    assert_eq!(
        user_service.get(&pubkey).await.unwrap().used_bytes,
        test_data.len() as u64 + FILE_METADATA_SIZE
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_data_usage_above_quota() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create_with_quota_mb(&pubkey, 1).await;

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    let test_data = vec![1u8; 1024 * 1024 + 1];
    let buffer = Buffer::from(test_data.clone());

    match file_service.write(&path, buffer).await {
        Ok(_) => panic!("Should error for file above quota"),
        Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
        Err(e) => {
            panic!("Should error for file above quota: {:?}", e);
        }
    }

    assert_eq!(user_service.get(&pubkey).await.unwrap().used_bytes, 0);
}

/// Override and existing entry and check if the data usage is updated correctly.
#[tokio::test]
#[pubky_test_utils::test]
async fn test_data_usage_override_existing_above_quota() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let user_service = context.user_service.clone();

    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    user_service.create_with_quota_mb(&pubkey, 1).await;

    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
    let test_data = vec![1u8; 1024];
    let buffer = Buffer::from(test_data.clone());

    file_service.write(&path, buffer).await.unwrap();

    let test_data2 = vec![2u8; 1024 * 1024 + 1];
    let buffer2 = Buffer::from(test_data2.clone());
    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

    match file_service.write(&path, buffer2).await {
        Ok(_) => panic!("Should error for file above quota"),
        Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
        Err(e) => {
            panic!("Should error for file above quota: {:?}", e);
        }
    }

    assert_eq!(
        user_service.get(&pubkey).await.unwrap().used_bytes,
        test_data.len() as u64 + FILE_METADATA_SIZE
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_legacy_entry_is_readable_and_rewritten_to_immutable_blob() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    let user = context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey, StoragePath::new("/pub/legacy.txt").unwrap());
    let legacy = Bytes::from_static(b"legacy");
    let metadata = file_service
        .opendal
        .write_blob_stream(
            path.as_str(),
            futures_util::stream::iter([Ok(legacy.clone())]),
            &path,
        )
        .await
        .unwrap();
    EntryRepository::create(
        user.id,
        path.path(),
        &metadata.hash,
        metadata.length as u64,
        &metadata.content_type,
        &mut context.sql_db.pool().into(),
    )
    .await
    .unwrap();

    assert_eq!(file_service.get(&path).await.unwrap(), legacy);
    let rewritten = file_service
        .write(&path, Buffer::from(b"new".to_vec()))
        .await
        .unwrap();
    assert!(rewritten.blob_key.is_some());
    assert_eq!(file_service.get(&path).await.unwrap().as_ref(), b"new");
    assert!(file_service
        .opendal
        .blob_exists(path.as_str())
        .await
        .unwrap());

    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE blob_read_leases SET expires_at = statement_timestamp()")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    file_service.recover_blob_storage().await.unwrap();
    assert!(!file_service
        .opendal
        .blob_exists(path.as_str())
        .await
        .unwrap());
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_legacy_entry_remains_readable_after_directory_move() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    let user = context.user_service.create(&pubkey).await.unwrap();
    let source_directory = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source").unwrap());
    let destination_directory =
        EntryPath::new(pubkey.clone(), StoragePath::new("/pub/moved").unwrap());
    let source = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/source/legacy.txt").unwrap(),
    );
    let destination = EntryPath::new(pubkey, StoragePath::new("/pub/moved/legacy.txt").unwrap());
    let content = Bytes::from_static(b"legacy");
    let metadata = file_service
        .opendal
        .write_blob_stream(
            source.as_str(),
            futures_util::stream::iter([Ok(content.clone())]),
            &source,
        )
        .await
        .unwrap();
    EntryRepository::create(
        user.id,
        source.path(),
        &metadata.hash,
        metadata.length as u64,
        &metadata.content_type,
        &mut context.sql_db.pool().into(),
    )
    .await
    .unwrap();

    file_service
        .admin_rename_directory(&source_directory, &destination_directory)
        .await
        .unwrap();

    assert!(matches!(
        file_service.get(&source).await,
        Err(FileIoError::NotFound)
    ));
    assert_eq!(file_service.get(&destination).await.unwrap(), content);
    let moved = file_service
        .get_info(&destination, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    assert_eq!(moved.blob_key.as_deref(), Some(source.as_str()));
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_failed_pointer_switch_preserves_previous_content() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey, StoragePath::new("/pub/state.bin").unwrap());
    let original = file_service
        .write(&path, Buffer::from(b"original".to_vec()))
        .await
        .unwrap();

    sqlx::query(
        r#"
            CREATE FUNCTION fail_blob_pointer_update() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced pointer failure';
            END;
            $$ LANGUAGE plpgsql
            "#,
    )
    .execute(context.sql_db.pool())
    .await
    .unwrap();
    sqlx::query(
        r#"
            CREATE TRIGGER fail_blob_pointer_update_trigger
            BEFORE UPDATE ON entries
            FOR EACH ROW EXECUTE FUNCTION fail_blob_pointer_update()
            "#,
    )
    .execute(context.sql_db.pool())
    .await
    .unwrap();

    file_service
        .write(&path, Buffer::from(b"replacement".to_vec()))
        .await
        .expect_err("pointer update should fail");
    let restarted_service = FileService::new_from_context(&context).unwrap();
    let entry = restarted_service
        .get_info(&path, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    assert_eq!(entry.blob_key, original.blob_key);
    assert_eq!(
        restarted_service.get(&path).await.unwrap().as_ref(),
        b"original"
    );

    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let abandoned_key: String = sqlx::query_scalar("SELECT blob_key FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(staged, 0);
    assert!(restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
    restarted_service.recover_blob_storage().await.unwrap();
    assert!(restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    restarted_service.recover_blob_storage().await.unwrap();
    assert!(!restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_event_failure_rolls_back_write_and_cleans_blob() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
    fail_all_event_inserts(&context).await;

    file_service
        .write(&path, Buffer::from(b"content".to_vec()))
        .await
        .expect_err("event failure should fail the write");

    let restarted_service = FileService::new_from_context(&context).unwrap();
    assert!(matches!(
        restarted_service.get(&path).await,
        Err(FileIoError::NotFound)
    ));
    assert_eq!(
        context.user_service.get(&pubkey).await.unwrap().used_bytes,
        0
    );
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let uploads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let abandoned_key: String = sqlx::query_scalar("SELECT blob_key FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(events, 0);
    assert_eq!(uploads, 0);
    assert!(restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
    restarted_service.recover_blob_storage().await.unwrap();
    assert!(restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    restarted_service.recover_blob_storage().await.unwrap();
    assert!(!restarted_service
        .opendal
        .blob_exists(&abandoned_key)
        .await
        .unwrap());
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_recovery_removes_stale_uploaded_blob() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    let path = EntryPath::new(pubkey, StoragePath::new("/pub/orphan.bin").unwrap());
    let blob_key = "__pubky/blobs/stale-upload";

    BlobRepository::stage_upload(blob_key, 1, 6, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    file_service
        .opendal
        .write_blob_stream(
            blob_key,
            futures_util::stream::iter([Ok(Bytes::from_static(b"orphan"))]),
            &path,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE blob_uploads SET updated_at = CURRENT_TIMESTAMP - INTERVAL '2 hours'")
        .execute(context.sql_db.pool())
        .await
        .unwrap();

    let restarted_service = FileService::new_from_context(&context).unwrap();
    restarted_service.recover_blob_storage().await.unwrap();
    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(staged, 0);
    assert_eq!(garbage, 1);
    assert!(restarted_service
        .opendal
        .blob_exists(blob_key)
        .await
        .unwrap());

    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    restarted_service.recover_blob_storage().await.unwrap();
    assert!(!restarted_service
        .opendal
        .blob_exists(blob_key)
        .await
        .unwrap());
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_reconciliation_removes_untracked_blob_only() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey, StoragePath::new("/pub/active.bin").unwrap());
    let active = file_service
        .write(&path, Buffer::from(b"active".to_vec()))
        .await
        .unwrap();
    let active_blob_key = active.blob_key.unwrap();
    let orphan_blob_key = format!("{}late-orphan", file_service.blob_prefix);
    file_service
        .opendal
        .write_blob_stream(
            &orphan_blob_key,
            futures_util::stream::iter([Ok(Bytes::from_static(b"orphan"))]),
            &path,
        )
        .await
        .unwrap();

    assert_eq!(file_service.reconcile_untracked_blobs().await.unwrap(), 1);
    file_service.recover_blob_storage().await.unwrap();

    assert!(file_service
        .opendal
        .blob_exists(&active_blob_key)
        .await
        .unwrap());
    assert!(!file_service
        .opendal
        .blob_exists(&orphan_blob_key)
        .await
        .unwrap());

    file_service
        .opendal
        .write_blob_stream(
            &orphan_blob_key,
            futures_util::stream::iter([Ok(Bytes::from_static(b"late"))]),
            &path,
        )
        .await
        .unwrap();
    assert_eq!(file_service.reconcile_untracked_blobs().await.unwrap(), 1);
    file_service.recover_blob_storage().await.unwrap();
    assert!(!file_service
        .opendal
        .blob_exists(&orphan_blob_key)
        .await
        .unwrap());
    assert_eq!(file_service.get(&path).await.unwrap().as_ref(), b"active");
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_reconciliation_is_isolated_between_databases_sharing_storage() {
    let first = filesystem_context().await;
    let second = AppContext::test().await;
    let first_service = &first.file_service;
    let second_service = FileService::new_from_config(
        &first.config_toml,
        first.data_dir.path(),
        second.sql_db.clone(),
        second.events_service.clone(),
        second.user_service.clone(),
    )
    .await
    .unwrap();
    assert_ne!(first_service.blob_prefix, second_service.blob_prefix);
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    first.user_service.create(&public_key).await.unwrap();
    second.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
    first_service
        .write(&path, Buffer::from(b"first".to_vec()))
        .await
        .unwrap();
    second_service
        .write(&path, Buffer::from(b"second".to_vec()))
        .await
        .unwrap();

    let orphan = format!("{}orphan", first_service.blob_prefix);
    first_service
        .opendal
        .write_blob_stream(
            &orphan,
            futures_util::stream::iter([Ok(Bytes::from_static(b"orphan"))]),
            &path,
        )
        .await
        .unwrap();

    let restarted = FileService::new_from_config(
        &first.config_toml,
        first.data_dir.path(),
        first.sql_db.clone(),
        first.events_service.clone(),
        first.user_service.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first_service.blob_prefix, restarted.blob_prefix);
    assert_eq!(second_service.reconcile_untracked_blobs().await.unwrap(), 0);
    assert_eq!(restarted.reconcile_untracked_blobs().await.unwrap(), 1);
    second_service.recover_blob_storage().await.unwrap();
    restarted.recover_blob_storage().await.unwrap();

    assert!(!restarted.opendal.blob_exists(&orphan).await.unwrap());
    assert_eq!(restarted.get(&path).await.unwrap().as_ref(), b"first");
    assert_eq!(second_service.get(&path).await.unwrap().as_ref(), b"second");
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_blob_cleanup_retries_backend_delete_failure() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let first_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/first.bin").unwrap());
    let second_path = EntryPath::new(pubkey, StoragePath::new("/pub/second.bin").unwrap());
    let first = file_service
        .write(&first_path, Buffer::from(b"first".to_vec()))
        .await
        .unwrap();
    let second = file_service
        .write(&second_path, Buffer::from(b"second".to_vec()))
        .await
        .unwrap();
    let first_blob_key = first.blob_key.unwrap();
    let second_blob_key = second.blob_key.unwrap();
    file_service.delete(&first_path).await.unwrap();
    file_service.delete(&second_path).await.unwrap();
    sqlx::query(
        "UPDATE blob_garbage SET available_at = CASE \
         WHEN blob_key = $1 THEN CURRENT_TIMESTAMP - INTERVAL '2 minutes' \
         ELSE CURRENT_TIMESTAMP - INTERVAL '1 minute' END",
    )
    .bind(&first_blob_key)
    .execute(context.sql_db.pool())
    .await
    .unwrap();

    file_service.opendal.fail_next_delete();
    file_service.recover_blob_storage().await.unwrap();
    assert!(file_service
        .opendal
        .blob_exists(&first_blob_key)
        .await
        .unwrap());
    assert!(!file_service
        .opendal
        .blob_exists(&second_blob_key)
        .await
        .unwrap());
    let pending: (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COUNT(claim_token) FROM blob_garbage WHERE blob_key = $1")
            .bind(&first_blob_key)
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
    assert_eq!(pending, (1, 1));
    assert!(
        BlobRepository::create_read_lease(
            &first_blob_key,
            "late-reader",
            READ_LEASE_SECONDS,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap()
        .is_none(),
        "an ambiguous backend deletion must remain tombstoned"
    );

    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP WHERE blob_key = $1")
        .bind(&first_blob_key)
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    file_service.recover_blob_storage().await.unwrap();
    assert!(!file_service
        .opendal
        .blob_exists(&first_blob_key)
        .await
        .unwrap());
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage WHERE blob_key = $1")
        .bind(&first_blob_key)
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(pending, 0);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_cleanup_recovers_after_blob_delete_before_acknowledgement() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
    let entry = file_service
        .write(&path, Buffer::from(b"content".to_vec()))
        .await
        .unwrap();
    let blob_key = entry.blob_key.unwrap();
    file_service.delete(&path).await.unwrap();
    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    let claim = BlobRepository::claim_garbage(
        1,
        STALE_GARBAGE_CLAIM_SECONDS,
        &mut context.sql_db.pool().into(),
    )
    .await
    .unwrap()
    .remove(0);
    file_service
        .opendal
        .delete_by_key(&claim.blob_key)
        .await
        .unwrap();

    sqlx::query("UPDATE blob_garbage SET claimed_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes'")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    let restarted_service = FileService::new_from_context(&context).unwrap();
    restarted_service.recover_blob_storage().await.unwrap();

    assert!(!restarted_service
        .opendal
        .blob_exists(&blob_key)
        .await
        .unwrap());
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(pending, 0);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_retained_versions_are_bounded_by_physical_quota() {
    let context = AppContext::test_with_config(|config| {
        config.storage.default_quota_mb = Some(1);
    })
    .await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
    let content_length = 800 * 1024;

    for byte in [1, 2, 3] {
        file_service
            .write_stream_with_size_hint(
                &path,
                futures_util::stream::iter([Ok(Bytes::from(vec![byte; content_length]))]),
                content_length as u64,
            )
            .await
            .unwrap();
    }

    let error = file_service
        .write_stream_with_size_hint(
            &path,
            futures_util::stream::iter([Ok(Bytes::from(vec![4; content_length]))]),
            content_length as u64,
        )
        .await
        .expect_err("retained versions must count toward physical storage limits");
    assert!(matches!(error, FileIoError::DiskSpaceQuotaExceeded));

    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    file_service.recover_blob_storage().await.unwrap();
    file_service
        .write_stream_with_size_hint(
            &path,
            futures_util::stream::iter([Ok(Bytes::from(vec![4; content_length]))]),
            content_length as u64,
        )
        .await
        .unwrap();
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_active_reader_delays_blob_cleanup() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
    let original = file_service
        .write(&path, Buffer::from(b"original".to_vec()))
        .await
        .unwrap();
    let original_key = original.blob_key.clone().unwrap();
    let stream = file_service.get_entry_stream(&original).await.unwrap();

    file_service
        .write(&path, Buffer::from(b"replacement".to_vec()))
        .await
        .unwrap();
    sqlx::query("UPDATE blob_garbage SET available_at = statement_timestamp()")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    file_service.recover_blob_storage().await.unwrap();
    assert!(file_service
        .opendal
        .get_stream_by_key(&original_key)
        .await
        .is_ok());

    drop(stream);
    for _ in 0..20 {
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        if leases == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    file_service.recover_blob_storage().await.unwrap();
    assert!(matches!(
        file_service.opendal.get_stream_by_key(&original_key).await,
        Err(FileIoError::NotFound)
    ));
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_concurrent_local_readers_share_and_release_one_lease() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
    let entry = file_service
        .write(&path, Buffer::from(b"content".to_vec()))
        .await
        .unwrap();

    let first = file_service.acquire_entry_read_lease(&entry).await.unwrap();
    let second = file_service.acquire_entry_read_lease(&entry).await.unwrap();

    assert!(Arc::ptr_eq(&first.inner, &second.inner));
    assert_eq!(
        file_service
            .read_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
    let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(leases, 1);

    drop(first);
    let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(leases, 1);
    drop(second);
    for _ in 0..20 {
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        if leases == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the final reader should release the shared database lease");
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_upload_heartbeat_times_out_while_row_is_locked() {
    let context = AppContext::test().await;
    BlobRepository::stage_upload("blob-a", 1, 10, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    let mut tx = context.sql_db.pool().begin().await.unwrap();
    sqlx::query("SELECT blob_key FROM blob_uploads WHERE blob_key = 'blob-a' FOR UPDATE")
        .execute(&mut *tx)
        .await
        .unwrap();

    let error = UploadHeartbeat::touch_upload(&context.sql_db, "blob-a", Duration::from_millis(25))
        .await
        .unwrap_err();
    tx.rollback().await.unwrap();

    assert!(matches!(error, FileIoError::UploadLeaseLost));
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_cleanup_drains_more_than_one_batch() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    let user = context.user_service.create(&public_key).await.unwrap();
    let content_path = EntryPath::new(public_key, StoragePath::new("/pub/blob").unwrap());

    for index in 0..80 {
        let blob_key = format!("__pubky/blobs/cleanup-{index}");
        file_service
            .opendal
            .write_blob_stream(
                &blob_key,
                futures_util::stream::iter([Ok(Bytes::from_static(b"x"))]),
                &content_path,
            )
            .await
            .unwrap();
        BlobRepository::enqueue_garbage(
            &blob_key,
            user.id,
            1,
            0,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap();
    }

    file_service.recover_blob_storage().await.unwrap();

    let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(garbage, 0);
    for index in 0..80 {
        assert!(!file_service
            .opendal
            .blob_exists(&format!("__pubky/blobs/cleanup-{index}"))
            .await
            .unwrap());
    }
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_overwrite_allows_legacy_file_directory_collisions() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let child = EntryPath::new(
        public_key.clone(),
        StoragePath::new("/pub/dir/child").unwrap(),
    );
    file_service
        .write(&child, Buffer::from(b"child".to_vec()))
        .await
        .unwrap();
    let parent = EntryPath::new(public_key.clone(), StoragePath::new("/pub/dir").unwrap());
    file_service
        .admin_write_stream(
            &parent,
            futures_util::stream::iter([Ok(Bytes::from_static(b"parent"))]),
        )
        .await
        .unwrap();

    let ancestor = EntryPath::new(public_key.clone(), StoragePath::new("/pub/file").unwrap());
    file_service
        .write(&ancestor, Buffer::from(b"file".to_vec()))
        .await
        .unwrap();
    let descendant = EntryPath::new(public_key, StoragePath::new("/pub/file/child").unwrap());
    file_service
        .admin_write_stream(
            &descendant,
            futures_util::stream::iter([Ok(Bytes::from_static(b"child"))]),
        )
        .await
        .unwrap();

    assert_eq!(file_service.get(&parent).await.unwrap().as_ref(), b"parent");
    assert_eq!(
        file_service.get(&descendant).await.unwrap().as_ref(),
        b"child"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_event_failure_rolls_back_delete() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
    let original = file_service
        .write(&path, Buffer::from(b"content".to_vec()))
        .await
        .unwrap();
    let usage = context.user_service.get(&pubkey).await.unwrap().used_bytes;
    fail_all_event_inserts(&context).await;

    file_service
        .delete(&path)
        .await
        .expect_err("event failure should fail the delete");

    let restarted_service = FileService::new_from_context(&context).unwrap();
    let entry = restarted_service
        .get_info(&path, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    assert_eq!(entry.blob_key, original.blob_key);
    assert_eq!(
        restarted_service.get(&path).await.unwrap().as_ref(),
        b"content"
    );
    assert_eq!(
        context.user_service.get(&pubkey).await.unwrap().used_bytes,
        usage
    );
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(events, 1);
    assert_eq!(garbage, 0);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_concurrent_file_folder_writes_commit_one() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let ancestor = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
    let descendant = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/app/foo/bar.json").unwrap(),
    );
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

    let ancestor_write = {
        let service = file_service.clone();
        let path = ancestor.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&path, Buffer::from(vec![1; 10])).await
        })
    };
    let descendant_write = {
        let service = file_service.clone();
        let path = descendant.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&path, Buffer::from(vec![2; 20])).await
        })
    };
    barrier.wait().await;
    let ancestor_result = ancestor_write.await.unwrap();
    let descendant_result = descendant_write.await.unwrap();

    assert_ne!(ancestor_result.is_ok(), descendant_result.is_ok());
    let collision = ancestor_result
        .as_ref()
        .err()
        .or_else(|| descendant_result.as_ref().err())
        .unwrap();
    assert!(matches!(collision, FileIoError::PathCollision));
    let ancestor_entry =
        EntryRepository::get_by_path(&ancestor, &mut context.sql_db.pool().into()).await;
    let descendant_entry =
        EntryRepository::get_by_path(&descendant, &mut context.sql_db.pool().into()).await;
    assert_ne!(ancestor_entry.is_ok(), descendant_entry.is_ok());
    let content_length = ancestor_entry
        .as_ref()
        .map(|entry| entry.content_length)
        .unwrap_or_else(|_| descendant_entry.unwrap().content_length);
    assert_eq!(
        context.user_service.get(&pubkey).await.unwrap().used_bytes,
        content_length + FILE_METADATA_SIZE
    );
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(events, 1);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_write_path_policy_rejects_disallowed_mutations() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    let user = context.user_service.create(&pubkey).await.unwrap();
    let quota = UserQuota {
        allowed_write_paths: Some(vec![StoragePath::new("/pub/allowed/").unwrap()]),
        ..Default::default()
    };
    context
        .user_service
        .set_quota_in_tx(user.id, &quota, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    let allowed = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/allowed/data.bin").unwrap(),
    );
    let blocked = EntryPath::new(pubkey, StoragePath::new("/pub/blocked.bin").unwrap());

    file_service
        .write(&allowed, Buffer::from(b"allowed".to_vec()))
        .await
        .unwrap();
    file_service
        .admin_write_stream(
            &blocked,
            futures_util::stream::iter([Ok(Bytes::from_static(b"blocked"))]),
        )
        .await
        .unwrap();

    assert!(matches!(
        file_service
            .write(&blocked, Buffer::from(b"replacement".to_vec()))
            .await,
        Err(FileIoError::WritePathForbidden)
    ));
    assert!(matches!(
        file_service.delete(&blocked).await,
        Err(FileIoError::WritePathForbidden)
    ));
    assert_eq!(
        file_service.get(&blocked).await.unwrap().as_ref(),
        b"blocked"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_loaded_entry_selects_one_immutable_version() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey, StoragePath::new("/pub/state.bin").unwrap());
    let original = file_service
        .write(&path, Buffer::from(b"original".to_vec()))
        .await
        .unwrap();
    file_service
        .write(&path, Buffer::from(b"replacement".to_vec()))
        .await
        .unwrap();

    let mut original_stream = file_service.get_entry_stream(&original).await.unwrap();
    let mut original_content = Vec::new();
    while let Some(chunk) = original_stream.next().await {
        original_content.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(original_content, b"original");
    assert_eq!(
        file_service.get(&path).await.unwrap().as_ref(),
        b"replacement"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_concurrent_writes_leave_one_complete_version() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

    let first = {
        let service = file_service.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&path, Buffer::from(b"aaa".to_vec())).await
        })
    };
    let second = {
        let service = file_service.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&path, Buffer::from(b"bbb".to_vec())).await
        })
    };
    barrier.wait().await;
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();

    let restarted_service = FileService::new_from_context(&context).unwrap();
    let content = restarted_service.get(&path).await.unwrap();
    assert!(content.as_ref() == b"aaa" || content.as_ref() == b"bbb");
    assert_eq!(
        context.user_service.get(&pubkey).await.unwrap().used_bytes,
        3 + FILE_METADATA_SIZE
    );
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(entries, 1);
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_concurrent_write_and_delete_leave_consistent_state() {
    let context = filesystem_context().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let public_key = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&public_key).await.unwrap();
    let path = EntryPath::new(
        public_key.clone(),
        StoragePath::new("/pub/state.bin").unwrap(),
    );
    file_service
        .write(&path, Buffer::from(b"old".to_vec()))
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

    let write = {
        let service = file_service.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&path, Buffer::from(b"new".to_vec())).await
        })
    };
    let delete = {
        let service = file_service.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.delete(&path).await
        })
    };
    barrier.wait().await;
    write.await.unwrap().unwrap();
    delete.await.unwrap().unwrap();

    let restarted_service = FileService::new_from_context(&context).unwrap();
    let content = restarted_service.get(&path).await;
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    let used_bytes = context
        .user_service
        .get(&public_key)
        .await
        .unwrap()
        .used_bytes;
    match content {
        Ok(content) => {
            assert_eq!(content.as_ref(), b"new");
            assert_eq!(entries, 1);
            assert_eq!(used_bytes, 3 + FILE_METADATA_SIZE);
        }
        Err(FileIoError::NotFound) => {
            assert_eq!(entries, 0);
            assert_eq!(used_bytes, 0);
        }
        Err(error) => panic!("unexpected read error after concurrent mutation: {error}"),
    }
    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(staged, 0);

    sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    restarted_service.recover_blob_storage().await.unwrap();
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
    assert_eq!(pending, 0);
    match restarted_service.get(&path).await {
        Ok(content) => assert_eq!(content.as_ref(), b"new"),
        Err(FileIoError::NotFound) => {}
        Err(error) => panic!("unexpected read error after cleanup: {error}"),
    }
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_copy_and_rename_use_logical_entries() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
    let copy = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/copy.txt").unwrap());
    let renamed = EntryPath::new(pubkey, StoragePath::new("/pub/renamed.txt").unwrap());

    file_service
        .write(&source, Buffer::from(b"content".to_vec()))
        .await
        .unwrap();
    file_service.admin_copy(&source, &copy).await.unwrap();
    assert_eq!(
        file_service.get(&source).await.unwrap().as_ref(),
        b"content"
    );
    assert_eq!(file_service.get(&copy).await.unwrap().as_ref(), b"content");

    let copied_entry = file_service
        .get_info(&copy, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    file_service.admin_rename(&copy, &renamed).await.unwrap();
    assert!(matches!(
        file_service.get(&copy).await,
        Err(FileIoError::NotFound)
    ));
    assert_eq!(
        file_service.get(&renamed).await.unwrap().as_ref(),
        b"content"
    );
    let renamed_entry = file_service
        .get_info(&renamed, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    assert_eq!(renamed_entry.blob_key, copied_entry.blob_key);
    file_service.admin_rename(&renamed, &renamed).await.unwrap();
    assert_eq!(
        file_service.get(&renamed).await.unwrap().as_ref(),
        b"content"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_copy_and_rename_preserve_legacy_collision_policy() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
    let destination = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/destination.txt").unwrap(),
    );
    file_service
        .write(&source, Buffer::from(b"source".to_vec()))
        .await
        .unwrap();
    file_service
        .write(&destination, Buffer::from(b"destination".to_vec()))
        .await
        .unwrap();

    assert!(matches!(
        file_service.admin_copy(&source, &destination).await,
        Err(FileIoError::PathCollision)
    ));
    assert!(matches!(
        file_service.admin_rename(&source, &destination).await,
        Err(FileIoError::PathCollision)
    ));
    assert_eq!(file_service.get(&source).await.unwrap().as_ref(), b"source");
    assert_eq!(
        file_service.get(&destination).await.unwrap().as_ref(),
        b"destination"
    );
    let destination_descendant = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/destination.txt/child.txt").unwrap(),
    );
    file_service
        .admin_copy(&source, &destination_descendant)
        .await
        .unwrap();
    assert_eq!(
        file_service
            .get(&destination_descendant)
            .await
            .unwrap()
            .as_ref(),
        b"source"
    );

    let source_directory = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source").unwrap());
    let destination_directory = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/destination").unwrap(),
    );
    let source_child = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/source/child.txt").unwrap(),
    );
    let destination_child = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/destination/child.txt").unwrap(),
    );
    file_service
        .write(&source_child, Buffer::from(b"source child".to_vec()))
        .await
        .unwrap();
    file_service
        .write(
            &destination_child,
            Buffer::from(b"destination child".to_vec()),
        )
        .await
        .unwrap();

    file_service
        .admin_copy(&source, &destination_directory)
        .await
        .unwrap();
    file_service
        .admin_delete(&destination_directory)
        .await
        .unwrap();
    file_service
        .admin_rename(&source, &destination_directory)
        .await
        .unwrap();
    let directory_below_file = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/destination.txt/moved").unwrap(),
    );
    file_service
        .admin_rename_directory(&source_directory, &directory_below_file)
        .await
        .unwrap();

    let moved_child = EntryPath::new(
        pubkey,
        StoragePath::new("/pub/destination.txt/moved/child.txt").unwrap(),
    );
    assert_eq!(
        file_service
            .get(&destination_directory)
            .await
            .unwrap()
            .as_ref(),
        b"source"
    );
    assert_eq!(
        file_service.get(&moved_child).await.unwrap().as_ref(),
        b"source child"
    );
    assert_eq!(
        file_service.get(&destination_child).await.unwrap().as_ref(),
        b"destination child"
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_rename_across_users_updates_accounting_and_events() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let source_pubkey = pubky_common::crypto::Keypair::random().public_key();
    let destination_pubkey = pubky_common::crypto::Keypair::random().public_key();
    let source_user = context.user_service.create(&source_pubkey).await.unwrap();
    let destination_user = context
        .user_service
        .create(&destination_pubkey)
        .await
        .unwrap();
    let source = EntryPath::new(
        source_pubkey.clone(),
        StoragePath::new("/pub/source.txt").unwrap(),
    );
    let destination = EntryPath::new(
        destination_pubkey.clone(),
        StoragePath::new("/pub/destination.txt").unwrap(),
    );
    let source_entry = file_service
        .write(&source, Buffer::from(b"source".to_vec()))
        .await
        .unwrap();

    file_service
        .admin_rename(&source, &destination)
        .await
        .unwrap();

    assert!(matches!(
        file_service.get(&source).await,
        Err(FileIoError::NotFound)
    ));
    assert_eq!(
        file_service.get(&destination).await.unwrap().as_ref(),
        b"source"
    );
    let destination_entry = file_service
        .get_info(&destination, &mut context.sql_db.pool().into())
        .await
        .unwrap();
    assert_eq!(destination_entry.blob_key, source_entry.blob_key);
    assert_eq!(
        context
            .user_service
            .get(&source_pubkey)
            .await
            .unwrap()
            .used_bytes,
        0
    );
    assert_eq!(
        context
            .user_service
            .get(&destination_pubkey)
            .await
            .unwrap()
            .used_bytes,
        b"source".len() as u64 + FILE_METADATA_SIZE
    );
    let events: Vec<(i32, String, String)> =
        sqlx::query_as("SELECT \"user\", type, path FROM events ORDER BY id DESC LIMIT 2")
            .fetch_all(context.sql_db.pool())
            .await
            .unwrap();
    assert_eq!(
        events,
        vec![
            (source_user.id, "DEL".to_string(), source.path().to_string()),
            (
                destination_user.id,
                "PUT".to_string(),
                destination.path().to_string()
            ),
        ]
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_directory_rename_across_users_respects_quota() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let source_pubkey = pubky_common::crypto::Keypair::random().public_key();
    let destination_pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&source_pubkey).await.unwrap();
    context
        .user_service
        .create_with_quota_mb(&destination_pubkey, 0)
        .await;
    let source_directory = EntryPath::new(
        source_pubkey.clone(),
        StoragePath::new("/pub/source").unwrap(),
    );
    let source = EntryPath::new(
        source_pubkey.clone(),
        StoragePath::new("/pub/source/file.txt").unwrap(),
    );
    let destination_directory = EntryPath::new(
        destination_pubkey.clone(),
        StoragePath::new("/pub/destination").unwrap(),
    );
    let destination = EntryPath::new(
        destination_pubkey.clone(),
        StoragePath::new("/pub/destination/file.txt").unwrap(),
    );
    file_service
        .write(&source, Buffer::from(b"content".to_vec()))
        .await
        .unwrap();
    let source_usage = context
        .user_service
        .get(&source_pubkey)
        .await
        .unwrap()
        .used_bytes;

    assert!(matches!(
        file_service
            .admin_rename_directory(&source_directory, &destination_directory)
            .await,
        Err(FileIoError::DiskSpaceQuotaExceeded)
    ));
    assert_eq!(
        file_service.get(&source).await.unwrap().as_ref(),
        b"content"
    );
    assert!(matches!(
        file_service.get(&destination).await,
        Err(FileIoError::NotFound)
    ));
    assert_eq!(
        context
            .user_service
            .get(&source_pubkey)
            .await
            .unwrap()
            .used_bytes,
        source_usage
    );
    assert_eq!(
        context
            .user_service
            .get(&destination_pubkey)
            .await
            .unwrap()
            .used_bytes,
        0
    );
}

#[tokio::test]
#[pubky_test_utils::test]
async fn test_admin_rename_serializes_source_overwrite() {
    let context = AppContext::test().await;
    let file_service = FileService::new_from_context(&context).unwrap();
    let pubkey = pubky_common::crypto::Keypair::random().public_key();
    context.user_service.create(&pubkey).await.unwrap();
    let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
    let renamed = EntryPath::new(
        pubkey.clone(),
        StoragePath::new("/pub/renamed.txt").unwrap(),
    );
    file_service
        .write(&source, Buffer::from(b"old".to_vec()))
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

    let rename = {
        let service = file_service.clone();
        let source = source.clone();
        let renamed = renamed.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.admin_rename(&source, &renamed).await
        })
    };
    let overwrite = {
        let service = file_service.clone();
        let source = source.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service.write(&source, Buffer::from(b"new".to_vec())).await
        })
    };
    barrier.wait().await;
    rename.await.unwrap().unwrap();
    overwrite.await.unwrap().unwrap();

    let source_content = file_service.get(&source).await;
    let renamed_content = file_service.get(&renamed).await.unwrap();
    match source_content {
        Ok(content) => {
            assert_eq!(content.as_ref(), b"new");
            assert_eq!(renamed_content.as_ref(), b"old");
            assert_eq!(
                context.user_service.get(&pubkey).await.unwrap().used_bytes,
                6 + 2 * FILE_METADATA_SIZE
            );
        }
        Err(FileIoError::NotFound) => {
            assert_eq!(renamed_content.as_ref(), b"new");
            assert_eq!(
                context.user_service.get(&pubkey).await.unwrap().used_bytes,
                3 + FILE_METADATA_SIZE
            );
        }
        Err(error) => panic!("unexpected source read error: {error}"),
    }
}
