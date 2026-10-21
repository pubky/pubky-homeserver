//! The storage contract: what the file service promises on every backend.
//!
//! Each case is a test of its own on each backend, under the layers
//! production puts on it, see [`storage_contract_tests`]. Add a case by
//! listing it there.

use bytes::Bytes;
use futures_util::StreamExt;

use crate::persistence::files::test_support::{storage_contract_tests, TestStorage};
use crate::persistence::files::{FileIoError, WriteStreamError};

/// A size for test data that spans several stream items.
const TEST_CHUNK_SIZE: usize = 16 * 1024;

storage_contract_tests!(
    reads_back_what_was_written,
    read_of_a_missing_file_is_not_found,
    overwrite_replaces_content_and_length,
    delete_removes_the_file,
    stores_names_that_urls_percent_encode,
    stores_an_empty_file,
    streams_a_multipart_sized_write,
    broken_stream_keeps_the_old_file,
    overwrite_mid_download_does_not_mix_versions,
);

/// Above the 5 MiB from which GCS uploads in parts.
const MULTIPART_SIZE: usize = 6 * 1024 * 1024;

/// A file reads back with its length, streamed in several items, its
/// entry describes it, and nothing is left staged.
async fn reads_back_what_was_written(storage: &TestStorage) {
    let path = storage.path("/pub/a.bin");
    let content = vec![1u8; 5 * TEST_CHUNK_SIZE];

    storage.service.write(&path, content.clone()).await.unwrap();

    let (length, mut stream) = storage.service.get_sized_stream(&path).await.unwrap();
    let mut read = Vec::new();
    while let Some(chunk) = stream.next().await {
        read.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(length, content.len() as u64);
    assert_eq!(read, content);
    storage.assert_entry_matches_file(&path).await;
    assert!(storage.staging_is_empty().await);
}

/// A read of a missing file fails before a reader is opened.
async fn read_of_a_missing_file_is_not_found(storage: &TestStorage) {
    let path = storage.path("/pub/missing.bin");

    assert!(matches!(
        storage.service.get_sized_stream(&path).await,
        Err(FileIoError::NotFound)
    ));
    assert!(!storage.service.exists(&path).await.unwrap());
}

async fn overwrite_replaces_content_and_length(storage: &TestStorage) {
    let path = storage.path("/pub/a.bin");
    storage
        .service
        .write(&path, vec![1u8; 3 * TEST_CHUNK_SIZE])
        .await
        .unwrap();

    storage.service.write(&path, vec![2u8; 10]).await.unwrap();

    assert_eq!(storage.service.blob_length(&path).await.unwrap(), 10);
    assert_eq!(
        storage.service.get(&path).await.unwrap().to_vec(),
        vec![2u8; 10]
    );
    storage.assert_entry_matches_file(&path).await;
    assert!(storage.staging_is_empty().await);
}

/// A deleted file is gone with its entry, and deleting a missing file
/// succeeds.
async fn delete_removes_the_file(storage: &TestStorage) {
    let path = storage.path("/pub/a.bin");
    storage.service.write(&path, vec![1u8; 10]).await.unwrap();

    storage.service.delete(&path).await.unwrap();

    assert!(!storage.service.exists(&path).await.unwrap());
    storage.assert_entry_matches_file(&path).await;
    storage
        .service
        .delete(&path)
        .await
        .expect("deleting a missing file succeeds");
}

/// Names with characters that URLs percent-encode, and one that is
/// percent-encoded already, are stored and read under their own name,
/// not under the decoded one.
async fn stores_names_that_urls_percent_encode(storage: &TestStorage) {
    let names = [
        "/pub/a b+c#d%e.txt",
        "/pub/\u{fc}\u{b7}~!'()*.txt",
        "/pub/Teest%20share/.keep",
    ];

    for name in names {
        let path = storage.path(name);
        storage
            .service
            .write(&path, name.as_bytes().to_vec())
            .await
            .unwrap();
        assert_eq!(
            storage.service.get(&path).await.unwrap().as_ref(),
            name.as_bytes(),
            "{name}"
        );
        storage.assert_entry_matches_file(&path).await;
    }
    let decoded = storage.path("/pub/Teest share/.keep");
    assert!(!storage.service.exists(&decoded).await.unwrap());
}

/// A stream of chunks that adds up to more than one upload request is
/// stored in order, and nothing is left staged.
async fn streams_a_multipart_sized_write(storage: &TestStorage) {
    let path = storage.path("/pub/large.bin");
    let chunks: Vec<Vec<u8>> = (0..6u8)
        .map(|chunk| vec![chunk; MULTIPART_SIZE / 6])
        .collect();
    let stream =
        futures_util::stream::iter(chunks.clone().into_iter().map(|chunk| Ok(chunk.into())));

    storage.service.write_stream(&path, stream).await.unwrap();

    assert_eq!(
        storage.service.get(&path).await.unwrap().to_vec(),
        chunks.concat()
    );
    storage.assert_entry_matches_file(&path).await;
    assert!(storage.staging_is_empty().await);
}

/// An empty file is stored, with an entry of length zero.
async fn stores_an_empty_file(storage: &TestStorage) {
    let path = storage.path("/pub/empty");

    storage
        .service
        .write(&path, Vec::<u8>::new())
        .await
        .unwrap();

    assert_eq!(storage.service.blob_length(&path).await.unwrap(), 0);
    assert!(storage.service.get(&path).await.unwrap().is_empty());
    storage.assert_entry_matches_file(&path).await;
    assert!(storage.staging_is_empty().await);
}

/// A body that breaks mid-stream is aborted: the caller gets the stream
/// error rather than a cleanup error, the old file and its entry stay,
/// and nothing is left staged.
async fn broken_stream_keeps_the_old_file(storage: &TestStorage) {
    let path = storage.path("/pub/a.txt");
    storage.service.write(&path, b"old".to_vec()).await.unwrap();
    let stream = futures_util::stream::iter([
        Ok(Bytes::from_static(b"partial")),
        Err(WriteStreamError::Other(anyhow::anyhow!("connection reset"))),
    ]);

    let result = storage.service.write_stream(&path, stream).await;

    assert!(matches!(result, Err(FileIoError::StreamBroken(_))));
    assert_eq!(
        storage.service.get(&path).await.unwrap(),
        Bytes::from_static(b"old")
    );
    storage.assert_entry_matches_file(&path).await;
    assert!(storage.staging_is_empty().await);
}

/// An overwrite landing mid-download does not mix the two versions: the
/// download delivers only bytes of the version it opened, and either
/// completes that version or fails. On a backend that delivers a download
/// in one item, the overwrite lands after it.
async fn overwrite_mid_download_does_not_mix_versions(storage: &TestStorage) {
    let path = storage.path("/pub/a.bin");
    // More than one stream item of the filesystem backend, which reads
    // 2 MiB at a time, and of a GCS response.
    let length = 3 * 1024 * 1024;
    storage
        .service
        .write(&path, vec![1u8; length])
        .await
        .unwrap();
    let (_, mut stream) = storage.service.get_sized_stream(&path).await.unwrap();
    let mut delivered = stream.next().await.unwrap().unwrap().to_vec();
    if storage.downloads_in_several_items() {
        assert!(delivered.len() < length, "the download is still going");
    }

    storage
        .service
        .write(&path, vec![2u8; length])
        .await
        .unwrap();

    let mut failed = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => delivered.extend_from_slice(&chunk),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(
        delivered.iter().all(|&byte| byte == 1),
        "bytes of the overwrite were mixed in"
    );
    assert!(
        failed || delivered.len() == length,
        "the download neither completed its version nor failed"
    );
    assert_eq!(
        storage.service.get(&path).await.unwrap().to_vec(),
        vec![2u8; length]
    );
    storage.assert_entry_matches_file(&path).await;
}
