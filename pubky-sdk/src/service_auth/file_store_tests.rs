use super::*;

fn options() -> FileReplayStoreOptions {
    FileReplayStoreOptions {
        max_entries: 3,
        max_journal_bytes: (HEADER_SIZE + RECORD_SIZE * 3) as u64,
    }
}

fn request(id: u8) -> ReplayRequest {
    let now = now_unix().unwrap();
    ReplayRequest {
        key: ReplayKey([id; 32]),
        not_before: now - 30,
        expires_at: now + 3600,
        policy: [1; 32],
    }
}

#[tokio::test]
async fn consumption_survives_reopening_and_rejects_a_second_owner() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("replay");
    let store = FileReplayStore::open(&path, options()).await.unwrap();
    assert!(matches!(
        FileReplayStore::open(&path, options()).await,
        Err(ReplayStoreError::AlreadyOpen)
    ));
    assert_eq!(
        store.consume_once(request(1)).await.unwrap(),
        ConsumeOutcome::Consumed
    );
    drop(store);
    let reopened = FileReplayStore::open(&path, options()).await.unwrap();
    assert_eq!(
        reopened.consume_once(request(1)).await.unwrap(),
        ConsumeOutcome::AlreadyConsumed
    );
    let mut changed_policy = request(2);
    changed_policy.policy = [9; 32];
    assert!(matches!(
        reopened.consume_once(changed_policy).await,
        Err(ReplayStoreError::PolicyMismatch)
    ));
}

#[tokio::test]
async fn owner_lock_excludes_another_process() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("replay");
    let _owner = FileReplayStore::open(&path, options()).await.unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "service_auth::file_store::tests::child_owner_probe",
            "--nocapture",
        ])
        .env("PUBKY_REPLAY_CHILD_PATH", &path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn child_owner_probe() {
    let Some(path) = std::env::var_os("PUBKY_REPLAY_CHILD_PATH") else {
        return;
    };
    assert!(matches!(
        FileReplayStore::open(PathBuf::from(path), options()).await,
        Err(ReplayStoreError::AlreadyOpen)
    ));
}

#[tokio::test]
async fn concurrent_consumption_and_capacity_are_atomic() {
    let temp = tempfile::tempdir().unwrap();
    let store = FileReplayStore::open(temp.path().join("replay"), options())
        .await
        .unwrap();
    let results =
        futures_util::future::join_all((0..16).map(|_| store.consume_once(request(1)))).await;
    assert_eq!(
        results
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ConsumeOutcome::Consumed)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ConsumeOutcome::AlreadyConsumed)))
            .count(),
        15
    );
    store.consume_once(request(2)).await.unwrap();
    store.consume_once(request(3)).await.unwrap();
    assert!(matches!(
        store.consume_once(request(4)).await,
        Err(ReplayStoreError::Capacity)
    ));
    assert_eq!(
        store.consume_once(request(1)).await.unwrap(),
        ConsumeOutcome::AlreadyConsumed
    );
}

/// Journal fixture containing one expired record and one live record.
async fn journal_with_expired_entry(path: &Path) {
    drop(FileReplayStore::open(path, options()).await.unwrap());
    let now = now_unix().unwrap();
    let index = ReplayIndex {
        policy: Some([1; 32]),
        last_seen: now - 100,
        ..ReplayIndex::default()
    };
    let header = header_bytes(&index);
    let first = record_bytes(
        ReplayKey([0; 32]),
        now - 50,
        now - 100,
        &header[49..].try_into().unwrap(),
    );
    let second = record_bytes(
        ReplayKey([1; 32]),
        now + 3600,
        now - 60,
        &first[48..].try_into().unwrap(),
    );
    let mut journal = File::create(path.join("journal")).unwrap();
    journal.write_all(&header).unwrap();
    journal.write_all(&first).unwrap();
    journal.write_all(&second).unwrap();
    journal.sync_all().unwrap();
}

#[tokio::test]
async fn compaction_discards_only_expired_records_and_preserves_live_replays() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("replay");
    journal_with_expired_entry(&path).await;
    let store = FileReplayStore::open(&path, options()).await.unwrap();
    store.consume_once(request(2)).await.unwrap();
    store.consume_once(request(3)).await.unwrap(); // Requires compaction of the expired record.
    assert_eq!(
        fs::metadata(path.join("journal")).unwrap().len(),
        options().max_journal_bytes
    );
    assert!(matches!(
        FileReplayStore::open(&path, options()).await,
        Err(ReplayStoreError::AlreadyOpen)
    ));
    drop(store);
    let reopened = FileReplayStore::open(&path, options()).await.unwrap();
    for key in 1..=3 {
        assert_eq!(
            reopened.consume_once(request(key)).await.unwrap(),
            ConsumeOutcome::AlreadyConsumed
        );
    }
}

#[tokio::test]
async fn corruption_truncation_and_missing_journals_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    for damage in ["checksum", "truncate", "missing"] {
        let path = temp.path().join(damage);
        let store = FileReplayStore::open(&path, options()).await.unwrap();
        store.consume_once(request(1)).await.unwrap();
        drop(store);
        let journal = path.join("journal");
        match damage {
            "checksum" => {
                let mut bytes = fs::read(&journal).unwrap();
                bytes[HEADER_SIZE + 10] ^= 1;
                fs::write(&journal, bytes).unwrap();
            }
            "truncate" => {
                let file = file_options().open(&journal).unwrap();
                file.set_len((HEADER_SIZE + 10) as u64).unwrap();
            }
            _ => fs::remove_file(&journal).unwrap(),
        }
        assert!(matches!(
            FileReplayStore::open(&path, options()).await,
            Err(ReplayStoreError::Corrupt(_))
        ));
    }
}

#[tokio::test]
async fn failed_append_poisoning_and_recovery_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    for (name, failure) in [
        ("partial", FailurePoint::PartialAppend),
        ("sync", FailurePoint::BeforeAppendSync),
    ] {
        let path = temp.path().join(name);
        let store = FileReplayStore::open(&path, options()).await.unwrap();
        store.consume_once(request(1)).await.unwrap();
        store.state.lock().unwrap().failure = Some(failure);
        assert!(matches!(
            store.consume_once(request(2)).await,
            Err(ReplayStoreError::Io(_))
        ));
        assert!(matches!(
            store.consume_once(request(3)).await,
            Err(ReplayStoreError::Unavailable)
        ));
        drop(store);
        let reopened = FileReplayStore::open(&path, options()).await;
        if failure == FailurePoint::PartialAppend {
            assert!(matches!(reopened, Err(ReplayStoreError::Corrupt(_))));
        } else {
            let reopened = reopened.unwrap();
            assert_eq!(
                reopened.consume_once(request(1)).await.unwrap(),
                ConsumeOutcome::AlreadyConsumed
            );
            assert_eq!(
                reopened.consume_once(request(2)).await.unwrap(),
                ConsumeOutcome::AlreadyConsumed
            );
        }
    }
}

#[tokio::test]
async fn compaction_failures_keep_prior_consumption_durable() {
    let temp = tempfile::tempdir().unwrap();
    for (name, failure) in [
        ("before", FailurePoint::BeforeRename),
        ("after", FailurePoint::AfterRename),
    ] {
        let path = temp.path().join(name);
        journal_with_expired_entry(&path).await;
        let store = FileReplayStore::open(&path, options()).await.unwrap();
        store.consume_once(request(2)).await.unwrap();
        store.state.lock().unwrap().failure = Some(failure);
        assert!(matches!(
            store.consume_once(request(3)).await,
            Err(ReplayStoreError::Io(_))
        ));
        drop(store);
        let reopened = FileReplayStore::open(&path, options()).await.unwrap();
        for id in 1..=2 {
            assert_eq!(
                reopened.consume_once(request(id)).await.unwrap(),
                ConsumeOutcome::AlreadyConsumed
            );
        }
        assert_eq!(
            reopened.consume_once(request(3)).await.unwrap(),
            ConsumeOutcome::Consumed
        );
    }
}

#[tokio::test]
async fn clock_rollback_is_rejected_on_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("replay");
    let store = FileReplayStore::open(&path, options()).await.unwrap();
    store.consume_once(request(1)).await.unwrap();
    {
        let mut state = store.state.lock().unwrap();
        state.index.last_seen = now_unix().unwrap() + 30;
        state.compact().unwrap();
    }
    drop(store);
    assert!(matches!(
        FileReplayStore::open(&path, options()).await,
        Err(ReplayStoreError::ClockRollback)
    ));
}

#[tokio::test]
async fn canceled_caller_cannot_interrupt_a_queued_durable_consumption() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("replay");
    let store = FileReplayStore::open(&path, options()).await.unwrap();
    let state = Arc::clone(&store.state);
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let _guard = state.lock().unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    locked_rx.await.unwrap();
    let references = Arc::strong_count(&store.state);
    let pending = store.clone();
    let task = tokio::spawn(async move { pending.consume_once(request(1)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while Arc::strong_count(&store.state) < references + 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();
    blocker.join().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if store
                .state
                .lock()
                .unwrap()
                .index
                .entries
                .contains_key(&ReplayKey([1; 32]))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The blocking job's handle must also be released before reopening.
    while Arc::strong_count(&store.state) != 1 {
        tokio::task::yield_now().await;
    }
    drop(store);
    let reopened = FileReplayStore::open(&path, options()).await.unwrap();
    assert_eq!(
        reopened.consume_once(request(1)).await.unwrap(),
        ConsumeOutcome::AlreadyConsumed
    );
}
