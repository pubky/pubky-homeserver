//! Single-owner replay journal. Success is returned only after syncing consumption.

use super::replay_store::{
    ConsumeOutcome, ReplayCheck, ReplayIndex, ReplayKey, ReplayRequest, ReplayStore,
    ReplayStoreError, now_unix,
};
use pubky_common::crypto::{Hasher, hash};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAGIC: &[u8; 8] = b"PKYRP001";
// V1 header: magic(8), policy-present(1), policy(32), clock floor(8), checksum(32).
// V1 record: replay key(32), deadline(8), observed time(8), chained checksum(32).
// Timestamps are big-endian Unix seconds. Fixed framing bounds recovery memory.
const HEADER_SIZE: usize = 81;
const RECORD_SIZE: usize = 80;

/// Explicit file-store bounds. Compaction temporarily uses a second bounded file.
#[derive(Clone, Copy, Debug)]
pub struct FileReplayStoreOptions {
    /// Maximum number of unexpired consumption records.
    pub max_entries: usize,
    /// Maximum bytes in the journal, including its header and expired records.
    pub max_journal_bytes: u64,
}

/// Durable replay storage in an exclusively owned local directory.
///
/// Clones share a store. A stable `owner.lock` file excludes other owners, even
/// during compaction. Keep all files together on a trusted local filesystem and
/// never delete or restore older versions while proofs may remain acceptable.
/// Currently supported on Unix, where directory synchronization is available.
/// Memory storage remains available on other native platforms.
#[derive(Clone, Debug)]
pub struct FileReplayStore {
    state: Arc<Mutex<FileState>>,
}

/// The owner lock remains held by blocking jobs even if their caller is canceled.
#[derive(Debug)]
struct FileState {
    directory: PathBuf,
    _owner: File,
    journal: File,
    bytes: u64,
    checksum: [u8; 32],
    index: ReplayIndex,
    options: FileReplayStoreOptions,
    healthy: bool,
    #[cfg(test)]
    failure: Option<FailurePoint>,
}

impl FileReplayStore {
    /// Open or create a replay directory under an existing parent directory.
    ///
    /// Requires a Tokio runtime. Opening, recovery, writes, and compaction run
    /// on its blocking pool. An existing corrupt or missing journal is never reset.
    ///
    /// # Errors
    /// Rejects invalid bounds, another owner, corruption, clock rollback, I/O
    /// failures, or platforms without the required directory-sync support.
    pub async fn open(
        directory: impl AsRef<Path>,
        options: FileReplayStoreOptions,
    ) -> Result<Self, ReplayStoreError> {
        if options.max_entries == 0
            || options.max_journal_bytes < (HEADER_SIZE + RECORD_SIZE) as u64
        {
            return Err(ReplayStoreError::InvalidConfiguration(
                "positive capacity and at least 161 journal bytes required",
            ));
        }
        let directory = directory.as_ref().to_owned();
        let state =
            tokio::task::spawn_blocking(move || FileState::open(&directory, options)).await??;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }
}

#[async_trait::async_trait]
impl ReplayStore for FileReplayStore {
    async fn consume_once(
        &self,
        request: ReplayRequest,
    ) -> Result<ConsumeOutcome, ReplayStoreError> {
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || {
            let mut state = state
                .lock()
                .map_err(|_error| ReplayStoreError::Unavailable)?;
            state.consume(&request)
        })
        .await?
    }
}

impl FileState {
    fn open(directory: &Path, options: FileReplayStoreOptions) -> Result<Self, ReplayStoreError> {
        if !cfg!(unix) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "durable file replay storage currently requires Unix directory synchronization",
            )
            .into());
        }
        match fs::create_dir(directory) {
            Ok(()) => {
                let parent = directory
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                sync_directory(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let directory = fs::canonicalize(directory)?;
        let (owner, new_owner_file) = match file_options()
            .create_new(true)
            .open(directory.join("owner.lock"))
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                (file_options().open(directory.join("owner.lock"))?, false)
            }
            Err(error) => return Err(error.into()),
        };
        match owner.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(ReplayStoreError::AlreadyOpen),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let path = directory.join("journal");
        if new_owner_file {
            let mut journal = file_options().create_new(true).open(&path)?;
            journal.write_all(&header_bytes(&ReplayIndex::default()))?;
            journal.sync_all()?;
            sync_directory(&directory)?;
        }
        let mut journal = file_options().append(true).open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReplayStoreError::Corrupt("missing journal")
            } else {
                ReplayStoreError::Io(error)
            }
        })?;
        let (index, checksum, bytes) = recover(&mut journal, options, now_unix()?)?;
        Ok(Self {
            directory,
            _owner: owner,
            journal,
            bytes,
            checksum,
            index,
            options,
            healthy: true,
            #[cfg(test)]
            failure: None,
        })
    }

    fn consume(&mut self, request: &ReplayRequest) -> Result<ConsumeOutcome, ReplayStoreError> {
        if !self.healthy {
            return Err(ReplayStoreError::Unavailable);
        }
        let now = now_unix()?;
        let check = self.index.prepare(request, now, self.options.max_entries)?;
        if check == ReplayCheck::AlreadyConsumed {
            return Ok(ConsumeOutcome::AlreadyConsumed);
        }
        let compacted_bytes =
            HEADER_SIZE as u64 + (self.index.entries.len() as u64 + 1) * RECORD_SIZE as u64;
        if compacted_bytes > self.options.max_journal_bytes {
            return Err(ReplayStoreError::Capacity);
        }

        // Once I/O starts, any error or panic makes this handle unusable. A canceled
        // async caller cannot cancel the blocking job or skip the index update.
        self.healthy = false;
        if self.index.policy.is_none()
            || self.bytes + RECORD_SIZE as u64 > self.options.max_journal_bytes
        {
            self.index.policy = Some(request.policy);
            self.compact()?;
        }
        let record = record_bytes(request.key, request.expires_at, now, &self.checksum);
        #[cfg(test)]
        if self.failure == Some(FailurePoint::PartialAppend) {
            self.journal.write_all(&record[..17])?;
            self.fail_at(FailurePoint::PartialAppend)?;
        }
        self.journal.write_all(&record)?;
        #[cfg(test)]
        self.fail_at(FailurePoint::BeforeAppendSync)?;
        self.journal.sync_all()?;
        self.checksum.copy_from_slice(&record[48..]);
        self.bytes += RECORD_SIZE as u64;
        self.index.record(request);
        self.healthy = true;
        Ok(ConsumeOutcome::Consumed)
    }

    fn compact(&mut self) -> Result<(), ReplayStoreError> {
        let temporary = self.directory.join("journal.next");
        let mut journal = file_options()
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        let header = header_bytes(&self.index);
        journal.write_all(&header)?;
        let mut checksum: [u8; 32] = header[49..].try_into().expect("fixed header checksum");
        for (&key, &deadline) in &self.index.entries {
            let record = record_bytes(key, deadline, self.index.last_seen, &checksum);
            journal.write_all(&record)?;
            checksum.copy_from_slice(&record[48..]);
        }
        journal.sync_all()?;
        #[cfg(test)]
        self.fail_at(FailurePoint::BeforeRename)?;
        fs::rename(&temporary, self.directory.join("journal"))?;
        #[cfg(test)]
        self.fail_at(FailurePoint::AfterRename)?;
        sync_directory(&self.directory)?;
        self.journal = file_options()
            .append(true)
            .open(self.directory.join("journal"))?;
        self.checksum = checksum;
        self.bytes = HEADER_SIZE as u64 + self.index.entries.len() as u64 * RECORD_SIZE as u64;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailurePoint {
    PartialAppend,
    BeforeAppendSync,
    BeforeRename,
    AfterRename,
}

#[cfg(test)]
impl FileState {
    fn fail_at(&mut self, point: FailurePoint) -> Result<(), ReplayStoreError> {
        if self.failure == Some(point) {
            self.failure = None;
            return Err(std::io::Error::other("injected journal failure").into());
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[path = "file_store_tests.rs"]
mod tests;

fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600)
    };
    options
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

fn header_bytes(index: &ReplayIndex) -> [u8; HEADER_SIZE] {
    let mut bytes = [0; HEADER_SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    if let Some(policy) = index.policy {
        bytes[8] = 1;
        bytes[9..41].copy_from_slice(&policy);
    }
    bytes[41..49].copy_from_slice(&index.last_seen.to_be_bytes());
    let checksum = hash(&bytes[..49]);
    bytes[49..].copy_from_slice(checksum.as_bytes());
    bytes
}

fn record_bytes(
    key: ReplayKey,
    deadline: u64,
    observed: u64,
    previous: &[u8; 32],
) -> [u8; RECORD_SIZE] {
    let mut bytes = [0; RECORD_SIZE];
    bytes[..32].copy_from_slice(key.as_bytes());
    bytes[32..40].copy_from_slice(&deadline.to_be_bytes());
    bytes[40..48].copy_from_slice(&observed.to_be_bytes());
    let mut hasher = Hasher::new();
    hasher.update(previous);
    hasher.update(&bytes[..48]);
    bytes[48..].copy_from_slice(hasher.finalize().as_bytes());
    bytes
}

fn recover(
    journal: &mut File,
    options: FileReplayStoreOptions,
    now: u64,
) -> Result<(ReplayIndex, [u8; 32], u64), ReplayStoreError> {
    let bytes = journal.metadata()?.len();
    if bytes > options.max_journal_bytes {
        return Err(ReplayStoreError::Capacity);
    }
    if bytes < HEADER_SIZE as u64
        || !(bytes - HEADER_SIZE as u64).is_multiple_of(RECORD_SIZE as u64)
    {
        return Err(ReplayStoreError::Corrupt("truncated journal"));
    }
    let mut header = [0; HEADER_SIZE];
    journal.read_exact(&mut header)?;
    if &header[..8] != MAGIC || header[8] > 1 || hash(&header[..49]).as_bytes() != &header[49..] {
        return Err(ReplayStoreError::Corrupt("invalid header"));
    }
    let mut index = ReplayIndex {
        policy: (header[8] == 1).then(|| header[9..41].try_into().expect("fixed policy bytes")),
        last_seen: u64::from_be_bytes(header[41..49].try_into().expect("fixed timestamp")),
        ..ReplayIndex::default()
    };
    let mut checksum: [u8; 32] = header[49..].try_into().expect("fixed checksum");
    for _ in 0..(bytes - HEADER_SIZE as u64) / RECORD_SIZE as u64 {
        let mut record = [0; RECORD_SIZE];
        journal.read_exact(&mut record)?;
        let key = ReplayKey(record[..32].try_into().expect("fixed replay key"));
        let deadline = u64::from_be_bytes(record[32..40].try_into().expect("fixed deadline"));
        let observed = u64::from_be_bytes(record[40..48].try_into().expect("fixed timestamp"));
        if record != record_bytes(key, deadline, observed, &checksum)
            || index.policy.is_none()
            || observed < index.last_seen
            || deadline <= observed
        {
            return Err(ReplayStoreError::Corrupt("invalid consumption record"));
        }
        if index
            .entries
            .get(&key)
            .is_some_and(|previous| *previous > observed)
        {
            return Err(ReplayStoreError::Corrupt("duplicate live consumption"));
        }
        checksum.copy_from_slice(&record[48..]);
        index.last_seen = observed;
        if deadline > now {
            index.entries.insert(key, deadline);
            if index.entries.len() > options.max_entries {
                return Err(ReplayStoreError::Capacity);
            }
        }
    }
    if now < index.last_seen {
        return Err(ReplayStoreError::ClockRollback);
    }
    index.last_seen = now;
    Ok((index, checksum, bytes))
}
