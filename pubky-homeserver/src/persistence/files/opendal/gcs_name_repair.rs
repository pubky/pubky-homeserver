//! Moves the objects that v0.13.0 to v0.16.1 stored under the wrong name in
//! Google Cloud Storage to the name they belong under.
//!
//! Up to 0.57, the GCS service of opendal percent-encoded the name of an
//! upload twice. Those versions uploaded straight to the entry's path, so an
//! entry whose path has a character that GCS keeps encoded, see
//! [`MISNAMED_ENCODE_SET`], was stored under its path percent-encoded once:
//! `a b` under `a%20b`. Reading it fails with 404. Since v0.16.2, uploads go
//! to a staging name without such characters and are published by a copy,
//! which encodes the name once, see
//! [`StagedPublishLayer`](crate::persistence::files::staged_publish_layer::StagedPublishLayer).
//! opendal 0.58.1 encodes the name of an upload once too.
//!
//! On startup, [`GcsNameRepairJob`] goes over every entry whose path has
//! such a character. If the entry's object is missing, it moves the
//! misnamed object to the entry's path; if not, it removes a misnamed object
//! an earlier run copied but failed to delete. Either only if the misnamed
//! object holds the entry's content, and a leftover only if the object in
//! place holds it too: when one entry's misnamed name is another entry's
//! path, as for `c d` and `c%20d`, the object in place may be the other
//! entry's, and the leftover this entry's only copy. Such a conflict is
//! logged and left for manual repair.
//!
//! The move copies only the version of the misnamed object whose content was
//! checked, and only to a path that has no object. A write that lands on
//! either name meanwhile, or another homeserver that moved the object first,
//! makes GCS refuse the copy, and the repair looks at the entry again. Both
//! writes can happen: the misnamed name can be another
//! entry's path, and the entry's path can get an object that no entry
//! refers to, from a write that rolled back after its publish was sent.
//!
//! A run that got through every entry is marked as [`FINISHED_MARKER`] in
//! the migrations table, and later startups skip the repair. A run that
//! failed on any entry is not, so the next startup tries again. Once every
//! deployment has finished it, remove this module.
//!
//! Not repaired:
//! - Misnamed objects of entries deleted before the repair: it only goes over
//!   the entries in the database.
//! - Misnamed objects left over from an older version of an entry that was
//!   overwritten since: they are counted as mismatched and left.
//! - An entry deleted while the repair moves its object: the moved object is
//!   left without an entry.
//!
//! The misnamed names assume the bucket root configured has no character of
//! [`MISNAMED_ENCODE_SET`].

use futures_util::StreamExt;
use opendal::options::ComposeSourceOptions;
use opendal::{ErrorKind, Metadata, Operator};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use pubky_common::crypto::{Hash, Hasher};
use tokio::task::JoinHandle;

use super::opendal_service::gcs_unstaged_backend;
use crate::data_directory::storage_config::GoogleBucketConfig;
use crate::persistence::files::staged_publish_layer::ExpectedGeneration;
use crate::persistence::sql::entry::{EntryEntity, EntryRepository};
use crate::persistence::sql::{Migrator, SqlDb};
use crate::shared::webdav::EntryPath;

/// The characters GCS kept percent-encoded in the name of a misnamed upload.
/// It kept the others as they are. Found against a real bucket, for single
/// request and multipart uploads alike.
const MISNAMED_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'*')
    .remove(b'!')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'~')
    .remove(b'/');

/// Matches an entry path with a character in [`MISNAMED_ENCODE_SET`]: every
/// byte of a non-ASCII character is in it too.
const AFFECTED_PATH_PATTERN: &str = "[^-A-Za-z0-9_.*!'()~/]";

/// Marks the repair as finished in the migrations table. Not a migration: it
/// is not in the migrator's list and runs in the background, after startup.
const FINISHED_MARKER: &str = "gcs_repair_object_names_2026_10";

/// Entries read from the database at a time.
const BATCH_SIZE: u64 = 100;

/// How many times the repair looks at an entry whose copy GCS keeps
/// refusing, before it counts the entry as failed.
const ATTEMPTS_PER_ENTRY: usize = 2;

/// The name the object of `path` was stored under by an affected version.
fn misnamed_object_name(path: &EntryPath) -> String {
    utf8_percent_encode(path.as_str(), MISNAMED_ENCODE_SET).to_string()
}

/// Whether `error` says the object does not exist. A read of a stream
/// reports it as an I/O error wrapping the opendal one.
fn is_not_found(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<opendal::Error>() {
        return error.kind() == ErrorKind::NotFound;
    }
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Runs the repair once in the background. Dropping it stops the repair.
pub(crate) struct GcsNameRepairJob {
    handle: JoinHandle<()>,
}

impl GcsNameRepairJob {
    /// Start the repair of the objects in the bucket of `config`.
    pub(crate) fn start(config: &GoogleBucketConfig, sql_db: SqlDb) -> Self {
        let operator = build_operator(config);
        let handle = tokio::spawn(async move {
            let operator = match operator {
                Ok(operator) => operator,
                Err(error) => {
                    tracing::error!(%error, "GCS name repair could not start");
                    return;
                }
            };
            let repair = GcsNameRepair { operator, sql_db };
            match repair.run_once().await {
                Ok(RepairRun::AlreadyFinished) => {
                    tracing::debug!("GCS name repair finished before; skipping");
                }
                Ok(RepairRun::Ran(summary)) if summary.is_complete() && summary.conflict == 0 => {
                    tracing::info!(?summary, "GCS name repair finished");
                }
                Ok(RepairRun::Ran(summary)) if summary.is_complete() => {
                    tracing::warn!(
                        ?summary,
                        "GCS name repair finished; the conflicts logged are left for manual repair"
                    );
                }
                Ok(RepairRun::Ran(summary)) => {
                    tracing::warn!(
                        ?summary,
                        "GCS name repair failed on some entries; it runs again on next startup"
                    );
                }
                Err(error) => tracing::error!(%error, "GCS name repair stopped"),
            }
        });
        Self { handle }
    }
}

impl Drop for GcsNameRepairJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// The backend the repair runs on, without the staged publish: the repair
/// copies and deletes objects itself, under conditions of its own.
fn build_operator(config: &GoogleBucketConfig) -> anyhow::Result<Operator> {
    let builder = config.to_builder()?;
    Ok(gcs_unstaged_backend(builder)?)
}

/// What one start of the repair did.
#[derive(Debug, PartialEq, Eq)]
enum RepairRun {
    /// An earlier run got through every entry; this one did nothing.
    AlreadyFinished,
    /// The repair went over every affected entry.
    Ran(Summary),
}

/// What the repair did with one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The object is under the entry's path, and no misnamed object with the
    /// entry's content is left to remove.
    InPlace,
    /// The misnamed object was moved to the entry's path.
    Moved,
    /// The misnamed object was copied to the entry's path, and kept because
    /// it is another entry's object.
    Copied,
    /// The object is under the entry's path, put there by an earlier run or
    /// by a write meanwhile, and the misnamed copy of the entry's content
    /// was removed.
    LeftoverRemoved,
    /// Neither the object nor a misnamed one exists.
    Missing,
    /// The misnamed object does not hold the entry's content. If the object
    /// is in place, the misnamed one is left over from an older version of
    /// the entry.
    Mismatch,
    /// The misnamed object holds the entry's content, but the object under
    /// the entry's path does not. That object is another entry's misnamed
    /// object, as when a user has both `c d` and `c%20d`, or a write to the
    /// path is in progress. Both are left as they are.
    Conflict,
}

/// What one look at an entry came to.
enum Attempt {
    Finished(Outcome),
    /// The objects changed while the repair looked at them, so the entry is
    /// looked at again: the misnamed object changed or was deleted, as when
    /// another homeserver moved it, or the entry's path got an object. GCS
    /// refusing the copy does not tell which.
    Raced,
}

/// How many entries ended in each outcome.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    in_place: u64,
    moved: u64,
    copied: u64,
    leftover_removed: u64,
    missing: u64,
    mismatch: u64,
    conflict: u64,
    failed: u64,
}

impl Summary {
    /// Whether every entry got its final outcome. A missing, mismatched or
    /// conflicting object is final: another run would find the same.
    fn is_complete(&self) -> bool {
        self.failed == 0
    }

    fn count(&mut self, outcome: Outcome) {
        let counter = match outcome {
            Outcome::InPlace => &mut self.in_place,
            Outcome::Moved => &mut self.moved,
            Outcome::Copied => &mut self.copied,
            Outcome::LeftoverRemoved => &mut self.leftover_removed,
            Outcome::Missing => &mut self.missing,
            Outcome::Mismatch => &mut self.mismatch,
            Outcome::Conflict => &mut self.conflict,
        };
        *counter += 1;
    }
}

/// What an affected version left of an entry under the misnamed name.
enum MisnamedCopy {
    /// A misnamed object that holds the entry's content.
    Found(MisnamedObject),
    /// No misnamed object of the entry: none at all, or another entry's
    /// object under that entry's path.
    Absent,
    /// A misnamed object with other content that is not another entry's
    /// object: left over from an older version of the entry.
    OtherContent,
    /// A misnamed object that was deleted while its content was read, as
    /// when another homeserver moved it.
    Vanished,
}

/// A misnamed object, as the repair saw it.
struct MisnamedObject {
    name: String,
    /// Its generation when seen, read before its content was checked. A copy
    /// or delete conditional on it applies only if no write landed since, so
    /// the content checked is the content copied, and a delete spares an
    /// object written since.
    generation: u64,
    /// Its content type, kept on the copy.
    content_type: Option<String>,
}

/// Repairs the objects of the affected entries, and records in the
/// migrations table when a run got through all of them, so the repair runs
/// to completion once.
struct GcsNameRepair {
    /// The backend, without the staged publish.
    operator: Operator,
    sql_db: SqlDb,
}

impl GcsNameRepair {
    /// Repair every affected entry unless an earlier run finished the
    /// repair, and mark it as finished if no entry failed.
    async fn run_once(&self) -> anyhow::Result<RepairRun> {
        let migrator = Migrator::new(&self.sql_db);
        if migrator.is_applied(FINISHED_MARKER).await? {
            return Ok(RepairRun::AlreadyFinished);
        }
        let summary = self.repair_all_affected_entries().await?;
        if summary.is_complete() {
            self.mark_finished(&migrator).await?;
        }
        Ok(RepairRun::Ran(summary))
    }

    /// Mark the repair as finished. Already marked by another homeserver
    /// that ran it on the same database at the same time is fine.
    async fn mark_finished(&self, migrator: &Migrator<'_>) -> anyhow::Result<()> {
        let mut tx = self.sql_db.pool().begin().await?;
        if let Err(error) = migrator
            .mark_migration_as_done(&mut tx, FINISHED_MARKER)
            .await
        {
            let already_marked = error
                .downcast_ref::<sqlx::Error>()
                .and_then(|error| error.as_database_error())
                .is_some_and(|error| error.is_unique_violation());
            return if already_marked { Ok(()) } else { Err(error) };
        }
        tx.commit().await?;
        Ok(())
    }

    /// Repair the affected entries in id order, logging each that needed
    /// something. A failure on one entry is counted, and the rest go on.
    async fn repair_all_affected_entries(&self) -> Result<Summary, sqlx::Error> {
        tracing::info!("GCS name repair started");
        let mut summary = Summary::default();
        let mut after_id = 0;
        loop {
            let batch = EntryRepository::list_by_path_pattern(
                AFFECTED_PATH_PATTERN,
                after_id,
                BATCH_SIZE,
                &mut self.sql_db.pool().into(),
            )
            .await?;
            let Some(last) = batch.last() else {
                return Ok(summary);
            };
            after_id = last.id;
            for entry in &batch {
                match self.repair(entry).await {
                    Ok(Outcome::InPlace) => summary.count(Outcome::InPlace),
                    Ok(Outcome::Conflict) => {
                        tracing::warn!(
                            path = %entry.path,
                            misnamed = %misnamed_object_name(&entry.path),
                            "GCS name repair: the object at the entry's path does not hold the \
                             entry's content (another entry's misnamed object, or a write in \
                             progress); the misnamed copy is kept for manual repair"
                        );
                        summary.count(Outcome::Conflict);
                    }
                    Ok(outcome) => {
                        tracing::info!(path = %entry.path, ?outcome, "GCS name repair");
                        summary.count(outcome);
                    }
                    Err(error) => {
                        tracing::warn!(path = %entry.path, %error, "GCS name repair failed");
                        summary.failed += 1;
                    }
                }
            }
        }
    }

    /// Repair one entry. Only a misnamed object that holds the entry's
    /// content is touched. Fails if the objects changed on every attempt.
    async fn repair(&self, entry: &EntryEntity) -> anyhow::Result<Outcome> {
        for _ in 0..ATTEMPTS_PER_ENTRY {
            if let Attempt::Finished(outcome) = self.attempt_repair(entry).await? {
                return Ok(outcome);
            }
        }
        anyhow::bail!(
            "the objects changed on all {ATTEMPTS_PER_ENTRY} attempts: writes or another \
             homeserver kept changing the entry's path or its misnamed name"
        )
    }

    /// Look at the entry's path and its misnamed name, and repair what they
    /// hold.
    async fn attempt_repair(&self, entry: &EntryEntity) -> anyhow::Result<Attempt> {
        match self.operator.stat(entry.path.as_str()).await {
            Ok(in_place) => Ok(Attempt::Finished(
                self.remove_leftover(entry, &in_place).await?,
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => self.move_misnamed(entry).await,
            Err(error) => Err(error.into()),
        }
    }

    /// Move the misnamed object to the entry's path, which had no object
    /// when looked at.
    async fn move_misnamed(&self, entry: &EntryEntity) -> anyhow::Result<Attempt> {
        let misnamed = match self.find_misnamed_copy(entry).await? {
            MisnamedCopy::Found(misnamed) => misnamed,
            MisnamedCopy::Absent => return Ok(Attempt::Finished(Outcome::Missing)),
            MisnamedCopy::OtherContent => return Ok(Attempt::Finished(Outcome::Mismatch)),
            MisnamedCopy::Vanished => return Ok(Attempt::Raced),
        };
        match self.copy_as_checked(&misnamed, entry.path.as_str()).await {
            Ok(()) => {}
            // A replaced or deleted source is answered with 404, as its checked
            // generation is gone, and an object at the path with 412.
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConditionNotMatch | ErrorKind::NotFound
                ) =>
            {
                return Ok(Attempt::Raced)
            }
            Err(error) => return Err(error.into()),
        }
        if self.is_object_of_an_entry(&misnamed.name).await? {
            return Ok(Attempt::Finished(Outcome::Copied));
        }
        self.delete_unless_replaced(&misnamed).await?;
        Ok(Attempt::Finished(Outcome::Moved))
    }

    /// Remove the misnamed object that an earlier run copied to the entry's
    /// path but failed to delete, or that a write to the path left behind,
    /// if the object in place holds the entry's content. If not, the object
    /// in place is another entry's misnamed object, or one that no entry
    /// refers to, and the misnamed one may be this entry's only copy.
    async fn remove_leftover(
        &self,
        entry: &EntryEntity,
        in_place: &Metadata,
    ) -> anyhow::Result<Outcome> {
        let misnamed = match self.find_misnamed_copy(entry).await? {
            MisnamedCopy::Found(misnamed) => misnamed,
            // Gone either way: nothing is left to remove.
            MisnamedCopy::Absent | MisnamedCopy::Vanished => return Ok(Outcome::InPlace),
            MisnamedCopy::OtherContent => return Ok(Outcome::Mismatch),
        };
        if !self
            .holds_content(entry.path.as_str(), in_place.content_length(), entry)
            .await?
        {
            return Ok(Outcome::Conflict);
        }
        self.delete_leftover(&misnamed).await
    }

    /// Delete `misnamed`, a copy of an object that is in place, unless it is
    /// another entry's object.
    async fn delete_leftover(&self, misnamed: &MisnamedObject) -> anyhow::Result<Outcome> {
        if self.is_object_of_an_entry(&misnamed.name).await? {
            return Ok(Outcome::InPlace);
        }
        self.delete_unless_replaced(misnamed).await?;
        Ok(Outcome::LeftoverRemoved)
    }

    /// Look up the misnamed object of `entry` and compare its content with
    /// the entry's.
    async fn find_misnamed_copy(&self, entry: &EntryEntity) -> anyhow::Result<MisnamedCopy> {
        let name = misnamed_object_name(&entry.path);
        let metadata = match self.operator.stat(&name).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(MisnamedCopy::Absent),
            Err(error) => return Err(error.into()),
        };
        let holds_content = match self
            .holds_content(&name, metadata.content_length(), entry)
            .await
        {
            Ok(holds_content) => holds_content,
            Err(error) if is_not_found(&error) => return Ok(MisnamedCopy::Vanished),
            Err(error) => return Err(error),
        };
        if !holds_content {
            if self.is_object_of_an_entry(&name).await? {
                return Ok(MisnamedCopy::Absent);
            }
            return Ok(MisnamedCopy::OtherContent);
        }
        let generation = metadata
            .version()
            .and_then(|version| version.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("GCS reported no generation for {name}"))?;
        Ok(MisnamedCopy::Found(MisnamedObject {
            name,
            generation,
            content_type: metadata.content_type().map(str::to_owned),
        }))
    }

    /// Whether the object `name` of `length` bytes holds the entry's
    /// content. Reads the whole object to hash it when its length matches.
    async fn holds_content(
        &self,
        name: &str,
        length: u64,
        entry: &EntryEntity,
    ) -> anyhow::Result<bool> {
        Ok(length == entry.content_length && self.content_hash(name).await? == entry.content_hash)
    }

    async fn content_hash(&self, name: &str) -> anyhow::Result<Hash> {
        let mut stream = self
            .operator
            .reader(name)
            .await?
            .into_bytes_stream(..)
            .await?;
        let mut hasher = Hasher::new();
        while let Some(chunk) = stream.next().await {
            hasher.update(&chunk?);
        }
        Ok(hasher.finalize())
    }

    /// Copy the generation of `misnamed` whose content was checked to `to`,
    /// conditional on `to` having no object, so only checked content is
    /// copied and a write to `to` is never replaced.
    ///
    /// A compose of one source, not a copy: opendal's GCS service does not
    /// take a source generation on a copy, but does on a compose. The object
    /// it makes is a composite one, which GCS keeps a CRC32C but no MD5 for,
    /// and which gets no metadata but the content type passed here.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::ConditionNotMatch`] if `to` has an object, and
    /// [`ErrorKind::NotFound`] if the checked generation of `misnamed` was
    /// replaced or deleted since.
    async fn copy_as_checked(&self, misnamed: &MisnamedObject, to: &str) -> opendal::Result<()> {
        let checked_source = ComposeSourceOptions {
            version: Some(misnamed.generation.to_string()),
            ..ComposeSourceOptions::default()
        };
        let mut compose = self
            .operator
            .compose_with([(misnamed.name.as_str(), checked_source)], to)
            .if_version_match(&ExpectedGeneration::Absent.version_condition());
        if let Some(content_type) = &misnamed.content_type {
            compose = compose.content_type(content_type);
        }
        compose.await?;
        Ok(())
    }

    /// Whether `name` is the path of an entry, which makes the object under
    /// it that entry's.
    async fn is_object_of_an_entry(&self, name: &str) -> Result<bool, sqlx::Error> {
        let Ok(path) = name.parse::<EntryPath>() else {
            return Ok(false);
        };
        match EntryRepository::get_by_path(&path, &mut self.sql_db.pool().into()).await {
            Ok(_) => Ok(true),
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Delete `misnamed`, conditional on its generation, so that an object a
    /// write has put there since it was seen stays. GCS also refuses the
    /// delete when the object is gone; then another repair running at the
    /// same time removed it, and the delete is done.
    async fn delete_unless_replaced(&self, misnamed: &MisnamedObject) -> opendal::Result<()> {
        let generation = ExpectedGeneration::Known(misnamed.generation);
        let deleted = self
            .operator
            .delete_with(&misnamed.name)
            .if_version_match(&generation.version_condition())
            .await;
        match deleted {
            Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {
                if self.operator.exists(&misnamed.name).await? {
                    Err(error)
                } else {
                    Ok(())
                }
            }
            deleted => deleted,
        }
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::{hash, Keypair};

    use super::super::opendal_service::gcs_operator;
    use super::*;
    use crate::persistence::files::staged_publish_layer::{
        under_expected_generation, STAGING_PREFIX,
    };
    use crate::persistence::sql::user::UserEntity;
    use crate::services::user_service::UserService;
    use crate::shared::webdav::StoragePath;

    fn entry_path(path: &str) -> EntryPath {
        let pubkey: pubky_common::crypto::PublicKey =
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
                .parse()
                .unwrap();
        EntryPath::new(pubkey, StoragePath::new(path).unwrap())
    }

    /// The names an affected version stored these paths under, as listed
    /// from a real bucket.
    #[test]
    fn misnamed_object_name_is_the_name_gcs_stored() {
        let cases = [
            ("/pub/plain.txt", "/pub/plain.txt"),
            ("/pub/Teest%20share/.keep", "/pub/Teest%2520share/.keep"),
            ("/pub/a b.txt", "/pub/a%20b.txt"),
            (
                "/pub/!\"#$%&'()*+,:;<=>?@[]^`{|}~ \u{fc}",
                "/pub/!%22%23%24%25%26'()*%2B%2C%3A%3B%3C%3D%3E%3F%40%5B%5D%5E%60%7B%7C%7D~%20%C3%BC",
            ),
            ("/pub/-_.*", "/pub/-_.*"),
        ];
        for (path, stored) in cases {
            let path = entry_path(path);
            let expected = format!("{}{stored}", path.pubkey().z32());
            assert_eq!(misnamed_object_name(&path), expected, "{path}");
        }
    }

    /// The pattern lists exactly the entries whose object name an affected
    /// version changed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn affected_path_pattern_matches_the_paths_that_were_misnamed() {
        let db = SqlDb::test().await;
        let pubkey = Keypair::random().public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();
        let mut affected = Vec::new();
        let characters = (b' '..=b'~').map(char::from).chain(['\u{fc}', '\u{b7}']);
        for character in characters {
            // A separator, not a character of a name.
            if character == '/' {
                continue;
            }
            // A character a path cannot have.
            let Ok(path) = StoragePath::new(&format!("/pub/a{character}b")) else {
                continue;
            };
            EntryRepository::create(
                user.id,
                &path,
                &Hash::from_bytes([0; 32]),
                0,
                "text/plain",
                &mut db.pool().into(),
            )
            .await
            .unwrap();
            let path = EntryPath::new(pubkey.clone(), path);
            if misnamed_object_name(&path) != path.as_str() {
                affected.push(path);
            }
        }

        let listed: Vec<EntryPath> = EntryRepository::list_by_path_pattern(
            AFFECTED_PATH_PATTERN,
            0,
            1000,
            &mut db.pool().into(),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.path)
        .collect();

        assert_eq!(listed, affected);
    }

    /// Creates an entry of `user` for `content` at `path`, without storing
    /// an object.
    async fn create_entry(db: &SqlDb, user: &UserEntity, path: &str, content: &[u8]) -> EntryPath {
        let path = StoragePath::new(path).unwrap();
        EntryRepository::create(
            user.id,
            &path,
            &hash(content),
            content.len() as u64,
            "application/octet-stream",
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        EntryPath::new(user.public_key.clone(), path)
    }

    /// Stores `content` under the name an affected version stored `path`
    /// under, with an entry for it.
    async fn misnamed_entry(
        db: &SqlDb,
        operator: &Operator,
        user: &UserEntity,
        path: &str,
        content: &[u8],
    ) -> EntryPath {
        let path = create_entry(db, user, path, content).await;
        operator
            .write(&misnamed_object_name(&path), content.to_vec())
            .await
            .unwrap();
        path
    }

    /// Stores `content` under `path`, as a fixed version does, with an entry
    /// for it.
    async fn entry_in_place(
        db: &SqlDb,
        operator: &Operator,
        user: &UserEntity,
        path: &str,
        content: &[u8],
    ) -> EntryPath {
        let path = create_entry(db, user, path, content).await;
        operator
            .write(path.as_str(), content.to_vec())
            .await
            .unwrap();
        path
    }

    /// A run that got through every entry is marked, and the repair does
    /// not run again.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_complete_run_is_marked_and_not_repeated() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let repair = GcsNameRepair {
            operator: fs.layer(Versioned::new("7")),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let first = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        assert_eq!(
            repair.run_once().await.unwrap(),
            RepairRun::Ran(Summary {
                moved: 1,
                ..Summary::default()
            })
        );
        assert!(repair.operator.exists(first.as_str()).await.unwrap());
        assert!(Migrator::new(&db)
            .is_applied(FINISHED_MARKER)
            .await
            .unwrap());

        let second = misnamed_entry(&db, &repair.operator, &user, "/pub/c d", b"c").await;
        assert_eq!(repair.run_once().await.unwrap(), RepairRun::AlreadyFinished);
        assert!(!repair.operator.exists(second.as_str()).await.unwrap());
    }

    /// A run that failed on an entry is not marked, and the next run
    /// finishes the entry: here, removing the misnamed object it copied.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_run_that_failed_on_an_entry_runs_again() {
        use std::sync::atomic::Ordering;

        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;
        let misnamed = misnamed_object_name(&path);

        versioned.refuse_deletes.store(true, Ordering::SeqCst);
        assert_eq!(
            repair.run_once().await.unwrap(),
            RepairRun::Ran(Summary {
                failed: 1,
                ..Summary::default()
            })
        );
        assert!(repair.operator.exists(path.as_str()).await.unwrap());
        assert!(repair.operator.exists(&misnamed).await.unwrap());
        assert!(!Migrator::new(&db)
            .is_applied(FINISHED_MARKER)
            .await
            .unwrap());

        versioned.refuse_deletes.store(false, Ordering::SeqCst);
        assert_eq!(
            repair.run_once().await.unwrap(),
            RepairRun::Ran(Summary {
                leftover_removed: 1,
                ..Summary::default()
            })
        );
        assert!(!repair.operator.exists(&misnamed).await.unwrap());
        assert_eq!(
            repair.operator.read(path.as_str()).await.unwrap().to_vec(),
            b"a".to_vec()
        );
        assert!(Migrator::new(&db)
            .is_applied(FINISHED_MARKER)
            .await
            .unwrap());
    }

    /// Runs the repair over every affected entry, and while its first copy is
    /// held back, lets `write_meanwhile` change the bucket. The copy is then
    /// refused, as GCS refuses a copy whose source or destination changed.
    async fn repair_with_a_write_before_the_copy(
        repair: &GcsNameRepair,
        versioned: &super::super::opendal_test_operators::Versioned,
        write_meanwhile: impl std::future::Future<Output = ()>,
    ) -> Summary {
        use std::sync::atomic::Ordering;

        let release = versioned.stall_next_compose();
        let (summary, ()) = tokio::join!(repair.repair_all_affected_entries(), async {
            versioned.until_compose_stalled().await;
            write_meanwhile.await;
            versioned.refuse_composes.store(true, Ordering::SeqCst);
            release.send(()).unwrap();
        });
        summary.unwrap()
    }

    /// A write of the entry's content that lands on the entry's path before
    /// the copy leaves the misnamed object a leftover, which is removed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_write_of_the_entry_content_before_the_copy_leaves_a_leftover_to_remove() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        let write_of_the_entry_content = async {
            repair
                .operator
                .write(path.as_str(), b"a".to_vec())
                .await
                .unwrap();
        };
        assert_eq!(
            repair_with_a_write_before_the_copy(&repair, &versioned, write_of_the_entry_content)
                .await,
            Summary {
                leftover_removed: 1,
                ..Summary::default()
            }
        );
        assert!(!repair
            .operator
            .exists(&misnamed_object_name(&path))
            .await
            .unwrap());
    }

    /// An object that no entry refers to, as a write that rolled back after
    /// its publish was sent leaves it, lands on the entry's path before the
    /// copy. The misnamed object is the entry's only copy and is kept.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_unreferenced_object_landing_before_the_copy_keeps_the_misnamed_one() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        let rolled_back_write = async {
            repair
                .operator
                .write(path.as_str(), b"rolled back".to_vec())
                .await
                .unwrap();
        };
        assert_eq!(
            repair_with_a_write_before_the_copy(&repair, &versioned, rolled_back_write).await,
            Summary {
                conflict: 1,
                ..Summary::default()
            }
        );
        assert_eq!(
            repair
                .operator
                .read(&misnamed_object_name(&path))
                .await
                .unwrap()
                .to_vec(),
            b"a"
        );
    }

    /// A write to the misnamed name, which is another entry's path, that
    /// lands after the misnamed object's content was checked is not copied
    /// to the entry's path.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_write_to_the_misnamed_name_before_the_copy_is_not_copied() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let space = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        let write_to_the_encoded_path = async {
            entry_in_place(&db, &repair.operator, &user, "/pub/a%20b", b"encoded").await;
        };
        assert_eq!(
            repair_with_a_write_before_the_copy(&repair, &versioned, write_to_the_encoded_path)
                .await,
            Summary {
                // `/pub/a b`: its content was overwritten by the user's write.
                missing: 1,
                // `/pub/a%20b`, the user's write.
                in_place: 1,
                ..Summary::default()
            }
        );
        assert!(!repair.operator.exists(space.as_str()).await.unwrap());
    }

    /// Another homeserver that moves the object between this run's content
    /// check and its copy leaves the source deleted. The copy fails with
    /// not found, and the entry is looked at again and found in place.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_object_another_homeserver_moved_before_the_copy_is_in_place() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let other_homeserver = GcsNameRepair {
            operator: repair.operator.clone(),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        let release = versioned.stall_next_compose();
        let (summary, ()) = tokio::join!(repair.repair_all_affected_entries(), async {
            versioned.until_compose_stalled().await;
            assert_eq!(
                other_homeserver
                    .repair_all_affected_entries()
                    .await
                    .unwrap(),
                Summary {
                    moved: 1,
                    ..Summary::default()
                }
            );
            release.send(()).unwrap();
        });

        assert_eq!(
            summary.unwrap(),
            Summary {
                in_place: 1,
                ..Summary::default()
            }
        );
        assert_eq!(
            repair.operator.read(path.as_str()).await.unwrap().to_vec(),
            b"a"
        );
    }

    /// Another homeserver that moves the object while this run reads it to
    /// check its content leaves the read failing with not found. The entry
    /// is looked at again and found in place.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_object_another_homeserver_moved_during_the_content_check_is_in_place() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let other_homeserver = GcsNameRepair {
            operator: repair.operator.clone(),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;

        let release = versioned.stall_next_read();
        let (summary, ()) = tokio::join!(repair.repair_all_affected_entries(), async {
            versioned.until_read_stalled().await;
            assert_eq!(
                other_homeserver
                    .repair_all_affected_entries()
                    .await
                    .unwrap(),
                Summary {
                    moved: 1,
                    ..Summary::default()
                }
            );
            release.send(()).unwrap();
        });

        assert_eq!(
            summary.unwrap(),
            Summary {
                in_place: 1,
                ..Summary::default()
            }
        );
    }

    /// The repair reads the affected entries in batches: entries on both
    /// sides of a batch boundary, among unaffected ones, are each moved once.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn entries_over_several_batches_are_each_moved_once() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let repair = GcsNameRepair {
            operator: fs.layer(Versioned::new("7")),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let affected_count = 2 * BATCH_SIZE + 1;
        let mut affected = Vec::new();
        for i in 0..affected_count {
            entry_in_place(
                &db,
                &repair.operator,
                &user,
                &format!("/pub/plain{i}"),
                b"x",
            )
            .await;
            let content = format!("content {i}").into_bytes();
            let path = format!("/pub/a b {i}");
            let path = misnamed_entry(&db, &repair.operator, &user, &path, &content).await;
            affected.push((path, content));
        }

        assert_eq!(
            repair.repair_all_affected_entries().await.unwrap(),
            Summary {
                moved: affected_count,
                ..Summary::default()
            }
        );
        for (path, content) in &affected {
            assert_eq!(
                &repair.operator.read(path.as_str()).await.unwrap().to_vec(),
                content
            );
        }
    }

    /// Identical content under colliding names, as empty `.keep` files are:
    /// the content check passes for both entries, and both end up served,
    /// with no misnamed object left, in either id order.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn identical_content_under_colliding_names_is_placed_for_both() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        for space_first in [true, false] {
            let db = SqlDb::test().await;
            let (fs, _tmp_dir) = get_fs_operator();
            let repair = GcsNameRepair {
                operator: fs.layer(Versioned::new("7")),
                sql_db: db.clone(),
            };
            let user = UserService::new(db.clone())
                .create(&Keypair::random().public_key())
                .await
                .unwrap();
            let mut names = ["/pub/Teest share/.keep", "/pub/Teest%20share/.keep"];
            if !space_first {
                names.reverse();
            }
            let mut paths = Vec::new();
            for name in names {
                paths.push(misnamed_entry(&db, &repair.operator, &user, name, b"").await);
            }

            assert_eq!(
                repair.repair_all_affected_entries().await.unwrap(),
                Summary {
                    copied: 1,
                    leftover_removed: 1,
                    ..Summary::default()
                },
                "space first: {space_first}"
            );
            let mut stored: Vec<String> = repair
                .operator
                .list_with("")
                .recursive(true)
                .await
                .unwrap()
                .into_iter()
                .filter(|entry| entry.metadata().is_file())
                .map(|entry| entry.path().to_string())
                .collect();
            stored.sort();
            let mut expected: Vec<String> = paths.iter().map(|path| path.to_string()).collect();
            expected.sort();
            assert_eq!(stored, expected, "space first: {space_first}");
        }
    }

    /// An entry whose copy GCS refuses on every attempt fails, so the run is
    /// not marked and the next startup tries again.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_entry_whose_copy_is_always_refused_fails() {
        use std::sync::atomic::Ordering;

        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = misnamed_entry(&db, &repair.operator, &user, "/pub/a b", b"a").await;
        versioned.refuse_composes.store(true, Ordering::SeqCst);

        assert_eq!(
            repair.run_once().await.unwrap(),
            RepairRun::Ran(Summary {
                failed: 1,
                ..Summary::default()
            })
        );
        assert_eq!(versioned.seen.lock().unwrap().len(), ATTEMPTS_PER_ENTRY);
        assert!(repair
            .operator
            .exists(&misnamed_object_name(&path))
            .await
            .unwrap());
        assert!(!Migrator::new(&db)
            .is_applied(FINISHED_MARKER)
            .await
            .unwrap());
    }

    /// A misnamed object with other content next to the entry's object is
    /// left over from an older version: a mismatch, left as it is.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_misnamed_object_of_an_older_version_is_a_kept_mismatch() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let repair = GcsNameRepair {
            operator: fs.layer(Versioned::new("7")),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let path = entry_in_place(&db, &repair.operator, &user, "/pub/a b", b"new").await;
        let misnamed = misnamed_object_name(&path);
        repair
            .operator
            .write(&misnamed, b"old".to_vec())
            .await
            .unwrap();

        assert_eq!(
            repair.repair_all_affected_entries().await.unwrap(),
            Summary {
                mismatch: 1,
                ..Summary::default()
            }
        );
        assert_eq!(
            repair.operator.read(path.as_str()).await.unwrap().to_vec(),
            b"new"
        );
        assert_eq!(
            repair.operator.read(&misnamed).await.unwrap().to_vec(),
            b"old"
        );
    }

    /// A misnamed name that is another entry's path holds that entry's
    /// object, which says nothing about the first entry: it is in place if
    /// its object is, and missing if not.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn another_entry_object_under_the_misnamed_name_is_no_mismatch() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let repair = GcsNameRepair {
            operator: fs.layer(Versioned::new("7")),
            sql_db: db.clone(),
        };
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        entry_in_place(&db, &repair.operator, &user, "/pub/c d", b"space").await;
        entry_in_place(&db, &repair.operator, &user, "/pub/c%20d", b"encoded").await;
        create_entry(&db, &user, "/pub/e f", b"space").await;
        entry_in_place(&db, &repair.operator, &user, "/pub/e%20f", b"encoded").await;

        assert_eq!(
            repair.repair_all_affected_entries().await.unwrap(),
            Summary {
                in_place: 3,
                missing: 1,
                ..Summary::default()
            }
        );
    }

    /// A refused delete of a misnamed object that is still there fails. One
    /// of an object that another repair removed meanwhile is done.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_misnamed_object_removed_meanwhile_counts_as_deleted() {
        use std::sync::atomic::Ordering;

        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let repair = GcsNameRepair {
            operator: fs.layer(versioned.clone()),
            sql_db: SqlDb::test().await,
        };
        let seen = MisnamedObject {
            name: "pk/pub/a%20b".to_string(),
            generation: 7,
            content_type: None,
        };
        repair
            .operator
            .write(&seen.name, b"a".to_vec())
            .await
            .unwrap();

        versioned.refuse_deletes.store(true, Ordering::SeqCst);
        repair
            .delete_unless_replaced(&seen)
            .await
            .expect_err("a refused delete of an object still there fails");
        versioned.refuse_deletes.store(false, Ordering::SeqCst);

        repair.operator.delete(&seen.name).await.unwrap();
        repair.delete_unless_replaced(&seen).await.unwrap();
    }

    /// When one entry's misnamed name is another entry's path, the object
    /// under that path is the first entry's. The second entry's content is
    /// only under its own misnamed name, which is kept, in either id order.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_misnamed_name_that_is_another_entry_path_loses_no_content() {
        use super::super::opendal_test_operators::{get_fs_operator, Versioned};

        for space_first in [true, false] {
            let db = SqlDb::test().await;
            let (fs, _tmp_dir) = get_fs_operator();
            let repair = GcsNameRepair {
                operator: fs.layer(Versioned::new("7")),
                sql_db: db.clone(),
            };
            let user = UserService::new(db.clone())
                .create(&Keypair::random().public_key())
                .await
                .unwrap();
            let mut files = [("/pub/c d", &b"space"[..]), ("/pub/c%20d", &b"encoded"[..])];
            if !space_first {
                files.reverse();
            }
            let mut paths = Vec::new();
            for (path, content) in files {
                paths.push(misnamed_entry(&db, &repair.operator, &user, path, content).await);
            }
            if !space_first {
                paths.reverse();
            }
            let [space, encoded] = <[EntryPath; 2]>::try_from(paths).unwrap();
            assert_eq!(misnamed_object_name(&space), encoded.as_str());

            assert_eq!(
                repair.repair_all_affected_entries().await.unwrap(),
                Summary {
                    copied: 1,
                    conflict: 1,
                    ..Summary::default()
                },
                "space first: {space_first}"
            );
            let read = |name: String| {
                let operator = repair.operator.clone();
                async move { operator.read(&name).await.unwrap().to_vec() }
            };
            assert_eq!(read(space.as_str().to_string()).await, b"space");
            assert_eq!(read(encoded.as_str().to_string()).await, b"space");
            assert_eq!(read(misnamed_object_name(&encoded)).await, b"encoded");
        }
    }

    /// Marking the repair as finished succeeds when another homeserver on the
    /// same database marked it meanwhile.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn marking_an_already_finished_repair_succeeds() {
        use super::super::opendal_test_operators::get_fs_operator;

        let db = SqlDb::test().await;
        let (fs, _tmp_dir) = get_fs_operator();
        let repair = GcsNameRepair {
            operator: fs,
            sql_db: db.clone(),
        };
        let migrator = Migrator::new(&db);

        repair.mark_finished(&migrator).await.unwrap();
        repair.mark_finished(&migrator).await.unwrap();
        assert!(migrator.is_applied(FINISHED_MARKER).await.unwrap());
    }

    /// Against the real bucket, see
    /// [`gcs_test_bucket`](super::super::gcs_test_bucket): the objects an
    /// affected version misnamed are moved to their entry's path, and
    /// nothing else is touched.
    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    #[pubky_test_utils::test]
    async fn repair_moves_misnamed_objects_to_their_entry_path() {
        use crate::persistence::files::opendal::gcs_test_bucket::TestBucket;

        let bucket = TestBucket::from_env();
        let _cleaner = bucket.cleaner();
        let operator = gcs_operator(bucket.builder()).unwrap();
        // The backend without the staged publish, to store objects under
        // the names an affected version gave them. Those names are pinned
        // against a real bucket by `misnamed_object_name_is_the_name_gcs_stored`.
        let backend = gcs_unstaged_backend(bucket.builder()).unwrap();
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let small = b"small".to_vec();
        let large = vec![7u8; 6 * 1024 * 1024];

        // Misnamed, below and above the multipart threshold: moved.
        let moved = create_entry(&db, &user, "/pub/Teest%20share/.keep", &small).await;
        backend
            .write(&misnamed_object_name(&moved), small.clone())
            .await
            .unwrap();
        let moved_large = create_entry(&db, &user, "/pub/big file.bin", &large).await;
        backend
            .write(&misnamed_object_name(&moved_large), large.clone())
            .await
            .unwrap();
        // Misnamed, but the object holds other content: left alone.
        let mismatch = create_entry(&db, &user, "/pub/other content", b"expected").await;
        backend
            .write(&misnamed_object_name(&mismatch), small.clone())
            .await
            .unwrap();
        // Written by a fixed version: in place.
        let in_place = create_entry(&db, &user, "/pub/fixed \u{fc}", &small).await;
        under_expected_generation(
            ExpectedGeneration::Absent,
            operator.write(in_place.as_str(), small.clone()),
        )
        .await
        .unwrap();
        // No object at all.
        let missing = create_entry(&db, &user, "/pub/missing file", &small).await;
        // Misnamed under a name that is another entry's path, as when a user
        // has both `c d` and `c%20d`: copied and kept for the other entry,
        // whose own misnamed object is kept as a conflict.
        let copied = create_entry(&db, &user, "/pub/c d", &small).await;
        backend
            .write(&misnamed_object_name(&copied), small.clone())
            .await
            .unwrap();
        let other_content = b"other".to_vec();
        let other = create_entry(&db, &user, "/pub/c%20d", &other_content).await;
        backend
            .write(&misnamed_object_name(&other), other_content.clone())
            .await
            .unwrap();

        let repair = GcsNameRepair {
            operator: gcs_unstaged_backend(bucket.builder()).unwrap(),
            sql_db: db.clone(),
        };
        assert_eq!(
            repair.repair_all_affected_entries().await.unwrap(),
            Summary {
                in_place: 1,
                moved: 2,
                copied: 1,
                missing: 1,
                mismatch: 1,
                conflict: 1,
                ..Summary::default()
            }
        );

        for (name, content) in [
            (moved.to_string(), &small),
            (moved_large.to_string(), &large),
            (in_place.to_string(), &small),
            (copied.to_string(), &small),
            // The conflict: left as it was.
            (other.to_string(), &small),
            (misnamed_object_name(&other), &other_content),
        ] {
            assert_eq!(&operator.read(&name).await.unwrap().to_vec(), content);
        }
        assert!(!operator
            .exists(&misnamed_object_name(&moved))
            .await
            .unwrap());
        assert!(!operator
            .exists(&misnamed_object_name(&moved_large))
            .await
            .unwrap());
        assert!(operator
            .exists(&misnamed_object_name(&mismatch))
            .await
            .unwrap());
        assert!(!operator.exists(mismatch.as_str()).await.unwrap());
        assert!(!operator.exists(missing.as_str()).await.unwrap());
        let staging = operator.list(STAGING_PREFIX).await.unwrap();
        assert!(staging.iter().all(|entry| !entry.metadata().is_file()));

        // A second run finds nothing left to move.
        assert_eq!(
            repair.repair_all_affected_entries().await.unwrap(),
            Summary {
                in_place: 4,
                missing: 1,
                mismatch: 1,
                conflict: 1,
                ..Summary::default()
            }
        );

        // A misnamed object replaced after the repair looked at it stays.
        let replaced = misnamed_object_name(&mismatch);
        let seen = repair.operator.stat(&replaced).await.unwrap();
        let generation = seen.version().unwrap().parse().unwrap();
        under_expected_generation(
            ExpectedGeneration::Known(generation),
            operator.write(&replaced, b"newer".to_vec()),
        )
        .await
        .unwrap();
        let as_seen = MisnamedObject {
            name: replaced.clone(),
            generation,
            content_type: None,
        };
        repair
            .delete_unless_replaced(&as_seen)
            .await
            .expect_err("the delete is conditional on the generation seen");
        assert_eq!(
            operator.read(&replaced).await.unwrap().to_vec(),
            b"newer".to_vec()
        );

        // A copy of it fails too, as the generation seen is gone, and the
        // entry's path stays empty.
        let refused = repair
            .copy_as_checked(&as_seen, mismatch.as_str())
            .await
            .expect_err("the copy reads the source generation seen");
        assert_eq!(refused.kind(), ErrorKind::NotFound);
        assert!(!operator.exists(mismatch.as_str()).await.unwrap());
    }
}
