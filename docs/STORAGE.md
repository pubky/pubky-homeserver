# Storage Operations

The homeserver keeps file metadata in PostgreSQL and file contents in the configured
storage backend. Replacing a file writes a separate blob before updating its database
entry. Readers use the selected version, even if a newer version is published.

## Cleanup and Storage Limits

Replaced and deleted blobs are normally kept for one hour so in-progress downloads
can finish. Cleanup runs every 15 minutes. A download or copy still using a blob
after it is removed may fail and need retrying. Unchanged files have no read deadline.

Retained blobs and in-progress uploads count toward a physical-storage limit of
three times the user's quota. If this limit blocks an upload, the homeserver tries
one bounded cleanup pass for that user and retries the reservation once. This can
delete old file versions before the hour ends, so an ongoing download or copy of
one of those versions may fail sooner. Current files and active uploads are not
removed. Failed or interrupted uploads keep their separate cleanup delays.

Cleanup failures leave blobs queued for another attempt. Storage may remain blocked
if cleanup fails or the bounded pass cannot free enough space. The user's quota on
current files still applies.

The homeserver also scans storage at startup and once a day to find completed blobs
missing from its database records. This is separate from the regular cleanup queue.

## Backups

Back up PostgreSQL and file storage together. Blobs are stored under
`__pubky/blobs/{namespace}/`, with the namespace recorded in the
`blob_storage_namespace` database table. Include that table in database backups.

Homeserver instances sharing a database use the same namespace. Separate databases
use different namespaces and can share a bucket. A restored database still points
to its original namespace: do not run it against the original deployment's live
storage, where its cleanup could remove newer files.

## Upgrading to Immutable Blob Storage

1. Stop every homeserver instance using the database.
2. Take a matching backup of PostgreSQL and file storage.
3. Upgrade and start one instance. Database migrations run automatically at startup.
4. Wait for migrations to finish before starting the remaining upgraded instances.

Existing file contents are not rewritten during migration. Do not run old and new
server versions together: they use different storage layouts.

After the first write using immutable blobs, rolling back requires restoring both
PostgreSQL and file storage from the same pre-upgrade backup. Downgrading only the
binary or restoring only the database is not supported.
