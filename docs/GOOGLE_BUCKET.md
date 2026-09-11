# Google Cloud Bucket Setup

The `google_bucket` backend stores file contents in Google Cloud Storage.
PostgreSQL is still required for metadata.

## Configure the Homeserver

Create a bucket and a service account with permission to read, write, list, and
delete its objects. Keep the service account credentials private.

Set the following in the homeserver's `config.toml`:

```toml
[storage]
type = "google_bucket"
bucket_name = "my_bucket"
credential = "/absolute/path/to/service-account.json"
```

When running in Docker, mount the credential file and use its path inside the
container. Restart the homeserver after updating the configuration.

## Allow Cleanup to Reclaim Space

- Disable **soft delete** and **Object Versioning**. Otherwise Google may keep extra
  copies after the homeserver deletes files, and those copies can still cost money.
- Add an `AbortIncompleteMultipartUpload` lifecycle rule for the `__pubky/blobs/`
  prefix. An interrupted upload can leave unfinished parts in the bucket. The
  homeserver only sees completed objects, so Google must clean up those parts.
- Do not add age-based deletion rules for completed blobs in that prefix. They
  may still hold current files; let the homeserver decide when to delete them.

See [Google's lifecycle documentation](https://docs.cloud.google.com/storage/docs/lifecycle#abort-mpu)
for the multipart cleanup rule. For backups and retention behavior, see
[Storage operations](./STORAGE.md).
