use super::super::app_state::AppState;
use crate::shared::{webdav::EntryPathPub, HttpResult};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

/// Delete a single entry from the database.
pub async fn delete_entry(
    State(state): State<AppState>,
    Path(entry_path): Path<EntryPathPub>,
) -> HttpResult<impl IntoResponse> {
    state.file_service.admin_delete(entry_path.inner()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::super::super::app_state::AppState;
    use super::*;
    use crate::persistence::files::{
        events::{EventRepository, EventType, EventVisibility},
        FileService,
    };
    use crate::persistence::sql::entry::EntryRepository;
    use crate::persistence::sql::user::UserRepository;
    use crate::shared::webdav::{EntryPath, StoragePath};
    use crate::AppContext;
    use axum::{routing::delete, Router};
    use opendal::Buffer;
    use pubky_common::crypto::Keypair;

    async fn write_test_file(file_service: &FileService, entry_path: &EntryPath) {
        let buffer = Buffer::from(vec![0; 10]);
        let _entry = file_service.write(entry_path, buffer).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_entry() {
        // Set everything up
        let context = AppContext::test().await;
        let keypair = Keypair::from_secret(&[0; 32]);
        let pubkey = keypair.public_key();
        let file_path = "my_file.txt";
        let db = context.sql_db.clone();
        let file_service = FileService::new_from_context(&context).unwrap();
        let app_state = AppState::new(
            context.sql_db.clone(),
            file_service.clone(),
            "",
            context.user_service.clone(),
            context.events_service.clone(),
            context.metrics.clone(),
        );
        let router = Router::new()
            .route("/webdav/{*entry_path}", delete(delete_entry))
            .with_state(app_state);

        // Write a test file
        let storage_path = StoragePath::new(format!("/pub/{}", file_path).as_str()).unwrap();
        UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let entry_path = EntryPath::new(pubkey.clone(), storage_path);

        write_test_file(&file_service, &entry_path).await;

        // Delete the file
        let server = axum_test::TestServer::new(router).unwrap();
        let response = server
            .delete(format!("/webdav/{}", entry_path.as_str()).as_str())
            .await;
        assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

        // Check that the file is deleted
        EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .expect_err("Should be deleted");
        // Verify the blob is also gone from the storage backend
        file_service
            .get(&entry_path)
            .await
            .expect_err("Blob should be deleted from storage");
        let events = EventRepository::get_by_cursor(
            None,
            Some(10),
            EventVisibility::All,
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        assert_eq!(
            events.len(),
            2,
            "One PUT and one DEL event should be created. Last entry is the cursor."
        );
        assert!(matches!(events[0].event_type, EventType::Put { .. }));
        assert_eq!(events[1].event_type, EventType::Delete);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_not_found() {
        // Set everything up
        let context = AppContext::test().await;
        let keypair = Keypair::from_secret(&[0; 32]);
        let pubkey = keypair.public_key();
        let file_path = "my_file.txt";
        let app_state = AppState::new(
            context.sql_db.clone(),
            FileService::new_from_context(&context).unwrap(),
            "",
            context.user_service.clone(),
            context.events_service.clone(),
            context.metrics.clone(),
        );
        let router = Router::new()
            .route("/webdav/{*entry_path}", delete(delete_entry))
            .with_state(app_state);

        // Delete the file
        let url = format!("/webdav/{}/pub/{}", pubkey.z32(), file_path);
        let server = axum_test::TestServer::new(router).unwrap();
        let response = server.delete(url.as_str()).await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_invalid_pubkey() {
        // Set everything up
        let context = AppContext::test().await;

        let sql_db = context.sql_db.clone();
        let app_state = AppState::new(
            sql_db.clone(),
            FileService::new_from_context(&context).unwrap(),
            "",
            context.user_service.clone(),
            context.events_service.clone(),
            context.metrics.clone(),
        );
        let router = Router::new()
            .route("/webdav/{*entry_path}", delete(delete_entry))
            .with_state(app_state);

        // Delete with invalid pubkey
        let server = axum_test::TestServer::new(router).unwrap();
        let response = server
            .delete("/webdav/1234/pub/test.txt".to_string().as_str())
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}
