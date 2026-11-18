use super::super::grant_session::{encode_delegated_child_state, encode_delegated_grant_state};
use super::record::*;
use super::*;
use js_sys::Reflect;
use serde::Serialize;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
export async function inspectApprovalStore(id, action) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(["storedSessions", "delegatedGrantKeys"], "readwrite");
      const sessions = tx.objectStore("storedSessions");
      const keys = tx.objectStore("delegatedGrantKeys");
      const record = sessions.get(id);
      const key = keys.get("test-pop");
      record.onsuccess = () => {
        if (action === "delete-pop") keys.delete("test-pop");
      };
      tx.oncomplete = () => resolve({ record: record.result, key: key.result });
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = inspectApprovalStore)]
    fn inspect_store(id: &str, action: &str) -> js_sys::Promise;
}

fn field(value: &JsValue, name: &str) -> JsValue {
    Reflect::get(value, &JsValue::from_str(name)).unwrap()
}

async fn inspect(id: &str, action: &str) -> JsValue {
    JsFuture::from(inspect_store(id, action)).await.unwrap()
}

#[wasm_bindgen_test]
fn metadata_presence_does_not_replace_restore_material() {
    let value = js_sys::JSON::parse(
            r#"{"version":"pubky-session-v2","id":"test","storageMode":"delegated","credential":"saved-grant","homeserver":"home","publicKey":"user","grantId":"grant","clientId":"client","capabilities":[],"grantExpiresAt":0,"createdAt":0,"hasStoredApproval":true}"#,
        )
        .unwrap();
    let metadata: StoredSessionMetadata = decode_store_value(value.clone(), "test").unwrap();
    assert!(validate_stored_metadata(metadata).is_ok());
    let record: StoredSessionRecord = decode_store_value(value.clone(), "test").unwrap();
    assert!(validate_record(record).is_err());

    // Neither legacy delegated records nor local tokens need a separate approval.
    for (version, mode) in [
        (STORE_VERSION, StorageMode::Delegated),
        (STORE_APPROVAL_VERSION, StorageMode::LocalSecret),
    ] {
        Reflect::set(&value, &"version".into(), &version.into()).unwrap();
        Reflect::set(&value, &"storageMode".into(), &mode.as_str().into()).unwrap();
        let record: StoredSessionRecord = decode_store_value(value.clone(), "test").unwrap();
        assert_eq!(record.metadata.storage_mode, mode);
        assert_eq!(
            StoredSessionInfo(record.metadata.clone()).storage_mode(),
            mode.as_str()
        );
        let serialized = serde_wasm_bindgen::to_value(&mode).unwrap();
        assert_eq!(serialized.as_string().unwrap(), mode.as_str());
        assert!(validate_record(record).is_ok());
    }

    // Unknown modes are rejected before restore dispatch.
    Reflect::set(&value, &"storageMode".into(), &"unsupported".into()).unwrap();
    assert!(decode_store_value::<StoredSessionRecord>(value.clone(), "test").is_err());
    assert!(decode_store_value::<StoredSessionMetadata>(value, "test").is_err());
}

#[wasm_bindgen_test]
fn records_preserve_the_flat_browser_storage_format() {
    let original = js_sys::JSON::parse(
            r#"{"version":"pubky-session-v2","id":"test","storageMode":"delegated","credential":"saved-grant","homeserver":"home","publicKey":"user","grantId":"grant","clientId":"client","capabilities":["/pub/chat/:r"],"grantExpiresAt":123,"createdAt":456,"signedApproval":"signed-approval"}"#,
        )
        .unwrap();
    let record = decode_store_value(original.clone(), "test").unwrap();
    let record = validate_record(record).unwrap();
    let serialized = record
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .unwrap();
    assert!(field(&serialized, "metadata").is_undefined());
    assert!(field(&serialized, "hasStoredApproval").is_undefined());
    for key in js_sys::Object::keys(&js_sys::Object::from(original.clone())).iter() {
        let name = key.as_string().unwrap();
        assert_eq!(
            js_sys::JSON::stringify(&field(&serialized, &name)).unwrap(),
            js_sys::JSON::stringify(&field(&original, &name)).unwrap(),
            "{name}",
        );
    }
}

#[wasm_bindgen_test]
async fn stored_approvals_survive_bearer_updates_and_signing_key_removal() {
    for mode in [StorageMode::Delegated, StorageMode::LocalSecret] {
        let id = format!("approval-storage-{}", mode.as_str());
        let record = js_sys::JSON::parse(
                r#"{"version":"pubky-session-v2","id":"placeholder","storageMode":"delegated","credential":"{\"keyId\":\"test-pop\"}","homeserver":"test-home","publicKey":"test-user","grantId":"test-grant","clientId":"test-client","capabilities":[],"grantExpiresAt":0,"createdAt":0}"#,
            )
            .unwrap();
        Reflect::set(&record, &"id".into(), &id.clone().into()).unwrap();
        Reflect::set(&record, &"storageMode".into(), &mode.as_str().into()).unwrap();
        let material_field = if mode == StorageMode::Delegated {
            "signedApproval"
        } else {
            "credential"
        };
        Reflect::set(
            &record,
            &material_field.into(),
            &"confidential-approval".into(),
        )
        .unwrap();
        let lease = js_session_acquire(&id, "test-home", true).unwrap();
        JsFuture::from(js_session_wait(lease)).await.unwrap();
        JsFuture::from(js_store_put(record.clone(), lease, false))
            .await
            .unwrap();

        let saved = inspect(&id, "read").await;
        assert!(field(&saved, "key").is_undefined());
        assert_eq!(
            field(&field(&saved, "record"), material_field),
            JsValue::from_str("confidential-approval")
        );
        inspect(&id, "delete-pop").await;
        let loaded = JsFuture::from(js_store_get(id.clone())).await.unwrap();
        assert_eq!(
            field(&loaded, material_field),
            JsValue::from_str("confidential-approval")
        );

        let metadata = JsFuture::from(js_store_list()).await.unwrap();
        for entry in js_sys::Array::from(&metadata).iter() {
            assert!(field(&entry, "signedApproval").is_undefined());
            assert!(field(&entry, "credential").is_undefined());
            assert!(field(&entry, "sharedSession").is_undefined());
        }
        let shared = js_sys::JSON::parse(r#"{"bearer":"test-bearer"}"#).unwrap();
        JsFuture::from(js_shared_store(lease, shared))
            .await
            .unwrap();
        assert_eq!(
            field(
                &JsFuture::from(js_store_get(id.clone())).await.unwrap(),
                material_field
            ),
            JsValue::from_str("confidential-approval")
        );

        let downgraded = js_sys::Object::assign(
            &js_sys::Object::new(),
            &js_sys::Object::from(record.clone()),
        );
        Reflect::set(&downgraded, &"version".into(), &STORE_VERSION.into()).unwrap();
        assert!(
            JsFuture::from(js_store_put(downgraded.into(), lease, false))
                .await
                .is_err()
        );
        assert!(
            JsFuture::from(js_store_put(record.clone(), 0, false))
                .await
                .is_err()
        );

        JsFuture::from(js_store_put(record.clone(), lease, false))
            .await
            .unwrap();
        let replaced = JsFuture::from(js_store_get(id.clone())).await.unwrap();
        assert_eq!(
            field(&replaced, material_field),
            JsValue::from_str("confidential-approval")
        );
        assert_eq!(
            field(&field(&replaced, "sharedSession"), "bearer"),
            JsValue::from_str("test-bearer")
        );
        JsFuture::from(js_shared_remove(lease)).await.unwrap();
        assert!(field(&inspect(&id, "read").await, "record").is_undefined());
        JsFuture::from(js_store_put(record, lease, false))
            .await
            .unwrap();
        js_session_release(lease);
        JsFuture::from(js_store_clear()).await.unwrap();
        assert!(field(&inspect(&id, "read").await, "record").is_undefined());
    }
}

#[wasm_bindgen(inline_js = r#"
export async function rawAuthDatabase(action, records) {
  if (action === "reset-v1") {
    await new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase("pubky-auth");
      request.onsuccess = resolve;
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("pubky-auth is still open"));
    });
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open("pubky-auth", 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("storedSessions", { keyPath: "id" });
        request.result.createObjectStore("delegatedGrantKeys", { keyPath: "keyId" });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise((resolve, reject) => {
      const tx = db.transaction(["storedSessions", "delegatedGrantKeys"], "readwrite");
      for (const record of records) tx.objectStore("storedSessions").put(record);
      tx.objectStore("delegatedGrantKeys").put({ keyId: "legacy-key", publicKeyRaw: new Uint8Array(32) });
      tx.oncomplete = resolve;
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
    db.close();
    return;
  }
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const stores = Array.from(db.objectStoreNames).sort();
    const tx = db.transaction(stores);
    const read = name => new Promise(resolve => {
      const request = tx.objectStore(name).getAll();
      request.onsuccess = () => resolve(request.result);
    });
    return {
      version: db.version,
      stores,
      sessions: await read("storedSessions"),
      keys: (await read("delegatedGrantKeys")).map(key => key.keyId),
      flows: stores.includes("redirectFlows") ? await read("redirectFlows") : [],
    };
  } finally { db.close(); }
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = rawAuthDatabase)]
    fn raw_auth_database(action: &str, records: JsValue) -> js_sys::Promise;
}

async fn raw(action: &str, records: JsValue) -> JsValue {
    JsFuture::from(raw_auth_database(action, records))
        .await
        .unwrap()
}

fn child_record(id: &str, approval: Option<&str>) -> JsValue {
    let record = js_sys::JSON::parse(&format!(
            r#"{{"version":"pubky-session-v3","id":"{id}","storageMode":"delegated","credential":"{{\"keyId\":\"child-key\"}}","homeserver":"test-home","publicKey":"user","grantId":"grant","clientId":"https://chat.example/cb","capabilities":[],"grantExpiresAt":0,"createdAt":0}}"#
        ))
        .unwrap();
    if let Some(approval) = approval {
        Reflect::set(&record, &"signedApproval".into(), &approval.into()).unwrap();
    }
    record
}

async fn lease(id: &str) -> u32 {
    let lease = js_session_acquire(id, "test-home", true).unwrap();
    JsFuture::from(js_session_wait(lease)).await.unwrap();
    lease
}

#[wasm_bindgen_test]
fn child_records_need_their_approval_until_sign_out_starts() {
    let approved = child_record("child", Some("approval"));
    let record: StoredSessionRecord = decode_store_value(approved, "child").unwrap();
    assert!(validate_record(record).unwrap().is_child());

    let without = child_record("child", None);
    let record: StoredSessionRecord = decode_store_value(without.clone(), "child").unwrap();
    assert!(validate_record(record).is_err());
    let metadata: StoredSessionMetadata = decode_store_value(without.clone(), "child").unwrap();
    assert!(validate_stored_metadata(metadata).is_err());

    // Only a record whose sign-out started may lack its approval.
    Reflect::set(&without, &"logoutPending".into(), &JsValue::TRUE).unwrap();
    let record: StoredSessionRecord = decode_store_value(without.clone(), "child").unwrap();
    assert!(validate_record(record).unwrap().logout_pending);
    let metadata: StoredSessionMetadata = decode_store_value(without, "child").unwrap();
    assert!(validate_stored_metadata(metadata).is_ok());

    // Child records always use a browser-held key.
    let local = child_record("child", Some("approval"));
    Reflect::set(&local, &"storageMode".into(), &"localSecret".into()).unwrap();
    let record: StoredSessionRecord = decode_store_value(local, "child").unwrap();
    assert!(validate_record(record).is_err());
}

#[wasm_bindgen_test]
fn child_and_direct_credentials_never_decode_as_each_other() {
    let key = pubky_common::crypto::Keypair::random().public_key();
    let state = pubky::DelegatedGrantCredentialState {
        grant_jws: "child".into(),
        homeserver_pk: key.clone(),
        key_id: "key".into(),
        client_pk: key,
    };
    let child = encode_delegated_child_state(state.clone(), "parent").unwrap();
    let direct = encode_delegated_grant_state(state).unwrap();
    let (decoded, parent) = decode_delegated_child_state(&child).unwrap();
    assert_eq!(
        (decoded.grant_jws.as_str(), parent.as_str()),
        ("child", "parent")
    );
    assert!(decode_delegated_grant_state(&child).is_err());
    assert!(decode_delegated_child_state(&direct).is_err());
    // Old SDKs clear a record's key through `credential.keyId`.
    let json: serde_json::Value = serde_json::from_str(&child).unwrap();
    assert_eq!(json["keyId"], "key");
}

#[wasm_bindgen_test]
async fn starting_a_child_sign_out_deletes_its_approval_in_the_same_write() {
    let id = "child-sign-out";
    let lease = lease(id).await;
    // Saving a child session only updates an existing record.
    assert!(
        JsFuture::from(js_store_put(child_record(id, Some("secret")), lease, true))
            .await
            .is_err()
    );
    JsFuture::from(js_store_put(child_record(id, Some("secret")), lease, false))
        .await
        .unwrap();
    let shared = js_sys::JSON::parse(r#"{"bearer":"b","logout_pending":false}"#).unwrap();
    JsFuture::from(js_shared_store(lease, shared))
        .await
        .unwrap();
    let saved = JsFuture::from(js_store_get(id.into())).await.unwrap();
    assert_eq!(field(&saved, "signedApproval"), JsValue::from_str("secret"));

    let shared = js_sys::JSON::parse(r#"{"bearer":"b","logout_pending":true}"#).unwrap();
    JsFuture::from(js_shared_store(lease, shared))
        .await
        .unwrap();
    let saved = JsFuture::from(js_store_get(id.into())).await.unwrap();
    assert!(!Reflect::has(&saved, &"signedApproval".into()).unwrap());
    assert_eq!(field(&saved, "logoutPending"), JsValue::TRUE);
    let metadata = JsFuture::from(js_store_metadata(id.into())).await.unwrap();
    assert_eq!(field(&metadata, "logoutPending"), JsValue::TRUE);
    assert_eq!(field(&metadata, "hasStoredApproval"), JsValue::FALSE);

    // A stale handle can't put the approval back.
    assert!(
        JsFuture::from(js_store_put(child_record(id, Some("secret")), lease, true))
            .await
            .is_err()
    );
    let record: StoredSessionRecord = load_record(id).await.unwrap();
    assert!(record.signed_approval.is_none());
    JsFuture::from(js_shared_remove(lease)).await.unwrap();
    js_session_release(lease);
}

#[wasm_bindgen_test]
async fn redirect_flows_change_only_from_the_flow_that_was_read() {
    let callback = "https://localhost/redirect-test";
    let (key_id, _) = BrowserGrantKeyStore::ensure_key(None).await.unwrap();
    let token = js_redirect_acquire(callback).unwrap();
    JsFuture::from(js_redirect_wait(token)).await.unwrap();
    let flow = |status: &str, state: &str| {
        js_sys::JSON::parse(&format!(
                r#"{{"callbackUrl":"{callback}","version":"pubky-redirect-flow-v1","status":"{status}","state":"{state}","keyId":"{key_id}"}}"#
            ))
            .unwrap()
    };
    let reference = |status: &str, state: &str| {
        js_sys::JSON::parse(&format!(
            r#"{{"status":"{status}","state":"{state}","keyId":"{key_id}"}}"#
        ))
        .unwrap()
    };
    let transition = |expected: JsValue, next: JsValue| async move {
        JsFuture::from(js_redirect_transition(
            token, callback, expected, next, None,
        ))
        .await
        .unwrap()
        .is_truthy()
    };
    assert!(transition(JsValue::NULL, flow("awaitingCallback", "a")).await);
    // A second start, or a change from a flow that isn't stored, does nothing.
    assert!(!transition(JsValue::NULL, flow("awaitingCallback", "b")).await);
    assert!(!transition(reference("awaitingCallback", "b"), JsValue::NULL).await);
    assert!(
        transition(
            reference("awaitingCallback", "a"),
            flow("exchangePending", "a")
        )
        .await
    );

    // Completion saves the session and finishes the flow together, once.
    let id = "redirect-commit";
    let session_lease = lease(id).await;
    let commit = || async {
        JsFuture::from(js_redirect_commit(
            token,
            callback,
            reference("exchangePending", "a"),
            flow("complete", "a"),
            child_record(id, Some("approval")),
            session_lease,
        ))
        .await
        .unwrap()
        .is_truthy()
    };
    assert!(commit().await);
    assert!(!commit().await);
    let stored = JsFuture::from(js_redirect_get(callback)).await.unwrap();
    assert_eq!(field(&stored, "status"), JsValue::from_str("complete"));
    assert!(
        !JsFuture::from(js_store_get(id.into()))
            .await
            .unwrap()
            .is_undefined()
    );
    JsFuture::from(js_shared_remove(session_lease))
        .await
        .unwrap();
    js_session_release(session_lease);

    // The lock belongs to its callback.
    assert!(
        JsFuture::from(js_redirect_transition(
            token,
            "https://localhost/other",
            JsValue::NULL,
            JsValue::NULL,
            None
        ))
        .await
        .is_err()
    );
    js_redirect_release(token);
    assert!(
        JsFuture::from(js_redirect_transition(
            token,
            callback,
            JsValue::NULL,
            JsValue::NULL,
            None
        ))
        .await
        .is_err()
    );

    // Both clear operations invalidate pending callbacks.
    JsFuture::from(js_store_clear()).await.unwrap();
    assert!(
        JsFuture::from(js_redirect_get(callback))
            .await
            .unwrap()
            .is_undefined()
    );
    JsFuture::from(js_store_clear_all(js_sys::Array::new().into()))
        .await
        .unwrap();
    assert!(
        JsFuture::from(js_redirect_get(callback))
            .await
            .unwrap()
            .is_undefined()
    );
}

#[wasm_bindgen_test]
async fn the_version_2_upgrade_keeps_existing_records_and_keys() {
    let legacy = js_sys::JSON::parse(
            r#"[{"version":"pubky-session-v1","id":"legacy-v1","storageMode":"localSecret","credential":"token","homeserver":"h","publicKey":"u","grantId":"g1","clientId":"c","capabilities":[],"grantExpiresAt":0,"createdAt":0},
                {"version":"pubky-session-v2","id":"legacy-v2","storageMode":"delegated","credential":"{\"keyId\":\"legacy-key\"}","signedApproval":"approval","homeserver":"h","publicKey":"u","grantId":"g2","clientId":"c","capabilities":[],"grantExpiresAt":0,"createdAt":0}]"#,
        )
        .unwrap();
    raw("reset-v1", legacy).await;
    let before = raw("read", JsValue::NULL).await;
    assert_eq!(field(&before, "version"), JsValue::from_f64(1.0));

    // Any SDK operation upgrades the database without touching the records.
    let listed = js_sys::Array::from(&JsFuture::from(js_store_list()).await.unwrap());
    assert_eq!(listed.length(), 2);
    let after = raw("read", JsValue::NULL).await;
    assert_eq!(field(&after, "version"), JsValue::from_f64(2.0));
    assert_eq!(
        js_sys::JSON::stringify(&field(&after, "stores")).unwrap(),
        r#"["delegatedGrantKeys","redirectFlows","storedSessions"]"#
    );
    assert_eq!(
        js_sys::JSON::stringify(&field(&after, "sessions")).unwrap(),
        js_sys::JSON::stringify(&field(&before, "sessions")).unwrap()
    );
    assert_eq!(
        js_sys::JSON::stringify(&field(&after, "keys")).unwrap(),
        r#"["legacy-key"]"#
    );
    let record: StoredSessionRecord = load_record("legacy-v2").await.unwrap();
    assert_eq!(record.signed_approval.as_deref(), Some("approval"));
    JsFuture::from(js_store_clear()).await.unwrap();
}
