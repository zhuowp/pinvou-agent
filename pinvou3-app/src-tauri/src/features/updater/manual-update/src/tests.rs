use super::*;

pub(crate) fn feed() -> serde_json::Value {
    serde_json::json!({
        "latest_version": "2.0.0", "notes": "Release", "pub_date": "2026-10-29",
        "platforms": { "windows-x64": {
            "format": "nsis", "url": "https://example.com/setup.exe",
            "sha256": "00".repeat(32), "size": 20
        }}
    })
}

pub(crate) fn parse(value: serde_json::Value, current: &str) -> Result<Selection, String> {
    parse_feed(&serde_json::to_vec(&value).unwrap(), current)
}

#[test]
fn selection_uses_stable_semver_and_fresh_identity() {
    assert!(parse(feed(), "1.10.0").unwrap().info.available);
    assert!(!parse(feed(), "2.0.0").unwrap().info.available);
    assert!(!parse(feed(), "3.0.0").unwrap().info.available);
    assert!(parse(feed(), "1.0.0-beta.1").is_err());
    assert_ne!(
        parse(feed(), "1.0.0").unwrap().info.selection_id,
        parse(feed(), "1.0.0").unwrap().info.selection_id
    );
}

#[test]
fn malformed_metadata_is_rejected() {
    for (key, value) in [
        ("size", serde_json::json!(0)),
        ("size", serde_json::json!(MAX_INSTALLER_SIZE + 1)),
        ("size", serde_json::json!(-1)),
        ("sha256", serde_json::json!("gg".repeat(32))),
        ("sha256", serde_json::json!("00".repeat(31))),
        ("url", serde_json::json!("http://example.com/setup.exe")),
        (
            "url",
            serde_json::json!("https://user:pass@example.com/setup.exe"),
        ),
        (
            "url",
            serde_json::json!("https://example.com/setup.exe#fragment"),
        ),
        ("version", serde_json::json!("1.0.0")),
        ("format", serde_json::json!("msi")),
    ] {
        let mut value_feed = feed();
        value_feed["platforms"]["windows-x64"][key] = value;
        assert!(parse(value_feed, "1.0.0").is_err(), "accepted {key}");
    }
    let mut value = feed();
    value["latest_version"] = serde_json::json!("2.0.0-rc.1");
    assert!(parse(value, "1.0.0").is_err());
    let mut value = feed();
    value["platforms"] = serde_json::json!({ "windows-aarch64": {} });
    assert!(parse(value, "1.0.0").is_err());
    assert!(parse_feed(b"{}", "1.0.0").is_err());
    assert!(parse_feed(&vec![b' '; MANIFEST_LIMIT + 1], "1.0.0").is_err());
}

#[test]
fn managed_download_must_stay_on_check_origin() {
    let origin = Url::parse("https://updates.example.com/v1/updates/manual/check").unwrap();
    assert!(same_origin(
        &Url::parse("https://updates.example.com/v1/updates/manual/download/2.0.0").unwrap(),
        &origin
    ));
    assert!(!same_origin(
        &Url::parse("https://cdn.example.com/installer.exe").unwrap(),
        &origin
    ));
}

#[test]
fn count_and_digest_bind_complete_download() {
    let bytes = b"installer";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut verifier = ByteVerifier::new(bytes.len() as u64, digest);
    verifier.update(&bytes[..3]).unwrap();
    verifier.update(&bytes[3..]).unwrap();
    verifier.finish().unwrap();
    let mut short = ByteVerifier::new(20, digest);
    short.update(bytes).unwrap();
    assert!(short.finish().is_err());
    let mut long = ByteVerifier::new(2, digest);
    assert!(long.update(bytes).is_err());
    let mut tampered = ByteVerifier::new(bytes.len() as u64, digest);
    tampered.update(b"tampered!").unwrap();
    assert!(tampered.finish().is_err());
}

pub(crate) fn updater() -> ManualUpdater {
    ManualUpdater::new(
        "https://example.com/feed.json",
        std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()),
    )
    .unwrap()
}

#[test]
fn device_id_is_stable_lower_hex_and_recreated_when_corrupt() {
    let root = std::env::temp_dir().join(format!("pinvou-device-id-{}", uuid::Uuid::new_v4()));
    let cache = root.join("cache");
    fs::create_dir_all(&root).unwrap();
    let first = load_or_create_device_id(&cache).unwrap();
    assert_eq!(first.len(), 64);
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(first, load_or_create_device_id(&cache).unwrap());
    fs::write(root.join(DEVICE_ID_FILE), "not-a-device-id").unwrap();
    let replacement = load_or_create_device_id(&cache).unwrap();
    assert_eq!(replacement.len(), 64);
    assert_ne!(replacement, "not-a-device-id");
    assert_eq!(replacement, load_or_create_device_id(&cache).unwrap());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_check_query_binds_device_and_current_version() {
    let url =
        Url::parse("https://updates.example/v1/updates/manual/check?tenant=community").unwrap();
    let device = "a".repeat(64);
    let request = check_request_url(&url, &device, "1.2.3");
    let pairs: std::collections::HashMap<_, _> = request.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("tenant").map(String::as_str), Some("community"));
    assert_eq!(
        pairs.get("deviceId").map(String::as_str),
        Some(device.as_str())
    );
    assert_eq!(
        pairs.get("currentVersion").map(String::as_str),
        Some("1.2.3")
    );
}

#[tokio::test]
async fn singleflight_and_failure_release_the_gate() {
    let updater = updater();
    let operation = updater.begin().unwrap();
    assert!(updater.begin().is_err());
    assert!(updater.check("1.0.0").await.is_err());
    drop(operation);
    assert!(updater.download("unselected", |_| {}).await.is_err());
    assert!(updater.begin().is_ok());
    assert!(!updater.cancel_download());
}

#[tokio::test]
async fn cancelled_pending_io_returns_promptly() {
    let cancellation = Arc::new(Cancellation::default());
    cancellation.cancelled.store(true, Ordering::SeqCst);
    assert!(
        cancellable(&cancellation, std::future::pending::<()>())
            .await
            .is_err()
    );
    cancellation.cancelled.store(false, Ordering::SeqCst);
    let cancel_clone = cancellation.clone();
    let task = async move {
        cancel_clone.cancelled.store(true, Ordering::SeqCst);
        cancel_clone.notify.notify_one();
    };
    let (result, ()) = tokio::join!(
        cancellable(&cancellation, std::future::pending::<()>()),
        task
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn stale_selection_cannot_download() {
    let updater = updater();
    let selected = parse(feed(), "1.0.0").unwrap();
    let old_id = selected.info.selection_id.clone();
    updater.state.lock().unwrap().selection = Some(parse(feed(), "1.0.0").unwrap());
    assert!(updater.download(&old_id, |_| {}).await.is_err());
    assert!(updater.begin().is_ok());
}

// The injected HTTP URL is rejected by the real HTTPS-only client before any
// socket is opened. This exercises actual download error cleanup without a server.
#[tokio::test]
async fn failed_and_cancelled_downloads_remove_partial_and_allow_retry() {
    let updater = updater();
    let mut selection = parse(feed(), "1.0.0").unwrap();
    selection.url = Url::parse("http://example.com/never-contacted.exe").unwrap();
    let id = selection.info.selection_id.clone();
    updater.state.lock().unwrap().selection = Some(selection);
    for _ in 0..2 {
        assert_eq!(
            updater.download(&id, |_| {}).await.unwrap_err(),
            "UPDATER_DOWNLOAD_FAILED"
        );
        assert_eq!(fs::read_dir(&updater.cache_root).unwrap().count(), 0);
    }
    let cancel = async {
        while !updater.cancel_download() {
            tokio::task::yield_now().await;
        }
    };
    let (result, ()) = tokio::join!(updater.download(&id, |_| {}), cancel);
    assert_eq!(result.unwrap_err(), "UPDATER_DOWNLOAD_CANCELLED");
    assert_eq!(fs::read_dir(&updater.cache_root).unwrap().count(), 0);
    assert!(!updater.cancel_download());
    assert!(updater.begin().is_ok());
    fs::remove_dir(&updater.cache_root).unwrap();
}
