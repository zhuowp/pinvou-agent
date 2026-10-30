//! Manual Windows stable updates from a build-controlled HTTPS feed.
//! SHA-256 binds the downloaded bytes to that feed; this is not signed metadata.

mod platform;

use reqwest::{Client, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

const MANIFEST_LIMIT: usize = 256 * 1024;
const MAX_INSTALLER_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const STALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize)]
pub struct CheckedUpdate {
    pub selection_id: String,
    pub version: String,
    pub notes: Option<String>,
    pub pub_date: Option<String>,
    pub download_size: u64,
    pub url: String,
    pub sha256: String,
    pub available: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct DownloadProgress {
    pub downloaded: u64,
    pub total: u64,
}

#[derive(Clone, Debug)]
pub struct DownloadedUpdate {
    pub version: String,
    pub installer_path: PathBuf,
}

/// Keep this value alive through native launch so the verified file stays held.
pub struct VerifiedInstaller {
    _file: File,
    path: PathBuf,
    version: String,
    _lease: Operation,
}

impl VerifiedInstaller {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Consume the receipt after ShellExecute reports a successful launch.
    /// Launch is not evidence that the installer completed successfully.
    pub fn commit_launch(self) {
        let mut state = self._lease.0.lock().unwrap_or_else(|e| e.into_inner());
        state.receipt = None;
        state.selection = None;
    }
}

#[derive(Deserialize)]
struct Feed {
    latest_version: String,
    notes: Option<String>,
    pub_date: Option<String>,
    platforms: HashMap<String, Package>,
}

#[derive(Deserialize)]
struct Package {
    version: Option<String>,
    format: String,
    url: String,
    sha256: String,
    size: u64,
}

#[derive(Clone)]
struct Selection {
    info: CheckedUpdate,
    url: Url,
    digest: [u8; 32],
}

#[derive(Clone)]
struct Receipt {
    selection: Selection,
    path: PathBuf,
}

#[derive(Default)]
struct State {
    busy: bool,
    selection: Option<Selection>,
    receipt: Option<Receipt>,
    cancellation: Option<Arc<Cancellation>>,
}

#[derive(Default)]
struct Cancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

/// Backend owns selection and download receipts. UI fields never supply authority.
pub struct ManualUpdater {
    client: Client,
    check_url: Url,
    device_id: String,
    cache_root: PathBuf,
    state: Arc<Mutex<State>>,
}

struct Operation(Arc<Mutex<State>>);

impl Drop for Operation {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.busy = false;
        state.cancellation = None;
    }
}

/// Removes only the randomly named directory created by this operation.
struct OwnedDownloadDir(PathBuf, bool);

impl Drop for OwnedDownloadDir {
    fn drop(&mut self) {
        if self.1 {
            return;
        }
        // Never recursively traverse paths that could have been replaced.
        let _ = fs::remove_file(self.0.join("installer.part"));
        let _ = fs::remove_file(self.0.join("installer.exe"));
        let _ = fs::remove_dir(&self.0);
    }
}

impl ManualUpdater {
    pub fn new(check_url: &str, cache_root: PathBuf) -> Result<Self, String> {
        let check_url = https_url(check_url)?;
        let device_id = load_or_create_device_id(&cache_root)?;
        let client = Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(STALL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || https_url(attempt.url().as_str()).is_err() {
                    attempt.error("Unsafe update redirect")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|_| "UPDATER_INTERNAL".to_string())?;
        Ok(Self {
            client,
            check_url,
            device_id,
            cache_root,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    fn begin(&self) -> Result<Operation, String> {
        let mut state = self.state.lock().map_err(|_| "UPDATER_INTERNAL")?;
        if state.busy {
            return Err("UPDATER_BUSY".into());
        }
        state.busy = true;
        Ok(Operation(self.state.clone()))
    }

    pub async fn check(&self, current_version: &str) -> Result<CheckedUpdate, String> {
        let _operation = self.begin()?;
        stable_version(current_version)?;
        // A failed new check cannot leave an older selection installable.
        self.clear_selection();
        let check_url = check_request_url(&self.check_url, &self.device_id, current_version);
        let mut response = self
            .client
            .get(check_url)
            .send()
            .await
            .map_err(|_| "UPDATER_CHECK_FAILED")?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            let info = CheckedUpdate {
                selection_id: uuid::Uuid::new_v4().to_string(),
                version: current_version.to_owned(),
                notes: None,
                pub_date: None,
                download_size: 0,
                url: String::new(),
                sha256: String::new(),
                available: false,
            };
            return Ok(info);
        }
        response = response
            .error_for_status()
            .map_err(|_| "UPDATER_CHECK_FAILED")?;
        if response
            .content_length()
            .is_some_and(|n| n > MANIFEST_LIMIT as u64)
        {
            return Err("UPDATER_METADATA_INVALID".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "UPDATER_CHECK_FAILED")? {
            if bytes.len().saturating_add(chunk.len()) > MANIFEST_LIMIT {
                return Err("UPDATER_METADATA_INVALID".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let selection = parse_feed(&bytes, current_version)?;
        let info = selection.info.clone();
        self.state.lock().map_err(|_| "UPDATER_INTERNAL")?.selection = Some(selection);
        Ok(info)
    }

    fn clear_selection(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.selection = None;
        if let Some(receipt) = state.receipt.take() {
            let _ = fs::remove_file(&receipt.path);
            if let Some(parent) = receipt.path.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
    }

    pub fn cancel_download(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cancellation) = &state.cancellation {
            cancellation.cancelled.store(true, Ordering::SeqCst);
            cancellation.notify.notify_one();
            true
        } else {
            false
        }
    }

    pub async fn download(
        &self,
        selection_id: &str,
        progress: impl Fn(DownloadProgress) + Send + Sync,
    ) -> Result<DownloadedUpdate, String> {
        let _operation = self.begin()?;
        let cancellation = Arc::new(Cancellation::default());
        let selection = {
            let mut state = self.state.lock().map_err(|_| "UPDATER_INTERNAL")?;
            let selection = state
                .selection
                .as_ref()
                .ok_or("UPDATER_SELECTION_CHANGED")?
                .clone();
            if !selection.info.available || selection.info.selection_id != selection_id {
                return Err("UPDATER_SELECTION_CHANGED".into());
            }
            if let Some(receipt) = state.receipt.take() {
                let _ = fs::remove_file(&receipt.path);
                if let Some(parent) = receipt.path.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            state.cancellation = Some(cancellation.clone());
            selection
        };
        tokio::fs::create_dir_all(&self.cache_root)
            .await
            .map_err(|_| "UPDATER_CACHE_FAILED")?;
        let cache_root = tokio::fs::canonicalize(&self.cache_root)
            .await
            .map_err(|_| "UPDATER_CACHE_FAILED")?;
        let dir = cache_root.join(uuid::Uuid::new_v4().to_string());
        tokio::fs::create_dir(&dir)
            .await
            .map_err(|_| "UPDATER_CACHE_FAILED")?;
        let mut owned_dir = OwnedDownloadDir(dir, false);
        let partial = owned_dir.0.join("installer.part");
        let final_path = owned_dir.0.join("installer.exe");
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .await
            .map_err(|_| "UPDATER_CACHE_FAILED")?;
        let mut response =
            cancellable(&cancellation, self.client.get(selection.url.clone()).send())
                .await?
                .map_err(|_| "UPDATER_DOWNLOAD_FAILED")?
                .error_for_status()
                .map_err(|_| "UPDATER_DOWNLOAD_FAILED")?;
        if response
            .content_length()
            .is_some_and(|n| n != selection.info.download_size)
        {
            return Err("UPDATER_INTEGRITY_FAILED".into());
        }
        let mut verifier = ByteVerifier::new(selection.info.download_size, selection.digest);
        progress(DownloadProgress {
            downloaded: 0,
            total: selection.info.download_size,
        });
        loop {
            let chunk = cancellable(&cancellation, response.chunk())
                .await?
                .map_err(|_| "UPDATER_DOWNLOAD_FAILED")?;
            let Some(chunk) = chunk else {
                break;
            };
            verifier.update(&chunk)?;
            file.write_all(&chunk)
                .await
                .map_err(|_| "UPDATER_CACHE_FAILED")?;
            progress(DownloadProgress {
                downloaded: verifier.count,
                total: selection.info.download_size,
            });
        }
        verifier.finish()?;
        ensure_not_cancelled(&cancellation)?;
        file.flush().await.map_err(|_| "UPDATER_CACHE_FAILED")?;
        file.sync_all().await.map_err(|_| "UPDATER_CACHE_FAILED")?;
        drop(file);
        tokio::fs::rename(&partial, &final_path)
            .await
            .map_err(|_| "UPDATER_CACHE_FAILED")?;
        let mut state = self.state.lock().map_err(|_| "UPDATER_INTERNAL")?;
        ensure_not_cancelled(&cancellation)?;
        let result = DownloadedUpdate {
            version: selection.info.version.clone(),
            installer_path: final_path.clone(),
        };
        state.receipt = Some(Receipt {
            selection,
            path: final_path,
        });
        state.cancellation = None;
        // Receipt now owns the published directory; errors and cancellation above clean up.
        owned_dir.1 = true;
        Ok(result)
    }

    pub fn verify_installer(&self, selection_id: &str) -> Result<VerifiedInstaller, String> {
        let operation = self.begin()?;
        let receipt = self
            .state
            .lock()
            .map_err(|_| "UPDATER_INTERNAL")?
            .receipt
            .clone()
            .ok_or("UPDATER_NOT_DOWNLOADED")?;
        if receipt.selection.info.selection_id != selection_id {
            return Err("UPDATER_SELECTION_CHANGED".into());
        }
        let mut file = platform::open_installer(&receipt.path)?;
        let mut verifier = ByteVerifier::new(
            receipt.selection.info.download_size,
            receipt.selection.digest,
        );
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|_| "UPDATER_INTEGRITY_FAILED")?;
            if n == 0 {
                break;
            }
            verifier.update(&buffer[..n])?;
        }
        verifier.finish()?;
        Ok(VerifiedInstaller {
            _file: file,
            path: receipt.path.clone(),
            version: receipt.selection.info.version.clone(),
            _lease: operation,
        })
    }
}

async fn cancellable<T>(
    cancellation: &Cancellation,
    future: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    ensure_not_cancelled(cancellation)?;
    tokio::select! {
        biased;
        _ = cancellation.notify.notified() => Err("UPDATER_DOWNLOAD_CANCELLED".into()),
        result = tokio::time::timeout(STALL_TIMEOUT, future) => result.map_err(|_| "UPDATER_DOWNLOAD_FAILED".into()),
    }
}

fn ensure_not_cancelled(cancellation: &Cancellation) -> Result<(), String> {
    if cancellation.cancelled.load(Ordering::SeqCst) {
        Err("UPDATER_DOWNLOAD_CANCELLED".into())
    } else {
        Ok(())
    }
}

fn stable_version(value: &str) -> Result<Version, String> {
    let version = Version::parse(value).map_err(|_| "UPDATER_METADATA_INVALID")?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    Ok(version)
}

fn https_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "UPDATER_METADATA_INVALID")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    Ok(url)
}

const DEVICE_ID_FILE: &str = "device-id";

fn check_request_url(base: &Url, device_id: &str, current_version: &str) -> Url {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("deviceId", device_id)
        .append_pair("currentVersion", current_version);
    url
}

fn load_or_create_device_id(cache_root: &Path) -> Result<String, String> {
    let storage_root = cache_root.parent().unwrap_or(cache_root);
    fs::create_dir_all(storage_root).map_err(|_| "UPDATER_CACHE_FAILED")?;
    let path = storage_root.join(DEVICE_ID_FILE);
    if let Ok(value) = fs::read_to_string(&path) {
        let value = value.trim();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(value.to_owned());
        }
    }
    let mut value = String::with_capacity(64);
    for byte in uuid::Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(uuid::Uuid::new_v4().as_bytes().iter())
    {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| "UPDATER_INTERNAL")?;
    }
    fs::write(&path, &value).map_err(|_| "UPDATER_CACHE_FAILED")?;
    Ok(value)
}

fn parse_feed(bytes: &[u8], current_version: &str) -> Result<Selection, String> {
    if bytes.len() > MANIFEST_LIMIT {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    let feed: Feed = serde_json::from_slice(bytes).map_err(|_| "UPDATER_METADATA_INVALID")?;
    let version = stable_version(&feed.latest_version)?;
    let current = stable_version(current_version)?;
    let package = feed
        .platforms
        .get("windows-x64")
        .ok_or("UPDATER_METADATA_INVALID")?;
    if package.format != "nsis"
        || package
            .version
            .as_ref()
            .is_some_and(|v| v != &feed.latest_version)
    {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    if package.size == 0 || package.size > MAX_INSTALLER_SIZE {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    if package.sha256.len() != 64 || !package.sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("UPDATER_METADATA_INVALID".into());
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&package.sha256[i * 2..i * 2 + 2], 16)
            .map_err(|_| "UPDATER_METADATA_INVALID")?;
    }
    Ok(Selection {
        info: CheckedUpdate {
            selection_id: uuid::Uuid::new_v4().to_string(),
            version: feed.latest_version,
            notes: feed.notes,
            pub_date: feed.pub_date,
            download_size: package.size,
            url: package.url.clone(),
            sha256: package.sha256.to_ascii_lowercase(),
            available: version > current,
        },
        url: https_url(&package.url)?,
        digest,
    })
}

struct ByteVerifier {
    count: u64,
    expected_size: u64,
    expected_digest: [u8; 32],
    hash: Sha256,
}
impl ByteVerifier {
    fn new(expected_size: u64, expected_digest: [u8; 32]) -> Self {
        Self {
            count: 0,
            expected_size,
            expected_digest,
            hash: Sha256::new(),
        }
    }
    fn update(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.count = self
            .count
            .checked_add(bytes.len() as u64)
            .ok_or("UPDATER_INTEGRITY_FAILED")?;
        if self.count > self.expected_size {
            return Err("UPDATER_INTEGRITY_FAILED".into());
        }
        self.hash.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<(), String> {
        if self.count != self.expected_size {
            return Err("UPDATER_INTEGRITY_FAILED".into());
        }
        if self.hash.finalize().as_slice() != self.expected_digest {
            return Err("UPDATER_INTEGRITY_FAILED".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
