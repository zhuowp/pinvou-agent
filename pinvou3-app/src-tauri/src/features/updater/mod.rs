//! Manual stable Windows updates with backend-owned receipts.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

pub mod cli_writer_admission;
pub(crate) mod download;
mod platform;
pub(crate) mod protocol;
pub(crate) mod startup_admission;
pub(crate) mod timing;
pub(crate) mod trusted_time;

pub(crate) fn cleanup_stale_backup() {
    platform::cleanup_stale_backup();
}

/// check_for_update 的返回值；前端原样传回 download_update。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    #[serde(default)]
    pub selection_id: String,
    pub available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub notes: String,
    pub pub_date: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default)]
    pub platform: String,
    /// 多平台清单:`{ "macos-universal": PlatformAsset, "linux-arm64": ..., ... }`。
    /// 旧版 latest.json 没这字段 → 空 map → 调用方回退到顶层 url/sha256/size。
    #[serde(default)]
    pub platforms: std::collections::HashMap<String, PlatformAsset>,
}

/// 多平台更新清单的单平台资产。`latest.json` 的 `platforms` map 每个值用这个类型。
/// 客户端按平台 key（如 `macos-universal`、`linux-arm64`）选自己平台的资产;缺失则回退到顶层 url/sha256/size。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformAsset {
    pub url: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub restart_after_install: bool,
    #[serde(default)]
    pub notes: String,
    /// 本平台资产自己的版本号。各平台独立发版(Mac 先发 0.7.0、Linux 还在 0.6.3)时,
    /// 客户端用**本平台**版本判要不要升级,而不是读顶层 .version —— 后者代表「最近一次
    /// Linux 发版」,Mac 客户端读它会被误导。旧 manifest / 旧 platform 条目无此字段 → 空
    /// 串 → 调用方回退到顶层 version(向后兼容)。
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingUpdateReportResult {
    pub had_pending: bool,
    pub reported: bool,
    pub result: String,
    pub message: String,
}
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check the build-controlled feed on supported Windows builds.
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION");
    platform::check_for_update_info(current)
        .await
        .inspect_err(|e| log::warn!("[updater] update check failed: {e}"))
}

/// Only the backend receipt authorizes install; this path is a transport hint.
#[derive(Debug, Clone, Serialize)]
pub struct DownloadedUpdate {
    pub installer_path: String,
}
pub async fn download_update(info: UpdateInfo, app: AppHandle) -> Result<DownloadedUpdate, String> {
    platform::download_update_package(&info, app).await
}

/// Verify and hand off the downloaded NSIS installer on a worker thread.
pub async fn install_update(
    deb_path: Option<String>,
    installer_path: Option<String>,
    info: Option<UpdateInfo>,
    app: AppHandle,
) -> Result<(), String> {
    let exit_after_start = tokio::task::spawn_blocking(move || {
        platform::install_downloaded_update(deb_path, installer_path, info)
    })
    .await
    .map_err(|e| {
        log::warn!("[updater] install task failed: {e}");
        "UPDATER_INSTALL_FAILED".to_owned()
    })?
    .inspect_err(|e| log::warn!("[updater] install failed: {e}"))?;
    if exit_after_start {
        crate::prepare_app_restart(&app).await;
        app.exit(0);
    }
    Ok(())
}

/// Cancel the actual domain download operation; native installation is separate.
pub fn cancel_download() {
    platform::cancel_download();
}

/// Observe a local pending handoff without claiming server acknowledgement.
pub async fn report_pending_update_result() -> Result<PendingUpdateReportResult, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build the HTTP client: {e}"))?;
    platform::report_pending_update_result_info(&client, env!("CARGO_PKG_VERSION")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_info_platforms_defaults_empty() {
        // 旧版 latest.json(无 platforms 字段)反序列化应得空 map,不报错。
        let json = r#"{
            "available": true,
            "current_version": "0.1.0",
            "latest_version": "0.2.0",
            "notes": "",
            "pub_date": "",
            "url": "https://example.com/p.pkg",
            "sha256": "abc",
            "size": 0
        }"#;
        let info: UpdateInfo = serde_json::from_str(json).unwrap();
        assert!(info.platforms.is_empty());
        assert!(info.selection_id.is_empty());
    }

    #[test]
    fn platform_asset_roundtrip() {
        let asset = PlatformAsset {
            url: "https://example.com/m.dmg".to_string(),
            format: "dmg".to_string(),
            sha256: "deadbeef".to_string(),
            size: 1024,
            restart_after_install: false,
            notes: "mac only".to_string(),
            version: "0.7.0".to_string(),
        };
        let json = serde_json::to_string(&asset).unwrap();
        let back: PlatformAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, asset.url);
        assert_eq!(back.size, 1024);
        assert_eq!(back.format, "dmg");
        assert_eq!(back.version, "0.7.0");
    }
}
