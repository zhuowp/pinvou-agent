use tauri::AppHandle;

use super::super::{DownloadedUpdate, PendingUpdateReportResult, UpdateInfo};

pub fn cleanup_stale_backup() {}

pub async fn check_for_update_info(_current_version: &str) -> Result<UpdateInfo, String> {
    Err("UPDATER_CHECK_UNSUPPORTED".to_owned())
}

pub async fn download_update_package(
    _info: &UpdateInfo,
    _app: AppHandle,
) -> Result<DownloadedUpdate, String> {
    Err("UPDATER_UNSUPPORTED".to_owned())
}

pub fn install_downloaded_update(
    _deb_path: Option<String>,
    _installer_path: Option<String>,
    _info: Option<UpdateInfo>,
) -> Result<bool, String> {
    Err("UPDATER_UNSUPPORTED".to_owned())
}

pub async fn report_pending_update_result_info(
    _client: &reqwest::Client,
    _current_version: &str,
) -> Result<PendingUpdateReportResult, String> {
    Ok(PendingUpdateReportResult {
        had_pending: false,
        reported: false,
        result: String::new(),
        message: "no pending update result to report".to_string(),
    })
}

pub fn cancel_download() {}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn unsupported_check_does_not_claim_installed_version_is_latest() {
        assert_eq!(
            super::check_for_update_info("0.1.0").await.unwrap_err(),
            "UPDATER_CHECK_UNSUPPORTED"
        );
    }
}
