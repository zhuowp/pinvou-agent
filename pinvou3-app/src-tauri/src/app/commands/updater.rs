use super::prelude::*;
use crate::features::updater as updater_domain;
use updater_domain::*;

sync_command_passthrough!(updater_domain, get_app_version() -> String);

/// Local-only diagnostic read; never performs a time HTTP request.
#[tauri::command]
pub async fn get_upgrade_trusted_time_status()
-> Result<updater_domain::trusted_time::TrustedTimeStatus, String> {
    tauri::async_runtime::spawn_blocking(updater_domain::trusted_time::inspect)
        .await
        .map_err(|_| "HOST_UNAVAILABLE".to_owned())?
}
/// Explicit user request. Accepted is not Known time or a cleanup result.
#[tauri::command]
pub async fn request_upgrade_trusted_time_refresh()
-> Result<updater_domain::trusted_time::TrustedTimeRefreshReply, String> {
    tauri::async_runtime::spawn_blocking(updater_domain::trusted_time::request_refresh)
        .await
        .map_err(|_| "HOST_UNAVAILABLE".to_owned())?
}
async_command_passthrough!(updater_domain, check_for_update() -> Result<UpdateInfo, String>);
async_command_passthrough!(
    updater_domain,
    download_update(info: UpdateInfo, app: AppHandle) -> Result<DownloadedUpdate, String>
);
/// Basic idle snapshot; this does not freeze all writers.
#[tauri::command]
pub async fn install_update(
    deb_path: Option<String>,
    installer_path: Option<String>,
    info: Option<UpdateInfo>,
    app: AppHandle,
) -> Result<(), String> {
    let engines = app
        .try_state::<EnginePool>()
        .ok_or("UPDATER_ACTIVE_TASKS")?
        .inner()
        .clone();
    // Existing lifecycle predicates take short synchronous locks internally.
    // A wedged state must refuse handoff without blocking the async command.
    let active = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(move || engines.has_active_work_for_update()),
    )
    .await
    .map_err(|_| "UPDATER_ACTIVE_TASKS")?
    .map_err(|_| "UPDATER_ACTIVE_TASKS")?;
    if active {
        return Err("UPDATER_ACTIVE_TASKS".into());
    }
    let acp = app
        .try_state::<crate::features::codex_acp::AcpPool>()
        .ok_or("UPDATER_ACTIVE_TASKS")?;
    if acp.has_active_work_for_update().await {
        return Err("UPDATER_ACTIVE_TASKS".into());
    }
    updater_domain::install_update(deb_path, installer_path, info, app.clone()).await
}
#[tauri::command]
pub async fn restart_app(app: AppHandle) -> Result<(), String> {
    crate::app::lifecycle::restart_application(app).await
}
sync_command_passthrough!(updater_domain, cancel_download());
async_command_passthrough!(updater_domain, report_pending_update_result() -> Result<PendingUpdateReportResult, String>);
