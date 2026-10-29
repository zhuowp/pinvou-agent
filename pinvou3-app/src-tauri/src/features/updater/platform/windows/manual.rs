//! Native NSIS handoff. A launched process is not an installation outcome.
use super::super::super::{DownloadedUpdate, PendingUpdateReportResult, UpdateInfo};
use pinvou_manual_update::ManualUpdater;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::OnceLock,
};
use tauri::{AppHandle, Emitter};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError},
    UI::{
        Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

static UPDATER: OnceLock<Result<ManualUpdater, String>> = OnceLock::new();
fn updater() -> Result<&'static ManualUpdater, String> {
    UPDATER
        .get_or_init(|| {
            let feed = option_env!("PINVOU3_UPDATE_URL")
                .filter(|v| !v.is_empty())
                .ok_or("UPDATER_CHECK_UNCONFIGURED")?;
            ManualUpdater::new(
                feed,
                crate::platform::paths::pinvou3_home().join("updates/manual"),
            )
        })
        .as_ref()
        .map_err(Clone::clone)
}
pub async fn check_for_update_info(current: &str) -> Result<UpdateInfo, String> {
    let checked = updater()?.check(current).await?;
    Ok(UpdateInfo {
        selection_id: checked.selection_id,
        available: checked.available,
        current_version: current.to_owned(),
        latest_version: checked.version,
        notes: checked.notes.unwrap_or_default(),
        pub_date: checked.pub_date.unwrap_or_default(),
        url: checked.url,
        sha256: checked.sha256,
        size: checked.download_size,
        platform: "windows-x64".into(),
        platforms: Default::default(),
    })
}
#[derive(Clone, Serialize)]
struct Progress {
    downloaded: u64,
    total: u64,
    progress: f64,
}
pub async fn download_update_package(
    info: &UpdateInfo,
    app: AppHandle,
) -> Result<DownloadedUpdate, String> {
    let downloaded = updater()?
        .download(&info.selection_id, move |bytes| {
            let _ = app.emit(
                "update:progress",
                Progress {
                    downloaded: bytes.downloaded,
                    total: bytes.total,
                    progress: if bytes.total == 0 {
                        0.0
                    } else {
                        bytes.downloaded as f64 / bytes.total as f64 * 100.0
                    },
                },
            );
        })
        .await?;
    Ok(DownloadedUpdate {
        installer_path: downloaded.installer_path.to_string_lossy().into_owned(),
    })
}
pub fn cancel_download() {
    if let Some(Ok(updater)) = UPDATER.get() {
        updater.cancel_download();
    }
}

/// Shell and NSIS receive conventional drive paths. UNC/device/root paths and
/// command delimiters are rejected even for paths derived from the executable.
fn shell_path(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("UPDATER_INSTALL_FAILED")?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    if bytes.len() <= 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || text.chars().any(|c| c.is_control() || c == '"')
    {
        return Err("UPDATER_INSTALL_FAILED".into());
    }
    Ok(text.to_owned())
}
fn install_directory() -> Result<String, String> {
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "UPDATER_INSTALL_FAILED")?;
    shell_path(executable.parent().ok_or("UPDATER_INSTALL_FAILED")?)
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
#[derive(Serialize, Deserialize)]
struct Pending {
    from: String,
    target: String,
    install_directory: String,
}
fn pending_path() -> std::path::PathBuf {
    crate::platform::paths::pinvou3_home().join("updates/manual/pending.json")
}
fn write_pending(pending: &Pending) -> Result<(), String> {
    let path = pending_path();
    fs::create_dir_all(path.parent().ok_or("UPDATER_INSTALL_FAILED")?)
        .map_err(|_| "UPDATER_INSTALL_FAILED")?;
    let bytes = serde_json::to_vec(pending).map_err(|_| "UPDATER_INSTALL_FAILED")?;
    let mut file = fs::File::create(path).map_err(|_| "UPDATER_INSTALL_FAILED")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "UPDATER_INSTALL_FAILED".into())
}

pub fn install_downloaded_update(
    _deb_path: Option<String>,
    _installer_path: Option<String>,
    info: Option<UpdateInfo>,
) -> Result<bool, String> {
    let info = info.ok_or("UPDATER_SELECTION_CHANGED")?;
    // This function is called on spawn_blocking. Keep both held file and exclusive
    // backend lease alive until ShellExecute confirms that a process was created.
    let verified = updater()?.verify_installer(&info.selection_id)?;
    let executable = wide(&shell_path(verified.path())?);
    let directory = install_directory()?;
    // NSIS /D must be the final argument and must not be quoted, even with spaces.
    let parameters = wide(&format!("/D={directory}"));
    let working_directory = wide(&directory);
    let verb = wide("runas");
    write_pending(&Pending {
        from: env!("CARGO_PKG_VERSION").into(),
        target: verified.version().into(),
        install_directory: directory,
    })?;
    let mut launch: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    launch.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = verb.as_ptr();
    launch.lpFile = executable.as_ptr();
    launch.lpParameters = parameters.as_ptr();
    launch.lpDirectory = working_directory.as_ptr();
    launch.nShow = SW_SHOWNORMAL;
    // SAFETY: pointers refer to live NUL-terminated buffers until this synchronous
    // native handoff returns. Any returned process handle is closed below.
    let launched = unsafe { ShellExecuteExW(&mut launch) };
    if launched == 0 {
        let error = unsafe { GetLastError() };
        let _ = fs::remove_file(pending_path());
        return Err(if error == ERROR_CANCELLED {
            "UPDATER_INSTALL_CANCELLED"
        } else {
            "UPDATER_INSTALL_FAILED"
        }
        .into());
    }
    // Direct EXE launch requests a process handle. A missing handle is an
    // unknown handoff: retain the pending observation and keep this app alive.
    if launch.hProcess.is_null() {
        return Err("UPDATER_INSTALL_FAILED".into());
    }
    unsafe {
        CloseHandle(launch.hProcess);
    }
    verified.commit_launch();
    Ok(true)
}
pub async fn report_pending_update_result_info(
    _client: &reqwest::Client,
    current: &str,
) -> Result<PendingUpdateReportResult, String> {
    let current = current.to_owned();
    tokio::task::spawn_blocking(move || {
        let path = pending_path();
        let had_pending = path.exists();
        let pending = fs::File::open(&path).ok().and_then(|file| {
            let mut bytes = Vec::new();
            file.take(16 * 1024 + 1).read_to_end(&mut bytes).ok()?;
            if bytes.len() > 16 * 1024 {
                return None;
            }
            serde_json::from_slice::<Pending>(&bytes).ok()
        });
        let observed = pending.is_some_and(|p| {
            p.target == current
                && install_directory()
                    .is_ok_and(|dir| dir.eq_ignore_ascii_case(&p.install_directory))
        });
        if observed {
            let _ = fs::remove_file(path);
        }
        Ok(PendingUpdateReportResult {
            had_pending,
            reported: false,
            result: if !had_pending {
                ""
            } else if observed {
                "version_now_target"
            } else {
                "unknown"
            }
            .into(),
            message: String::new(),
        })
    })
    .await
    .map_err(|_| "UPDATER_INTERNAL".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shell_paths_reject_unsafe_destinations_and_normalize_drive_prefix() {
        assert_eq!(
            shell_path(Path::new(r"\\?\C:\Program Files\Pinvou")).unwrap(),
            r"C:\Program Files\Pinvou"
        );
        for path in [
            r"\\server\share\Pinvou",
            r"C:\",
            "C:\\app\n/evil",
            "relative",
            r#"C:\app"bad"#,
        ] {
            assert!(shell_path(Path::new(path)).is_err(), "{path}");
        }
    }
}
