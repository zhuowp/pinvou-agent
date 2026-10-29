#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(super) use windows::open_installer;

#[cfg(not(target_os = "windows"))]
pub(super) fn open_installer(_: &std::path::Path) -> Result<std::fs::File, String> {
    Err("UPDATER_UNSUPPORTED".into())
}
