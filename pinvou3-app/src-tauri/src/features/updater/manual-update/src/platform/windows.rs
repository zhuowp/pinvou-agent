use std::{
    fs::{File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(crate) fn open_installer(path: &Path) -> Result<File, String> {
    const FILE_SHARE_READ: u32 = 1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| "UPDATER_INTEGRITY_FAILED")?;
    let metadata = file.metadata().map_err(|_| "UPDATER_INTEGRITY_FAILED")?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("UPDATER_INTEGRITY_FAILED".into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use crate::tests::{feed, parse, updater};
    use crate::*;

    #[test]
    fn held_verified_installer_rejects_tampering_and_releases_gate() {
        let updater = updater();
        fs::create_dir(&updater.cache_root).unwrap();
        let path = updater.cache_root.join("installer.exe");
        fs::write(&path, b"installer").unwrap();
        let mut selection = parse(feed(), "1.0.0").unwrap();
        selection.digest = Sha256::digest(b"installer").into();
        selection.info.download_size = 9;
        let id = selection.info.selection_id.clone();
        updater.state.lock().unwrap().receipt = Some(Receipt {
            selection,
            path: path.clone(),
        });
        let installer = updater.verify_installer(&id).unwrap();
        assert!(updater.begin().is_err());
        assert!(fs::write(&path, b"tampered!").is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(installer);
        fs::write(&path, b"tampered!").unwrap();
        assert!(updater.verify_installer(&id).is_err());
        assert!(updater.begin().is_ok());
        updater.clear_selection();
        assert!(!path.exists());
    }
}
