// Display only localized causes; transport errors can include private URLs.
export function updateErrorCopy(state, text) {
  const error = state?.updateError || state?.updateCheckError;
  const causes = {
    UPDATER_CHECK_UNSUPPORTED: text.updateCheckUnsupported,
    UPDATER_CHECK_UNCONFIGURED: text.updateCheckUnconfigured,
    UPDATER_BUSY: text.updateBusy,
    UPDATER_DOWNLOAD_CANCELLED: text.updateDownloadCancelled,
    UPDATER_INSTALL_CANCELLED: text.updateInstallCancelled,
    UPDATER_UNSUPPORTED: text.updateCheckUnsupported,
    UPDATER_ACTIVE_TASKS: text.updateActiveTasks,
    UPDATER_SELECTION_CHANGED: text.updateRecheckRequired,
    UPDATER_NOT_DOWNLOADED: text.updateRecheckRequired,
    UPDATER_METADATA_INVALID: text.updateRecheckRequired,
    UPDATER_CACHE_FAILED: text.updateCacheFailed,
    UPDATER_DOWNLOAD_FAILED: text.updateDownloadFailed,
    UPDATER_DOWNLOAD_INVALID: text.updateIntegrityFailed,
    UPDATER_INTEGRITY_FAILED: text.updateIntegrityFailed,
  };
  if (Object.hasOwn(causes, error) && causes[error]) return causes[error];
  if (error && /(?:HASH|SIGNATURE|INTEGRITY|SHA256|SIZE_MISMATCH)/.test(error)) return text.updateIntegrityFailed;
  if (state?.updateError) return text.updateInstallFailed;
  if (error && error !== 'latest') return text.updateCheckFailed;
  return '';
}

// Only the backend's local running-version observation has display copy.
export function updateOutcomeCopy(state, text) {
  if (state?.updateOutcome === 'version_now_target') return text.updateOutcomeVersionNowTarget;
  if (state?.updateOutcome === 'unknown') return text.updateOutcomeUnknown;
  return '';
}
