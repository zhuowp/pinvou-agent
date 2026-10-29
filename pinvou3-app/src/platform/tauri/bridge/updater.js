/**
 * updater feature for the Tauri bridge.
 * Registered before bridge.js builds the backwards-compatible facade.
 */
(function (root) {
  // biome-ignore lint/suspicious/noRedundantUseStrict: verbatim classic-script artifact; strict mode is part of the payload
  "use strict";
  // biome-ignore lint/suspicious/noAssignInExpressions: registry bootstrap of the verbatim payload; splitting statements would diverge from the artifact
  const registry = root.__PINVOU_TAURI_BRIDGE_FEATURES__ = root.__PINVOU_TAURI_BRIDGE_FEATURES__ || {};
  registry["updater"] = function (context) {let pinvouSharedtauriUpdaterCache = null;
function pinvouSharedtauriUpdater() {
  if (!pinvouSharedtauriUpdaterCache) pinvouSharedtauriUpdaterCache = window.PinvouBridgeShared.create("tauriUpdater", { state, notify, invoke });
  return pinvouSharedtauriUpdaterCache;
}


  const state = context.state;
  const notify = context.notify;
  const invoke = context.invoke;
  // Manual updates and independent local trusted-time diagnostics.
  let timeStatusPending = null;
  let timeRefreshPending = null;
  function inspectTrustedTime() {
    if (!timeStatusPending) {
      const request = Promise.resolve().then(() => invoke("get_upgrade_trusted_time_status"))
        .finally(() => {
          if (timeStatusPending === request) timeStatusPending = null;
        });
      timeStatusPending = request;
    }
    return timeStatusPending;
  }
  function requestTrustedTimeRefresh() {
    if (!timeRefreshPending) {
      timeRefreshPending = Promise.resolve().then(() => invoke("request_upgrade_trusted_time_refresh"))
        .then(reply => {
          // A post-ACK read must not reuse an observation begun before refresh.
          // Existing callers retain their promise; its finalizer cannot evict a
          // newer observation.
          timeStatusPending = null;
          return reply;
        })
        .finally(() => { timeRefreshPending = null; });
    }
    return timeRefreshPending;
  }
  async function loadAppVersion() {
    try {
      state.appVersion = await invoke("get_app_version");
    } catch { /* leaving the version empty on read failure is fine */ }
  }
  // Startup performs a local version read only.
  async function checkForUpdateSilently() { await loadAppVersion(); }
  let downloadedCandidate = null;
  function infoKey(info) {
    return JSON.stringify(info, info ? Object.keys(info).sort((left, right) => left < right ? -1 : left > right ? 1 : 0) : undefined);
  }
  function clearCandidate() {
    downloadedCandidate = null;
    state.updateDownloaded = false;
    state.updateReady = false;
    state.updateProgress = 0;
  }
  function busy() {
    return state.updateChecking || state.updateDownloading || state.updateInstalling;
  }
  function discardStaleCandidate() {
    if (downloadedCandidate && infoKey(state.updateInfo) !== infoKey(downloadedCandidate.info)) clearCandidate();
  }
  async function checkForUpdate() {
    if (busy() || state.updateReady) return false;
    await pinvouSharedtauriUpdater().checkForUpdate();
    discardStaleCandidate();
    notify();
  }

  // Installed once with the bridge feature, never per React mount or click.
  const progressListener = context.listen
    ? Promise.resolve(context.listen("update:progress", function (event) {
      if (!state.updateDownloading || state.updateCancelling) return;
      const progress = Number(event && event.payload && event.payload.progress);
      if (!Number.isFinite(progress)) return;
      state.updateProgress = Math.max(state.updateProgress, Math.min(100, Math.max(0, progress)));
      notify();
    }))
    : Promise.resolve();
  progressListener.catch(function () {});

  // First click downloads; a separate click confirms installation and quitting.
  // The verified path and captured metadata stay private to this bridge instance.
  async function downloadAndInstallUpdate() {
    if (busy() || state.updateReady) return false;
    discardStaleCandidate();
    if (!state.updateInfo || !state.updateInfo.available) return false;
    state.updateError = null;
    if (downloadedCandidate) {
      const candidate = downloadedCandidate;
      state.updateInstalling = true;
      notify();
      try {
        await invoke("install_update", { installerPath: candidate.installerPath, info: candidate.info });
        // The installer started; the next startup checks the actual outcome.
        state.updateReady = true;
        return true;
      } catch (error) {
        state.updateError = error && error.message || String(error);
        // UAC cancellation leaves the verified candidate available for retry.
        if (!["UPDATER_INSTALL_CANCELLED", "UPDATER_BUSY", "UPDATER_ACTIVE_TASKS"].includes(state.updateError)) clearCandidate();
        return false;
      } finally {
        state.updateInstalling = false;
        notify();
      }
    }
    const info = JSON.parse(JSON.stringify(state.updateInfo));
    state.updateDownloading = true;
    state.updateCancelling = false;
    state.updateProgress = 0;
    notify();
    try {
      await progressListener;
      const result = await invoke("download_update", { info });
      if (state.updateCancelling) {
        state.updateError = "UPDATER_DOWNLOAD_CANCELLED";
        state.updateProgress = 0;
        return false;
      }
      if (infoKey(state.updateInfo) !== infoKey(info)) {
        clearCandidate();
        return false;
      }
      if (!result || typeof result.installer_path !== "string" || !result.installer_path) throw new Error("UPDATER_DOWNLOAD_INVALID");
      downloadedCandidate = { info, installerPath: result.installer_path };
      state.updateDownloaded = true;
      state.updateProgress = 100;
      return true;
    } catch (error) {
      clearCandidate();
      state.updateError = state.updateCancelling ? "UPDATER_DOWNLOAD_CANCELLED" : error && error.message || String(error);
      return false;
    } finally {
      state.updateDownloading = false;
      state.updateCancelling = false;
      notify();
    }
  }
  function cancelUpdate() {
    if (!state.updateDownloading || state.updateCancelling) return;
    state.updateCancelling = true;
    notify();
    invoke("cancel_download").catch(function () {});
  }
  function restartApp() {
    invoke("restart_app").catch(function () { /* restart 成功不会返回 */ });
  }
  async function reportPendingUpdateResult() {
    let outcome = null;
    try {
      const reply = await invoke("report_pending_update_result");
      // This observes the running version locally; it is not installer completion.
      if (reply && reply.had_pending === true && ["version_now_target", "unknown"].includes(reply.result)) {
        outcome = reply.result;
      }
    } catch { /* Keep the local observation absent when the backend cannot read it. */ }
    state.updateOutcome = outcome;
    notify();
  }

    return {
      loadAppVersion,
      inspectTrustedTime,
      requestTrustedTimeRefresh,
      checkForUpdateSilently,
      checkForUpdate,
      downloadAndInstallUpdate,
      cancelUpdate,
      restartApp,
      reportPendingUpdateResult
    };
  };
})(window);
