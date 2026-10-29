(function () {
  // biome-ignore lint/suspicious/noRedundantUseStrict: verbatim copy of a classic script; strict mode is the payload
  "use strict";

  function previewEnabled(loc) {
    if (!loc || !loc.search) return false;
    try {
      const params = new URLSearchParams(loc.search);
      return params.get("mockUpdate") === "1";
    } catch {
      return false;
    }
  }

  function previewInfo() {
    // 根据当前运行平台派生预览平台,让开发者在本机看到的更新卡片行为与真实一致。
    // navigator 可能在非浏览器环境(test vm)缺失 → 回退 linux。
    const nav = (typeof navigator === "undefined") ? null : navigator;
    const platformStr = (((nav && nav.platform) || "") + " " + ((nav && nav.userAgent) || "")).toLowerCase();
    let platform = "linux";
    if (/mac|darwin/.test(platformStr)) platform = "macos";
    else if (/win/.test(platformStr)) platform = "windows";
    return {
      available: true,
      latest_version: "1.2.0",
      current_version: "1.1.0",
      platform,
      notes: "优化了模型响应速度，并修复了部分工具调用失败的问题。",
    };
  }

  function updateInfoFor(bs, opts) {
    opts = opts || {};
    if (bs && bs.updateInfo && bs.updateInfo.available) return bs.updateInfo;
    if (opts.preview) return previewInfo();
    return null;
  }

  function versionKey(info) {
    if (!info) return "";
    return String(info.latest_version || info.current_version || "");
  }

  function text(labels, key, fallback) {
    labels = labels || {};
    return labels[key] || fallback;
  }

  function viewModel(bs, info, fallbackVersion, labels) {
    if (!info) return {};
    const downloading = !!(bs && bs.updateDownloading);
    const ready = !!(bs && bs.updateReady);
    const progress = (bs && bs.updateProgress) || 0;
    const installing = !!(bs && bs.updateInstalling);
    const downloaded = !!(bs && bs.updateDownloaded);
    const checking = !!(bs && bs.updateChecking);
    const version = info.latest_version || info.current_version || fallbackVersion || "1.2.0";
    const label = ready
      ? text(labels, "updateInstallerStarted", "安装器已启动")
      : installing ? text(labels, "installing", "安装中...")
      : checking ? text(labels, "checking", "检查中…")
      : downloading ? text(labels, "downloading", "下载中") + " " + progress + "%"
      : downloaded ? text(labels, "updateInstallAndQuit", "安装并退出")
      : text(labels, "updateDownload", "下载更新");
    return {
      downloading: downloading || installing,
      downloaded,
      version,
      label,
      action: ready || downloading || installing || checking ? "none" : downloaded ? "install" : "download",
      disabled: downloading || installing || checking || ready,
      // Localized hint only: the raw error may carry request details and be
      // untranslated; it stays on bridge state for diagnostics.
      error: bs && bs.updateError ? text(labels, "updateErrorMessage", text(labels, "updateInstallFailed", "更新失败")) : "",
    };
  }

  window.UpdateNoticeLogic = {
    previewEnabled,
    updateInfoFor,
    versionKey,
    viewModel,
  };
})();
