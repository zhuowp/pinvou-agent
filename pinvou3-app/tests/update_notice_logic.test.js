#!/usr/bin/env node
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const logicPath = path.join(__dirname, '..', 'src', 'features', 'updater', 'update-notice-logic.js');
const code = fs.readFileSync(logicPath, 'utf8');
const ctx = {
  window: {},
  URLSearchParams,
};
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(code, ctx, { filename: logicPath });

const logic = ctx.window.UpdateNoticeLogic;

assert.strictEqual(logic.previewEnabled({ search: '?mockUpdate=1' }), true);
assert.strictEqual(logic.previewEnabled({ search: '?mockUpdate=0' }), false);
assert.strictEqual(logic.previewEnabled({ search: '' }), false);

assert.strictEqual(logic.updateInfoFor(null), null);
assert.deepStrictEqual(
  logic.updateInfoFor({ updateInfo: { available: true, latest_version: '2.0.0' } }),
  { available: true, latest_version: '2.0.0' }
);
assert.strictEqual(
  logic.updateInfoFor({ updateInfo: { available: false, latest_version: '2.0.0' } }),
  null
);
assert.strictEqual(logic.updateInfoFor(null, { preview: true }).latest_version, '1.2.0');

assert.strictEqual(logic.versionKey(null), '');
assert.strictEqual(logic.versionKey({ latest_version: '2.0.0', current_version: '1.0.0' }), '2.0.0');
assert.strictEqual(logic.versionKey({ current_version: '1.0.0' }), '1.0.0');

// vm-realm objects fail deepStrictEqual against test-realm literals; compare keys instead.
assert.deepStrictEqual(Object.keys(logic.viewModel(null, null)), []);

const vmIdle = logic.viewModel(
  { appVersion: '1.1.0' },
  { available: true, latest_version: '1.2.0', platform: 'linux' }
);
assert.strictEqual(vmIdle.version, '1.2.0');
assert.strictEqual(vmIdle.label, '下载更新');
assert.strictEqual(vmIdle.action, 'download');
assert.strictEqual(vmIdle.disabled, false);

const vmWindowsIdle = logic.viewModel(
  { appVersion: '1.1.0' },
  { available: true, latest_version: '1.2.0', platform: 'windows' }
);
assert.strictEqual(vmWindowsIdle.label, '下载更新');

const vmCustomLabels = logic.viewModel(
  { appVersion: '1.1.0' },
  { available: true, latest_version: '1.2.0', platform: 'linux' },
  null,
  { updateDownload: 'Download update' }
);
assert.strictEqual(vmCustomLabels.label, 'Download update');

const vmDownloading = logic.viewModel(
  { updateDownloading: true, updateProgress: 42 },
  { available: true, latest_version: '1.2.0' }
);
assert.strictEqual(vmDownloading.label, '下载中 42%');
assert.strictEqual(vmDownloading.action, 'none');
assert.strictEqual(vmDownloading.disabled, true);

const vmInstalling = logic.viewModel(
  { updateDownloading: true, updateProgress: 100 },
  { available: true, latest_version: '1.2.0' }
);
assert.strictEqual(vmInstalling.label, '下载中 100%');
assert.strictEqual(vmInstalling.action, 'none');

const vmReady = logic.viewModel(
  { updateReady: true },
  { available: true, latest_version: '1.2.0', platform: 'linux' }
);
assert.strictEqual(vmReady.label, '安装器已启动');
assert.strictEqual(vmReady.action, 'none');
assert.strictEqual(vmReady.disabled, true);

const vmWindowsReady = logic.viewModel(
  { updateReady: true },
  { available: true, latest_version: '1.2.0', platform: 'windows' }
);
assert.strictEqual(vmWindowsReady.label, '安装器已启动');
assert.strictEqual(vmWindowsReady.action, 'none');
assert.strictEqual(vmWindowsReady.disabled, true);

// Ready means installer launch, not installation completion.
const vmMacReady = logic.viewModel(
  { updateReady: true },
  { available: true, latest_version: '1.2.0', platform: 'macos' }
);
assert.strictEqual(vmMacReady.label, '安装器已启动');
assert.strictEqual(vmMacReady.action, 'none');
assert.strictEqual(vmMacReady.disabled, true);

const vmMacIdle = logic.viewModel(
  { appVersion: '1.1.0' },
  { available: true, latest_version: '1.2.0', platform: 'macos' }
);
assert.strictEqual(vmMacIdle.label, '下载更新');
assert.strictEqual(vmMacIdle.action, 'download');
assert.strictEqual(vmMacIdle.disabled, false);

// The raw backend error (may carry request details, often untranslated) must
// never reach the view model: the localized hint does, the raw string stays on
// bridge state for diagnostics.
const vmError = logic.viewModel(
  { updateError: 'sha256 failed' },
  { available: true, latest_version: '1.2.0' },
  '1.1.0',
  { updateInstallFailed: 'Update failed' }
);
assert.strictEqual(vmError.error, 'Update failed');
assert.strictEqual(
  logic.viewModel(
    { updateError: 'sha256 failed' },
    { available: true, latest_version: '1.2.0' }
  ).error,
  '更新失败',
  'labels without the key fall back to the default hint, never the raw error'
);

// The manual download action never promises an automatic restart.
const vmUnknownIdle = logic.viewModel(
  { appVersion: '1.1.0' },
  { available: true, latest_version: '1.2.0', platform: 'freebsd' }
);
assert.strictEqual(vmUnknownIdle.label, '下载更新');
assert.strictEqual(vmUnknownIdle.action, 'download');
assert.strictEqual(vmUnknownIdle.disabled, false);

console.log('update_notice_logic: ok');

const downloaded = logic.viewModel({ updateDownloaded: true }, { available: true, platform: 'windows' }, '', { updateInstallAndQuit: 'Install and quit' });
assert.strictEqual(downloaded.action, 'install');
assert.strictEqual(downloaded.label, 'Install and quit');
assert.strictEqual(downloaded.disabled, false);
const installing = logic.viewModel({ updateDownloaded: true, updateInstalling: true }, { available: true, platform: 'windows' });
assert.strictEqual(installing.action, 'none');
assert.strictEqual(installing.disabled, true);
const checking = logic.viewModel({ updateChecking: true }, { available: true, platform: 'windows' });
assert.strictEqual(checking.disabled, true);
