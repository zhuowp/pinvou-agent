import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const updaterSource = fs.readFileSync(
  path.join(here, '..', 'src', 'platform', 'tauri', 'bridge', 'updater.js'),
  'utf8',
);

function loadUpdaterFeature(options = {}) {
  const root = { __PINVOU_TAURI_BRIDGE_FEATURES__: {} };
  const context = vm.createContext({ window: root });
  vm.runInContext(fs.readFileSync(path.join(here, '..', 'src/shared/bridge-shared-helpers.js'), 'utf8'), context);
  vm.runInContext(updaterSource, context);

  const state = {
    updateProgress: 0,
    updateDownloading: false,
    updateCancelling: false,
    updateError: null,
    updateReady: false,
    updateInfo: { available: true, platform: 'windows', latest_version: '2.0.0', selection_id: 'candidate-1' },
    ...options.state,
  };
  const notifications = [];
  const invokeCalls = [];
  const listeners = [];
  const factory = root.__PINVOU_TAURI_BRIDGE_FEATURES__.updater;
  const updater = factory({
    state,
    listen(name, callback) { listeners.push({ name, callback }); return Promise.resolve(() => {}); },
    notify() {
      notifications.push(state.updateProgress);
    },
    invoke(command, args) {
      invokeCalls.push({ command, args });
      return options.invoke ? options.invoke(command, args) : Promise.resolve(null);
    },
  });

  return { updater, state, notifications, invokeCalls, listeners };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test('downloadAndInstallUpdate guards against missing or already-running updates', async () => {
  const missing = loadUpdaterFeature({ state: { updateInfo: null } });
  assert.equal(await missing.updater.downloadAndInstallUpdate(), false);
  assert.equal(missing.invokeCalls.length, 0, 'no backend command may run without update info');

  const unavailable = loadUpdaterFeature({ state: { updateInfo: { available: false, platform: 'linux' } } });
  assert.equal(await unavailable.updater.downloadAndInstallUpdate(), false);
  assert.equal(unavailable.invokeCalls.length, 0);

  const busy = loadUpdaterFeature({ state: { updateDownloading: true } });
  assert.equal(await busy.updater.downloadAndInstallUpdate(), false);
  assert.equal(busy.invokeCalls.length, 0);
});

test('a failed download surfaces updateError and clears the downloading flag', async () => {
  const runtime = loadUpdaterFeature({
    invoke: (command) => command === 'download_update'
      ? Promise.reject(new Error('network unavailable'))
      : Promise.resolve(null),
  });

  const installed = await runtime.updater.downloadAndInstallUpdate();

  assert.equal(installed, false);
  assert.match(String(runtime.state.updateError), /network unavailable/);
  assert.equal(runtime.state.updateDownloading, false);
  assert.equal(runtime.state.updateCancelling, false);
  assert.equal(runtime.state.updateReady, false, 'a failed download must not mark the update ready');
  assert.ok(!runtime.invokeCalls.some(call => call.command === 'install_update'),
    'a failed download must not reach the install step');
  assert.ok(!runtime.invokeCalls.some(call => call.command === 'restart_app'),
    'a failed download must not restart the app');
});

test('a cancelled download resets progress with a localized cancellation code', async () => {
  const downloadGate = deferred();
  const runtime = loadUpdaterFeature({
    invoke: (command) => {
      if (command === 'download_update') return downloadGate.promise;
      if (command === 'cancel_download') return Promise.resolve(null);
      return Promise.resolve(null);
    },
  });

  const pending = runtime.updater.downloadAndInstallUpdate();
  await Promise.resolve();
  assert.equal(runtime.state.updateDownloading, true);
  assert.equal(runtime.state.updateProgress, 0);

  runtime.updater.cancelUpdate();
  assert.equal(runtime.state.updateCancelling, true, 'cancelling must raise the flag before the backend acks');
  assert.ok(runtime.invokeCalls.some(call => call.command === 'cancel_download'),
    'cancelling must interrupt the backend download loop');

  downloadGate.reject(new Error('Download cancelled'));
  const installed = await pending;
  assert.equal(installed, false);
  assert.equal(runtime.state.updateProgress, 0, 'a cancelled download must reset progress');
  assert.equal(runtime.state.updateError, 'UPDATER_DOWNLOAD_CANCELLED');
  assert.equal(runtime.state.updateDownloading, false);
  assert.equal(runtime.state.updateCancelling, false);
});


const installer = { installer_path: 'C:/updates/pinvou-setup.exe' };
test('download and install require separate actions; progress 100 never installs', async () => {
  const gate = deferred();
  const runtime = loadUpdaterFeature({ invoke: command => command === 'download_update' ? gate.promise : Promise.resolve(null) });
  assert.equal(runtime.listeners.length, 1);
  assert.equal(runtime.listeners[0].name, 'update:progress');
  const pending = runtime.updater.downloadAndInstallUpdate();
  await Promise.resolve();
  runtime.listeners[0].callback({ payload: { downloaded: 10, total: 10, progress: 100 } });
  assert.equal(runtime.state.updateProgress, 100);
  assert.equal(runtime.state.updateDownloading, true);
  assert.equal(runtime.state.updateDownloaded, undefined);
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), false);
  await runtime.updater.checkForUpdate();
  assert.equal(runtime.invokeCalls.length, 1, 'busy blocks checking and repeated download');
  gate.resolve(installer);
  assert.equal(await pending, true);
  assert.equal(runtime.state.updateDownloaded, true);
  assert.equal(runtime.state.updateReady, false);
  assert.equal(runtime.invokeCalls.length, 1, 'download completion never installs');
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), true);
  assert.equal(runtime.state.updateReady, true);
  const call = runtime.invokeCalls.find(call => call.command === 'install_update');
  assert.equal(call.args.installerPath, installer.installer_path);
  assert.equal(call.args.info.selection_id, 'candidate-1');
  assert.equal(runtime.invokeCalls.some(call => call.command === 'restart_app'), false);
  assert.equal(runtime.listeners.length, 1);
});

test('UAC cancellation preserves verified candidate and retries install without another download', async () => {
  let attempts = 0;
  const gate = deferred();
  const runtime = loadUpdaterFeature({ invoke(command) {
    if (command === 'download_update') return Promise.resolve(installer);
    if (command === 'install_update') return ++attempts === 1 ? Promise.reject('UPDATER_INSTALL_CANCELLED') : gate.promise;
    return Promise.resolve();
  } });
  await runtime.updater.downloadAndInstallUpdate();
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), false);
  assert.equal(runtime.state.updateDownloaded, true);
  assert.equal(runtime.state.updateReady, false);
  assert.equal(runtime.state.updateError, 'UPDATER_INSTALL_CANCELLED');
  const pending = runtime.updater.downloadAndInstallUpdate();
  assert.equal(runtime.state.updateInstalling, true);
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), false);
  await runtime.updater.checkForUpdate();
  gate.resolve(null);
  assert.equal(await pending, true);
  assert.equal(runtime.invokeCalls.filter(c => c.command === 'download_update').length, 1);
});

test('download captures metadata and rejects stale completion without overwriting new info', async () => {
  const gate = deferred();
  const runtime = loadUpdaterFeature({ invoke: () => gate.promise });
  const pending = runtime.updater.downloadAndInstallUpdate();
  await Promise.resolve();
  runtime.state.updateInfo.latest_version = '3.0.0';
  runtime.state.updateInfo.selection_id = 'candidate-2';
  gate.resolve(installer);
  assert.equal(await pending, false);
  assert.equal(runtime.invokeCalls[0].args.info.latest_version, '2.0.0');
  assert.equal(runtime.state.updateInfo.latest_version, '3.0.0');
  assert.equal(runtime.state.updateDownloaded, false);
  assert.equal(runtime.state.updateReady, false);
});

test('new checked selection invalidates candidate even at the same version', async () => {
  const runtime = loadUpdaterFeature({ invoke: command => Promise.resolve(command === 'download_update' ? installer : { available: true, platform: 'windows', latest_version: '2.0.0', selection_id: 'candidate-2' }) });
  await runtime.updater.downloadAndInstallUpdate();
  await runtime.updater.checkForUpdate();
  assert.equal(runtime.state.updateDownloaded, false);
  await runtime.updater.downloadAndInstallUpdate();
  assert.equal(runtime.invokeCalls.filter(c => c.command === 'install_update').length, 0);
  assert.equal(runtime.invokeCalls.filter(c => c.command === 'download_update').length, 2);
});

test('invalid download and failed install never report success', async () => {
  const invalid = loadUpdaterFeature();
  assert.equal(await invalid.updater.downloadAndInstallUpdate(), false);
  assert.equal(invalid.state.updateError, 'UPDATER_DOWNLOAD_INVALID');
  const failed = loadUpdaterFeature({ invoke: command => command === 'download_update' ? Promise.resolve(installer) : Promise.reject('UPDATER_INTEGRITY_FAILED') });
  await failed.updater.downloadAndInstallUpdate();
  assert.equal(await failed.updater.downloadAndInstallUpdate(), false);
  assert.equal(failed.state.updateDownloaded, false);
  assert.equal(failed.state.updateReady, false);
});

test('active tasks preserve candidate and the original info stays captured during installer launch', async () => {
  let attempts = 0;
  const gate = deferred();
  const runtime = loadUpdaterFeature({ invoke(command) {
    if (command === 'download_update') return Promise.resolve(installer);
    return ++attempts === 1 ? Promise.reject('UPDATER_ACTIVE_TASKS') : gate.promise;
  } });
  await runtime.updater.downloadAndInstallUpdate();
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), false);
  assert.equal(runtime.state.updateDownloaded, true);
  const pending = runtime.updater.downloadAndInstallUpdate();
  runtime.state.updateInfo = { available: true, latest_version: '9.0.0', platform: 'windows' };
  gate.resolve(null);
  assert.equal(await pending, true);
  const installs = runtime.invokeCalls.filter(c => c.command === 'install_update');
  assert.equal(installs[1].args.info.latest_version, '2.0.0');
  assert.equal(installs[1].args.info.selection_id, 'candidate-1');
});

test('fixed backend cancellation without UI cancel is retryable and late progress is ignored', async () => {
  let downloads = 0;
  const runtime = loadUpdaterFeature({ invoke: () => ++downloads === 1 ? Promise.reject('UPDATER_DOWNLOAD_CANCELLED') : Promise.resolve(installer) });
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), false);
  assert.equal(runtime.state.updateProgress, 0);
  assert.equal(runtime.state.updateError, 'UPDATER_DOWNLOAD_CANCELLED');
  assert.equal(await runtime.updater.downloadAndInstallUpdate(), true);
  runtime.listeners[0].callback({ payload: { progress: 25 } });
  assert.equal(runtime.state.updateProgress, 100);
  assert.equal(runtime.state.updateDownloaded, true);
  assert.equal(runtime.state.updateReady, false);
});
