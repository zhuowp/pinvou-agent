import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';
import { dict } from './helpers/i18n-all.js';
import { updateErrorCopy, updateOutcomeCopy } from '../src/features/settings/update-check-copy.js';

function updater(invoke, initial = {}) {
  const window = {};
  const context = vm.createContext({ window });
  for (const path of ['../src/shared/bridge-shared-helpers.js', '../src/platform/tauri/bridge/updater.js']) {
    vm.runInContext(readFileSync(new URL(path, import.meta.url), 'utf8'), context, { filename: path });
  }
  const state = { updateInfo: null, updateCheckError: null, ...initial };
  let notifications = 0;
  const feature = window.__PINVOU_TAURI_BRIDGE_FEATURES__.updater({
    state, invoke, notify: () => { notifications += 1; },
  });
  return { state, feature, notifications: () => notifications };
}

test('real updater bridge keeps unsupported startup silent and manual status truthful', async () => {
  const calls = [];
  const invoke = async command => {
    calls.push(command);
    // Tauri rejects with the serialized Rust error string.
    // eslint-disable-next-line prefer-promise-reject-errors
    return Promise.reject('UPDATER_CHECK_UNSUPPORTED');
  };
  const run = updater(invoke, { appVersion: '1.2.3' });
  await run.feature.checkForUpdateSilently();
  assert.equal(run.state.updateCheckError, null);
  assert.equal(run.notifications(), 0);
  assert.equal(run.state.appVersion, '1.2.3');
  run.state.updateInfo = { available: true, latest_version: 'stale' };
  await run.feature.checkForUpdate();
  assert.deepEqual(calls, ['get_app_version', 'check_for_update']);
  assert.equal(run.state.updateCheckError, 'UPDATER_CHECK_UNSUPPORTED');
  assert.equal(run.state.updateInfo, null);
  assert.equal(run.state.updateChecking, false);
  for (const language of ['zh', 'en', 'ja']) {
    const message = updateErrorCopy(run.state, dict[language]);
    assert.equal(message, dict[language].updateCheckUnsupported);
    assert.notEqual(message, dict[language].upToDate);
    assert.ok(message.length > 0);
  }
});

test('manual check preserves genuine success and generic failure semantics', async () => {
  const current = updater(async command => {
    assert.equal(command, 'check_for_update');
    return { available: false, current_version: '1.2.3' };
  });
  await current.feature.checkForUpdate();
  assert.equal(current.state.updateCheckError, 'latest');
  assert.equal(current.state.appVersion, '1.2.3');
  const failed = updater(async command => {
    assert.equal(command, 'check_for_update');
    throw new Error('network offline');
  });
  await failed.feature.checkForUpdate();
  assert.equal(failed.state.updateCheckError, 'network offline');
  assert.equal(updateErrorCopy(failed.state, dict.en), dict.en.updateCheckFailed);
  assert.notEqual(failed.state.updateCheckError, 'latest');
});

test('fixed causes have distinct localized copy in all languages and never expose URLs', () => {
  for (const language of ['zh', 'en', 'ja']) {
    const text = dict[language];
    for (const [code, key] of Object.entries({ UPDATER_CHECK_UNCONFIGURED: 'updateCheckUnconfigured', UPDATER_BUSY: 'updateBusy', UPDATER_DOWNLOAD_CANCELLED: 'updateDownloadCancelled', UPDATER_INSTALL_CANCELLED: 'updateInstallCancelled', UPDATER_INTEGRITY_FAILED: 'updateIntegrityFailed', UPDATER_ACTIVE_TASKS: 'updateActiveTasks', UPDATER_CACHE_FAILED: 'updateCacheFailed', UPDATER_SELECTION_CHANGED: 'updateRecheckRequired' })) {
      assert.ok(text[key]);
      assert.equal(updateErrorCopy({ updateError: code }, text), text[key]);
    }
    assert.equal(updateErrorCopy({ updateError: 'https://private.example/file?token=secret' }, text), text.updateInstallFailed);
    assert.ok(text.updateInstallAndQuit);
  }
});

test('a new manual check clears old operation errors and invalid replies never claim latest', async () => {
  const current = updater(async () => ({ available: false }), { updateError: 'UPDATER_DOWNLOAD_FAILED' });
  await current.feature.checkForUpdate();
  assert.equal(current.state.updateError, null);
  assert.equal(current.state.updateCheckError, 'latest');
  const invalid = updater(async () => null);
  await invalid.feature.checkForUpdate();
  assert.equal(invalid.state.updateCheckError, 'UPDATER_METADATA_INVALID');
  assert.equal(invalid.state.updateInfo, null);
});

test('startup consumes only whitelisted local pending-version outcomes without claiming latest or installation completion', async () => {
  for (const result of ['version_now_target', 'unknown']) {
    const calls = [];
    const run = updater(async command => { calls.push(command); return { had_pending: true, result }; });
    await run.feature.reportPendingUpdateResult();
    assert.deepEqual(calls, ['report_pending_update_result']);
    assert.equal(run.state.updateOutcome, result);
    assert.equal(run.notifications(), 1);
    assert.equal(run.state.updateCheckError, null);
    assert.equal(run.state.updateInfo, null);
    assert.equal(run.state.updateReady, undefined);
    for (const language of ['zh', 'en', 'ja']) {
      const key = result === 'version_now_target' ? 'updateOutcomeVersionNowTarget' : 'updateOutcomeUnknown';
      assert.ok(dict[language][key]);
      assert.equal(updateOutcomeCopy(run.state, dict[language]), dict[language][key]);
      assert.notEqual(updateOutcomeCopy(run.state, dict[language]), dict[language].upToDate);
      assert.notEqual(updateOutcomeCopy(run.state, dict[language]), dict[language].updateInstallerStarted);
    }
  }
});

test('no pending result, malformed outcomes and failed reads clear prior startup observation', async () => {
  for (const reply of [null, { had_pending: false, result: 'version_now_target' }, { had_pending: 'true', result: 'version_now_target' }, { had_pending: true, result: 'installer_completed' }, { had_pending: true }]) {
    const run = updater(async () => reply, { updateOutcome: 'version_now_target' });
    await run.feature.reportPendingUpdateResult();
    assert.equal(run.state.updateOutcome, null);
    assert.equal(run.notifications(), 1);
    assert.equal(updateOutcomeCopy(run.state, dict.en), '');
  }
  const failed = updater(async () => { throw new Error('local record unavailable'); }, { updateOutcome: 'version_now_target' });
  await failed.feature.reportPendingUpdateResult();
  assert.equal(failed.state.updateOutcome, null);
  assert.equal(failed.state.updateCheckError, null);
  assert.equal(updateOutcomeCopy(failed.state, dict.en), '');
});
