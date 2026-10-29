import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildWindowsUpdateManifest } from '../build-windows-update-manifest.mjs';

test('Windows feed binds the exact installer bytes and stable release asset', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'pinvou-feed-'));
  try {
    // Synthetic PE bytes test metadata generation, not a working NSIS installer.
    const bytes = Buffer.alloc(256);
    bytes.write('MZ');
    bytes.writeUInt32LE(128, 0x3c);
    bytes.writeUInt32LE(0x4550, 128);
    bytes.writeUInt16LE(0x14c, 132);
    bytes.writeUInt16LE(2, 150);
    const installer = path.join(root, 'pinvou-agent_1.2.3-windows-x64-setup.exe');
    await writeFile(installer, bytes);
    const options = { installer, repository: 'owner/project', version: '1.2.3', publishedAt: '2026-10-29T00:00:00Z' };
    const feed = await buildWindowsUpdateManifest(options);
    assert.equal(feed.latest_version, '1.2.3');
    assert.equal(feed.platforms['windows-x64'].format, 'nsis');
    assert.equal(feed.platforms['windows-x64'].sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(feed.platforms['windows-x64'].size, 256);
    assert.equal(feed.platforms['windows-x64'].url,
      'https://github.com/owner/project/releases/download/v1.2.3/pinvou-agent_1.2.3-windows-x64-setup.exe');
    await assert.rejects(buildWindowsUpdateManifest({ ...options, version: '1.2.3-beta.1' }), /stable/);
    await assert.rejects(buildWindowsUpdateManifest({ ...options, version: '1.2.4' }), /name/);
    await assert.rejects(buildWindowsUpdateManifest({ ...options, repository: 'owner/project?token=x' }), /repository/);
    bytes.writeUInt16LE(0x2002, 150);
    await writeFile(installer, bytes);
    await assert.rejects(buildWindowsUpdateManifest(options), /executable/);
    await writeFile(installer, Buffer.from('not an installer'));
    await assert.rejects(buildWindowsUpdateManifest(options), /size/);
  } finally {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('pinvou-feed-'));
    await rm(root, { recursive: true, force: true });
  }
});
