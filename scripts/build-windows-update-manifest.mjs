import { createHash } from 'node:crypto';
import { open, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export async function buildWindowsUpdateManifest({
  installer, repository, version, notes = '', publishedAt = new Date().toISOString(),
}) {
  if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]*\/[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(repository || '')) {
    throw new Error('Expected a GitHub owner/repository');
  }
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version || '')
      || version.split('.').some(part => Number(part) > 65535)) {
    throw new Error('Expected a stable three-component Windows version');
  }
  const name = 'pinvou-agent_' + version + '-windows-x64-setup.exe';
  if (path.basename(installer) !== name) throw new Error('Installer name does not match the release version');
  if (!Number.isFinite(Date.parse(publishedAt))) throw new Error('Invalid publication date');
  const file = await open(installer, 'r');
  let size;
  let digest;
  try {
    const before = await file.stat();
    if (!before.isFile() || before.size < 64 || before.size > 4 * 1024 ** 3) {
      throw new Error('Invalid installer size or file type');
    }
    const dos = Buffer.alloc(64);
    await file.read(dos, 0, dos.length, 0);
    const peOffset = dos.readUInt32LE(0x3c);
    if (dos.toString('ascii', 0, 2) !== 'MZ' || peOffset < 64 || peOffset > before.size - 24) {
      throw new Error('Installer has no valid PE header');
    }
    const pe = Buffer.alloc(24);
    await file.read(pe, 0, pe.length, peOffset);
    if (pe.readUInt32LE(0) !== 0x4550 || ![0x14c, 0x8664].includes(pe.readUInt16LE(4))
        || !(pe.readUInt16LE(22) & 2) || (pe.readUInt16LE(22) & 0x2000)) {
      throw new Error('Installer is not a Windows executable');
    }
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ start: 0, autoClose: false })) hash.update(chunk);
    const after = await file.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino) {
      throw new Error('Installer changed while hashing');
    }
    size = after.size;
    digest = hash.digest('hex');
  } finally {
    await file.close();
  }
  return {
    latest_version: version,
    notes,
    pub_date: new Date(publishedAt).toISOString(),
    platforms: {
      'windows-x64': {
        version,
        format: 'nsis',
        url: 'https://github.com/' + repository + '/releases/download/v' + version + '/' + name,
        sha256: digest,
        size,
      },
    },
  };
}

async function main() {
  const options = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!['--installer', '--repository', '--version', '--output', '--notes-file'].includes(process.argv[i])
        || !process.argv[i + 1]) throw new Error('Expected --installer PATH --repository OWNER/REPO --output PATH');
    options[process.argv[i].slice(2)] = process.argv[i + 1];
  }
  if (!options.installer || !options.output) throw new Error('Installer and output paths are required');
  const version = options.version || (await readFile(new URL('../VERSION', import.meta.url), 'utf8')).trim();
  const repository = options.repository || process.env.GITHUB_REPOSITORY;
  const notes = options['notes-file'] ? await readFile(options['notes-file'], 'utf8') : '';
  const manifest = await buildWindowsUpdateManifest({ installer: options.installer, repository, version, notes });
  await writeFile(options.output, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write('Created Windows update manifest: ' + options.output + '\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
