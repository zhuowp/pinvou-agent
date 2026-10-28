// Public cryptographic DATA only. Fresh private keys never leave memory.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createFixtureSet, NOW } from '../specs/upgrade/v1/reference/tests/fixtures.mjs';
import { canonicalize } from '../specs/upgrade/v1/reference/canonical-json.mjs';
import { publicKeyDescriptor, signEnvelope, envelopeReference, verifyRootChain, verifyTimeResponse } from '../specs/upgrade/v1/reference/signatures.mjs';
import { verifyPublicChain } from '../specs/upgrade/v1/reference/metadata-chain.mjs';
const require = createRequire(import.meta.url);
const { TARGET, LAYOUT, sha256 } = require('../pinvou3-app/scripts/tauri/windows-host-profile.js');
const destination = process.argv[2];
if (!destination || !path.isAbsolute(destination) || process.argv.length !== 3) throw new Error('absolute fixture directory required');
const f = createFixtureSet();
const timeKey = generateKeyPairSync('ed25519').privateKey;
const newMeta = generateKeyPairSync('ed25519').privateKey;
const oldId = f.descriptors[3].keyId, newId = publicKeyDescriptor(newMeta).keyId;
const windows = value => JSON.parse(JSON.stringify(value).replaceAll('linux-x86_64-deb-perMachine', TARGET).replaceAll('"format":"deb"', '"format":"nsis"'));
const root1 = windows(f.metadata.root);
root1.issuedAt = NOW - 1000;
root1.expiresAt -= 1000;
root1.keys.push(publicKeyDescriptor(timeKey), publicKeyDescriptor(newMeta));
root1.roles.push({ role: 'time', component: 'app', channel: null, targetKey: null,
  threshold: 1, keyIds: [publicKeyDescriptor(timeKey).keyId] });
const root2 = { ...structuredClone(root1), version: 2, issuedAt: NOW + 900 };
const root3 = { ...structuredClone(root1), version: 3, issuedAt: NOW + 900 };
for (const role of root2.roles) if (!['root', 'time'].includes(role.role)) role.keyIds = [oldId, newId];
for (const role of root3.roles) if (!['root', 'time'].includes(role.role)) role.keyIds = [newId];
const rootBytes = [root1, root2, root3].map(root => Buffer.from(signEnvelope(root, f.keys.slice(0, 2))));
// Reuse the reviewed graph templates, then rebuild references bottom-up.
const graph = {};
for (const role of ['package', 'release', 'target', 'snapshot', 'timestamp']) {
  const body = windows(f.metadata[role]);
  if (body.issuedAt) body.issuedAt = NOW - 100;
  if (body.expiresAt) body.expiresAt = NOW + 500;
  if (role === 'release') body.targets[0].packageManifest = envelopeReference(graph.package);
  if (role === 'target') body.baselineRelease = envelopeReference(graph.release);
  if (role === 'snapshot') body.entries = ['target', 'release', 'package'].map(r => envelopeReference(graph[r]));
  if (role === 'timestamp') body.snapshot = envelopeReference(graph.snapshot);
  graph[role] = Buffer.from(signEnvelope(body, [f.keys[3]]));
}
const active = Object.values(graph).map(bytes => {
  const body = JSON.parse(bytes).signed;
  return { bytes, expected: { role: body.role, product: body.product, component: body.component, scope: body.scope } };
});
verifyPublicChain({ trustedRoot: root1, product: 'pinvou', component: 'app', now: NOW,
  timestampBytes: graph.timestamp, snapshotBytes: graph.snapshot, members: [graph.target, graph.release, graph.package] });
assert.throws(() => verifyPublicChain({ trustedRoot: root2, product: 'pinvou', component: 'app', now: NOW + 1000,
  timestampBytes: graph.timestamp, snapshotBytes: graph.snapshot, members: [graph.target, graph.release, graph.package] }), { code: 'TIME_WINDOW_CLOSED' });
verifyRootChain([rootBytes[1]], { trustedRoot: root1, product: 'pinvou', now: NOW + 1000, activeEnvelopes: active });
assert.throws(() => verifyRootChain(rootBytes.slice(1), { trustedRoot: root1, product: 'pinvou', now: NOW + 1000, activeEnvelopes: active }), { code: 'SIGNING_KEY_NOT_AUTHORIZED' });
const observations = rootBytes.map((raw, index) => {
  const root = { version: index + 1, sha256: sha256(raw) };
  const request = { protocolVersion: 1, product: 'pinvou', component: 'app', requestNonce: Buffer.alloc(32, index + 21).toString('base64url'), root };
  const serverTime = NOW + (index === 0 ? 0 : 1000);
  const response = Buffer.from(signEnvelope({ protocolVersion: 1, role: 'time', product: 'pinvou', component: 'app',
    scope: {}, purpose: 'trusted-time.v1', requestNonce: request.requestNonce, root, serverTime, uncertaintyMs: 5 }, [timeKey]));
  const checked = verifyTimeResponse(response, { request, trustedRootBytes: rootBytes[0], rootSuccessors: rootBytes.slice(1, index + 1),
    sentMonotonicMs: 1000, receivedMonotonicMs: 1020, maxRoundTripMs: 20, maxUncertaintyMs: 5, trustedTimeFloor: 0, deniedKeyIds: [] });
  return { request, response: response.toString('utf8'), earliest: checked.earliest, latest: checked.latest };
});
const seed = { hostSeedVersion: 1, profileKind: 'lab', profileId: 'metadata-component-test', product: 'pinvou', component: 'app', targetKey: TARGET,
  buildId: 'b'.repeat(64), appVersion: '1.0.0', layoutId: LAYOUT, hostIpcVersion: 1, hostStateVersion: 1,
  originalRoot: { size: rootBytes[0].length, sha256: sha256(rootBytes[0]) },
  approvedInitialPublisherPolicy: { policyId: 'isolated-test-only', signerCertificateSha256: 'c'.repeat(64) } };
const fixture = { boundary: 'Public signed DATA; native test writes historical journal format and never constructs service authority or commits Root promotion.',
  original: rootBytes[0].toString('utf8'), successors: rootBytes.slice(1).map(b => b.toString('utf8')), observations,
  alpha: { timestamp: graph.timestamp.toString('utf8'), snapshot: graph.snapshot.toString('utf8'), members: [graph.target, graph.release, graph.package].map(b => b.toString('utf8')) }, oldMetadataKeyId: oldId };
for (const [name, bytes] of [['root.json', rootBytes[0]], ['seed.json', Buffer.from(canonicalize(seed))], ['fixture.json', Buffer.from(canonicalize(fixture))]])
  fs.writeFileSync(path.join(destination, name), bytes, { flag: 'wx' });
console.log('Root publication fixture: signed Alpha, dual-trust success and old-key exit refusal verified; public files written.');
