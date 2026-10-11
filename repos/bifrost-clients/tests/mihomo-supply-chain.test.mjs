import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const lockPath = path.join(root, 'core-adapters', 'mihomo.lock.json');
const toolPath = path.join(root, 'tools', 'prepare-mihomo-core.mjs');

test('Windows release uses one pinned stable Mihomo artifact', () => {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  assert.equal(lock.schema, 'bifrost-mihomo-lock-v1');
  assert.equal(lock.version, 'v1.19.30');
  assert.equal(lock.platform, 'windows-amd64-compatible');
  assert.equal(lock.archive_url, 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-windows-amd64-compatible-v1.19.30.zip');
  assert.equal(lock.archive_size, 18_529_108);
  assert.equal(lock.archive_sha256, '289fde5e29d37a5b3326480590d8b3551c5bf7f8737290355c19bce74d57a563');
  assert.equal(lock.executable_name, 'mihomo.exe');
  assert.match(lock.executable_sha256, /^[0-9a-f]{64}$/);
  assert.equal(lock.license, 'GPL-3.0-only');
  assert.equal(lock.source, 'https://github.com/MetaCubeX/mihomo/tree/v1.19.30');
  assert.deepEqual(Object.keys(lock).sort(), [
    'archive_sha256', 'archive_size', 'archive_url', 'executable_name',
    'executable_sha256', 'license', 'platform', 'schema', 'source', 'version',
  ].sort());
});

test('preparation tool rejects an archive before extraction when its digest is wrong', () => {
  const scratch = mkdtempSync(path.join(tmpdir(), 'bifrost-mihomo-supply-'));
  try {
    const archive = path.join(scratch, 'mihomo.zip');
    const output = path.join(scratch, 'mihomo.exe');
    writeFileSync(archive, Buffer.from('not the pinned archive', 'utf8'));
    const result = spawnSync(process.execPath, [toolPath, '--lock', lockPath, '--archive', archive, '--output', output], {
      cwd: root,
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /BF-MIHOMO-ARCHIVE-(?:SIZE|HASH)/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('prepared executable reports the exact locked stable version', { skip: !process.env.BIFROST_MIHOMO_ARCHIVE }, () => {
  const scratch = mkdtempSync(path.join(tmpdir(), 'bifrost-mihomo-version-'));
  try {
    const output = path.join(scratch, 'mihomo.exe');
    execFileSync(process.execPath, [toolPath, '--lock', lockPath, '--archive', process.env.BIFROST_MIHOMO_ARCHIVE, '--output', output], {
      cwd: root,
      windowsHide: true,
    });
    const version = execFileSync(output, ['-v'], { encoding: 'utf8', windowsHide: true });
    assert.match(version, /Mihomo Meta v1\.19\.30/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
