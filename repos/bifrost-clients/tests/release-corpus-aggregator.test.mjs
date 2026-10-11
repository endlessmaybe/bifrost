import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { runReleaseCorpus } from '../tools/release-corpus-runner.mjs';

const repo = path.resolve(import.meta.dirname, '..');
const umbrella = path.resolve(repo, '..', '..');
const dotnet = path.join(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');

function runDotnetFixture() {
  const project = path.join(repo, 'tests', 'ui-state-fixture', 'BifrostUiStateFixture.csproj');
  const corpus = JSON.parse(readFileSync(path.join(repo, 'config-contracts', 'release-envelope-corpus-v2.json'), 'utf8'));
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-corpus-binding-'));
  const root = path.join(temp, 'root.json');
  writeFileSync(root, JSON.stringify(corpus.trust) + '\n', 'utf8');
  try {
    const props = [`-p:BifrostReleaseTrustRootFile=${root}`, '-p:BifrostReleaseTrustRootTestOnly=true'];
    const build = spawnSync(dotnet, ['build', project, '-c', 'Debug', '--no-restore', '-t:Rebuild', '--nologo', ...props], { cwd: repo, encoding: 'utf8', timeout: 240000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(build.status, 0, build.stderr || build.stdout);
    const binding = spawnSync(dotnet, ['run', '--project', project, '-c', 'Debug', '--no-restore', '--no-build', '--', '--release-compiled-binding'], { cwd: repo, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(binding.status, 0, binding.stderr || binding.stdout);
    assert.match(binding.stdout, /RELEASE-COMPILED-BINDING PASS/);
    const run = spawnSync(dotnet, ['run', '--project', project, '-c', 'Debug', '--no-restore', '--no-build', '--', '--release-envelope-corpus'], { cwd: repo, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    return run.stdout.split(/\r?\n/).filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

function runAndroidFixture() {
  const gradle = path.join(repo, 'android-app', 'gradlew.bat');
  const corpus = JSON.parse(readFileSync(path.join(repo, 'config-contracts', 'release-envelope-corpus-v2.json'), 'utf8'));
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-corpus-android-'));
  const rootFile = path.join(temp, 'root.json');
  writeFileSync(rootFile, JSON.stringify(corpus.trust) + '\n', 'utf8');
  try {
    const args = ['--offline', '--no-daemon', '--rerun-tasks', 'testDebugUnitTest', '--tests', 'com.bifrost.client.BifrostReleaseContractCorpusTest', '-PbifrostTestVariant=true', '-PreleaseTrustRootFile=' + rootFile, '-PreleaseTrustRootTestOnly=true', '--console=plain'];
    const run = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'call', gradle, ...args], { cwd: path.join(repo, 'android-app'), encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
    assert.equal(run.status, 0, `${run.error?.message || ''}\n${run.stdout || ''}\n${run.stderr || ''}`);
    const xml = path.join(repo, 'android-app', 'build', 'test-results', 'testDebugUnitTest', 'TEST-com.bifrost.client.BifrostReleaseContractCorpusTest.xml');
    assert.ok(existsSync(xml), 'Android corpus XML is missing');
    const text = readFileSync(xml, 'utf8');
    assert.match(text, /tests="2" skipped="0" failures="0" errors="0"/);
    const output = text.match(/<system-out><!\[CDATA\[([\s\S]*?)\]\]><\/system-out>/)?.[1] || '';
    const rows = output.split(/\r?\n/).filter((line) => line.trim().startsWith('{')).map((line) => JSON.parse(line));
    assert.equal(rows.length, runReleaseCorpus().length, 'Android runner did not emit one row per full vector');
    return rows;
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

test('release corpus JS, C# and Android production runners have identical per-vector outcomes', () => {
  const js = runReleaseCorpus();
  const cs = runDotnetFixture();
  const android = runAndroidFixture();
  assert.equal(new Set(js.map((row) => row.id)).size, js.length, 'JS runner emitted duplicate vector ids');
  assert.equal(new Set(cs.map((row) => row.id)).size, cs.length, 'C# runner emitted duplicate vector ids');
  assert.equal(new Set(android.map((row) => row.id)).size, android.length, 'Android runner emitted duplicate vector ids');
  assert.equal(cs.length, js.length);
  assert.equal(android.length, js.length);
  const byId = new Map(cs.map((row) => [row.id, row]));
  const androidById = new Map(android.map((row) => [row.id, row]));
  assert.equal(byId.size, js.length);
  assert.equal(androidById.size, js.length);
  for (const row of js) {
    const other = byId.get(row.id);
    assert.ok(other, `C# runner omitted ${row.id}`);
    for (const field of ['disposition', 'error_family', 'manifest_digest', 'envelope_digest', 'allowlist_digest', 'authority_digest', 'root_fingerprint']) assert.equal(other[field] ?? null, row[field] ?? null, `${row.id}:${field}`);
    const androidRow = androidById.get(row.id);
    assert.ok(androidRow, `Android runner omitted ${row.id}`);
    for (const field of ['disposition', 'error_family', 'manifest_digest', 'envelope_digest', 'allowlist_digest', 'authority_digest', 'root_fingerprint']) assert.equal(androidRow[field] ?? null, row[field] ?? null, `Android ${row.id}:${field}`);
  }
});
