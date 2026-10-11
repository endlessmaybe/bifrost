import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const dotnet = process.env.BIFROST_DOTNET ?? path.resolve(root, '../../build-work/toolchains/dotnet/dotnet.exe');
function run(project, ...args) {
  return execFileSync(dotnet, ['run', '--project', path.join(root, 'tests', project), '-c', 'Release', '--no-restore', '--', ...args],
    { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 60000 });
}

test('unchanged runtime polling preserves route lists and notifies every changed state binding', () => {
  const output = run('ui-state-fixture/BifrostUiStateFixture.csproj', '--runtime-refresh');
  assert.match(output, /"full_refreshes":0/);
  assert.match(output, /PASS runtime refresh/);
});

test('tunnel accounting handles counter epochs, interface gaps and long sessions', () => {
  assert.match(run('ui-state-fixture/BifrostUiStateFixture.csproj', '--tunnel-telemetry'), /PASS tunnel telemetry/);
});

test('service diagnostics stay bounded and nonblocking through slow or failing disk writes', () => {
  assert.match(run('RuntimePerformanceFixture/RuntimePerformanceFixture.csproj'), /PASS bounded nonblocking trace/);
});
