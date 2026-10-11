import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const dotnet = process.env.BIFROST_DOTNET ?? path.resolve(root, '../../build-work/toolchains/dotnet/dotnet.exe');

test('unified WPF pages preserve connection fences, SmartGate, update actions and scaled control reachability', () => {
  const output = process.env.BIFROST_UI_DASHBOARD_OUTPUT ?? fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-dashboard-'));
  const result = execFileSync(dotnet, ['run', '--project', 'tests/ui-render/BifrostUiRender.csproj', '-c', 'Release', '--no-restore', '--', '--dashboard', output],
    { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 90000, maxBuffer: 4 * 1024 * 1024 });
  assert.match(result, /PASS unified WPF dashboard/);
  const evidence = JSON.parse(fs.readFileSync(path.join(output, 'dashboard-validation.json'), 'utf8'));
  assert.equal(evidence.status, 'PASS');
  assert.equal(evidence.scenarios.length, 57);
  assert.deepEqual(evidence.bindingErrors, []);
  assert.ok(evidence.scenarios.some(row => row.width === 760 && row.scale === 140 && row.state === 'navigation-modes-update'));
});
