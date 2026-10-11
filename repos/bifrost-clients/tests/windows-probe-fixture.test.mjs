import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

test('Windows production probe is asynchronous, bounded, and exercised by a real .NET WSS fixture', () => {
  const engine = readFileSync(path.resolve(import.meta.dirname, '../windows-app/CandidateProbeEngine.cs'), 'utf8');
  assert.match(engine, /new TcpClient\(dialIp\.AddressFamily\)/);
  assert.match(engine, /ConnectAsync\(/);
  assert.match(engine, /ConnectAsync[\s\S]*ConfigureAwait\(false\)/);
  assert.match(engine, /AuthenticateAsClientAsync/);
  assert.match(engine, /RandomNumberGenerator\.GetBytes\(16\)/);
  assert.match(engine, /SHA1\.HashData/);
  assert.match(engine, /ProbeBudget/);
  assert.match(engine, /async Task<ProbeResult\?> ProbeAsync/);
  assert.match(engine, /async Task<int> WebSocketProbeAsync/);
  assert.doesNotMatch(engine, /\.Wait\(|\.Result\b|GetAwaiter\(\)\.GetResult/);

  const dotnet = process.env.BIFROST_DOTNET ?? path.resolve(import.meta.dirname, '../../../build-work/toolchains/dotnet/dotnet.exe');
  const project = path.resolve(import.meta.dirname, 'windows-probe-fixture/BifrostProbeFixture.csproj');
  const output = execFileSync(dotnet, ['run', '--project', project, '-c', 'Release', '--no-restore'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    encoding: 'utf8',
    timeout: 30_000,
    windowsHide: true,
  });
  assert.match(output, /PASS windows production WSS probe fixture \(async\/TLS\/SNI\/WS\/budget\/bootstrap\/network-buckets\)/);
  assert.match(output, /budget/);
});
