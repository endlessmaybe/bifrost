import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const toolchains = path.resolve(root, '../../build-work/toolchains');
const dotnet = process.env.BIFROST_DOTNET ?? path.join(toolchains, 'dotnet/dotnet.exe');

test('live tunnel health survives the recorded TLS jitter and fragmented HTTP responses', () => {
  const output = execFileSync(dotnet, ['run', '--project',
    path.join(root, 'tests/DataPlaneHealthFixture/DataPlaneHealthFixture.csproj'), '-c', 'Release'],
    { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 60000 });
  assert.match(output, /PASS DATAPLANE-HEALTH/);
});

test('TUN DNS commits and recovers without modifying physical or reused interfaces', () => {
  const output = execFileSync(dotnet, ['run', '--project',
    path.join(root, 'tests/MihomoHandoverFixture/MihomoHandoverFixture.csproj'),
    '-c', 'Release', '--no-restore'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 60000 });
  assert.match(output, /MIHOMO-TUN-DNS lifecycle, recovery and foreign-owner preservation PASS/);
  assert.match(output, /MIHOMO-HANDOVER-FIXTURE PASS/);
});

test('shipped Mihomo accepts every routing mode and forwards the first upload UDP datagram', () => {
  const output = execFileSync(dotnet, ['run', '--project',
    path.join(root, 'tests/MihomoCompilerFixture/MihomoCompilerFixture.csproj'),
    '-c', 'Release', '--no-restore'], {
    // The real-core fixture validates all routing modes, IPv4/IPv6 fallback
    // and two SOCKS5 UDP association paths. On a loaded Windows host the
    // complete bounded run can legitimately exceed one minute even when every
    // individual network operation remains tightly timed out.
    cwd: root, encoding: 'utf8', windowsHide: true, timeout: 120000,
    env: { ...process.env,
      BIFROST_MIHOMO_EXE: process.env.BIFROST_MIHOMO_EXE
        ?? path.join(toolchains, 'cores/mihomo/1.19.30/windows-amd64-compatible/mihomo.exe'),
      BIFROST_MIHOMO_GEODATA_DIR: process.env.BIFROST_MIHOMO_GEODATA_DIR
        ?? path.join(toolchains, 'cores/mihomo-rules/2026-09-22'),
    },
  });
  assert.match(output, /MIHOMO-UPLOAD-DATAGRAM first and repeated packets PASS/);
  assert.match(output, /MIHOMO-FIXED-CANDIDATE exact runtime membership PASS/);
  assert.match(output, /MIHOMO-COMPILER-FIXTURE PASS/);
});
