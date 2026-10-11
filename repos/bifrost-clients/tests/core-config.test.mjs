import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildSingBoxClientConfig, buildXrayClientConfig } from '../core-adapters/config-builder.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const xray = process.env.BIFROST_TEST_XRAY_PATH || path.join(root, 'build-work', 'toolchains', 'xray-test', 'xray.exe');
const singBox = process.env.BIFROST_TEST_SING_BOX_PATH || path.join(root, 'build-work', 'toolchains', 'sing-box-test', 'sing-box.exe');

const source = {
  code: 'A', configured: true, server_name: 'bifrost-test-only.local', ws_path: '/bifrost-test-only-vmess',
  candidates: [{ label: 'A-01', dial_address: '127.0.0.1', port: 19443 }],
  transport: { type: 'vmess', network: 'ws', tls: true, security: 'auto', alter_id: 0, host: 'bifrost-test-only.local', sni: 'bifrost-test-only.local', alpn: '' }
};
const profile = { profile_id: 'profile-test-1', uuid: '11111111-2222-4333-8444-555555555555' };
const routing = { dns_policy: { version: 'dns-policy-v1', remote: 'https://remote.example.invalid/dns-query', direct: 'https://direct.example.invalid/dns-query', smart_gate_remote: true, plaintext_fallback: false, ipv4: 'proxy', ipv6: 'proxy', failure: 'block' } };

test('country mode uses only the selected opaque VMess profile; SOCKS stays node-side', () => {
  const countryProfile = { profile_id: 'country-profile-test-only', uuid: '22222222-3333-4444-8555-666666666666' };
  const sing = buildSingBoxClientConfig({ source, candidate: 'A-01', profile: countryProfile, routing });
  assert.equal(sing.route.final, 'proxy');
  assert.equal(sing.outbounds.some((item) => item.tag === 'country-socks'), false);
  assert.doesNotMatch(JSON.stringify(sing), /username|password|country-socks/i);
  const chained = buildXrayClientConfig({ source, candidate: 'A-01', profile: countryProfile, frontVmess: { source, candidate: 'A-01', profile } });
  assert.equal(chained.routing.rules[0].outboundTag, 'proxy');
  assert.deepEqual(chained.outbounds.find((item) => item.tag === 'proxy').proxySettings, { tag: 'front-vmess' });
  assert.equal(chained.outbounds.some((item) => item.tag === 'country-socks'), false);
});

test('generated Xray config passes the locked core parser', () => {
  assert.ok(existsSync(xray), `Xray binary not found: ${xray}`);
  const dir = mkdtempSync(path.join(tmpdir(), 'bifrost-xray-config-'));
  const configPath = path.join(dir, 'config.json');
  try {
    writeFileSync(configPath, JSON.stringify(buildXrayClientConfig({ source, candidate: 'A-01', profile, listen: { port: 18080 } }), null, 2));
    const result = spawnSync(xray, ['run', '-test', '-c', configPath], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('generated sing-box config has no insecure or plaintext transport flags', () => {
  const config = buildSingBoxClientConfig({ source, candidate: 'A-01', profile, routing, tun: { auto_route: false } });
  assert.equal(config.outbounds[0].tls.insecure, false);
  assert.equal(config.dns.servers.every((server) => ['https', 'tls'].includes(server.type) && server.tls.enabled === true), true);
  assert.ok(existsSync(singBox), `sing-box binary not found: ${singBox}`);
  const dir = mkdtempSync(path.join(tmpdir(), 'bifrost-sing-box-config-'));
  const configPath = path.join(dir, 'config.json');
  try {
    writeFileSync(configPath, JSON.stringify(config, null, 2));
    const result = spawnSync(singBox, ['check', '-c', configPath], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
