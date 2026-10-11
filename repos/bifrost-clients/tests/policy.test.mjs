import test from 'node:test';
import assert from 'node:assert/strict';
import { decideRoute, routeFailure } from '../routing-policy/policy.mjs';
import { selectPreferredCandidate, SelectionScheduler, scoreCandidate } from '../routing-policy/selector.mjs';
import { assertNoPlaintextDns, chooseDnsRoute, validateDnsPolicy } from '../routing-policy/dns.mjs';
import { decideNetworkPath } from '../routing-policy/network-policy.mjs';
import { newConnectionState, advanceConnection, completeConnection, failConnection, ERROR_CODES } from '../core-adapters/contract/protocol.mjs';
import { assertNoPlaintextDns as assertNoPlaintextCoreDns, buildSingBoxClientConfig, buildXrayClientConfig } from '../core-adapters/config-builder.mjs';
import net from 'node:net';

test('routing prioritizes explicit LAN and smart gate', () => {
  assert.deepEqual(decideRoute({ mode: 'smart_gate', ip: '192.168.1.8' }), { action: 'direct', reason: 'lan' });
  assert.deepEqual(decideRoute({ mode: 'smart_gate', domain: 'example.com', ip: '203.0.113.8' }), { action: 'proxy', reason: 'smart_gate' });
  assert.deepEqual(routeFailure({ mode: 'global', route: { action: 'proxy', reason: 'default' } }), { action: 'block', reason: 'proxy_unavailable' });
});

test('connection state arms kill switch before route', () => {
  const state = newConnectionState('sing-box', 'smart');
  assert.equal(state.killSwitchArmed, false);
  advanceConnection(state, 'prepare');
  assert.equal(state.killSwitchArmed, true);
  completeConnection(state, { coreReady: true, tunConsumed: true, dnsReady: true, probePassed: false });
  assert.equal(state.connected, false);
  assert.equal(state.failureCode, ERROR_CODES.CORE);
  failConnection(state, ERROR_CODES.TLS);
  assert.equal(state.connected, false);
  assert.equal(state.failureCode, ERROR_CODES.TLS);
});

test('connection becomes connected only with core, TUN, DNS and probe evidence', () => {
  const state = newConnectionState('xray', 'global');
  advanceConnection(state, 'prepare');
  advanceConnection(state, 'dns', { dnsReady: true });
  advanceConnection(state, 'starting_tun', { coreReady: true, tunConsumed: true });
  completeConnection(state, { probePassed: true });
  assert.equal(state.connected, true);
  assert.equal(state.failureCode, undefined);
});

test('auto-selection probes only the selected source group and has no direct fallback', async (t) => {
  const server = net.createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen({ host: '127.0.0.1', port: 0 }, resolve));
  const port = server.address().port;
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const result = await selectPreferredCandidate({
    candidates: [
      { label: 'A-01', dial_address: '127.0.0.1', port: 1 },
      { label: 'A-02', dial_address: '127.0.0.1', port },
      { label: 'B-01', dial_address: '127.0.0.1', port }
    ],
    sourceGroup: 'A',
    previousLabel: 'A-02',
    timeoutMs: 100
  });
  assert.equal(result.ok, true); assert.equal(result.candidate.label, 'A-02');
  assert.deepEqual(result.attempts.map((attempt) => attempt.label), ['A-01', 'A-02']);
  const closed = await selectPreferredCandidate({ candidates: [{ label: 'A-01', dial_address: '127.0.0.1', port: 1 }], timeoutMs: 50 });
  assert.deepEqual({ ok: closed.ok, failureCode: closed.failureCode, safeClose: closed.safeClose }, { ok: false, failureCode: 'BF-NODE-UNAVAILABLE', safeClose: true });
});

test('auto-selection uses composite metrics, byte budget and hysteresis', async () => {
  const probes = new Map([
    ['A-01', { ok: true, rttMs: 40, tlsMs: 20, handshakeMs: 30, jitterMs: 4, lossRate: 0.02, successRate: 0.98, bytes: 128 }],
    ['A-02', { ok: true, rttMs: 45, tlsMs: 1, handshakeMs: 4, jitterMs: 1, lossRate: 0, successRate: 1, bytes: 128 }]
  ]);
  const result = await selectPreferredCandidate({
    candidates: [{ label: 'A-01', dial_address: '198.51.100.1', port: 443, tls: true }, { label: 'A-02', dial_address: '198.51.100.2', port: 443, tls: true }],
    sourceGroup: 'A', previousLabel: 'A-01', probe: async (candidate) => probes.get(candidate.label), budget: { maxBytes: 1024 }
  });
  assert.equal(result.ok, true);
  assert.equal(result.candidate.label, 'A-02');
  assert.equal(result.budget.usedProbes, 2);
  assert.equal(result.budget.usedBytes, 256);
  assert.ok(scoreCandidate(probes.get('A-02')) < scoreCandidate(probes.get('A-01')));
  const scheduler = new SelectionScheduler({ intervalMs: 7200000, now: (() => { let now = 1000; return () => now; })(), select: async () => ({ ok: true }) });
  assert.equal((await scheduler.runStartup({})).refreshReason, 'startup');
  assert.equal((await scheduler.maybeRefresh({})).skipped, true);
  assert.equal((await scheduler.runManual({})).refreshReason, 'manual');
});

test('DNS and network policy forbid plaintext fallback and fail closed', () => {
  const policy = validateDnsPolicy({ version: 'dns-policy-v1', remote: 'https://remote.example.invalid/dns-query', direct: 'https://direct.example.invalid/dns-query', smart_gate_remote: true, plaintext_fallback: false, ipv4: 'proxy', ipv6: 'proxy', failure: 'block' });
  assert.equal(chooseDnsRoute({ policy, mode: 'smart', domainClass: 'foreign' }).path, 'proxy-dns');
  assert.equal(chooseDnsRoute({ policy, mode: 'smart', domainClass: 'domestic', strictKillSwitch: true }).path, 'direct-dns');
  assert.throws(() => validateDnsPolicy({ version: 'dns-policy-v1', remote: 'udp://1.1.1.1:53', direct: 'https://direct.example.invalid/dns-query', smart_gate_remote: true, plaintext_fallback: false, ipv4: 'proxy', ipv6: 'proxy', failure: 'block' }), /plaintext|HTTPS/);
  assert.throws(() => assertNoPlaintextDns({ transport: 'udp', port: 53 }), /plaintext/);
  const common = { policy: { ipv6: 'proxy_or_block', udp: 'capability', strict_kill_switch: true }, routeAction: 'proxy', coreReady: false, tunConsumed: false, killSwitchArmed: false };
  assert.equal(decideNetworkPath({ ...common, protocol: 'tcp' }), 'block');
  assert.equal(decideNetworkPath({ ...common, protocol: 'udp', coreReady: true, tunConsumed: true, killSwitchArmed: true, capabilities: { udp: false } }), 'block');
  assert.equal(decideNetworkPath({ ...common, protocol: 'tcp', coreReady: true, tunConsumed: true, dnsReady: true, killSwitchArmed: true }), 'proxy');
});

test('core config compiler emits strict VMess AEAD/WSS for both cores', () => {
  const source = {
    code: 'A', configured: true, server_name: 'source-a.example.invalid', ws_path: '/bifrost-test-only',
    candidates: [
      { label: 'A-01', dial_address: '198.51.100.10', port: 443 },
      { label: 'B-01', dial_address: '198.51.100.11', port: 443 }
    ],
    transport: { type: 'vmess', network: 'ws', tls: true, security: 'auto', alter_id: 0, host: 'source-a.example.invalid', sni: 'source-a.example.invalid', alpn: 'h2,http/1.1' }
  };
  const profile = { profile_id: 'profile-test-1', uuid: '11111111-2222-4333-8444-555555555555' };
  const routing = { dns_policy: { version: 'dns-policy-v1', remote: 'https://remote.example.invalid/dns-query', direct: 'https://direct.example.invalid/dns-query', smart_gate_remote: true, plaintext_fallback: false, ipv4: 'proxy', ipv6: 'proxy', failure: 'block' } };
  const sing = buildSingBoxClientConfig({ source, candidate: 'A-01', profile, routing, tun: { auto_route: false } });
  assert.equal(sing.outbounds[0].type, 'vmess');
  assert.equal(sing.outbounds[0].alter_id, 0);
  assert.equal(sing.outbounds[0].tls.insecure, false);
  assert.equal(sing.outbounds[0].server, '198.51.100.10');
  assert.equal(sing.route.final, 'proxy');
  assert.doesNotThrow(() => assertNoPlaintextCoreDns(sing));

  const xray = buildXrayClientConfig({ source, candidate: 'A-01', profile, listen: { port: 18080 } });
  assert.equal(xray.outbounds[0].protocol, 'vmess');
  assert.equal(xray.outbounds[0].settings.vnext[0].users[0].alterId, 0);
  assert.equal(xray.outbounds[0].streamSettings.tlsSettings.allowInsecure, false);
  assert.equal(xray.outbounds[0].streamSettings.wsSettings.path, '/bifrost-test-only');
  assert.throws(() => buildXrayClientConfig({ source, candidate: 'B-01', profile }), /source group/);
});

test('country mode uses an opaque VMess profile and optional front VMess without client SOCKS data', () => {
  const source = {
    code: 'A', configured: true, server_name: 'source-a.example.invalid', ws_path: '/bifrost-test-only',
    candidates: [{ label: 'A-01', dial_address: '198.51.100.10', port: 443 }],
    transport: { type: 'vmess', network: 'ws', tls: true, security: 'auto', alter_id: 0, host: 'source-a.example.invalid', sni: 'source-a.example.invalid', alpn: '' }
  };
  const profile = { profile_id: 'profile-test-1', uuid: '11111111-2222-4333-8444-555555555555' };
  const countryProfile = { profile_id: 'country-profile-test-only', uuid: '22222222-3333-4444-8555-666666666666' };
  const sing = buildSingBoxClientConfig({ source, candidate: 'A-01', profile: countryProfile, tun: { auto_route: false }, routing: { dns_policy: { version: 'dns-policy-v1', remote: 'https://remote.example.invalid/dns-query', direct: 'https://direct.example.invalid/dns-query', smart_gate_remote: true, plaintext_fallback: false, ipv4: 'proxy', ipv6: 'proxy', failure: 'block' } } });
  assert.equal(sing.route.final, 'proxy');
  assert.equal(sing.outbounds.some((item) => item.tag === 'country-socks'), false);
  assert.doesNotMatch(JSON.stringify(sing), /username|password|country-socks/i);
  const chained = buildXrayClientConfig({ source, candidate: 'A-01', profile: countryProfile, frontVmess: { source, candidate: 'A-01', profile } });
  assert.equal(chained.routing.rules[0].outboundTag, 'proxy');
  assert.deepEqual(chained.outbounds.find((item) => item.tag === 'proxy').proxySettings, { tag: 'front-vmess' });
  assert.equal(chained.outbounds.some((item) => item.tag === 'country-socks'), false);
});
