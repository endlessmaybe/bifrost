const STAGES = Object.freeze([
  'prepare', 'dns', 'tcp', 'tls', 'websocket', 'vmess', 'session', 'starting_tun', 'route'
]);

export const ERROR_CODES = Object.freeze({
  NETWORK: 'BF-NET-001',
  TLS: 'BF-TLS-002',
  AUTH: 'BF-AUTH-003',
  SMART_GATE: 'BF-SG-004',
  CONFIG: 'BF-CFG-005',
  CORE: 'BF-CORE-006',
  KILL_SWITCH: 'BF-KS-007'
});

export function assertCoreContract(contract) {
  if (!contract || !['sing-box', 'xray'].includes(contract.core)) {
    throw new Error('unsupported core');
  }
  if (contract.tun?.enabled !== true || contract.dns?.plaintext_fallback !== false) {
    throw new Error('unsafe tunnel contract');
  }
  if (contract.transport?.session_header !== 'X-Bifrost-Session') {
    throw new Error('invalid session header');
  }
  if (contract.kill_switch?.enabled !== true) {
    throw new Error('kill switch is mandatory');
  }
  return true;
}

export function newConnectionState(core, routeMode) {
  assertCoreContract({
    core,
    tun: { enabled: true, protected_sockets: 1 },
    dns: { mode: routeMode === 'smart_gate' ? 'remote_socks' : 'doh', plaintext_fallback: false },
    route: { mode: routeMode, unmatched_action: 'proxy' },
    kill_switch: { enabled: true, scope: 'normal' },
    transport: { vmess_aead: true, wss: true, strict_tls: true, session_header: 'X-Bifrost-Session' }
  });
  return {
    core,
    routeMode,
    stage: 'prepare',
    killSwitchArmed: false,
    coreReady: false,
    tunConsumed: false,
    dnsReady: false,
    probePassed: false,
    connected: false,
    startedAt: Date.now()
  };
}

/**
 * Advance only after the platform adapter reports evidence for the stage.
 * Reaching the route stage alone is never a connection success signal.
 */
export function advanceConnection(state, stage, evidence = {}) {
  if (!STAGES.includes(stage)) throw new Error('unknown stage');
  if (STAGES.indexOf(stage) < STAGES.indexOf(state.stage)) throw new Error('connection stage regression');
  state.stage = stage;
  if (stage === 'prepare') state.killSwitchArmed = true;
  if (evidence.coreReady === true) state.coreReady = true;
  if (evidence.tunConsumed === true) state.tunConsumed = true;
  if (evidence.dnsReady === true) state.dnsReady = true;
  if (evidence.probePassed === true) state.probePassed = true;
  if (stage === 'route') {
    state.connected = state.killSwitchArmed && state.coreReady && state.tunConsumed && state.dnsReady && state.probePassed;
    if (!state.connected) state.failureCode = ERROR_CODES.CORE;
  }
  return state;
}

export function completeConnection(state, evidence = {}) {
  return advanceConnection(state, 'route', evidence);
}

export function failConnection(state, code = ERROR_CODES.NETWORK) {
  state.connected = false;
  state.failureCode = code;
  state.failureStage = state.stage;
  state.killSwitchArmed = true;
  return state;
}

export { STAGES };
