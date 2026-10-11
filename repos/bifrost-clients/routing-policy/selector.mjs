import net from 'node:net';
import tls from 'node:tls';

export class SelectionError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SelectionError';
    this.code = code;
    this.details = details;
  }
}
const NETWORK_TYPES = new Set(['wifi', 'cellular', 'ethernet', 'unknown']);
const DEFAULT_BUDGET = Object.freeze({ maxCandidates: 3, maxBytes: 12 * 1024, maxProbes: 3, timeoutMs: 3000 });
const DEFAULT_POLICY = Object.freeze({
  incumbentBonus: 8,
  switchMargin: 12,
  cooldownMs: 5 * 60 * 1000,
  failurePenalty: 35,
  lossPenalty: 1.25,
  jitterPenalty: 0.35,
  tlsPenalty: 0.15,
  networkPenalty: 4
});

function number(value, fallback = 0) {
  const result = Number(value);
  return Number.isFinite(result) ? result : fallback;
}

function normalizeCandidate(candidate, index) {
  const label = String(candidate?.label || '').trim();
  const address = String(candidate?.dial_address || candidate?.address || '').trim();
  const port = Number(candidate?.port);
  if (!label || !address || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SelectionError('BF-SELECT-CONFIG', `candidate ${index + 1} is incomplete`);
  }
  if (address.includes('://') || /[\s/]/.test(address)) throw new SelectionError('BF-SELECT-CONFIG', `candidate ${label} has an invalid address`);
  const inferredGroup = label.includes('-') ? label.split('-', 1)[0].toUpperCase() : null;
  return {
    label,
    dial_address: address,
    port,
    source_code: candidate?.source_code ? String(candidate.source_code).toUpperCase() : inferredGroup,
    server_name: candidate?.server_name ? String(candidate.server_name) : undefined,
    tls: Boolean(candidate?.tls),
    network_type: NETWORK_TYPES.has(String(candidate?.network_type || '').toLowerCase()) ? String(candidate.network_type).toLowerCase() : 'unknown'
  };
}

export function buildProbeCohort(candidates, { start = 0, limit = DEFAULT_BUDGET.maxCandidates, incumbent = null } = {}) {
  const clean = [...candidates];
  if (!clean.length || limit <= 0) return [];
  const count = Math.min(Math.max(0, limit), clean.length);
  const offset = ((Math.trunc(start) % clean.length) + clean.length) % clean.length;
  const selected = Array.from({ length: count }, (_, index) => clean[(offset + index) % clean.length]);
  const incumbentItem = incumbent == null ? null : clean.find((item) => item.label === incumbent);
  if (incumbentItem && !selected.some((item) => item.label === incumbentItem.label)) {
    if (selected.length) selected[selected.length - 1] = incumbentItem;
    else selected.push(incumbentItem);
  }
  return selected;
}

export function validateCandidates(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) throw new SelectionError('BF-SELECT-EMPTY', 'no candidates are available');
  const normalized = candidates.map(normalizeCandidate);
  const labels = new Set();
  for (const candidate of normalized) {
    if (labels.has(candidate.label)) throw new SelectionError('BF-SELECT-CONFIG', `duplicate candidate label ${candidate.label}`);
    labels.add(candidate.label);
  }
  return normalized;
}

function connectWithTimeout(candidate, timeoutMs) {
  const started = performance.now();
  return new Promise((resolve, reject) => {
    let socket;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      if (error) reject(error); else resolve({ ...result, rttMs: Math.max(0, Math.round(performance.now() - started)), bytes: 0, tlsMs: result.stage === 'tls' ? Math.max(0, Math.round(performance.now() - started)) : 0 });
    };
    const timer = setTimeout(() => finish(new SelectionError('BF-SELECT-TIMEOUT', 'candidate probe timed out')), timeoutMs);
    const options = { host: candidate.dial_address, port: candidate.port };
    if (candidate.tls) {
      options.servername = candidate.server_name || candidate.dial_address;
      options.rejectUnauthorized = true;
      socket = tls.connect(options, () => finish(null, { ok: true, stage: 'tls' }));
    } else {
      socket = net.connect(options, () => finish(null, { ok: true, stage: 'tcp' }));
    }
    socket.once('error', (error) => finish(new SelectionError('BF-SELECT-UNREACHABLE', error.message)));
  });
}

/**
 * Probe only the candidate endpoint. No destination traffic is sent and the
 * budget is explicit so automatic selection cannot become an exfiltration
 * mechanism. Custom probes may return rttMs, tlsMs, jitterMs, lossRate,
 * successRate, handshakeMs and bytes for the composite scorer.
 */
export async function probeTcpCandidate(candidate, { timeoutMs = DEFAULT_BUDGET.timeoutMs } = {}) {
  const normalized = normalizeCandidate(candidate, 0);
  return connectWithTimeout(normalized, timeoutMs);
}

function normalizeProbe(result) {
  const success = result?.ok === true;
  return {
    ok: success,
    rttMs: Math.max(0, number(result?.rttMs, Number.POSITIVE_INFINITY)),
    tlsMs: Math.max(0, number(result?.tlsMs, 0)),
    handshakeMs: Math.max(0, number(result?.handshakeMs, 0)),
    jitterMs: Math.max(0, number(result?.jitterMs, 0)),
    lossRate: Math.min(1, Math.max(0, number(result?.lossRate, success ? 0 : 1))),
    successRate: Math.min(1, Math.max(0, number(result?.successRate, success ? 1 : 0))),
    recentFailures: Math.max(0, number(result?.recentFailures, success ? 0 : 1)),
    bytes: Math.max(0, number(result?.bytes, 0)),
    stage: String(result?.stage || 'probe')
  };
}

export function scoreCandidate(metrics = {}, { incumbent = false, networkType = 'unknown' } = {}) {
  const p = { ...DEFAULT_POLICY, ...(metrics.policy || {}) };
  const probe = normalizeProbe(metrics);
  const preferredNetwork = String(metrics.preferredNetwork || networkType || 'unknown').toLowerCase();
  const networkPenalty = metrics.network_type && preferredNetwork !== 'unknown' && metrics.network_type !== preferredNetwork ? p.networkPenalty : 0;
  const failurePenalty = probe.recentFailures * p.failurePenalty;
  const base = probe.rttMs + probe.handshakeMs + probe.tlsMs * p.tlsPenalty + probe.jitterMs * p.jitterPenalty + probe.lossRate * 100 * p.lossPenalty + failurePenalty + networkPenalty;
  return Math.max(0, base - (incumbent ? p.incumbentBonus : 0));
}

function pickHealthy(results, { previousLabel, previousScore, networkType, policy }) {
  const healthy = results.filter((entry) => !entry.error && entry.metrics.ok && Number.isFinite(entry.metrics.rttMs));
  healthy.sort((left, right) => {
    const leftScore = scoreCandidate({ ...left.metrics, network_type: left.candidate.network_type }, { incumbent: left.candidate.label === previousLabel, networkType });
    const rightScore = scoreCandidate({ ...right.metrics, network_type: right.candidate.network_type }, { incumbent: right.candidate.label === previousLabel, networkType });
    return leftScore - rightScore || left.candidate.label.localeCompare(right.candidate.label);
  });
  if (!healthy.length) return { healthy, selected: null, selectedScore: null };
  const best = healthy[0];
  const bestScore = scoreCandidate({ ...best.metrics, network_type: best.candidate.network_type }, { incumbent: best.candidate.label === previousLabel, networkType });
  const incumbent = healthy.find((entry) => entry.candidate.label === previousLabel);
  if (incumbent) {
    const incumbentScore = scoreCandidate({ ...incumbent.metrics, network_type: incumbent.candidate.network_type }, { incumbent: true, networkType });
    const margin = Number(policy.switchMargin ?? DEFAULT_POLICY.switchMargin);
    if (incumbentScore <= bestScore + margin) return { healthy, selected: incumbent, selectedScore: incumbentScore };
  } else if (Number.isFinite(previousScore) && bestScore > previousScore) {
    return { healthy, selected: best, selectedScore: bestScore };
  }
  return { healthy, selected: best, selectedScore: bestScore };
}

/**
 * Select within one source group. It probes at most maxCandidates and
 * maxProbes and rejects over-budget custom probe reports. Selection combines
 * transport success, TLS/handshake latency, RTT, jitter, loss, recent
 * failures, network type and incumbent hysteresis. A failed set is an
 * explicit safe-close result; there is no direct fallback.
 */
export async function selectPreferredCandidate({ candidates, sourceGroup = null, probe = probeTcpCandidate, previousLabel = null, previousScore = null, networkType = 'unknown', maxCandidates = DEFAULT_BUDGET.maxCandidates, timeoutMs = DEFAULT_BUDGET.timeoutMs, budget = {}, policy = {} } = {}) {
  const allCandidates = validateCandidates(candidates);
  const group = sourceGroup ? String(sourceGroup).trim().toUpperCase() : null;
  const limits = { ...DEFAULT_BUDGET, ...budget, maxCandidates, timeoutMs };
  const sourceCandidates = group ? allCandidates.filter((candidate) => candidate.source_code === group) : allCandidates;
  const normalized = buildProbeCohort(sourceCandidates, {
    start: Number.isInteger(budget.cohortStart) ? budget.cohortStart : 0,
    limit: Math.min(limits.maxCandidates, limits.maxProbes),
    incumbent: previousLabel
  });
  if (!normalized.length) return { ok: false, failureCode: 'BF-NODE-UNAVAILABLE', safeClose: true, attempts: [], sourceGroup: group, budget: { ...limits, usedProbes: 0, usedBytes: 0 } };
  const results = [];
  let usedBytes = 0;
  for (const candidate of normalized) {
    try {
      const raw = await probe(candidate, { timeoutMs: limits.timeoutMs, budget: limits });
      const metrics = normalizeProbe(raw);
      usedBytes += metrics.bytes;
      if (usedBytes > limits.maxBytes) throw new SelectionError('BF-SELECT-BUDGET', 'probe byte budget exceeded');
      if (!metrics.ok) throw new SelectionError('BF-SELECT-UNREACHABLE', 'candidate probe did not pass');
      results.push({ candidate, metrics });
    } catch (error) {
      results.push({ candidate, error: { code: error.code || 'BF-SELECT-UNREACHABLE', message: error.message } });
    }
  }
  const picked = pickHealthy(results, { previousLabel, previousScore, networkType, policy: { ...DEFAULT_POLICY, ...policy } });
  if (!picked.selected) return { ok: false, failureCode: 'BF-NODE-UNAVAILABLE', safeClose: true, attempts: results.map((entry) => ({ label: entry.candidate.label, ok: false, error: entry.error })), sourceGroup: group, budget: { ...limits, usedProbes: results.length, usedBytes } };
  const selected = picked.selected;
  return {
    ok: true,
    candidate: { label: selected.candidate.label, dial_address: selected.candidate.dial_address, port: selected.candidate.port },
    score: picked.selectedScore,
    rttMs: selected.metrics.rttMs,
    stage: selected.metrics.stage,
    metrics: selected.metrics,
    attempts: results.map((entry) => ({ label: entry.candidate.label, ok: !entry.error, score: entry.error ? null : scoreCandidate({ ...entry.metrics, network_type: entry.candidate.network_type }, { incumbent: entry.candidate.label === previousLabel, networkType }), rttMs: entry.metrics?.rttMs ?? null, error: entry.error || null })),
    sourceGroup: group,
    budget: { ...limits, usedProbes: results.length, usedBytes }
  };
}

export class SelectionScheduler {
  constructor({ intervalMs = 2 * 60 * 60 * 1000, now = () => Date.now(), select = selectPreferredCandidate } = {}) {
    this.intervalMs = intervalMs;
    this.now = now;
    this.select = select;
    this.lastRunAt = 0;
    this.lastResult = null;
  }

  async runStartup(input) { return this.run(input, 'startup'); }
  async runManual(input) { return this.run(input, 'manual'); }
  async maybeRefresh(input) {
    if (!this.lastRunAt || this.now() - this.lastRunAt >= this.intervalMs) return this.run(input, 'scheduled');
    return { ...this.lastResult, skipped: true, reason: 'cooldown', nextAt: this.lastRunAt + this.intervalMs };
  }
  async run(input, reason) {
    const result = await this.select(input);
    const attemptedAt = this.now();
    if (result?.ok === true) this.lastRunAt = attemptedAt;
    this.lastResult = { ...result, refreshReason: reason, attemptedAt, refreshedAt: result?.ok === true ? attemptedAt : this.lastRunAt };
    return this.lastResult;
  }
}
