import net from 'node:net';

const ALLOWED_MODES = new Set(['smart', 'smart_gate', 'global', 'direct']);
const DNS_POLICY_KEYS = new Set(['version', 'remote', 'direct', 'smart_gate_remote', 'plaintext_fallback', 'ipv4', 'ipv6', 'failure']);

export class DnsPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DnsPolicyError';
    this.code = code;
  }
}

function resolver(value, label) {
  let parsed;
  try { parsed = new URL(String(value)); } catch { throw new DnsPolicyError('BF-DNS-CONFIG', `${label} is not a valid resolver URL`); }
  if (parsed.protocol !== 'https:' || (parsed.port && parsed.port !== '443') || parsed.search || parsed.hash) throw new DnsPolicyError('BF-DNS-PLAINTEXT', `${label} must use HTTPS on port 443; plaintext is forbidden`);
  if (!parsed.hostname || parsed.username || parsed.password) throw new DnsPolicyError('BF-DNS-CONFIG', `${label} must not contain credentials`);
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(host) !== 0 || host === 'localhost' || host.endsWith('.localhost') || host === 'test' || host.endsWith('.test')) throw new DnsPolicyError('BF-DNS-CONFIG', `${label} host is not an approved policy endpoint`);
  if (parsed.protocol === 'https:' && parsed.pathname === '/') parsed.pathname = '/dns-query';
  if (parsed.protocol === 'tls:' && parsed.pathname !== '/') throw new DnsPolicyError('BF-DNS-CONFIG', `${label} DoT endpoint cannot contain a path`);
  return parsed.toString();
}

export function validateDnsPolicy(policy = {}) {
  const keys = Object.keys(policy);
  if (keys.length !== DNS_POLICY_KEYS.size || keys.some((key) => !DNS_POLICY_KEYS.has(key))) throw new DnsPolicyError('BF-DNS-CONFIG', 'versioned DNS policy is required');
  if (policy.version !== 'dns-policy-v1' || policy.smart_gate_remote !== true || policy.plaintext_fallback !== false || policy.failure !== 'block' || !['proxy', 'block'].includes(policy.ipv4) || !['proxy', 'block'].includes(policy.ipv6)) throw new DnsPolicyError('BF-DNS-CONFIG', 'DNS policy enforcement is invalid');
  const remote = resolver(policy.remote, 'remote DNS');
  const direct = resolver(policy.direct, 'direct DNS');
  if (policy.plaintext_fallback === true || policy.system_fallback === true) throw new DnsPolicyError('BF-DNS-PLAINTEXT', 'plaintext/system DNS fallback is forbidden');
  return Object.freeze({ version: 'dns-policy-v1', remote, direct, smart_gate_remote: true, plaintext_fallback: false, ipv4: policy.ipv4, ipv6: policy.ipv6, failure: 'block' });
}

export function chooseDnsRoute({ policy, mode = 'smart', domainClass = 'foreign', strictKillSwitch = true } = {}) {
  const validated = validateDnsPolicy(policy);
  if (!ALLOWED_MODES.has(mode)) throw new DnsPolicyError('BF-DNS-CONFIG', `unsupported routing mode ${mode}`);
  const directAllowed = mode === 'direct' || (mode === 'smart' && domainClass === 'domestic');
  // A kill switch prevents fail-open fallback; it does not cancel an explicit
  // DIRECT policy decision.  Smart-mode domestic DNS therefore stays on the
  // encrypted direct resolver and must fail closed if that resolver fails.
  if (directAllowed) return { transport: validated.direct.startsWith('tls:') ? 'dot' : 'doh', resolver: validated.direct, path: 'direct-dns' };
  return { transport: validated.remote.startsWith('tls:') ? 'dot' : 'doh', resolver: validated.remote, path: 'proxy-dns' };
}

export function assertNoPlaintextDns(config) {
  if (config?.transport === 'udp' || config?.transport === 'tcp' || config?.port === 53 || config?.fallback === 'system') throw new DnsPolicyError('BF-DNS-PLAINTEXT', 'external plaintext DNS is blocked');
  return true;
}
