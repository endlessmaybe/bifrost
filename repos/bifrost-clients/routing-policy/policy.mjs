const PRIVATE_RANGES = [
  ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16],
  ['127.0.0.0', 8], ['169.254.0.0', 16]
];

function ipv4ToInt(value) {
  const parts = String(value).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return parts.reduce((acc, n) => ((acc << 8) | n) >>> 0, 0);
}

function inCidr(ip, cidrIp, bits) {
  const a = ipv4ToInt(ip); const b = ipv4ToInt(cidrIp);
  if (a === null || b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

export function isPrivateAddress(ip) {
  return PRIVATE_RANGES.some(([base, bits]) => inCidr(ip, base, bits));
}

export function decideRoute({ mode, domain = '', ip = '', localLan = true, customRules = [], appId = null }) {
  for (const rule of customRules) {
    const appMatch = !rule.apps?.length || rule.apps.includes(appId);
    const domainMatch = rule.domain && (domain === rule.domain || (rule.domain.startsWith('*.') && domain.endsWith(rule.domain.slice(1))));
    const cidrMatch = rule.cidr && ip && inCidr(ip, rule.cidr.split('/')[0], Number(rule.cidr.split('/')[1]));
    if (appMatch && (domainMatch || cidrMatch)) return { action: rule.action, reason: 'custom' };
  }
  if (localLan && (isPrivateAddress(ip) || domain === 'localhost')) return { action: 'direct', reason: 'lan' };
  if (mode === 'smart_gate') return { action: 'proxy', reason: 'smart_gate' };
  if (mode === 'global') return { action: 'proxy', reason: 'global' };
  if (domain.endsWith('.cn') || domain.endsWith('.中国')) return { action: 'direct', reason: 'domestic' };
  return { action: 'proxy', reason: 'default' };
}

export function routeFailure({ mode, strictKillSwitch = false, route }) {
  if (route.action === 'direct' && mode === 'smart' && !strictKillSwitch && route.reason === 'domestic') return { action: 'direct', reason: 'explicit_domestic_exception' };
  return { action: 'block', reason: 'proxy_unavailable' };
}
