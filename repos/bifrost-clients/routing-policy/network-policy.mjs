export class NetworkPolicyError extends Error {
  constructor(code, message) { super(message); this.name = 'NetworkPolicyError'; this.code = code; }
}

export function validateNetworkPolicy(policy = {}) {
  const ipv6 = policy.ipv6 || 'proxy_or_block';
  if (!['proxy_or_block', 'direct', 'block'].includes(ipv6)) throw new NetworkPolicyError('BF-NETWORK-CONFIG', 'invalid IPv6 policy');
  const udp = policy.udp || 'capability';
  if (!['capability', 'block', 'proxy'].includes(udp)) throw new NetworkPolicyError('BF-NETWORK-CONFIG', 'invalid UDP policy');
  return Object.freeze({ ipv6, udp, strict_kill_switch: policy.strict_kill_switch !== false });
}

/** Decide a path without ever falling back to a direct route for proxy traffic. */
export function decideNetworkPath({ policy, protocol = 'tcp', family = 4, routeAction = 'proxy', coreReady = false, tunConsumed = false, dnsReady = false, killSwitchArmed = false, capabilities = {} } = {}) {
  const validated = validateNetworkPolicy(policy);
  if (protocol === 'dns') return dnsReady && coreReady && tunConsumed ? 'dns-remote' : 'block';
  if (validated.strict_kill_switch && !killSwitchArmed) return 'block';
  if (routeAction === 'direct') {
    if (protocol === 'udp' && validated.udp === 'block') return 'block';
    if (family === 6 && validated.ipv6 === 'block') return 'block';
    return 'direct';
  }
  if (!coreReady || !tunConsumed) return 'block';
  if (protocol === 'udp' && !(validated.udp === 'proxy' || (validated.udp === 'capability' && capabilities.udp === true))) return 'block';
  if (family === 6 && validated.ipv6 === 'block') return 'block';
  return 'proxy';
}
