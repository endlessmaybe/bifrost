import net from 'node:net';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CORES = new Set(['sing-box', 'xray']);
const SECURITY = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']);

export class CoreConfigError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CoreConfigError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new CoreConfigError(code, message);
}

function text(value, field, max = 512) {
  const result = String(value ?? '').trim();
  if (!result || result.length > max || /[\u0000-\u001f\u007f]/.test(result)) fail('BF-CFG-TEXT', `${field} is invalid`);
  return result;
}

function host(value, field) {
  const result = text(value, field, 253);
  if (result.includes('://') || /[\s/]/.test(result)) fail('BF-CFG-HOST', `${field} must be a host or IP address`);
  if (net.isIP(result) === 0 && !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(result)) {
    fail('BF-CFG-HOST', `${field} is not a valid host`);
  }
  return result;
}

function port(value, field) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 1 || result > 65535) fail('BF-CFG-PORT', `${field} port is invalid`);
  return result;
}

function uuid(value, field = 'profile UUID') {
  const result = text(value, field, 64).toLowerCase();
  if (!UUID.test(result)) fail('BF-CFG-UUID', `${field} is invalid`);
  return result;
}

function wsPath(value) {
  const result = text(value, 'WebSocket path', 255);
  if (!result.startsWith('/') || result.includes('..') || /\s/.test(result)) fail('BF-CFG-WS-PATH', 'WebSocket path must be an absolute safe path');
  return result;
}

function validateSource(source) {
  if (!source || typeof source !== 'object') fail('BF-CFG-SOURCE', 'source is required');
  if (source.configured !== true) fail('BF-CFG-SOURCE', 'source has not passed backend configuration checks');
  if (!source.transport || source.transport.type !== 'vmess') fail('BF-CFG-VMESS', 'only VMess transport is supported');
  const transport = source.transport;
  if (transport.network !== 'ws' || transport.tls !== true || Number(transport.alter_id) !== 0) fail('BF-CFG-VMESS', 'VMess must use AEAD alterId=0, WebSocket and TLS');
  if (!SECURITY.has(String(transport.security || 'auto').toLowerCase())) fail('BF-CFG-VMESS', 'unsupported VMess security mode');
  const serverName = host(source.server_name || transport.sni, 'source server name');
  const sni = host(transport.sni || serverName, 'VMess SNI');
  const wsHost = host(transport.host || serverName, 'VMess WebSocket Host');
  const path = wsPath(source.ws_path || transport.path);
  if (!Array.isArray(source.candidates) || source.candidates.length === 0) fail('BF-CFG-CANDIDATE', 'source has no optimized candidates');
  return { serverName, sni, wsHost, path, transport };
}

function selectCandidate(source, candidate, sourceGroup = source.code) {
  const group = String(sourceGroup || source.code || '').toUpperCase();
  if (!['A', 'B'].includes(group)) fail('BF-CFG-SOURCE', 'source group must be A or B');
  const candidates = source.candidates.filter((item) => String(item.label || '').toUpperCase().startsWith(`${group}-`));
  if (!candidates.length) fail('BF-CFG-CANDIDATE', `source ${group} has no candidates`);
  const selected = candidate ? (typeof candidate === 'string' ? candidates.find((item) => item.label === candidate) : candidate) : candidates[0];
  if (!selected || !candidates.some((item) => item.label === selected.label && item.dial_address === selected.dial_address && Number(item.port) === Number(selected.port))) fail('BF-CFG-CANDIDATE', 'selected candidate is not in the requested source group');
  return { label: text(selected.label, 'candidate label', 64), address: host(selected.dial_address, 'candidate address'), port: port(selected.port, 'candidate'), group };
}

function validateProfile(profile) {
  if (!profile || typeof profile !== 'object') fail('BF-CFG-PROFILE', 'a per-device profile is required');
  const keys = Object.keys(profile).sort();
  if (keys.some((key) => !['profile_id', 'uuid'].includes(key))) fail('BF-CFG-PROFILE', 'profile contains unsupported fields');
  return { uuid: uuid(profile.uuid), profileId: text(profile.profile_id, 'profile id', 128) };
}

function tlsOptions(source) {
  return {
    enabled: true,
    server_name: source.sni,
    insecure: false,
    ...(String(source.transport.alpn || '').trim() ? { alpn: String(source.transport.alpn).split(',').map((value) => value.trim()).filter(Boolean) } : {})
  };
}

export function buildVmessOutbound({ source, candidate, profile, tag = 'proxy', detour = undefined }) {
  const normalized = validateSource(source);
  const selected = selectCandidate(source, candidate, source.code);
  const user = validateProfile(profile);
  return {
    tag,
    server: selected.address,
    server_port: selected.port,
    uuid: user.uuid,
    security: String(normalized.transport.security || 'auto').toLowerCase(),
    alter_id: 0,
    transport: { type: 'ws', path: normalized.path, headers: { Host: normalized.wsHost } },
    tls: tlsOptions(normalized),
    ...(detour ? { detour: text(detour, 'VMess detour', 64) } : {}),
    metadata: { source_group: selected.group, candidate_label: selected.label, profile_id: user.profileId }
  };
}

function buildDns(dns = {}) {
  const required = ['version', 'remote', 'direct', 'smart_gate_remote', 'plaintext_fallback', 'ipv4', 'ipv6', 'failure'];
  if (Object.keys(dns).some((key) => !required.includes(key)) || required.some((key) => !Object.prototype.hasOwnProperty.call(dns, key))) fail('BF-CFG-DNS', 'versioned DNS policy is required');
  if (dns.version !== 'dns-policy-v1' || dns.smart_gate_remote !== true || dns.plaintext_fallback !== false || dns.failure !== 'block' || !['proxy', 'block'].includes(dns.ipv4) || !['proxy', 'block'].includes(dns.ipv6)) fail('BF-CFG-DNS', 'DNS policy enforcement is invalid');
  const remote = String(dns.remote || '').trim();
  const direct = String(dns.direct || '').trim();
  if (!/^https:\/\//i.test(remote) || !/^https:\/\//i.test(direct) || dns.plaintext_fallback !== false) fail('BF-CFG-DNS', 'encrypted remote and direct DNS with no plaintext fallback are required');
  const server = (value, tag) => {
    let parsed;
    try { parsed = new URL(value); } catch { fail('BF-CFG-DNS', `${tag} DNS URL is invalid`); }
    if (!['https:', 'tls:'].includes(parsed.protocol)) fail('BF-CFG-DNS', `${tag} DNS must use HTTPS or TLS`);
    if (parsed.protocol !== 'https:' || (parsed.port && parsed.port !== '443') || parsed.username || parsed.password || parsed.search || parsed.hash) fail('BF-CFG-DNS', `${tag} DNS endpoint is not canonical`);
    const serverHost = host(parsed.hostname, `${tag} DNS host`);
    const normalizedHost = serverHost.toLowerCase().replace(/\.$/, '');
    if (net.isIP(normalizedHost) !== 0 || normalizedHost === 'localhost' || normalizedHost.endsWith('.localhost') || normalizedHost === 'test' || normalizedHost.endsWith('.test')) fail('BF-CFG-DNS', `${tag} DNS host is not an approved policy endpoint`);
    const serverPort = parsed.port ? port(parsed.port, `${tag} DNS`) : (parsed.protocol === 'tls:' ? 853 : 443);
    // The remote resolver must follow the encrypted proxy, while the direct
    // resolver deliberately uses the direct outbound.  This is a semantic
    // distinction: sending both resolvers through proxy breaks CN/private
    // direct routing and can create a resolver loop.
    const detour = tag === 'direct' ? 'direct' : 'proxy';
    return parsed.protocol === 'https:'
      ? { type: 'https', tag, server: serverHost, server_port: serverPort, path: parsed.pathname || '/dns-query', tls: { enabled: true, server_name: serverHost }, detour, domain_resolver: { server: 'remote' } }
      : { type: 'tls', tag, server: serverHost, server_port: serverPort, tls: { enabled: true, server_name: serverHost }, detour, domain_resolver: { server: 'remote' } };
  };
  return {
    servers: [server(remote, 'remote'), server(direct, 'direct')],
    final: 'remote',
    strategy: 'prefer_ipv4',
    independent_cache: true
  };
}

/**
 * Compile one control-plane source/profile into a real sing-box client
 * configuration. sing-box owns the TUN, DNS and route policy; the selected
 * VMess AEAD/WSS outbound is the only default route, so there is no silent
 * direct fallback when the transport is unavailable.
 */
export function buildSingBoxClientConfig({ source, candidate, profile, routing = {}, tun = {}, frontVmess = null }) {
  const outbound = buildVmessOutbound({ source, candidate, profile, tag: 'proxy' });
  const front = frontVmess ? buildVmessOutbound({ ...frontVmess, tag: 'front-vmess' }) : null;
  // Country routing is represented by the selected opaque VMess profile. The
  // country SOCKS endpoint remains node-side and is never serialized here.
  const finalOutbound = outbound.tag;
  const mode = String(routing.mode || 'smart').toLowerCase();
  if (!['smart', 'global', 'per-app'].includes(mode)) fail('BF-CFG-ROUTE', 'unsupported route mode');
  const includePackages = Array.isArray(routing.include_packages) ? routing.include_packages.map((item) => text(item, 'included package', 256)) : [];
  const excludePackages = Array.isArray(routing.exclude_packages) ? routing.exclude_packages.map((item) => text(item, 'excluded package', 256)) : [];
  if (includePackages.some((item) => excludePackages.includes(item))) fail('BF-CFG-ROUTE', 'package cannot be in both include and exclude lists');
  const appRules = mode === 'per-app' && includePackages.length
      ? [{ package_name: includePackages, outbound: finalOutbound }]
    : mode === 'per-app' && excludePackages.length
      ? [{ package_name: excludePackages, outbound: 'direct' }]
      : [];
  return {
    log: { level: 'warn', timestamp: true },
    dns: buildDns(routing.dns_policy || routing.dns || {}),
    inbounds: [{
      type: 'tun',
      tag: 'bifrost-tun',
      address: tun.address || ['172.19.0.1/30', 'fd00:bf::1/126'],
      auto_route: tun.auto_route !== false,
      strict_route: true,
      ...(tun.interface_name ? { interface_name: text(tun.interface_name, 'TUN interface', 64) } : {})
    }],
    outbounds: [
      ...(front ? [{ ...front, type: 'vmess', metadata: undefined }] : []),
      { ...outbound, type: 'vmess', metadata: undefined },
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' }
    ],
    route: {
      auto_detect_interface: false,
      default_domain_resolver: { server: 'remote' },
      final: finalOutbound,
      rules: [
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        { ip_is_private: true, outbound: 'direct' },
        ...(mode === 'smart' ? [{ domain_suffix: ['.cn'], outbound: 'direct' }] : []),
        ...(appRules.length ? appRules : [])
      ]
    },
    experimental: { cache_file: { enabled: true } }
  };
}

/**
 * Compile the optional Xray transport adapter. It deliberately exposes only
 * a loopback SOCKS hand-off; TUN/DNS/route policy remains in sing-box.
 */
export function buildXrayClientConfig({ source, candidate, profile, listen = {}, frontVmess = null }) {
  const outbound = buildVmessOutbound({ source, candidate, profile, tag: 'proxy' });
  const front = frontVmess ? buildVmessOutbound({ ...frontVmess, tag: 'front-vmess' }) : null;
  const listenHost = host(listen.host || '127.0.0.1', 'Xray loopback listen host');
  const listenPort = port(listen.port || 10808, 'Xray loopback listen');
  const xrayVmess = (value) => ({
    tag: value.tag,
    protocol: 'vmess',
    settings: { vnext: [{ address: value.server, port: value.server_port, users: [{ id: value.uuid, alterId: 0, security: value.security }] }] },
    streamSettings: {
      network: 'ws', security: 'tls',
      tlsSettings: { serverName: value.tls.server_name, allowInsecure: false, ...(value.tls.alpn ? { alpn: value.tls.alpn } : {}) },
      wsSettings: { path: value.transport.path, headers: value.transport.headers }
    }
  });
  const xrayProxy = front ? { ...xrayVmess(outbound), proxySettings: { tag: 'front-vmess' } } : xrayVmess(outbound);
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ listen: listenHost, port: listenPort, protocol: 'socks', tag: 'bifrost-xray-socks', settings: { auth: 'noauth', udp: false } }],
    outbounds: [
      ...(front ? [xrayVmess(front)] : []),
      xrayProxy,
      { tag: 'direct', protocol: 'freedom', settings: {} },
      { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'none' } } }
    ],
    routing: { domainStrategy: 'AsIs', rules: [{ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' }] }
  };
}

export function compileCoreConfig({ core, ...input }) {
  if (!CORES.has(core)) fail('BF-CFG-CORE', 'unsupported core');
  return core === 'sing-box' ? buildSingBoxClientConfig(input) : buildXrayClientConfig(input);
}

export function assertNoPlaintextDns(config) {
  const textConfig = JSON.stringify(config);
  if (/\"(?:address|server)\"\s*:\s*\"(?:udp|tcp):/i.test(textConfig) || /allowInsecure\"\s*:\s*true|insecure\"\s*:\s*true/i.test(textConfig)) fail('BF-CFG-DNS', 'plaintext DNS or insecure TLS is forbidden');
  return true;
}
