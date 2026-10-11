import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonicalProtocolJson } from './protocol-contract.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ERROR_REGISTRY = Object.freeze(JSON.parse(readFileSync(path.join(here, 'error-registry-v1.json'), 'utf8')));
export const ERROR_REGISTRY_ID = String(ERROR_REGISTRY.contract_id);
export const ERROR_REGISTRY_VERSION = String(ERROR_REGISTRY.version);
export const ERROR_REGISTRY_FINGERPRINT = createHash('sha256').update(canonicalProtocolJson(ERROR_REGISTRY), 'utf8').digest('hex');

function matchesFamily(value, pattern) {
  if (!pattern.includes('*')) return value === pattern;
  const parts = pattern.split('*');
  const head = parts[0];
  const tail = parts[parts.length - 1];
  return value.startsWith(head) && value.endsWith(tail) && value.length > head.length + tail.length;
}

export function errorDescriptor(code) {
  const value = String(code || '');
  if (!/^BF-[A-Z0-9]+(?:-[A-Z0-9]+)*$/.test(value)) return ERROR_REGISTRY.default;
  const exact = ERROR_REGISTRY.entries?.find?.((entry) => entry.code === value);
  if (exact) return Object.freeze({ ...ERROR_REGISTRY.default, ...exact });
  const family = (ERROR_REGISTRY.families || []).find((entry) => entry.patterns.some((pattern) => matchesFamily(value, pattern)));
  return Object.freeze({ ...ERROR_REGISTRY.default, ...(family ? { http_status: family.http_status, retryable: family.retryable, audit_severity: family.audit_severity, existence_leak: family.existence_leak } : {}) });
}
