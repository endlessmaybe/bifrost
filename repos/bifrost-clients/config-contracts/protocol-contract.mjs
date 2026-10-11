import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourcePath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'protocol-contract-v1.json');
const sourceBytes = readFileSync(sourcePath);
const source = JSON.parse(sourceBytes.toString('utf8'));

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new Error('BF-CONTRACT-NUMBER');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  throw new Error('BF-CONTRACT-TYPE');
}

export const PROTOCOL_CONTRACT = Object.freeze(source);
export const PROTOCOL_CONTRACT_ID = source['x-bifrost'].contract_id;
export const PROTOCOL_CONTRACT_VERSION = source['x-bifrost'].contract_version;
export const PROTOCOL_CONTRACT_FINGERPRINT = createHash('sha256').update(Buffer.from(canonical(source), 'utf8')).digest('hex');
export const PROTOCOL_CONTRACT_SOURCE_PATH = sourcePath;
export const canonicalProtocolJson = canonical;

const budgets = PROTOCOL_CONTRACT['x-bifrost'].budgets;

function resolveSchema(schema) {
  if (schema?.$ref && schema.$ref.startsWith('#/components/schemas/')) {
    const target = PROTOCOL_CONTRACT.components.schemas[schema.$ref.slice('#/components/schemas/'.length)] || {};
    const { $ref, ...overrides } = schema;
    return Object.keys(overrides).length ? { ...target, ...overrides } : target;
  }
  return schema || {};
}

function validateValue(schema, value, depth = 0) {
  if (depth > budgets.json_depth) throw new Error('BF-CONTRACT-DEPTH');
  const actual = resolveSchema(schema || {});
  if (!actual || typeof actual !== 'object' || value === undefined) throw new Error('BF-CONTRACT-SHAPE');
  if (value === null) {
    if (actual.nullable === true) return;
    throw new Error('BF-CONTRACT-TYPE');
  }
  if (actual.const !== undefined && value !== actual.const) throw new Error('BF-CONTRACT-VALUE');
  if (actual.enum && !actual.enum.includes(value)) throw new Error('BF-CONTRACT-VALUE');
  if (actual.type === 'object') {
    if (typeof value !== 'object' || Array.isArray(value)) throw new Error('BF-CONTRACT-TYPE');
    const keys = Object.keys(value);
    if ((actual.minProperties !== undefined && keys.length < actual.minProperties) || keys.length > budgets.object_properties || (actual.maxProperties !== undefined && keys.length > actual.maxProperties)) throw new Error('BF-CONTRACT-PROPERTIES');
    const properties = actual.properties || {};
    if (actual.additionalProperties === false && keys.some((key) => !Object.prototype.hasOwnProperty.call(properties, key))) throw new Error('BF-CONTRACT-SHAPE');
    const required = Array.isArray(actual.required) ? actual.required : [];
    if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new Error('BF-CONTRACT-SHAPE');
    for (const key of keys) validateValue(properties[key], value[key], depth + 1);
    return;
  }
  if (actual.type === 'array') {
    if (!Array.isArray(value) || (actual.minItems !== undefined && value.length < actual.minItems) || value.length > budgets.array_items || (actual.maxItems !== undefined && value.length > actual.maxItems)) throw new Error('BF-CONTRACT-ARRAY');
    for (const item of value) validateValue(actual.items, item, depth + 1);
    return;
  }
  if (actual.type === 'string') {
    if (typeof value !== 'string' || value.length > (actual.maxLength !== undefined ? actual.maxLength : budgets.string_chars) || (actual.minLength !== undefined && value.length < actual.minLength)) throw new Error('BF-CONTRACT-STRING');
    if (actual.pattern && !(new RegExp(actual.pattern).test(value))) throw new Error('BF-CONTRACT-VALUE');
    return;
  }
  if (actual.type === 'integer') {
    if (!Number.isSafeInteger(value) || (actual.minimum !== undefined && value < actual.minimum) || (actual.maximum !== undefined && value > actual.maximum)) throw new Error('BF-CONTRACT-NUMBER');
    return;
  }
  if (actual.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value) || (actual.minimum !== undefined && value < actual.minimum) || (actual.maximum !== undefined && value > actual.maximum)) throw new Error('BF-CONTRACT-NUMBER');
    return;
  }
  if (actual.type === 'boolean' && typeof value !== 'boolean') throw new Error('BF-CONTRACT-TYPE');
}

export function exactObject(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('BF-CONTRACT-SHAPE');
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (keys.length !== new Set(keys).size || keys.some((key) => !allowed.has(key)) || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new Error('BF-CONTRACT-SHAPE');
  return value;
}

export function validateContractEnvelope(name, value) {
  const schema = PROTOCOL_CONTRACT.components.schemas[name];
  if (!schema) throw new Error('BF-CONTRACT-SCHEMA');
  validateValue(schema, value, 0);
  return true;
}
