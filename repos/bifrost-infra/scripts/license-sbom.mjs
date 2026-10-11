import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, statSync, writeFileSync, mkdirSync, openSync, readSync, closeSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { binaryPlanDigest, canonicalBinaryPlan } from './release-plan.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const MAX_FILE_BYTES = 1024 * 1024 * 1024;
function hashFile(file, { maxBytes = MAX_FILE_BYTES } = {}) {
  const descriptor = openSync(file, 'r'); const digest = createHash('sha256'); let total = 0; const buffer = Buffer.alloc(1024 * 1024);
  try { while (true) { const count = readSync(descriptor, buffer, 0, buffer.length, null); if (count === 0) break; total += count; if (total > maxBytes) fail('BF-OPS-PAYLOAD'); digest.update(buffer.subarray(0, count)); } }
  finally { closeSync(descriptor); }
  return { bytes: total, sha256: digest.digest('hex') };
}
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
const readCanonicalJson = (file, code = 'BF-OPS-SBOM') => {
  const bytes = readFileSync(file);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(code); }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail(code);
  let value; try { value = JSON.parse(text); } catch { fail(code); }
  if (`${canonical(value)}\n` !== text) fail(code);
  return value;
};
const fail = (code, message = code) => { const error = new Error(message); error.code = code; throw error; };

function loadDependencyLicenseManifest(file, { testOnly = false } = {}) {
  if (!file) {
    if (!testOnly) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
    return new Map();
  }
  const value = readCanonicalJson(file, 'BF-OPS-SBOM-LICENSE-MANIFEST');
  if (value.format !== 'BIFROST-DEPENDENCY-LICENSES-1' || !Array.isArray(value.components) || value.components.length < 1 || value.components.length > 4096 || Object.keys(value).some((key) => !['format', 'components'].includes(key))) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
  const byRef = new Map(); const byPurl = new Map();
  for (const item of value.components) {
    const required = ['bom_ref', 'purl', 'license_expression', 'copyright', 'notice', 'source', 'modified'];
    if (!item || Object.keys(item).some((key) => !required.includes(key)) || required.some((key) => !Object.prototype.hasOwnProperty.call(item, key)) || typeof item.bom_ref !== 'string' || typeof item.purl !== 'string' || !item.purl.startsWith('pkg:') || typeof item.license_expression !== 'string' || typeof item.copyright !== 'string' || typeof item.notice !== 'string' || typeof item.source !== 'string' || typeof item.modified !== 'boolean' || !item.license_expression.trim() || !item.copyright.trim() || !item.notice.trim() || !item.source.trim()) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
    if (byRef.has(item.bom_ref) || byPurl.has(item.purl)) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
    if (!testOnly && /^(?:LicenseRef-|UNKNOWN|NOASSERTION)/i.test(item.license_expression)) fail('BF-OPS-SBOM-LICENSE');
    const descriptor = { ...item };
    byRef.set(item.bom_ref, descriptor); byPurl.set(item.purl, descriptor);
  }
  return { byRef, byPurl, value };
}

function applyDependencyLicense(component, catalog, { testOnly = false } = {}) {
  if (!catalog || testOnly) return component;
  const descriptor = catalog.byRef.get(component['bom-ref']) || catalog.byPurl.get(component.purl);
  if (!descriptor) fail('BF-OPS-SBOM-LICENSE', component['bom-ref']);
  return {
    ...component,
    licenses: [{ expression: descriptor.license_expression }],
    properties: [...(component.properties || []).filter((property) => property?.name !== 'bifrost.modified'),
      { name: 'bifrost.copyright', value: descriptor.copyright },
      { name: 'bifrost.notice', value: descriptor.notice },
      { name: 'bifrost.license_source', value: descriptor.source },
      { name: 'bifrost.modified', value: String(descriptor.modified) }]
  };
}

function assertNoLinkChain(file, root) {
  const absoluteRoot = path.resolve(root); const absolute = path.resolve(file); const relative = path.relative(absoluteRoot, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) fail('BF-OPS-MANIFEST');
  let current = absoluteRoot;
  for (const part of relative.split(path.sep).filter(Boolean)) { current = path.join(current, part); const stat = lstatSync(current); if (stat.isSymbolicLink() || (!stat.isDirectory() && stat.nlink > 1)) fail('BF-OPS-MANIFEST'); }
}

function canonical(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item) ?? 'null').join(',')}]`;
  return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function schemaType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function validatePinnedSchema(value, schema, root, context = { external: {} }, pointer = '$', depth = 0) {
  if (value === undefined) return;
  if (depth > 64) fail('BF-OPS-SBOM-SCHEMA');
  const resolveRef = (ref) => {
    const text = String(ref); const hash = text.indexOf('#'); const file = hash < 0 ? text : text.slice(0, hash); const fragment = hash < 0 ? '' : text.slice(hash + 1);
    const document = file ? context.external[file] : root;
    if (!document) fail('BF-OPS-SBOM-SCHEMA');
    if (!fragment) return document;
    if (!fragment.startsWith('/')) fail('BF-OPS-SBOM-SCHEMA');
    const target = fragment.slice(1).split('/').reduce((node, key) => node?.[key.replaceAll('~1', '/').replaceAll('~0', '~')], document);
    if (!target) fail('BF-OPS-SBOM-SCHEMA');
    return target;
  };
  if (schema?.$ref) return validatePinnedSchema(value, resolveRef(schema.$ref), root, context, pointer, depth + 1);
  if (schema?.allOf) for (const choice of schema.allOf) validatePinnedSchema(value, choice, root, context, pointer, depth + 1);
  if (schema?.oneOf) {
    let matches = 0; for (const choice of schema.oneOf) { try { validatePinnedSchema(value, choice, root, context, pointer, depth + 1); matches += 1; } catch {} }
    if (matches !== 1) fail('BF-OPS-SBOM-SCHEMA', `BF-OPS-SBOM-SCHEMA:${pointer}:oneOf`);
  }
  if (schema?.anyOf) {
    let matches = 0; for (const choice of schema.anyOf) { try { validatePinnedSchema(value, choice, root, context, pointer, depth + 1); matches += 1; } catch {} }
    if (matches < 1) fail('BF-OPS-SBOM-SCHEMA', `BF-OPS-SBOM-SCHEMA:${pointer}:anyOf`);
  }
  if (schema?.not) {
    let matched = false;
    try { validatePinnedSchema(value, schema.not, root, context, pointer, depth + 1); matched = true; } catch {}
    if (matched) fail('BF-OPS-SBOM-SCHEMA', `BF-OPS-SBOM-SCHEMA:${pointer}:not`);
  }
  if (schema?.const !== undefined && (typeof schema.const === 'object' ? canonical(value) !== canonical(schema.const) : value !== schema.const)) fail('BF-OPS-SBOM-SCHEMA');
  if (schema?.enum && !schema.enum.some((candidate) => (typeof candidate === 'object' ? canonical(candidate) === canonical(value) : candidate === value))) fail('BF-OPS-SBOM-SCHEMA');
  if (schema?.type) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = schemaType(value);
    const compatible = allowed.includes(actual) || (actual === 'integer' && allowed.includes('number'));
    if (!compatible) fail('BF-OPS-SBOM-SCHEMA');
  }
  if (schema?.pattern && typeof value === 'string' && !(new RegExp(schema.pattern, 'u')).test(value)) fail('BF-OPS-SBOM-SCHEMA', `BF-OPS-SBOM-SCHEMA:${pointer}:pattern`);
  if (schema?.format === 'date-time' && typeof value === 'string' && !Number.isFinite(Date.parse(value))) fail('BF-OPS-SBOM-SCHEMA');
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) fail('BF-OPS-SBOM-SCHEMA');
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) fail('BF-OPS-SBOM-SCHEMA');
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (schema.minimum !== undefined && value < schema.minimum) || (schema.maximum !== undefined && value > schema.maximum) || (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) || (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum)) fail('BF-OPS-SBOM-SCHEMA');
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail('BF-OPS-SBOM-SCHEMA');
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail('BF-OPS-SBOM-SCHEMA');
    if (schema.uniqueItems && new Set(value.map((item) => canonical(item))).size !== value.length) fail('BF-OPS-SBOM-SCHEMA');
    if (Array.isArray(schema.items)) {
      value.forEach((item, index) => { if (index < schema.items.length) validatePinnedSchema(item, schema.items[index], root, context, `${pointer}[${index}]`, depth + 1); else if (schema.additionalItems === false) fail('BF-OPS-SBOM-SCHEMA'); else if (schema.additionalItems && typeof schema.additionalItems === 'object') validatePinnedSchema(item, schema.additionalItems, root, context, `${pointer}[${index}]`, depth + 1); });
    } else if (schema.items) value.forEach((item, index) => validatePinnedSchema(item, schema.items, root, context, `${pointer}[${index}]`, depth + 1));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value); const required = schema.required || [];
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) fail('BF-OPS-SBOM-SCHEMA');
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) fail('BF-OPS-SBOM-SCHEMA');
    if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) fail('BF-OPS-SBOM-SCHEMA');
    const properties = schema.properties || {}; const patterns = schema.patternProperties || {};
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(properties, key)) validatePinnedSchema(value[key], properties[key], root, context, `${pointer}.${key}`, depth + 1);
      else {
        const matching = Object.entries(patterns).filter(([pattern]) => new RegExp(pattern, 'u').test(key));
        if (matching.length) matching.forEach(([, child]) => validatePinnedSchema(value[key], child, root, context, `${pointer}.${key}`, depth + 1));
        else if (schema.additionalProperties === false) fail('BF-OPS-SBOM-SCHEMA', `${pointer}.${key}`);
        else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') validatePinnedSchema(value[key], schema.additionalProperties, root, context, `${pointer}.${key}`, depth + 1);
      }
    }
    if (schema.dependencies) for (const [key, requirement] of Object.entries(schema.dependencies)) if (Object.prototype.hasOwnProperty.call(value, key)) { if (Array.isArray(requirement) && requirement.some((requiredKey) => !Object.prototype.hasOwnProperty.call(value, requiredKey))) fail('BF-OPS-SBOM-SCHEMA'); else if (requirement && typeof requirement === 'object' && !Array.isArray(requirement)) validatePinnedSchema(value, requirement, root, context, pointer, depth + 1); }
  }
}

function validateCycloneDx(sbom, { allowTestOnly = false } = {}) {
  const schemaPath = path.join(import.meta.dirname, '..', 'config', 'cyclonedx-1.5-bifrost.schema.json');
  if (!existsSync(schemaPath)) fail('BF-OPS-SBOM-SCHEMA');
  const pinned = readJson(schemaPath);
  if (pinned.$id !== 'http://cyclonedx.org/schema/bom-1.5.schema.json' || !pinned.properties?.bomFormat?.enum?.includes('CycloneDX') || !pinned.properties?.specVersion?.examples?.includes('1.5') || !pinned.definitions?.component || !pinned.definitions?.dependency) fail('BF-OPS-SBOM-SCHEMA');
  const external = {};
  for (const name of ['spdx.schema.json', 'jsf-0.82.schema.json']) { const referencePath = path.join(import.meta.dirname, '..', 'config', name); if (!existsSync(referencePath)) fail('BF-OPS-SBOM-SCHEMA'); external[name] = readJson(referencePath); }
  validatePinnedSchema(sbom, pinned, pinned, { external });
  return sbom;
}

function packageComponents(lockPath, ecosystem, testOnly, workspaceRoot = process.cwd(), licenseCatalog = null, logicalPrefix = null) {
  if (!existsSync(lockPath)) { if (testOnly) return []; fail('BF-OPS-SBOM-LOCK', `missing ${lockPath}`); }
  const lock = readJson(lockPath); const components = []; const dependencies = [];
  const packages = lock.packages && typeof lock.packages === 'object' ? lock.packages : null;
  if (!packages) fail('BF-OPS-SBOM-LOCK');
  for (const [location, item] of Object.entries(packages)) {
    if (!location || location === '' || !item?.version) continue;
    const name = location.replace(/^node_modules\//, '').split('node_modules/').pop();
    const version = String(item.version); const license = item.license || item.licenses;
    const resolved = item.resolved || '';
    const integrity = item.integrity || '';
    const purl = `pkg:${ecosystem}/${encodeURIComponent(name).replaceAll('%40', '@')}@${encodeURIComponent(version)}`;
    const ref = `${ecosystem}:${name}@${version}`;
    const integrityParts = typeof integrity === 'string' && integrity.includes('-') ? integrity.split('-', 2) : [];
    let hash = [];
    if (integrityParts.length === 2) { try { const decoded = Buffer.from(integrityParts[1], 'base64'); if (decoded.length > 0) hash = [{ alg: integrityParts[0].toUpperCase(), content: decoded.toString('hex') }]; } catch { fail('BF-OPS-SBOM-LOCK'); } }
    const source = logicalPrefix || path.relative(workspaceRoot, lockPath).replaceAll('\\', '/');
    components.push(applyDependencyLicense({ type: 'library', 'bom-ref': ref, name, version, purl, hashes: hash, licenses: [{ expression: typeof license === 'string' ? license : 'LicenseRef-TEST-ONLY-UNKNOWN' }], scope: 'required', properties: [{ name: 'bifrost.source', value: source }, { name: 'bifrost.resolved', value: resolved }, { name: 'bifrost.integrity', value: integrity }, { name: 'bifrost.modified', value: 'false' }] }, licenseCatalog, { testOnly }));
    // package-lock dependency values are ranges.  Resolve every edge to the
    // concrete package-lock node; never manufacture a bom-ref that is not in
    // the resolved graph.
    dependencies.push({ ref, dependsOn: Object.keys(item.dependencies || {}).map((dep) => {
      const candidates = Object.entries(packages).filter(([location, candidate]) => location.endsWith(`node_modules/${dep}`) && candidate?.version);
      const match = candidates.find(([, candidate]) => String(candidate.version) === String(item.dependencies[dep])) || candidates[0];
      return match ? `${ecosystem}:${dep}@${String(match[1].version)}` : null;
    }).filter(Boolean) });
  }
  return { components, dependencies, lock_sha256: sha256(readFileSync(lockPath)) };
}

// Resolve a build graph input by its canonical workspace path.  A verified
// source bundle deliberately does not contain workspace obj directories: the
// source-bundle builder places every declared lock/assets input under
// build-inputs/declared/<canonical path>.  Never fall back to a caller's
// ambient workspace when the graph is being rebuilt from an unpacked bundle.
function resolveLogicalInput(root, logicalPath, { sourceBundle = false, required = true, sourceFallback = null } = {}) {
  const canonicalPath = String(logicalPath || '').replaceAll('\\', '/');
  if (!canonicalPath || path.isAbsolute(canonicalPath) || canonicalPath.split('/').some((part) => !part || part === '.' || part === '..' || part.endsWith('.') || part.endsWith(' '))) fail('BF-OPS-SBOM-LOCK');
  if (!sourceBundle) {
    const direct = path.resolve(root, canonicalPath);
    if (!direct.startsWith(`${path.resolve(root)}${path.sep}`) || !existsSync(direct) || !lstatSync(direct).isFile() || lstatSync(direct).nlink > 1) {
      if (required) fail('BF-OPS-SBOM-LOCK', `BF-OPS-SBOM-LOCK:${canonicalPath}`);
      return null;
    }
    assertNoLinkChain(direct, root);
    return direct;
  }
  const declared = path.resolve(root, 'build-inputs', 'declared', canonicalPath);
  if (declared.startsWith(`${path.resolve(root)}${path.sep}`) && existsSync(declared) && lstatSync(declared).isFile() && lstatSync(declared).nlink === 1) {
    assertNoLinkChain(declared, root);
    return declared;
  }
  if (sourceFallback) {
    const fallback = path.resolve(root, sourceFallback);
    if (fallback.startsWith(`${path.resolve(root)}${path.sep}`) && existsSync(fallback) && lstatSync(fallback).isFile() && lstatSync(fallback).nlink === 1) {
      assertNoLinkChain(fallback, root);
      return fallback;
    }
  }
  if (required) fail('BF-OPS-SBOM-LOCK', `BF-OPS-SBOM-LOCK:${canonicalPath}`);
  return null;
}

function clientGraph(root, clients, testOnly, coreProvenance = null, licenseCatalog = null, { sourceBundle = false, platforms = null } = {}) {
  const platformSet = platforms instanceof Set ? platforms : new Set(platforms || ['android', 'windows']);
  const graphInputs = [];
  const logicalPath = (file) => {
    const relative = path.relative(root, file).replaceAll('\\', '/');
    if (!sourceBundle) return relative;
    if (relative.startsWith('build-inputs/declared/')) return relative.slice('build-inputs/declared/'.length);
    if (relative === 'clients' || relative.startsWith('clients/')) return `repos/bifrost-clients/${relative.slice('clients/'.length)}`;
    if (relative === 'infra' || relative.startsWith('infra/')) return `repos/bifrost-infra/${relative.slice('infra/'.length)}`;
    return relative;
  };
  // npm is an optional client input in the current desktop build; when it is
  // present, source-bundle mode still resolves it through the same canonical
  // path.  The platform lock/assets below are mandatory for production.
  const npmLock = resolveLogicalInput(root, 'repos/bifrost-clients/package-lock.json', { sourceBundle, required: false });
  const npm = npmLock ? packageComponents(npmLock, 'npm', testOnly, root, licenseCatalog, sourceBundle ? 'repos/bifrost-clients/package-lock.json' : null) : { components: [], dependencies: [], lock_sha256: null };
  if (npmLock) graphInputs.push({ path: logicalPath(npmLock), sha256: npm.lock_sha256 });
  // Test-only graph fixtures deliberately do not carry production provenance;
  // keep that lane explicit without weakening the production requirement.
  const mihomo = coreProvenance?.mihomo ?? (testOnly ? { version: 'TEST-ONLY', patch_digest: '0'.repeat(64) } : null);
  if (!mihomo?.version || !mihomo?.patch_digest) fail('BF-OPS-CORE-PROVENANCE');
  const geodataLockPath = testOnly ? null : resolveLogicalInput(root, 'repos/bifrost-clients/core-adapters/mihomo-geodata.lock.json', {
    sourceBundle,
    required: platformSet.has('windows'),
    sourceFallback: 'clients/core-adapters/mihomo-geodata.lock.json'
  });
  let geodataComponents = [];
  if (geodataLockPath) {
    const geodata = readJson(geodataLockPath);
    if (geodata?.format !== 'BIFROST-MIHOMO-GEODATA-LOCK-1' || !/^[0-9a-f]{40}$/.test(String(geodata.commit || '')) ||
        !Array.isArray(geodata.assets) || geodata.assets.length !== 2 ||
        new Set(geodata.assets.map((asset) => asset?.id)).size !== 2 ||
        geodata.assets.some((asset) => !['geosite', 'geoip'].includes(asset?.id) || !/^[0-9a-f]{64}$/.test(String(asset?.sha256 || '')) || !Number.isSafeInteger(asset?.bytes) || asset.bytes < 1))
      fail('BF-OPS-CORE-PROVENANCE');
    graphInputs.push({ path: logicalPath(geodataLockPath), sha256: sha256(readFileSync(geodataLockPath)) });
    geodataComponents = [
      { type: 'data', 'bom-ref': `meta-rules-dat@${geodata.commit}`, name: 'meta-rules-dat', version: geodata.commit, purl: `pkg:generic/meta-rules-dat@${geodata.commit}`, licenses: [{ expression: 'GPL-3.0-only' }], scope: 'required', properties: [{ name: 'bifrost.source', value: geodata.repository }, { name: 'bifrost.release_id', value: String(geodata.release_id) }, { name: 'bifrost.assets', value: canonical(geodata.assets) }, { name: 'bifrost.modified', value: 'false' }] }
    ];
  }
  const coreComponents = [
    { type: 'library', 'bom-ref': `mihomo@${mihomo.version}`, name: 'mihomo', version: mihomo.version, purl: `pkg:generic/mihomo@${mihomo.version}`, licenses: [{ expression: 'GPL-3.0-only' }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'core provenance artifact' }, { name: 'bifrost.patch_digest', value: mihomo.patch_digest }, { name: 'bifrost.modified', value: 'false' }] },
    ...geodataComponents
  ];
  if (!testOnly && platformSet.has('android')) {
    const nativeLock = resolveLogicalInput(root, 'repos/bifrost-clients/core-adapters/android-runtime.lock.json', { sourceBundle, required: true });
    const native = readJson(nativeLock);
    if (native.format !== 'BIFROST-ANDROID-RUNTIME-1' || !native.sing_box || !native.xray) fail('BF-OPS-CORE-PROVENANCE');
    graphInputs.push({ path: logicalPath(nativeLock), sha256: sha256(readFileSync(nativeLock)) });
    for (const [name, version, license, modified] of [['sing-box', native.sing_box, 'GPL-3.0-only', true], ['xray-core', native.xray, 'MPL-2.0', false]]) {
      coreComponents.push({ type: 'library', 'bom-ref': `${name}@${version}`, name, version, purl: `pkg:generic/${name}@${version}`, licenses: [{ expression: license }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'Android runtime source archive and overlay' }, { name: 'bifrost.modified', value: String(modified) }] });
    }
  }
  const coreRefs = coreComponents.map((component) => component['bom-ref']);
  let components = [
     { type: 'application', 'bom-ref': 'bifrost', name: 'Bifrost', version: 'release-bound', purl: 'pkg:generic/bifrost', licenses: [{ expression: 'GPL-3.0-only' }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'repos/bifrost-clients' }, { name: 'bifrost.modified', value: 'true' }] },
     { type: 'application', 'bom-ref': 'bifrost-clients', name: 'bifrost-clients', version: 'release-bound', purl: 'pkg:generic/bifrost-clients', licenses: [{ expression: 'GPL-3.0-only' }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'repos/bifrost-clients' }, { name: 'bifrost.modified', value: 'true' }] },
     { type: 'library', 'bom-ref': 'bifrost-client-runtime@release-bound', name: 'bifrost-client-runtime', version: 'release-bound', purl: 'pkg:generic/bifrost-client-runtime@release-bound', licenses: [{ expression: 'GPL-3.0-only' }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'android-app/windows-app' }, { name: 'bifrost.modified', value: 'true' }] },
     ...coreComponents,
     ...npm.components
  ].map((component) => applyDependencyLicense(component, licenseCatalog, { testOnly }));
  const dependencies = [{ ref: 'bifrost', dependsOn: ['bifrost-clients', 'bifrost-client-runtime@release-bound', ...coreRefs] }, ...npm.dependencies];
  const addComponent = (component, deps = []) => {
    if (components.some((item) => item['bom-ref'] === component['bom-ref'])) return;
    components.push(component); dependencies.push({ ref: component['bom-ref'], dependsOn: deps });
  };
  const gradleLock = resolveLogicalInput(root, 'repos/bifrost-clients/android-app/gradle.lockfile', { sourceBundle, required: !testOnly && platformSet.has('android') });
  if (!testOnly && platformSet.has('android') && gradleLock) {
    const text = readFileSync(gradleLock, 'utf8'); graphInputs.push({ path: logicalPath(gradleLock), sha256: sha256(Buffer.from(text, 'utf8')) });
    const verificationFile = resolveLogicalInput(root, 'repos/bifrost-clients/android-app/gradle/verification-metadata.xml', { sourceBundle, required: true }); const verificationText = readFileSync(verificationFile, 'utf8');
    const artifactHashes = new Map();
    for (const match of verificationText.matchAll(/<component group="([^"]+)" name="([^"]+)" version="([^"]+)">([\s\S]*?)<\/component>/g)) {
      const ref = `gradle:${match[1]}:${match[2]}@${match[3]}`; const hash = (match[4].match(/value="([0-9a-f]{64})"/i) || [])[1]; if (hash) artifactHashes.set(ref, hash.toLowerCase());
    }
    graphInputs.push({ path: logicalPath(verificationFile), sha256: sha256(Buffer.from(verificationText, 'utf8')) });
    for (const line of text.split(/\r?\n/)) {
      // Only libraries on the shipped runtime classpath belong in the APK
      // inventory. Build tools and test fixtures retain their lock evidence.
      if (!line.split('=')[1]?.split(',').includes('releaseRuntimeClasspath')) continue;
      const match = line.match(/^\s*([^:#\s]+):([^:#\s]+):([^=:#\s]+)(?:=[^\s]+)?/); if (!match) continue;
      const [, group, name, version] = match; const ref = `gradle:${group}:${name}@${version}`;
      const licenseId = (line.match(/(?:license|licenses)=([^\s]+)/i) || [])[1] || (licenseCatalog?.byRef.get(ref)?.license_expression || licenseCatalog?.byPurl.get(`pkg:maven/${group}/${name}@${version}`)?.license_expression) || (testOnly ? 'LicenseRef-TEST-ONLY-DECLARED' : null);
      if (!licenseId) fail('BF-OPS-SBOM-LICENSE', `${group}:${name}@${version}`);
      addComponent(applyDependencyLicense({ type: 'library', 'bom-ref': ref, name: `${group}:${name}`, version, purl: `pkg:maven/${group}/${name}@${version}`, hashes: artifactHashes.has(ref) ? [{ alg: 'SHA-256', content: artifactHashes.get(ref) }] : [], licenses: [{ expression: licenseId }], scope: 'required', properties: [{ name: 'bifrost.source', value: 'android-app/gradle.lockfile' }, { name: 'bifrost.modified', value: 'false' }] }, licenseCatalog, { testOnly }));
    }
  }
  const nugetInputs = testOnly || !platformSet.has('windows') ? [] : [
    ['repos/bifrost-clients/windows-app/obj/project.assets.json', 'windows-app'],
    ['repos/bifrost-clients/windows-service/obj/project.assets.json', 'windows-service'],
    ['repos/bifrost-infra/installer/obj/project.assets.json', 'installer']
  ];
  for (const [logicalAssets, project] of nugetInputs) {
    const fallback = sourceBundle ? null : logicalAssets;
    const assets = resolveLogicalInput(root, logicalAssets, { sourceBundle, required: true, sourceFallback: fallback });
    const raw = readFileSync(assets); graphInputs.push({ path: logicalPath(assets), sha256: hashFile(assets).sha256 });
    let parsed; try { parsed = JSON.parse(raw); } catch { fail('BF-OPS-SBOM-LOCK'); }
    for (const [key, item] of Object.entries(parsed.libraries || {})) {
      const separator = key.lastIndexOf('/'); if (separator < 1) continue; const name = key.slice(0, separator); const version = key.slice(separator + 1); const ref = `nuget:${name}@${version}`;
      const targets = Object.values(parsed.targets || {}).find((target) => target?.[key]);
      const targetInfo = targets?.[key] || {};
      const deps = Object.keys(targetInfo.dependencies || item.dependencies || {}).map((dep) => {
        const depKey = Object.keys(parsed.libraries || {}).find((candidate) => candidate.startsWith(`${dep}/`));
        if (!depKey) return null;
        const depSeparator = depKey.lastIndexOf('/');
        return depSeparator > 0 ? `nuget:${depKey.slice(0, depSeparator)}@${depKey.slice(depSeparator + 1)}` : null;
      }).filter(Boolean);
      const purl = `pkg:nuget/${name}@${version}`;
      const licenseId = item.licenseExpression || item.license || (licenseCatalog?.byRef.get(ref)?.license_expression || licenseCatalog?.byPurl.get(purl)?.license_expression) || (testOnly ? 'LicenseRef-DECLARED-BY-ASSET' : null);
      if (!licenseId) fail('BF-OPS-SBOM-LICENSE', name);
      let hash = item.sha512 ? String(item.sha512).replace(/^sha512-/, '') : '';
      if (hash && !/^[0-9a-f]+$/i.test(hash)) {
        try { hash = Buffer.from(hash, 'base64').toString('hex'); } catch { fail('BF-OPS-SBOM-LOCK'); }
      }
      if (hash && !/^[0-9a-f]+$/i.test(hash)) fail('BF-OPS-SBOM-LOCK');
      addComponent(applyDependencyLicense({ type: 'library', 'bom-ref': ref, name, version, purl, hashes: hash ? [{ alg: 'SHA-512', content: hash.toLowerCase() }] : [], licenses: [{ expression: licenseId }], scope: 'required', properties: [{ name: 'bifrost.source', value: logicalPath(assets) }, { name: 'bifrost.modified', value: 'false' }] }, licenseCatalog, { testOnly }), deps);
    }
  }
  components.sort((a, b) => String(a['bom-ref']).localeCompare(String(b['bom-ref']))); dependencies.sort((a, b) => String(a.ref).localeCompare(String(b.ref)));
  const graph = { components, dependencies, graph_inputs: graphInputs };
  return { ...graph, graph_digest: sha256(Buffer.from(canonical(graph), 'utf8')), lockfiles: { client_npm_lock_sha256: npm.lock_sha256, graph_inputs: graphInputs } };
}

function requireLicenseFiles(clientRoot, testOnly) {
  const files = [path.join(clientRoot, 'COPYING'), path.join(clientRoot, 'licenses', 'GPL-3.0-only.txt'), path.join(clientRoot, 'licenses', 'Apache-2.0.txt'), path.join(clientRoot, 'licenses', 'MPL-2.0.txt'), path.join(clientRoot, 'licenses', 'MIT.txt')];
  const results = [];
  for (const file of files) {
    if (!existsSync(file) || !lstatSync(file).isFile()) { if (testOnly) continue; fail('BF-OPS-LICENSES', file); }
    assertNoLinkChain(file, clientRoot);
    const bytes = readFileSync(file);
    if (bytes.length < 128 || bytes.includes(0)) fail('BF-OPS-LICENSES', file);
    const text = bytes.toString('utf8');
    const marker = path.basename(file) === 'COPYING' || file.endsWith('GPL-3.0-only.txt') ? /GNU GENERAL PUBLIC LICENSE[\s\S]*How to Apply These Terms/ :
      file.endsWith('Apache-2.0.txt') ? /Apache License[\s\S]*Version 2\.0/ :
        file.endsWith('MPL-2.0.txt') ? /Mozilla Public License Version 2\.0/ : /Permission is hereby granted/;
    if (!marker.test(text)) fail('BF-OPS-LICENSES', file);
    results.push({ path: path.relative(clientRoot, file).replaceAll('\\', '/'), bytes: bytes.length, sha256: sha256(bytes) });
  }
  if (!testOnly && !results.some((item) => item.path === 'COPYING' && item.bytes > 30000)) fail('BF-OPS-LICENSES');
  return results;
}

function requireNoticeFiles(clientRoot, testOnly) {
  const files = [
    path.join(clientRoot, 'THIRD_PARTY_NOTICES.md'),
    path.join(clientRoot, 'INSTALLATION_INFORMATION.md'),
    path.join(clientRoot, 'CORE_PROVENANCE.md')
  ];
  const notices = [];
  for (const file of files) {
    if (!existsSync(file) || !lstatSync(file).isFile()) { if (testOnly) continue; fail('BF-OPS-NOTICE'); }
    assertNoLinkChain(file, clientRoot);
    const bytes = readFileSync(file); const text = bytes.toString('utf8');
    if (bytes.length < 128 || bytes.includes(0) || !/license|provenance|installation/i.test(text)) fail('BF-OPS-NOTICE');
    notices.push({ path: path.relative(clientRoot, file).replaceAll('\\', '/'), bytes: bytes.length, sha256: sha256(bytes) });
  }
  if (!testOnly && notices.length !== files.length) fail('BF-OPS-NOTICE');
  return notices;
}

function validateReleaseArtifacts(root, releases, testOnly, manifestValue = null) {
  const releasePath = path.join(releases, 'RELEASE-MANIFEST.json');
  const buildPath = path.join(releases, 'BUILD-MANIFEST.json');
  const manifestPath = existsSync(releasePath) ? releasePath : buildPath;
  if (!manifestValue && !existsSync(manifestPath)) { if (testOnly) return []; fail('BF-OPS-MANIFEST'); }
  const manifest = manifestValue || readJson(manifestPath); const artifacts = manifest.build?.artifacts || manifest.artifacts;
  if (!Array.isArray(artifacts) || artifacts.length === 0) fail('BF-OPS-MANIFEST');
  const ids = new Set(); const paths = new Set(); const byId = new Map();
  const rows = artifacts.map((artifact) => {
    const kinds = new Set(['apk', 'exe', 'service-exe', 'installer', 'core', 'core-manifest', 'node-agent', 'metadata', 'notice', 'source']);
    if (typeof artifact.id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(artifact.id) || ids.has(artifact.id) || typeof artifact.path !== 'string' || path.isAbsolute(artifact.path) || /^[A-Za-z]:/.test(artifact.path) || artifact.path.includes('..') || !/^[0-9a-f]{64}$/i.test(String(artifact.sha256)) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 || !['android', 'windows', 'linux'].includes(artifact.platform) || typeof artifact.arch !== 'string' || !/^[A-Za-z0-9._-]+$/.test(artifact.arch) || (!testOnly && !kinds.has(artifact.kind))) fail('BF-OPS-MANIFEST');
    const normalizedPath = artifact.path.replaceAll('\\', '/').normalize('NFC').toLowerCase();
    if (paths.has(normalizedPath) || normalizedPath.includes(':') || normalizedPath.split('/').some((part) => !part || part === '.' || part === '..' || part.endsWith('.') || part.endsWith(' '))) fail('BF-OPS-MANIFEST');
    ids.add(artifact.id); paths.add(normalizedPath);
    const file = path.resolve(releases, artifact.path); const base = `${releases}${path.sep}`;
    if (!file.startsWith(base) || !existsSync(file) || !lstatSync(file).isFile() || lstatSync(file).nlink > 1) fail('BF-OPS-MANIFEST');
    assertNoLinkChain(file, releases);
    const identity = hashFile(file); if (identity.bytes !== artifact.bytes || identity.sha256 !== String(artifact.sha256).toLowerCase()) fail('BF-OPS-MANIFEST');
    if (!testOnly && (Object.keys(artifact).sort().join('|') !== ['arch', 'bytes', 'dependencies', 'id', 'install_path', 'kind', 'notice', 'path', 'platform', 'sha256', 'source_bundle'].join('|') || typeof artifact.install_path !== 'string' || typeof artifact.source_bundle !== 'string' || typeof artifact.notice !== 'string' || !Array.isArray(artifact.dependencies) || artifact.dependencies.some((value) => typeof value !== 'string'))) fail('BF-OPS-MANIFEST');
    const row = { id: artifact.id, path: artifact.path.replaceAll('\\', '/'), install_path: String(artifact.install_path || artifact.path).replaceAll('\\', '/'), bytes: identity.bytes, sha256: identity.sha256, platform: artifact.platform, arch: artifact.arch, kind: artifact.kind, source_bundle: artifact.source_bundle, notice: artifact.notice, dependencies: Array.isArray(artifact.dependencies) ? [...artifact.dependencies] : [] };
    byId.set(row.id, row); return row;
  });
  if (!testOnly) {
    const allowedPlatform = new Map(rows.map((row) => [row.id, `${row.platform}/${row.arch}/${row.kind}`]));
    for (const row of rows) {
      for (const reference of [row.source_bundle, row.notice, ...row.dependencies]) {
        if (!byId.has(reference)) fail('BF-OPS-MANIFEST');
      }
      if (row.source_bundle && byId.get(row.source_bundle).kind !== 'source') fail('BF-OPS-MANIFEST');
      if (row.notice && byId.get(row.notice).kind !== 'notice') fail('BF-OPS-MANIFEST');
      for (const dependency of row.dependencies) {
        const target = byId.get(dependency); if (target.platform !== row.platform || (target.arch !== row.arch && target.arch !== 'any')) fail('BF-OPS-MANIFEST');
      }
    }
    const visiting = new Set(); const visited = new Set();
    const walk = (id) => { if (visiting.has(id)) fail('BF-OPS-MANIFEST-CYCLE'); if (visited.has(id)) return; visiting.add(id); for (const dep of byId.get(id).dependencies) walk(dep); visiting.delete(id); visited.add(id); };
    rows.forEach((row) => walk(row.id));
  }
  return rows;
}

function requireBuildInputs(root, testOnly, { buildInputManifestPath, coreProvenancePath, platforms = null } = {}) {
  const platformSet = platforms instanceof Set ? platforms : new Set(platforms || ['android', 'windows']);
  const checks = [];
  if (platformSet.has('android')) checks.push(
    [path.join(root, 'repos', 'bifrost-clients', 'android-app', 'gradle', 'verification-metadata.xml'), 'android verification metadata'],
    [path.join(root, 'repos', 'bifrost-clients', 'android-app', 'gradle.lockfile'), 'android gradle lock']
  );
  if (platformSet.has('windows')) checks.push(
    [path.join(root, 'repos', 'bifrost-clients', 'windows-app', 'obj', 'project.assets.json'), 'windows app NuGet assets'],
    [path.join(root, 'repos', 'bifrost-clients', 'windows-service', 'obj', 'project.assets.json'), 'windows service NuGet assets'],
    [path.join(root, 'repos', 'bifrost-infra', 'installer', 'obj', 'project.assets.json'), 'installer NuGet assets']
  );
  const present = [];
  for (const [file, label] of checks) {
    if (!existsSync(file) || !lstatSync(file).isFile()) {
      if (!testOnly) fail('BF-OPS-SBOM-LOCK', label);
      continue;
    }
    const bytes = readFileSync(file);
    if (bytes.length === 0 || bytes.includes(0)) fail('BF-OPS-SBOM-LOCK', label);
    present.push({ path: path.relative(root, file).replaceAll('\\', '/'), bytes: bytes.length, sha256: sha256(bytes) });
  }
  for (const [file, kind] of [[coreProvenancePath, 'core-provenance'], [buildInputManifestPath, 'build-input-manifest']]) {
    if (!file) { if (!testOnly) fail('BF-OPS-CORE-PROVENANCE'); continue; }
    const absolute = path.resolve(file);
    if (!path.isAbsolute(file) || !existsSync(absolute) || !lstatSync(absolute).isFile() || lstatSync(absolute).nlink > 1) fail('BF-OPS-CORE-PROVENANCE');
    const bytes = readFileSync(absolute); if (!bytes.length || bytes.includes(0)) fail('BF-OPS-CORE-PROVENANCE');
    let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { fail('BF-OPS-CORE-PROVENANCE'); }
    if (!value || typeof value !== 'object') fail('BF-OPS-CORE-PROVENANCE');
    if (kind === 'core-provenance' && (value.format !== 'BIFROST-CORE-PROVENANCE-1' || !/^[0-9a-f]{64}$/.test(String(value.patches_digest || '')))) fail('BF-OPS-CORE-PROVENANCE');
    if (kind === 'build-input-manifest' && (value.format !== 'BIFROST-BUILD-INPUTS-1' || !Array.isArray(value.inputs) || value.inputs.length < 1)) fail('BF-OPS-BUILD-INPUTS');
    present.push({ path: path.relative(root, absolute).replaceAll('\\', '/'), bytes: bytes.length, sha256: sha256(bytes), kind });
  }
  return present;
}

function scanPayload(artifacts, releases, testOnly) {
  for (const artifact of artifacts) {
    if (artifact.kind === 'source' || artifact.kind === 'notice') continue;
    if (!testOnly && /\.pdb$/i.test(artifact.path)) fail('BF-OPS-PAYLOAD');
    if (artifact.bytes > 1024 * 1024 * 1024) fail('BF-OPS-PAYLOAD');
    const source = path.join(releases, artifact.path);
    if (!testOnly && existsSync(source)) {
      const descriptor = openSync(source, 'r'); const buffer = Buffer.alloc(1024 * 1024); let carry = Buffer.alloc(0);
      try {
        while (true) {
          const count = readSync(descriptor, buffer, 0, buffer.length, null); if (count === 0) break;
          const chunk = Buffer.concat([carry, buffer.subarray(0, count)]); const text = chunk.toString('utf8');
          for (const marker of ['BEGIN PRIVATE KEY', 'BIFROST_TEST_HARNESS', 'TEST-ONLY-PRIVATE', 'admin_token=']) if (text.includes(marker)) fail('BF-OPS-PAYLOAD');
          carry = chunk.subarray(Math.max(0, chunk.length - 128));
        }
      } finally { closeSync(descriptor); }
    }
  }
}

function generateSbom({ root, releases = path.join(root, 'releases'), output = path.join(releases, 'SBOM.json'), testOnly = false, sourceManifestPath, sourceManifestEvidencePath = null, coreProvenancePath, buildInputManifestPath, dependencyLicenseManifestPath, dependencyLicenseManifestEvidencePath = null, releaseManifestValue = null, draftManifestPath = null, licenseInventoryPath = null, writeInventoryOnly = false, boundGraphRoot = null } = {}) {
  root = path.resolve(root); releases = path.resolve(releases); const clients = path.join(root, 'repos', 'bifrost-clients');
  const licenses = requireLicenseFiles(clients, testOnly);
  const notices = requireNoticeFiles(clients, testOnly);
  const inventory = [
    'Bifrost license inventory (complete texts are shipped under the client source bundle).',
    ...licenses.map((entry) => `${entry.path}\tbytes=${entry.bytes}\tsha256=${entry.sha256}`),
    'Private Control/Node source is excluded from the GPL client source bundle.',
    'No additional restriction is imposed on GPLv3 copying, modification or redistribution.'
  ].join('\n') + '\n';
  const inventoryPath = licenseInventoryPath || path.join(releases, 'LICENSES.txt');
  mkdirSync(path.dirname(inventoryPath), { recursive: true });
  writeFileSync(inventoryPath, inventory, { encoding: 'utf8', mode: 0o644 });
  if (writeInventoryOnly) return { output, inventory: inventoryPath, inventory_sha256: sha256(Buffer.from(inventory, 'utf8')) };
  // BUILD-MANIFEST.json is an unsigned compilation plan. PowerShell emits it
  // as ordinary formatted JSON, and the final release signer later replaces
  // it with canonical, fully referenced release metadata. Do not impose the
  // signed/canonical artifact shape on this draft, but keep all file/digest,
  // source-plan, dependency, license and payload scans in production mode.
  if (draftManifestPath) releaseManifestValue = readJson(path.resolve(draftManifestPath));
  const draftShape = Boolean(draftManifestPath);
  const artifacts = validateReleaseArtifacts(root, releases, testOnly || draftShape || (!releaseManifestValue && !existsSync(path.join(releases, 'RELEASE-MANIFEST.json'))), releaseManifestValue); scanPayload(artifacts, releases, testOnly);
  const releasePlatforms = new Set(artifacts.filter((artifact) => !['source', 'notice'].includes(artifact.kind)).map((artifact) => artifact.platform));
  const buildInputs = requireBuildInputs(root, testOnly, { buildInputManifestPath, coreProvenancePath, platforms: releasePlatforms });
  if (dependencyLicenseManifestPath) {
    const licensePath = path.resolve(dependencyLicenseManifestPath);
    if (!existsSync(licensePath) || !lstatSync(licensePath).isFile() || lstatSync(licensePath).nlink > 1) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
    const licenseBytes = readFileSync(licensePath);
    buildInputs.push({ path: path.relative(root, licensePath).replaceAll('\\', '/'), bytes: licenseBytes.length, sha256: sha256(licenseBytes), kind: 'dependency-license' });
  } else if (!testOnly) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
  const coreProvenanceComplete = buildInputs.some((item) => item.kind === 'core-provenance') && buildInputs.some((item) => item.kind === 'build-input-manifest');
  if (!testOnly && !coreProvenanceComplete) fail('BF-OPS-CORE-PROVENANCE');
  const coreValue = coreProvenancePath && existsSync(coreProvenancePath) ? readCanonicalJson(coreProvenancePath, 'BF-OPS-CORE-PROVENANCE') : null;
  const sourceManifest = sourceManifestPath && existsSync(sourceManifestPath) ? { path: sourceManifestEvidencePath || path.relative(root, path.resolve(sourceManifestPath)).replaceAll('\\', '/'), sha256: sha256(readFileSync(sourceManifestPath)) } : null;
  if (!testOnly && !sourceManifest) fail('BF-OPS-SOURCE-MANIFEST');
  let sourceManifestValue = null;
  if (sourceManifest) {
    sourceManifestValue = readCanonicalJson(sourceManifestPath, 'BF-OPS-SOURCE-MANIFEST');
    if (sourceManifestValue.format !== 'BIFROST-SOURCE-BUNDLE-1' || !Array.isArray(sourceManifestValue.binary_artifacts) || typeof sourceManifestValue.binary_artifacts_sha256 !== 'string') fail('BF-OPS-SOURCE-MANIFEST');
    const releaseIds = new Set(artifacts.filter((artifact) => !['source', 'notice'].includes(artifact.kind)).map((artifact) => artifact.id));
    const sourceIds = new Set(sourceManifestValue.binary_artifacts.map((artifact) => artifact.id));
    const releasePlan = artifacts.filter((artifact) => !['source', 'notice'].includes(artifact.kind));
    if (releaseIds.size !== sourceIds.size || [...releaseIds].some((id) => !sourceIds.has(id)) || binaryPlanDigest(releasePlan) !== sourceManifestValue.build_plan_sha256 || binaryPlanDigest(sourceManifestValue.binary_artifacts) !== sourceManifestValue.build_plan_sha256 || canonicalBinaryPlan(releasePlan) !== canonicalBinaryPlan(sourceManifestValue.binary_artifacts)) fail('BF-OPS-SOURCE-MANIFEST');
  }
  const licenseCatalog = loadDependencyLicenseManifest(dependencyLicenseManifestPath, { testOnly });
  const graphRoot = path.resolve(boundGraphRoot || root);
  const graphClients = existsSync(path.join(graphRoot, 'repos', 'bifrost-clients')) ? path.join(graphRoot, 'repos', 'bifrost-clients') : path.join(graphRoot, 'clients');
  const graph = clientGraph(graphRoot, graphClients, testOnly, coreValue, licenseCatalog, { sourceBundle: !existsSync(path.join(graphRoot, 'repos', 'bifrost-clients')), platforms: releasePlatforms });
  const components = graph.components;
  const dependencyEdges = graph.dependencies;
  const graphId = graph.graph_digest.slice(0, 32); const uuid = `${graphId.slice(0, 8)}-${graphId.slice(8, 12)}-4${graphId.slice(13, 16)}-8${graphId.slice(17, 20)}-${graphId.slice(20, 32)}`;
  const evidenceProperties = [
    { name: 'bifrost.fixed_timestamp', value: '1970-01-01T00:00:00.000Z' },
    { name: 'bifrost.graph_digest', value: graph.graph_digest },
    { name: 'bifrost.source_plan', value: sourceManifestValue ? canonical({ binary_artifacts_sha256: sourceManifestValue.binary_artifacts_sha256, build_plan_sha256: sourceManifestValue.build_plan_sha256 }) : '' },
    { name: 'bifrost.source_manifest', value: sourceManifest ? canonical(sourceManifest) : '' },
    { name: 'bifrost.lockfiles', value: canonical({ client_npm_lock_sha256: graph.lockfiles.client_npm_lock_sha256, build_inputs: buildInputs, android_gradle_lock_required: !testOnly && releasePlatforms.has('android'), nuget_assets_required: !testOnly && releasePlatforms.has('windows') }) },
    { name: 'bifrost.artifacts', value: canonical(artifacts) },
    { name: 'bifrost.graph_inputs', value: canonical(graph.graph_inputs) },
    { name: 'bifrost.licenses', value: canonical(licenses) },
    { name: 'bifrost.notices', value: canonical(notices) },
    { name: 'bifrost.core_provenance', value: canonical(coreValue) },
    { name: 'bifrost.license_documents', value: canonical(licenses.map((item) => ({ path: item.path, sha256: item.sha256 }))) },
    { name: 'bifrost.notice_documents', value: canonical(notices) }
  ];
  if (dependencyLicenseManifestPath) evidenceProperties.push({ name: 'bifrost.dependency_license_manifest', value: canonical({ path: dependencyLicenseManifestEvidencePath || path.relative(graphRoot, path.resolve(dependencyLicenseManifestPath)).replaceAll('\\', '/'), sha256: sha256(readFileSync(dependencyLicenseManifestPath)) }) });
  const licenseInventory = { path: 'LICENSES.txt', bytes: Buffer.byteLength(inventory), sha256: sha256(Buffer.from(inventory, 'utf8')) };
  evidenceProperties.push({ name: 'bifrost.license_inventory', value: canonical(licenseInventory) });
  if (testOnly) {
    evidenceProperties.push({ name: 'bifrost.test_only', value: 'true' });
    evidenceProperties.push({ name: 'bifrost.production_eligible', value: 'false' });
  }
  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${uuid}`, version: 1,
    metadata: { timestamp: '1970-01-01T00:00:00.000Z', tools: [{ vendor: 'Bifrost', name: 'license-sbom.mjs', version: '1' }], component: { type: 'application', 'bom-ref': 'bifrost', name: 'Bifrost', version: 'release-bound' }, properties: evidenceProperties },
    components,
    dependencies: dependencyEdges
  };
  validateCycloneDx(sbom, { allowTestOnly: testOnly });
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, `${canonical(sbom)}\n`, { encoding: 'utf8', mode: 0o644 });
  return { output, sha256: sha256(readFileSync(output)), component_count: components.length, artifact_count: artifacts.length, license_count: licenses.length };
}

function verifySbom({ sbomPath, releases, root, boundGraphRoot = null, allowTestOnly = false, manifestValue = null, licenseInventoryPath = null, dependencyLicenseManifestPath = null } = {}) {
  if (!existsSync(sbomPath)) fail('BF-OPS-SBOM'); const sbom = readCanonicalJson(sbomPath); validateCycloneDx(sbom, { allowTestOnly });
  if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.5' || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(sbom.serialNumber || '')) || sbom.version !== 1 || !sbom.metadata || !Array.isArray(sbom.metadata.properties) || !Array.isArray(sbom.components) || !Array.isArray(sbom.dependencies)) fail('BF-OPS-SBOM');
  const props = new Map(sbom.metadata.properties.map((item) => [String(item?.name || ''), item?.value]));
  const parseProperty = (name, fallback = null) => { if (!props.has(name)) return fallback; const raw = props.get(name); if (raw === '' || raw === null || raw === undefined) return fallback; try { return JSON.parse(String(raw)); } catch { fail('BF-OPS-SBOM'); } };
  const artifactsFromEvidence = parseProperty('bifrost.artifacts');
  const licensesFromEvidence = parseProperty('bifrost.licenses');
  const noticesFromEvidence = parseProperty('bifrost.notices');
  const graphInputs = parseProperty('bifrost.graph_inputs', []);
  const graphDigest = props.get('bifrost.graph_digest');
  const coreEvidence = parseProperty('bifrost.core_provenance');
  if (!Array.isArray(artifactsFromEvidence) || !Array.isArray(licensesFromEvidence) || !Array.isArray(noticesFromEvidence) || !Array.isArray(graphInputs) || typeof graphDigest !== 'string') fail('BF-OPS-SBOM');
  const expected = validateReleaseArtifacts(path.dirname(path.dirname(releases)), releases, allowTestOnly, manifestValue);
  const actualByPath = new Map(artifactsFromEvidence.map((artifact) => [artifact.path, artifact]));
  if (actualByPath.size !== artifactsFromEvidence.length || actualByPath.size !== expected.length) fail('BF-OPS-SBOM');
  for (const artifact of expected) { const row = actualByPath.get(artifact.path); if (!row || canonical({ id: row.id, path: row.path, install_path: row.install_path, platform: row.platform, arch: row.arch, kind: row.kind, bytes: row.bytes, sha256: row.sha256 }) !== canonical({ id: artifact.id, path: artifact.path, install_path: artifact.install_path, platform: artifact.platform, arch: artifact.arch, kind: artifact.kind, bytes: artifact.bytes, sha256: artifact.sha256 })) fail('BF-OPS-SBOM'); }
  const inventoryPath = licenseInventoryPath || path.join(releases, 'LICENSES.txt');
  const licenseInventory = parseProperty('bifrost.license_inventory');
  if (!existsSync(inventoryPath) || !licenseInventory || licenseInventory.path !== 'LICENSES.txt' || sha256(readFileSync(inventoryPath)) !== licenseInventory.sha256 || statSync(inventoryPath).size !== licenseInventory.bytes) fail('BF-OPS-LICENSES');
  if (!allowTestOnly && (!props.has('bifrost.lockfiles') || !props.has('bifrost.source_plan'))) fail('BF-OPS-SBOM-LOCK');
  const graphRoot = path.resolve(boundGraphRoot || root || path.join(path.dirname(releases), '..'));
  const sourceBundleGraph = !existsSync(path.join(graphRoot, 'repos', 'bifrost-clients')) && existsSync(path.join(graphRoot, 'clients'));
  if (!allowTestOnly && !boundGraphRoot && !root) fail('BF-OPS-SBOM-BOUND-INPUTS');
  const licenseManifestEvidence = parseProperty('bifrost.dependency_license_manifest', null);
  const resolveBoundInput = (logical) => {
    const clean = String(logical || '').replaceAll('\\', '/');
    if (!clean || path.isAbsolute(clean) || clean.split('/').some((part) => part === '..' || part === '')) return null;
    const direct = path.resolve(graphRoot, clean);
    if (direct.startsWith(`${graphRoot}${path.sep}`) && existsSync(direct)) return direct;
    if (sourceBundleGraph) {
      const declared = path.resolve(graphRoot, 'build-inputs', 'declared', clean);
      if (declared.startsWith(`${graphRoot}${path.sep}`) && existsSync(declared)) return declared;
      const clientsPath = clean.replace(/^repos\/bifrost-clients\//, 'clients/').replace(/^repos\/bifrost-infra\//, 'infra/');
      const sourceFile = path.resolve(graphRoot, clientsPath);
      if (sourceFile.startsWith(`${graphRoot}${path.sep}`) && existsSync(sourceFile)) return sourceFile;
    }
    return null;
  };
  const licenseManifestPath = dependencyLicenseManifestPath || (licenseManifestEvidence?.path ? resolveBoundInput(licenseManifestEvidence.path) : null);
  if (licenseManifestPath) {
    const resolvedLicenseManifest = path.resolve(licenseManifestPath);
    if (!resolvedLicenseManifest.startsWith(`${graphRoot}${path.sep}`) || !existsSync(resolvedLicenseManifest) || lstatSync(resolvedLicenseManifest).isSymbolicLink() || lstatSync(resolvedLicenseManifest).nlink > 1) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
  }
  const licenseCatalog = loadDependencyLicenseManifest(licenseManifestPath, { testOnly: allowTestOnly });
  if (!allowTestOnly && (!licenseManifestPath || !licenseManifestEvidence || !existsSync(licenseManifestPath) || sha256(readFileSync(licenseManifestPath)) !== licenseManifestEvidence.sha256)) fail('BF-OPS-SBOM-LICENSE-MANIFEST');
  const graphClients = existsSync(path.join(graphRoot, 'repos', 'bifrost-clients')) ? path.join(graphRoot, 'repos', 'bifrost-clients') : path.join(graphRoot, 'clients');
  const releasePlatforms = new Set(expected.filter((artifact) => !['source', 'notice'].includes(artifact.kind)).map((artifact) => artifact.platform));
  const rebuilt = clientGraph(graphRoot, graphClients, allowTestOnly, coreEvidence, licenseCatalog, { sourceBundle: sourceBundleGraph, platforms: releasePlatforms });
  if (graphDigest !== rebuilt.graph_digest || canonical(sbom.components) !== canonical(rebuilt.components) || canonical(sbom.dependencies) !== canonical(rebuilt.dependencies)) fail('BF-OPS-SBOM-GRAPH');
  const componentRefs = new Set(sbom.components.map((component) => String(component['bom-ref'] || '')));
  const licenseValue = (entry) => String(entry?.expression || entry?.license?.id || entry?.license?.expression || '');
  for (const component of sbom.components) {
    const licenses = Array.isArray(component.licenses) ? component.licenses : [];
    if (licenses.length !== 1 || !licenseValue(licenses[0])) fail('BF-OPS-SBOM-LICENSE');
    for (const hash of component.hashes || []) if (!/^[0-9a-f]+$/i.test(String(hash.content || ''))) fail('BF-OPS-SBOM-GRAPH');
  }
  if (!allowTestOnly) for (const edge of sbom.dependencies) if (!componentRefs.has(String(edge.ref)) || !Array.isArray(edge.dependsOn) || edge.dependsOn.some((ref) => !componentRefs.has(String(ref)))) fail('BF-OPS-SBOM-GRAPH');
  for (const input of graphInputs || []) {
    if (!input || path.isAbsolute(String(input.path)) || String(input.path).includes('..')) fail('BF-OPS-SBOM-GRAPH');
    const file = resolveBoundInput(input.path);
    if (!file.startsWith(`${graphRoot}${path.sep}`) || !existsSync(file) || sha256(readFileSync(file)) !== input.sha256) fail('BF-OPS-SBOM-GRAPH');
  }
  if (root || !allowTestOnly) {
    const clientRoot = existsSync(path.join(graphRoot, 'repos', 'bifrost-clients')) ? path.join(graphRoot, 'repos', 'bifrost-clients') : path.join(graphRoot, 'clients');
    const expectedLicenses = requireLicenseFiles(clientRoot, allowTestOnly); const expectedNotices = requireNoticeFiles(clientRoot, allowTestOnly);
    if (canonical(licensesFromEvidence) !== canonical(expectedLicenses) || canonical(noticesFromEvidence) !== canonical(expectedNotices)) fail('BF-OPS-LICENSES');
  }
  if (!allowTestOnly && sbom.components.some((component) => component.licenses?.some((entry) => licenseValue(entry).startsWith('LicenseRef-')))) fail('BF-OPS-SBOM-LICENSE');
  const sourcePlan = parseProperty('bifrost.source_plan');
  if (!allowTestOnly && (!sourcePlan || !/^[0-9a-f]{64}$/.test(String(sourcePlan.binary_artifacts_sha256)) || !/^[0-9a-f]{64}$/.test(String(sourcePlan.build_plan_sha256)))) fail('BF-OPS-SOURCE-MANIFEST');
  const allowedLicenses = new Set(['GPL-3.0-only', 'Apache-2.0', 'MPL-2.0', 'MIT', ...(allowTestOnly ? ['LicenseRef-TEST-ONLY-DECLARED', 'LicenseRef-DECLARED-BY-VERIFICATION', 'LicenseRef-DECLARED-BY-ASSET', 'LicenseRef-Bifrost-Proprietary'] : [])]);
  if (sbom.components.some((component) => (component.licenses || []).some((entry) => { const value = licenseValue(entry); return !allowTestOnly && !allowedLicenses.has(value) && !value.includes(' OR ') && !value.includes(' AND '); }))) fail('BF-OPS-SBOM-LICENSE');
  if (!allowTestOnly) {
    const documents = new Map(licensesFromEvidence.map((document) => [document.path === 'COPYING' || document.path.endsWith('GPL-3.0-only.txt') ? 'GPL-3.0-only' : document.path.endsWith('Apache-2.0.txt') ? 'Apache-2.0' : document.path.endsWith('MPL-2.0.txt') ? 'MPL-2.0' : 'MIT', document]));
    for (const component of sbom.components) {
      const ids = (component.licenses || []).map((entry) => licenseValue(entry));
      if (ids.length !== 1 || !documents.has(ids[0])) fail('BF-OPS-LICENSES');
      const sourceProperty = Array.isArray(component.properties) ? component.properties.find((property) => property?.name === 'bifrost.source')?.value : null;
      if (typeof sourceProperty !== 'string' || path.isAbsolute(sourceProperty) || sourceProperty.includes('..')) fail('BF-OPS-SBOM-GRAPH');
      const modified = component.properties?.find((property) => property.name === 'bifrost.modified');
      if (!modified || !['true', 'false'].includes(String(modified.value))) fail('BF-OPS-LICENSES');
    }
  }
  if (!allowTestOnly) {
    const sourceManifestEvidence = parseProperty('bifrost.source_manifest');
    if (!sourceManifestEvidence || path.isAbsolute(String(sourceManifestEvidence.path)) || !/^[^:]+$/.test(String(sourceManifestEvidence.path))) fail('BF-OPS-SOURCE-MANIFEST');
    const sourceRoot = graphRoot;
    const sourceFile = resolveBoundInput(sourceManifestEvidence.path) || path.resolve(sourceRoot, sourceManifestEvidence.path);
    if (!sourceFile.startsWith(`${sourceRoot}${path.sep}`) || !existsSync(sourceFile) || sha256(readFileSync(sourceFile)) !== sourceManifestEvidence.sha256) fail('BF-OPS-SOURCE-MANIFEST');
    const sourceManifestValue = readCanonicalJson(sourceFile, 'BF-OPS-SOURCE-MANIFEST');
    const releaseBinaryPlan = artifactsFromEvidence.filter((artifact) => !['source', 'notice'].includes(artifact.kind));
    if (sourceManifestValue.format !== 'BIFROST-SOURCE-BUNDLE-1' || !Array.isArray(sourceManifestValue.binary_artifacts) || canonicalBinaryPlan(sourceManifestValue.binary_artifacts) !== canonicalBinaryPlan(releaseBinaryPlan) || sourcePlan?.binary_artifacts_sha256 !== binaryPlanDigest(releaseBinaryPlan) || sourcePlan?.build_plan_sha256 !== binaryPlanDigest(releaseBinaryPlan)) fail('BF-OPS-SOURCE-MANIFEST');
  }
  return { ok: true, component_count: sbom.components.length, artifact_count: artifactsFromEvidence.length, license_count: licensesFromEvidence.length };
}

function runCli(argv = process.argv.slice(2)) {
  const arg = (name, fallback) => { const index = argv.indexOf(name); return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback; };
  const command = argv[0]; const root = path.resolve(arg('--root', path.resolve(import.meta.dirname, '..', '..', '..'))); const testOnly = argv.includes('--test-only');
  if (command === 'generate') { const result = generateSbom({ root, releases: arg('--releases', path.join(root, 'releases')), output: arg('--output', path.join(root, 'releases', 'SBOM.json')), testOnly, sourceManifestPath: arg('--source-manifest'), coreProvenancePath: arg('--core-provenance'), buildInputManifestPath: arg('--build-input-manifest'), dependencyLicenseManifestPath: arg('--dependency-license-manifest'), boundGraphRoot: arg('--bound-root'), draftManifestPath: arg('--draft-manifest') }); console.log(JSON.stringify(result)); return result; }
  if (command === 'verify') { const result = verifySbom({ root, boundGraphRoot: arg('--bound-root'), sbomPath: arg('--sbom', path.join(root, 'releases', 'SBOM.json')), releases: arg('--releases', path.join(root, 'releases')), allowTestOnly: testOnly, dependencyLicenseManifestPath: arg('--dependency-license-manifest'), licenseInventoryPath: arg('--licenses') }); console.log(JSON.stringify(result)); return result; }
  fail('BF-OPS-SBOM-USAGE');
}

export { generateSbom, verifySbom, runCli, canonical, validateCycloneDx, loadDependencyLicenseManifest, clientGraph };

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { runCli(); } catch (error) { console.error(error.code || 'BF-OPS-SBOM'); process.exitCode = 1; }
}
