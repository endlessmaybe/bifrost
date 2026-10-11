import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const index = process.argv.indexOf('--root');
const root = path.resolve(index >= 0 ? process.argv[index + 1] : path.resolve(import.meta.dirname, '../../..'));
const canonical = value => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value)
  ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const read = relative => JSON.parse(readFileSync(path.join(root, relative), 'utf8'));
const write = (relative, value) => writeFileSync(path.join(root, relative), canonical(value) + '\n');
const identity = relative => { const bytes = readFileSync(path.join(root, relative)); return { path: relative, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }; };
const declared = (relative, kind) => ({ ...identity(relative), kind, mode: '644' });
const lockPath = 'repos/bifrost-clients/core-adapters/android-runtime.lock.json';
const runtime = read(lockPath);
if (runtime.format !== 'BIFROST-ANDROID-RUNTIME-1') throw new Error('BF-ANDROID-RUNTIME-LOCK');
const core = read('build-inputs/core-provenance.json');
for (const item of runtime.artifacts.slice(1)) {
  const actual = identity(item.path);
  if (actual.sha256 !== item.sha256 || actual.bytes !== item.bytes) throw new Error('BF-ANDROID-RUNTIME-SOURCE');
  const rows = item.path.endsWith('.go') ? core.overlay : core.source_archive;
  const previous = rows.find(row => row.path === item.path);
  if (previous) Object.assign(previous, actual); else rows.push(actual);
}
for (const relative of ['repos/bifrost-infra/scripts/sing-box-tproxy_bifrost.go', 'repos/bifrost-infra/scripts/sing-box-tproxy_bifrost_test.go']) {
  const actual = identity(relative);
  const previous = core.overlay.find(row => row.path === relative);
  if (previous) Object.assign(previous, actual); else core.overlay.push(actual);
}
core.patches_digest = createHash('sha256').update(canonical(core.overlay)).digest('hex');
write('build-inputs/core-provenance.json', core);

const inputs = read('build-inputs/build-input-manifest.json');
const extra = [
  [lockPath, 'lock'],
  ['repos/bifrost-clients/android-app/build.gradle.kts', 'source'],
  ['repos/bifrost-clients/android-app/gradle.lockfile', 'lock'],
  ['repos/bifrost-clients/android-app/gradle/verification-metadata.xml', 'verification'],
  ['repos/bifrost-clients/android-app/gradle/wrapper/gradle-wrapper.properties', 'wrapper'],
  ['repos/bifrost-clients/android-app/gradle/wrapper/gradle-wrapper.jar', 'wrapper'],
  ['repos/bifrost-infra/scripts/prepare-android-release-evidence.mjs', 'script'],
  ['repos/bifrost-infra/scripts/build-unified-libbox.ps1', 'script'],
  ['repos/bifrost-infra/scripts/libbox-xray-bridge.go', 'source'],
  ['repos/bifrost-infra/scripts/sing-tun-gvisor-filter_bifrost.go', 'source'],
  ['repos/bifrost-infra/scripts/sing-tun-gvisor-detach_test.go', 'source'],
  ['repos/bifrost-infra/scripts/sing-box-tproxy_bifrost.go', 'source'],
  ['repos/bifrost-infra/scripts/sing-box-tproxy_bifrost_test.go', 'source'],
];
inputs.inputs.push(...extra.map(([relative, kind]) => declared(relative, kind)));
const catalog = read('build-inputs/dependency-license-manifest.json');
const routingLock = read('repos/bifrost-clients/core-adapters/mihomo-geodata.lock.json');
const routingManifestPath = 'repos/bifrost-clients/android-app/src/main/assets/routing/manifest.json';
if (existsSync(path.join(root, routingManifestPath))) {
  inputs.inputs.push(declared(routingManifestPath, 'metadata'));
  inputs.inputs.push(declared('repos/bifrost-clients/tools/export-android-routing.py', 'script'));
  for (const row of read(routingManifestPath).files) {
    const relative = `repos/bifrost-clients/android-app/src/main/assets/routing/${row.name}`;
    const actual = declared(relative, 'source');
    if (actual.sha256 !== row.sha256 || actual.bytes !== row.bytes) throw new Error('BF-CONFIG-DIGEST');
    inputs.inputs.push(actual);
  }
  const ref = `meta-rules-dat@${routingLock.commit}`;
  if (!catalog.components.some(row => row.bom_ref === ref)) catalog.components.push({
    bom_ref: ref, purl: `pkg:generic/meta-rules-dat@${routingLock.commit}`, license_expression: 'GPL-3.0-only',
    copyright: 'Copyright MetaCubeX/meta-rules-dat contributors and upstream rule-data contributors',
    notice: 'Android routing data is converted from the exact pinned Windows geodata. Input/output hashes and exporter source are included.',
    source: `${routingLock.repository}/tree/${routingLock.commit}`, modified: true,
  });
}
for (const [name, version, license, modified, source] of [
  ['sing-box', runtime.sing_box, 'GPL-3.0-only', true, 'https://github.com/SagerNet/sing-box/tree/v' + runtime.sing_box],
  ['xray-core', runtime.xray, 'MPL-2.0', false, 'https://github.com/XTLS/Xray-core/tree/v' + runtime.xray],
  ['sing-tun', runtime.sing_tun, 'GPL-3.0-only', true, 'https://github.com/SagerNet/sing-tun/tree/3a09076491df'],
]) catalog.components.push({ bom_ref: `${name}@${version}`, purl: `pkg:generic/${name}@${version}`, license_expression: license,
  copyright: `Copyright ${name} contributors`, notice: `${name} native runtime and corresponding source are release-bound; see the bundled upstream source and Bifrost bridge.`, source, modified });

const cache = path.join(process.env.GRADLE_USER_HOME || path.join(os.homedir(), '.gradle'), 'caches/modules-2/files-2.1');
const licenseId = text => {
  if (/apache/i.test(text)) return 'Apache-2.0';
  if (/\bMIT\b/i.test(text)) return 'MIT';
  if (/BSD.*3|3.*BSD/i.test(text)) return 'BSD-3-Clause';
  if (/BSD.*2|2.*BSD/i.test(text)) return 'BSD-2-Clause';
  if (/Eclipse Public License.*2/i.test(text)) return 'EPL-2.0';
  throw new Error('Unresolved Maven license: ' + text);
};
for (const line of readFileSync(path.join(root, 'repos/bifrost-clients/android-app/gradle.lockfile'), 'utf8').split(/\r?\n/)) {
  if (!line.split('=')[1]?.split(',').includes('releaseRuntimeClasspath')) continue;
  const match = line.match(/^([^:#\s]+):([^:#\s]+):([^=:#\s]+)=/);
  if (!match) continue;
  const [, group, name, version] = match;
  const ref = `gradle:${group}:${name}@${version}`;
  // Older signed catalogs use the Maven coordinate directly for libsu.
  // Preserve that verified license record instead of demanding license tags
  // from its Gradle-generated POM, which contains none.
  if (catalog.components.some(item => item.bom_ref === ref || item.bom_ref === `${group}:${name}@${version}`)) continue;
  const directory = path.join(cache, group, name, version);
  const pom = existsSync(directory) ? readdirSync(directory).map(hash => path.join(directory, hash, `${name}-${version}.pom`)).find(existsSync) : null;
  if (!pom) throw new Error('Missing cached Maven POM: ' + ref);
  const text = readFileSync(pom, 'utf8');
  let licenses = (text.match(/<licenses>([\s\S]*?)<\/licenses>/) || [])[1];
  if (!licenses) {
    const parent = (text.match(/<parent>([\s\S]*?)<\/parent>/) || [])[1] || '';
    const fields = ['groupId', 'artifactId', 'version'].map(key => (parent.match(new RegExp(`<${key}>([^<]+)</${key}>`)) || [])[1]);
    if (fields.every(Boolean)) {
      const [pg, pn, pv] = fields;
      const folder = path.join(cache, pg, pn, pv);
      const parentPom = existsSync(folder) ? readdirSync(folder).map(hash => path.join(folder, hash, `${pn}-${pv}.pom`)).find(existsSync) : null;
      if (parentPom) {
        licenses = (readFileSync(parentPom, 'utf8').match(/<licenses>([\s\S]*?)<\/licenses>/) || [])[1];
        const parentRelative = `build-inputs/evidence/gradle-poms/${pg}.${pn}.${pv}.pom`;
        mkdirSync(path.dirname(path.join(root, parentRelative)), { recursive: true });
        copyFileSync(parentPom, path.join(root, parentRelative));
        if (!inputs.inputs.some(item => item.path === parentRelative)) inputs.inputs.push(declared(parentRelative, 'metadata'));
      }
    }
  }
  if (!licenses) throw new Error('Missing Maven license: ' + ref);
  const names = [...licenses.matchAll(/<license>([\s\S]*?)<\/license>/g)].map(item => licenseId(item[1]));
  if (!names.length) throw new Error('Empty Maven license: ' + ref);
  const relative = `build-inputs/evidence/gradle-poms/${group}.${name}.${version}.pom`;
  mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
  copyFileSync(pom, path.join(root, relative));
  inputs.inputs.push(declared(relative, 'metadata'));
  const expression = [...new Set(names)].join(' OR ');
  catalog.components.push({ bom_ref: ref, purl: `pkg:maven/${group}/${name}@${version}`, license_expression: expression,
    copyright: `Copyright holders identified in ${group}:${name} upstream metadata`, notice: `${name} ${version}: ${expression}; exact Maven metadata is included in build-inputs/evidence/gradle-poms.`,
    source: `${group.startsWith('androidx.') || group.startsWith('com.android.') ? 'https://dl.google.com/dl/android/maven2' : 'https://repo.maven.apache.org/maven2'}/${group.replaceAll('.', '/')}/${name}/${version}/${name}-${version}.pom`, modified: false });
}
// A release based on an earlier signed input inventory can already contain
// these paths. Keep the freshly measured identity once per path.
inputs.inputs = [...new Map(inputs.inputs.map(item => [item.path, item])).values()];
inputs.inputs.sort((a, b) => a.path.localeCompare(b.path));
catalog.components = [...new Map(catalog.components.map(item => [item.bom_ref, item])).values()];
catalog.components.sort((a, b) => a.bom_ref.localeCompare(b.bom_ref));
write('build-inputs/build-input-manifest.json', inputs);
write('build-inputs/dependency-license-manifest.json', catalog);
console.log(JSON.stringify({ android_runtime: runtime.sing_box, xray: runtime.xray, declared_inputs: inputs.inputs.length, license_components: catalog.components.length }));
