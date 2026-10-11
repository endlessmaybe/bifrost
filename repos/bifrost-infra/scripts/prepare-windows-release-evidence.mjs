import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const argument = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
};
const root = path.resolve(argument('--root', path.resolve(import.meta.dirname, '..', '..', '..')));
const inputsRoot = path.join(root, 'build-inputs');
const evidenceRoot = path.join(inputsRoot, 'evidence');
const coreEvidenceRoot = path.join(inputsRoot, 'core');

const canonical = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fileIdentity = (file) => {
  const bytes = readFileSync(file);
  return { bytes: bytes.length, sha256: sha256(bytes) };
};
const relative = (file) => path.relative(root, file).replaceAll('\\', '/');
const requireFile = (file, code = 'BF-EVIDENCE-MISSING') => {
  if (!existsSync(file) || !statSync(file).isFile() || statSync(file).size < 1) throw new Error(`${code}:${relative(file)}`);
  return file;
};
const writeCanonical = (file, value) => {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${canonical(value)}\n`, 'utf8');
};
const run = (file, args, cwd = root) => {
  const result = spawnSync(file, args, { cwd, encoding: 'utf8', windowsHide: true, maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`${path.basename(file)} failed: ${result.stderr || result.stdout || result.status}`);
  return String(result.stdout || '').trim();
};
const fetchPinnedEvidence = async (url, cacheFile, expectedSha256, maxBytes = 8 * 1024 * 1024) => {
  const accept = (bytes, source) => {
    if (!bytes.length || bytes.length > maxBytes) throw new Error(`evidence ${source} size invalid: ${url}`);
    const actual = sha256(bytes);
    if (actual !== expectedSha256) throw new Error(`evidence ${source} digest mismatch: ${url} expected=${expectedSha256} actual=${actual}`);
    return bytes;
  };
  // Official release metadata is evidence, not mutable runtime state.  Once
  // the exact byte stream has been acquired and pinned by SHA-256, a release
  // build must be reproducible during an external outage instead of silently
  // depending on live network availability.  A stale/tampered cache is never
  // accepted: it must match the source-controlled digest below exactly.
  if (existsSync(cacheFile)) return accept(readFileSync(cacheFile), 'cache');
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`evidence fetch failed ${response.status}: ${url}`);
  const bytes = accept(Buffer.from(await response.arrayBuffer()), 'download');
  mkdirSync(path.dirname(cacheFile), { recursive: true });
  writeFileSync(cacheFile, bytes);
  return bytes;
};

function archiveGitTree(repo, revision, output) {
  requireFile(path.join(repo, 'go.mod'));
  rmSync(output, { force: true });
  run('git.exe', ['-C', repo, 'archive', '--format=tar', `--output=${output}`, revision]);
  requireFile(output);
  if (statSync(output).size > 64 * 1024 * 1024) throw new Error(`core source archive exceeds release evidence limit: ${output}`);
}

function row(file, kind, mode = '644') {
  requireFile(file);
  const identity = fileIdentity(file);
  return { path: relative(file), sha256: identity.sha256, bytes: identity.bytes, mode, kind };
}

function packageFolders(assetsFiles) {
  const roots = new Set();
  for (const file of assetsFiles) {
    const value = JSON.parse(readFileSync(file, 'utf8'));
    for (const folder of Object.keys(value.packageFolders || {})) roots.add(path.resolve(folder));
  }
  return [...roots];
}

function findNuspec(roots, name, version) {
  const packageName = name.toLowerCase(); const packageVersion = version.toLowerCase();
  for (const rootDir of roots) {
    const dir = path.join(rootDir, packageName, packageVersion);
    if (!existsSync(dir)) continue;
    const candidate = readdirSync(dir).find((item) => item.toLowerCase().endsWith('.nuspec'));
    if (candidate) return path.join(dir, candidate);
  }
  return null;
}

function dependencyLicenseManifest(assetsFiles) {
  const roots = packageFolders(assetsFiles);
  const rows = [
    { bom_ref: 'bifrost', purl: 'pkg:generic/bifrost', license_expression: 'GPL-3.0-only', copyright: 'Copyright Bifrost contributors', notice: 'Bifrost client components are distributed under GPL-3.0-only; complete license text is bundled.', source: 'repos/bifrost-clients', modified: true },
    { bom_ref: 'bifrost-clients', purl: 'pkg:generic/bifrost-clients', license_expression: 'GPL-3.0-only', copyright: 'Copyright Bifrost contributors', notice: 'Bifrost client source and corresponding installation information are bundled with the release source archive.', source: 'repos/bifrost-clients', modified: true },
    { bom_ref: 'bifrost-client-runtime@release-bound', purl: 'pkg:generic/bifrost-client-runtime@release-bound', license_expression: 'GPL-3.0-only', copyright: 'Copyright Bifrost contributors', notice: 'Bifrost native client runtime is release-bound and distributed under GPL-3.0-only.', source: 'repos/bifrost-clients/windows-app;repos/bifrost-clients/windows-service', modified: true },
    { bom_ref: 'mihomo@1.19.30', purl: 'pkg:generic/mihomo@1.19.30', license_expression: 'GPL-3.0-only', copyright: 'Copyright MetaCubeX/mihomo contributors', notice: 'Windows release uses the unmodified official Mihomo v1.19.30 windows-amd64-compatible binary; its archive, executable and corresponding source tag are SHA-256 bound by release evidence.', source: 'https://github.com/MetaCubeX/mihomo/tree/v1.19.30', modified: false },
    { bom_ref: 'meta-rules-dat@4178770badecb1b349fbcd62c737e0d7a2079729', purl: 'pkg:generic/meta-rules-dat@4178770badecb1b349fbcd62c737e0d7a2079729', license_expression: 'GPL-3.0-only', copyright: 'Copyright MetaCubeX/meta-rules-dat contributors and upstream rule-data contributors', notice: 'GeoSite.dat and geoip.metadb are pinned to release 393387661 published 2026-09-22; the generator source tree remains commit 4178770badecb1b349fbcd62c737e0d7a2079729 and both asset/source SHA-256 values are release-bound.', source: 'https://github.com/MetaCubeX/meta-rules-dat/tree/4178770badecb1b349fbcd62c737e0d7a2079729', modified: false }
  ];
  const seen = new Set(rows.map((item) => item.bom_ref));
  for (const assetsFile of assetsFiles) {
    const assets = JSON.parse(readFileSync(assetsFile, 'utf8'));
    for (const key of Object.keys(assets.libraries || {})) {
      const separator = key.lastIndexOf('/'); if (separator < 1) continue;
      const name = key.slice(0, separator); const version = key.slice(separator + 1); const bomRef = `nuget:${name}@${version}`;
      if (seen.has(bomRef)) continue;
      const nuspec = findNuspec(roots, name, version);
      if (!nuspec) throw new Error(`NuGet nuspec missing: ${name}@${version}`);
      const text = readFileSync(nuspec, 'utf8');
      const license = (text.match(/<license\s+type=["']expression["'][^>]*>([^<]+)<\/license>/i) || [])[1]?.trim();
      if (!license) throw new Error(`NuGet license expression missing: ${name}@${version}`);
      const repository = text.match(/<repository\s+[^>]*url=["']([^"']+)["'][^>]*?(?:commit=["']([^"']+)["'])?[^>]*\/?>/i);
      const projectUrl = (text.match(/<projectUrl>([^<]+)<\/projectUrl>/i) || [])[1]?.trim();
      const source = repository?.[1] ? `${repository[1]}${repository[2] ? `@${repository[2]}` : ''}` : (projectUrl || `NuGet:${name}@${version}`);
      rows.push({ bom_ref: bomRef, purl: `pkg:nuget/${name}@${version}`, license_expression: license, copyright: `Copyright holders identified by ${name} upstream package metadata`, notice: `${name} ${version} is redistributed under ${license}; see the bundled license text and upstream package metadata.`, source, modified: false });
      seen.add(bomRef);
    }
  }
  rows.sort((a, b) => a.bom_ref.localeCompare(b.bom_ref));
  return { format: 'BIFROST-DEPENDENCY-LICENSES-1', components: rows };
}

async function main() {
  mkdirSync(evidenceRoot, { recursive: true }); mkdirSync(coreEvidenceRoot, { recursive: true });
  const clients = path.join(root, 'repos', 'bifrost-clients');
  const infra = path.join(root, 'repos', 'bifrost-infra');
  const downloads = path.join(root, 'build-work', 'toolchains', 'cores', 'downloads');
  const downloadedSource = requireFile(path.join(downloads, 'mihomo-v1.19.30-source.tar.gz'));
  if (fileIdentity(downloadedSource).sha256 !== 'ee8a7107707e4bd485460139b1944e7be30016393783f2b4e928c14880c8ca8b')
    throw new Error('Mihomo v1.19.30 source archive digest mismatch');
  const mihomoSource = path.join(coreEvidenceRoot, 'mihomo-v1.19.30-source.tar.gz');
  copyFileSync(downloadedSource, mihomoSource);
  const downloadedRulesSource = requireFile(path.join(downloads, 'meta-rules-dat-4178770badecb1b349fbcd62c737e0d7a2079729.tar.gz'));
  if (fileIdentity(downloadedRulesSource).sha256 !== '6e8d87b0439cfe46618a55f0d8c90fea07450c59f586d1dab48d920f2e5db0a0')
    throw new Error('meta-rules-dat source archive digest mismatch');
  const rulesSource = path.join(coreEvidenceRoot, 'meta-rules-dat-4178770badecb1b349fbcd62c737e0d7a2079729.tar.gz');
  copyFileSync(downloadedRulesSource, rulesSource);
  const mihomoPatch = path.join(coreEvidenceRoot, 'mihomo-NO-PATCH.txt');
  writeFileSync(mihomoPatch, 'BIFROST-WINDOWS-CORE-PATCH-ATTESTATION-1\ncomponent=mihomo\nversion=1.19.30\nvariant=windows-amd64-compatible\npatches=none\nbinary_source=official-upstream-release\n', 'utf8');
  const sourceRows = [row(mihomoSource, 'source'), row(rulesSource, 'source')].map(({ path: p, bytes, sha256: digest }) => ({ path: p, bytes, sha256: digest }));
  const overlayRows = [row(mihomoPatch, 'patch')].map(({ path: p, bytes, sha256: digest }) => ({ path: p, bytes, sha256: digest }));
  const patchesDigest = sha256(readFileSync(mihomoPatch));
  const coreProvenance = {
    format: 'BIFROST-CORE-PROVENANCE-1',
    mihomo: { version: '1.19.30', source_digest: fileIdentity(mihomoSource).sha256, patch_digest: fileIdentity(mihomoPatch).sha256, source_path: relative(mihomoSource), patch_path: relative(mihomoPatch) },
    patches_digest: patchesDigest,
    source_archive: sourceRows,
    overlay: overlayRows
  };
  const coreProvenancePath = path.join(inputsRoot, 'core-provenance.json'); writeCanonical(coreProvenancePath, coreProvenance);

  const dotnetMetadataUrl = 'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json';
  const nodeChecksumsUrl = 'https://nodejs.org/dist/v24.19.0/SHASUMS256.txt';
  const dotnetMetadataPath = path.join(evidenceRoot, 'dotnet-10.0-releases.json');
  const nodeChecksumsPath = path.join(evidenceRoot, 'node-v24.19.0-SHASUMS256.txt');
  const dotnetMetadata = await fetchPinnedEvidence(
    dotnetMetadataUrl,
    dotnetMetadataPath,
    '5e3f4d08e6be9724ee3407b10ca19e33b6e895d74b6f122651b8bcac22b54fdb');
  const nodeChecksums = await fetchPinnedEvidence(
    nodeChecksumsUrl,
    nodeChecksumsPath,
    'be0629ee2bcd8e40bb856abdd3407f0762101b76bd60a36b8867f637733631c0',
    1024 * 1024);
  // Rewrite only after the pinned bytes have been accepted.  This preserves
  // canonical evidence paths without allowing a failed fetch to truncate a
  // previously valid cache.
  writeFileSync(dotnetMetadataPath, dotnetMetadata);
  writeFileSync(nodeChecksumsPath, nodeChecksums);
  const dotnetRelease = JSON.parse(dotnetMetadata).releases?.find((entry) => entry?.sdk?.version === '10.0.302');
  const sdkZip = dotnetRelease?.sdk?.files?.find((entry) => entry.rid === 'win-x64' && String(entry.name || '').endsWith('.zip'));
  if (!sdkZip?.url || !sdkZip?.hash) throw new Error('official .NET 10.0.302 win-x64 metadata missing');
  const nodeLine = nodeChecksums.toString('utf8').split(/\r?\n/).find((line) => line.endsWith('  node-v24.19.0-win-x64.zip'));
  if (!nodeLine || !/^[0-9a-f]{64}\s{2}/.test(nodeLine)) throw new Error('official Node v24.19.0 win-x64 checksum missing');

  const nodeExe = run('where.exe', ['node.exe']).split(/\r?\n/)[0];
  const dotnetExe = path.join(root, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe'); requireFile(dotnetExe);
  const toolchainLocalPath = path.join(evidenceRoot, 'local-toolchain.json');
  writeCanonical(toolchainLocalPath, {
    format: 'BIFROST-LOCAL-TOOLCHAIN-EVIDENCE-1',
    dotnet: { version: run(dotnetExe, ['--version']), executable_sha256: fileIdentity(dotnetExe).sha256, official_sdk_url: sdkZip.url, official_sdk_sha512: String(sdkZip.hash).toLowerCase() },
    node: { version: run(nodeExe, ['--version']), executable_sha256: fileIdentity(nodeExe).sha256, official_zip_sha256: nodeLine.split(/\s+/)[0] }
  });

  const assetsFiles = [
    path.join(clients, 'windows-app', 'obj', 'project.assets.json'),
    path.join(clients, 'windows-service', 'obj', 'project.assets.json'),
    path.join(infra, 'installer', 'obj', 'project.assets.json')
  ].map((file) => requireFile(file));
  const licenseManifestPath = path.join(inputsRoot, 'dependency-license-manifest.json');
  writeCanonical(licenseManifestPath, dependencyLicenseManifest(assetsFiles));

  const declared = [
    ...assetsFiles.map((file) => row(file, 'lock')),
    row(path.join(clients, 'windows-app', 'BifrostApp.csproj'), 'source'),
    row(path.join(clients, 'windows-service', 'BifrostClientService.csproj'), 'source'),
    row(path.join(infra, 'installer', 'BifrostSetup.csproj'), 'source'),
    row(path.join(clients, 'release', 'ReleaseUpdateManager.cs'), 'source'),
    row(path.join(clients, 'release', 'ReleaseArtifactPolicy.cs'), 'source'),
    row(path.join(clients, 'config-contracts', 'release-contract-v1.json'), 'metadata'),
    row(path.join(infra, 'scripts', 'build-clients.ps1'), 'script', '755'),
    row(path.join(infra, 'scripts', 'setup-core-binaries.ps1'), 'script', '755'),
    row(path.join(clients, 'core-adapters', 'mihomo.lock.json'), 'metadata'),
    row(path.join(clients, 'core-adapters', 'mihomo-geodata.lock.json'), 'metadata'),
    row(path.join(root, 'build-work', 'toolchains', 'cores', 'downloads', 'mihomo-windows-amd64-compatible-v1.19.30.zip'), 'core'),
    row(path.join(root, 'build-work', 'toolchains', 'cores', 'mihomo-rules', '2026-09-22', 'geosite.dat'), 'core'),
    row(path.join(root, 'build-work', 'toolchains', 'cores', 'mihomo-rules', '2026-09-22', 'geoip.metadb'), 'core'),
    row(mihomoSource, 'source'),
    row(rulesSource, 'source'),
    row(dotnetMetadataPath, 'toolchain'), row(nodeChecksumsPath, 'toolchain'), row(toolchainLocalPath, 'toolchain')
  ];
  declared.sort((a, b) => a.path.localeCompare(b.path));
  const buildInputsPath = path.join(inputsRoot, 'build-input-manifest.json');
  writeCanonical(buildInputsPath, {
    format: 'BIFROST-BUILD-INPUTS-1',
    inputs: declared,
    toolchain: { required: [
      { name: '.NET SDK release metadata', version: '10.0.302', download_url: dotnetMetadataUrl, sha256: sha256(dotnetMetadata) },
      { name: 'Node.js release checksums', version: '24.19.0', download_url: nodeChecksumsUrl, sha256: sha256(nodeChecksums) }
    ] }
  });

  process.stdout.write(`${JSON.stringify({ core_provenance: coreProvenancePath, build_inputs: buildInputsPath, dependency_licenses: licenseManifestPath, inputs: declared.length })}\n`);
}

main().catch((error) => { process.stderr.write(`${error?.stack || error}\n`); process.exitCode = 1; });
