import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const fail = (code) => { throw new Error(code); };
const option = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};
const absolute = (value, code) => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) fail(code);
  return path.resolve(value);
};
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const exactKeys = (value, expected, code) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\n') !== [...expected].sort().join('\n')) fail(code);
};

function validateLock(lock) {
  exactKeys(lock, [
    'schema', 'version', 'platform', 'archive_url', 'archive_size', 'archive_sha256',
    'executable_name', 'executable_sha256', 'license', 'source',
  ], 'BF-MIHOMO-LOCK-SHAPE');
  if (lock.schema !== 'bifrost-mihomo-lock-v1' || lock.version !== 'v1.19.30' ||
      lock.platform !== 'windows-amd64-compatible' ||
      lock.archive_url !== 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-windows-amd64-compatible-v1.19.30.zip' ||
      !Number.isSafeInteger(lock.archive_size) || lock.archive_size <= 0 ||
      !/^[0-9a-f]{64}$/.test(lock.archive_sha256) || lock.executable_name !== 'mihomo.exe' ||
      !/^[0-9a-f]{64}$/.test(lock.executable_sha256) || lock.license !== 'GPL-3.0-only' ||
      lock.source !== 'https://github.com/MetaCubeX/mihomo/tree/v1.19.30') fail('BF-MIHOMO-LOCK-SHAPE');
}

function validateLeaf(file, code) {
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(code);
  return stat;
}

const lockFile = absolute(option('--lock'), 'BF-MIHOMO-LOCK-PATH');
const archive = absolute(option('--archive'), 'BF-MIHOMO-ARCHIVE-PATH');
const output = absolute(option('--output'), 'BF-MIHOMO-OUTPUT-PATH');
const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
validateLock(lock);
const archiveStat = validateLeaf(archive, 'BF-MIHOMO-ARCHIVE-PATH');
if (archiveStat.size !== lock.archive_size) fail('BF-MIHOMO-ARCHIVE-SIZE');
if (sha256(archive) !== lock.archive_sha256) fail('BF-MIHOMO-ARCHIVE-HASH');

mkdirSync(path.dirname(output), { recursive: true });
if (existsSync(output)) {
  validateLeaf(output, 'BF-MIHOMO-OUTPUT-PATH');
  if (sha256(output) !== lock.executable_sha256) fail('BF-MIHOMO-OUTPUT-EXISTS');
  process.stdout.write(`${JSON.stringify({ output, sha256: lock.executable_sha256, reused: true })}\n`);
  process.exit(0);
}

const scratch = mkdtempSync(path.join(path.dirname(output), '.mihomo-prepare-'));
const upstreamName = 'mihomo-windows-amd64-compatible.exe';
const script = String.raw`
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($env:BIFROST_MIHOMO_ARCHIVE)
try {
  $root=[IO.Path]::GetFullPath($env:BIFROST_MIHOMO_SCRATCH).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
  $files=@($zip.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
  if($files.Count -ne 1 -or $files[0].FullName -ne 'mihomo-windows-amd64-compatible.exe'){throw 'BF-MIHOMO-ARCHIVE-CONTENT'}
  foreach($entry in $zip.Entries){
    if([IO.Path]::IsPathRooted($entry.FullName) -or $entry.FullName -match '(^|[\\/])\.\.([\\/]|$)'){throw 'BF-MIHOMO-ARCHIVE-PATH'}
    $target=[IO.Path]::GetFullPath((Join-Path $root $entry.FullName))
    if(-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'BF-MIHOMO-ARCHIVE-PATH'}
  }
} finally { $zip.Dispose() }
[IO.Compression.ZipFile]::ExtractToDirectory($env:BIFROST_MIHOMO_ARCHIVE,$env:BIFROST_MIHOMO_SCRATCH)
`;
try {
  const extract = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30_000,
    env: { ...process.env, BIFROST_MIHOMO_ARCHIVE: archive, BIFROST_MIHOMO_SCRATCH: scratch },
  });
  if (extract.status !== 0) fail(/BF-MIHOMO-ARCHIVE-(?:CONTENT|PATH)/.test(`${extract.stdout}\n${extract.stderr}`)
    ? `${extract.stdout}\n${extract.stderr}`.match(/BF-MIHOMO-ARCHIVE-(?:CONTENT|PATH)/)[0]
    : 'BF-MIHOMO-ARCHIVE-EXTRACT');
  const extracted = path.join(scratch, upstreamName);
  validateLeaf(extracted, 'BF-MIHOMO-EXECUTABLE-MISSING');
  if (sha256(extracted) !== lock.executable_sha256) fail('BF-MIHOMO-EXECUTABLE-HASH');
  const staged = path.join(path.dirname(output), `.${path.basename(output)}.${process.pid}.new`);
  copyFileSync(extracted, staged);
  if (sha256(staged) !== lock.executable_sha256) fail('BF-MIHOMO-EXECUTABLE-HASH');
  renameSync(staged, output);
  process.stdout.write(`${JSON.stringify({ output, sha256: lock.executable_sha256, reused: false })}\n`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
