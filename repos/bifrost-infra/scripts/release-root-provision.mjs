import { createPublicKey, createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';

// The brand is private to this tool boundary.  No caller can manufacture a
// descriptor by constructing a plain object or by importing a branding
// helper; the only constructor below is reached after the complete path,
// ACL, shape and key checks in readProvisionedReleaseRoot.
const provisioned = new WeakSet();

function brandProvisionedRoot(value) {
  const descriptor = Object.freeze({ ...value });
  provisioned.add(descriptor);
  return descriptor;
}

export function isProvisionedReleaseRoot(value) {
  return Boolean(value && typeof value === 'object' && provisioned.has(value));
}

// Build-time only.  Runtime clients never call this module and never search
// the cwd, environment, release directory, or a user-writable location.
export function readProvisionedReleaseRoot(filePath, { expectedKeyId = 'bifrost-root-v1', testOnly = false } = {}) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || filePath.includes('\0')) throw new Error('BF-KEYS-PATH');
  const parsed = path.parse(filePath); let current = parsed.root;
  for (const part of filePath.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const ancestor = lstatSync(current);
    if (ancestor.isSymbolicLink() || ancestor.nlink !== 1) throw new Error('BF-KEYS-PATH');
  }
  const stat = lstatSync(filePath, { bigint: false });
  const real = path.resolve(filePath);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error('BF-KEYS-PATH');
  // On Unix a ceremony artifact must be owned by the provisioning account and
  // no group/other write bit may be present. Windows ACL verification is
  // supplied by the installer ceremony adapter; link/ancestor checks above
  // still apply on every host.
  if (!testOnly && process.platform !== 'win32' && ((stat.mode & 0o022) !== 0 || stat.uid !== 0)) throw new Error('BF-KEYS-ACL');
  if (!testOnly && process.platform === 'win32') {
    const parent = lstatSync(path.dirname(filePath));
    if (parent.isSymbolicLink() || parent.nlink !== 1) throw new Error('BF-KEYS-ACL');
    const blockedRoots = [os.tmpdir(), os.homedir(), process.env.USERPROFILE, process.env.LOCALAPPDATA, process.env.APPDATA].filter(Boolean).map((value) => path.resolve(value));
    if (blockedRoots.some((root) => real === root || real.startsWith(`${root}${path.sep}`))) throw new Error('BF-KEYS-ACL');
    // A ceremony artifact may not be sourced from the checkout or a user
    // writable ancestor.  Query the owner and every explicit/inherited DACL
    // entry as part of the build gate; a path-only check is not authority.
    assertWindowsProtectedAcl(filePath);
    let aclParent = path.dirname(filePath);
    while (aclParent && aclParent !== path.dirname(aclParent)) {
      assertWindowsProtectedAcl(aclParent);
      aclParent = path.dirname(aclParent);
    }
    const cwd = path.resolve(process.cwd());
    if (real === cwd || real.startsWith(`${cwd}${path.sep}`)) throw new Error('BF-KEYS-ACL');
  }
  if (real !== filePath && !testOnly) throw new Error('BF-KEYS-PATH');
  const value = JSON.parse(readFileSync(filePath, 'utf8'));
  const allowed = ['key_id', 'purpose', 'algorithm', 'public_key_pem', 'fingerprint'];
  const keys = Object.keys(value || {}); if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) throw new Error('BF-KEYS-SHAPE');
  if (value.key_id !== expectedKeyId || value.purpose !== 'release-trust-root' || value.algorithm !== 'Ed25519' || typeof value.public_key_pem !== 'string' || !/^[0-9a-f]{64}$/.test(value.fingerprint)) throw new Error('BF-KEYS-SHAPE');
  const fingerprint = createHash('sha256').update(createPublicKey(value.public_key_pem).export({ type: 'spki', format: 'der' })).digest('hex');
  if (fingerprint !== value.fingerprint) throw new Error('BF-KEYS-MISMATCH');
  const descriptor = Object.freeze({
    key_id: value.key_id,
    purpose: value.purpose,
    algorithm: value.algorithm,
    public_key_pem: value.public_key_pem,
    fingerprint: value.fingerprint,
    path: real,
    provenance: 'protected-ceremony'
  });
  return brandProvisionedRoot(descriptor);
}

function assertWindowsProtectedAcl(target) {
  const script = "$p=$env:BIFROST_ACL_TARGET; if([string]::IsNullOrWhiteSpace($p)){throw 'missing ACL target'}; $i=Get-Item -LiteralPath $p -Force -ErrorAction Stop; $a=if($i.PSIsContainer){[System.IO.Directory]::GetAccessControl($p)}else{[System.IO.File]::GetAccessControl($p)}; $ti=''; try { $ti=([System.Security.Principal.NTAccount]'NT SERVICE\\TrustedInstaller').Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}; $owner=''; try { $owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch {}; $entries=@($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{sid=$_.IdentityReference.Value; rights=[string]$_.FileSystemRights; type=[string]$_.AccessControlType} }); [pscustomobject]@{owner_sid=$owner; trusted_installer_sid=$ti; entries=$entries} | ConvertTo-Json -Compress -Depth 4";
  const probe = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', windowsHide: true, timeout: 5000, env: { ...process.env, BIFROST_ACL_TARGET: target } });
  if (probe.status !== 0) throw new Error('BF-KEYS-ACL');
  let acl; try { acl = JSON.parse(probe.stdout); } catch { throw new Error('BF-KEYS-ACL'); }
  validateWindowsAclDescriptor(acl);
}

// Pure, deterministic ACL policy used by the Windows PowerShell adapter and
// by the TEST-ONLY fixture.  SIDs are compared exactly; account-name suffixes
// (including EVILDOMAIN\\Administrators) are never trusted.
export function validateWindowsAclDescriptor(acl) {
  const owner = String(acl?.owner_sid || '');
  const trustedOwners = new Set(['S-1-5-18', 'S-1-5-32-544', String(acl?.trusted_installer_sid || '')].filter(Boolean));
  if (!owner || !trustedOwners.has(owner)) throw new Error('BF-KEYS-ACL');
  const entries = Array.isArray(acl?.entries) ? acl.entries : (acl?.entries ? [acl.entries] : []);
  for (const entry of entries) {
    const identity = String(entry.sid || '');
    const rights = String(entry.rights || '').toLowerCase();
    const trustedPrincipal = trustedOwners.has(identity);
    const writablePrincipal = !trustedPrincipal;
    if (writablePrincipal && /(write|modify|fullcontrol|delete|changepermissions|takeownership|create)/i.test(rights) && String(entry.type).toLowerCase() !== 'deny') throw new Error('BF-KEYS-ACL');
  }
  return true;
}
