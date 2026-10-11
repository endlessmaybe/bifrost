// TEST-ONLY protected binding adapter.  The production updater never imports
// this module.  Its provenance/path fields make accidental in-memory JSON
// self-branding fail closed at the shared brand boundary.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { readProvisionedReleaseRoot } from '../config-contracts/release-root-provision.mjs';

export function markTestRoot(value) {
  const file = path.join(os.tmpdir(), 'bifrost-test-only-root.json');
  fs.writeFileSync(file, JSON.stringify({ key_id: value.key_id, purpose: value.purpose, algorithm: value.algorithm, public_key_pem: value.public_key_pem, fingerprint: value.fingerprint }) + '\n', 'utf8');
  return readProvisionedReleaseRoot(file, { testOnly: true });
}
