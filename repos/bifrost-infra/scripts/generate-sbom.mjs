import { runCli } from './license-sbom.mjs';

// Compatibility wrapper used by build-clients.ps1.  The implementation lives
// in license-sbom.mjs so release builds cannot silently use the former static
// component list.  A command is optional for the historical `--root ...`
// invocation; all other arguments are passed through unchanged.
const args = process.argv.slice(2);
try {
  runCli(args[0] === 'generate' || args[0] === 'verify' ? args : ['generate', ...args]);
} catch (error) {
  console.error(error.code || 'BF-OPS-SBOM');
  process.exitCode = 1;
}
