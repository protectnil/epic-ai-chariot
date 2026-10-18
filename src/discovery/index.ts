/**
 * Internal API Discovery — TypeScript interface to the Rust scanner.
 *
 * Exposes the discovery engine for use by the Chariot CLI and programmatic consumers.
 */

import { requireNativeBinding } from '../license/binding.js';
import { collectOversizeSkippedFiles, MAX_DISCOVERY_FILE_BYTES, type SkippedFile } from './helpers.js';

// Re-export all helpers so tests and consumers can import from '@epicai/chariot/discovery'
export {
  isAdminEndpoint,
  serviceSlug,
  codebaseHash,
  canonicalizePath,
  validateAuthType,
  validateDiscoveryConfig,
  loadDiscoveryConfigFile,
  collectOversizeSkippedFiles,
  filterAllowlist,
  resolveServiceConfig,
  computeRescanDiff,
  VALID_AUTH_TYPES,
  MAX_DISCOVERY_FILE_BYTES,
} from './helpers.js';

export type {
  DiscoveryScanRecord,
  DiscoveredServiceRecord,
  DiscoveryConfigFile,
  RescanDiff,
  ServiceChangeDiff,
  EndpointKey,
  AuthType,
  SkippedFile,
} from './helpers.js';

export interface DiscoveredEndpoint {
  method: string;
  path: string;
  handlerName?: string;
  filePath: string;
  lineNumber: number;
}

export interface DiscoveredService {
  name: string;
  framework: string;
  basePath: string;
  endpoints: DiscoveredEndpoint[];
  specFile?: string;
}

export interface DiscoveryResult {
  services: DiscoveredService[];
  totalEndpoints: number;
  scanDurationMs: number;
  /**
   * Candidate source files that exceeded the scanner read cap and were NOT
   * scanned. Present (possibly empty) so consumers can see the scan was
   * incomplete rather than silently trusting a false-negative-clean result.
   * Endpoints in these files are absent from `services`.
   */
  skippedFiles: SkippedFile[];
}

/**
 * Scan a codebase directory for internal APIs.
 *
 * Currently supports:
 * - OpenAPI/Swagger spec files (JSON and YAML)
 * - Express.js route definitions
 *
 * Returns structured results for the CLI to present for human review.
 */
export function discover(codebasePath: string): DiscoveryResult {
  const binding = requireNativeBinding();
  const native = binding.discoverInternalApis(codebasePath);

  // CH-31 (CHARIOT::§23.2::45) — the native scanner silently drops any candidate
  // source file larger than its read cap (~4 MiB), which can hide entire
  // internal APIs behind an ok:true / services:0 result. Detect those skips
  // and surface them honestly: attach them to the result AND emit a stderr
  // warning so the scan is never a silent false-negative. stderr keeps the
  // `--json` stdout envelope pure (CH-32) while breaking the silence.
  const skippedFiles = collectOversizeSkippedFiles(codebasePath);
  if (skippedFiles.length > 0) {
    const lines = skippedFiles.map(
      (f) => `  - ${f.filePath} (${(f.bytes / (1024 * 1024)).toFixed(1)} MiB)`,
    );
    process.stderr.write(
      `chariot discover: WARNING — ${skippedFiles.length} candidate source ` +
      `file(s) exceeded the ${MAX_DISCOVERY_FILE_BYTES}-byte scan cap and were NOT scanned; ` +
      `any APIs they define are ABSENT from this result:\n${lines.join('\n')}\n`,
    );
  }

  return { ...native, skippedFiles };
}

// Re-export the signed-envelope surface so production catalog loaders
// can consume verified discovered-adapter payloads through one path.
// Unsigned or tampered files are rejected with a stderr warning rather
// than silently trusted — closing the trust gap.
export {
  signDiscoveredAdapter,
  verifyDiscoveredAdapter,
  loadVerifiedDiscoveredAdapters,
  defaultEnvelopePaths,
  type EnvelopePaths,
  type SignedAdapterEnvelope,
} from './envelope.js';
