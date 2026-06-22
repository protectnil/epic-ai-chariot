/**
 * Internal API Discovery — TypeScript interface to the Rust scanner.
 *
 * Exposes the discovery engine for use by the Chariot CLI and programmatic consumers.
 */

import { requireNativeBinding } from '../license/binding.js';

// Re-export all helpers so tests and consumers can import from '@epicai/chariot/discovery'
export {
  isAdminEndpoint,
  serviceSlug,
  codebaseHash,
  canonicalizePath,
  validateAuthType,
  validateDiscoveryConfig,
  filterAllowlist,
  resolveServiceConfig,
  computeRescanDiff,
  VALID_AUTH_TYPES,
} from './helpers.js';

export type {
  DiscoveryScanRecord,
  DiscoveredServiceRecord,
  DiscoveryConfigFile,
  RescanDiff,
  ServiceChangeDiff,
  EndpointKey,
  AuthType,
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
  return binding.discoverInternalApis(codebasePath);
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
