/**
 * @epicai/chariot — bundled catalog artifact loaders.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AdapterCatalogEntry } from '../engine/index.js';
import { createLogger } from '../engine/logger.js';
import { verifiedReadOrNull } from '../engine/keys/verifyCatalogSignature.js';
import { confinePath } from '../engine/keys/pathConfinement.js';

const log = createLogger('catalog.artifacts');

export interface ChariotRegistryEntry {
  id: string;
  name: string;
  description: string;
  category: string;
  keywords: string[];
  type: 'mcp' | 'rest' | 'both';
  mcp?: {
    transport: 'stdio' | 'streamable-http' | 'sse';
    command?: string;
    args?: string[];
    envKeys?: string[];
    url?: string;
    toolCount?: number;
    toolNames?: string[];
    /**
 * per-tool metadata including JSON-Schema inputSchema.
     * Populated by the publisher materializer from upstream mcp.tools[]
     * arrays. validateForHandlerInner reads this field to look up a
     * tool's inputSchema before adapter dispatch on the 4 non-REST
     * transports. Absent when source documents have no per-tool schema
     * data; validator emits warn-once and lets the call proceed.
     */
    tools?: Array<{
      name: string;
      description?: string;
      inputSchema?: Record<string, unknown>;
    }>;
  };
  /**
   * REST-typed adapter dispatch metadata. Present when `type` is 'rest'
   * or 'both'. The bundle currently emits `module` + `className` for
   * 757 REST entries; `envKey` is the canonical credential env-var
   * name for the REST surface (when the upstream publisher emits it).
   * cmdHealth and ChariotState.getConfiguredAdapterIds gate REST
   * credentials via this field through credentialStatus — see
   * src/engine/types/canonical-credentialed-brands.ts. Today
   * `rest.envKey` is absent from every bundle entry — the type is
   * declared so the cmdHealth REST gate compiles AND will activate
   * automatically when the upstream catalog publisher begins emitting
   * the field.
   */
  rest?: {
    module?: string;
    className?: string;
    envKey?: string;
  };
  catalogVerified?: boolean;
  reviewVerdict?: string;
  publishedAt?: string;
  entitlement?: 'chariot';
}

function packageRoot(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return resolve(dirname(thisFile), '..', '..');
}

function resolveCurrentDir(): string {
  const root = packageRoot();
  const manifestPath = resolve(root, 'chariot-current.json');
  if (!existsSync(manifestPath)) return root;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as { versionDir?: string };
 // defense: the local-build versionDir is an absolute
    // /opt path that does not exist on customer installations. If
    // the resolved directory is missing, fall back to the package
    // root where the catalog/bundle/registry JSONs are shipped.
 // defense: confine versionDir to the package root so an
    // attacker who can write chariot-current.json cannot redirect the
    // catalog loader at an arbitrary directory outside the package.
    if (manifest.versionDir) {
      const confined = confinePath(manifest.versionDir, root);
      if (confined.ok) return confined.resolved;
    }
  } catch {
    // fall back to the compatibility exports below
  }
  return root;
}

export function chariotCatalogPath(): string {
  return resolve(resolveCurrentDir(), 'chariot-adapter-catalog.json');
}

export function chariotBundlePath(): string {
  return resolve(resolveCurrentDir(), 'chariot-adapter-bundle.json');
}

function unpackArray<T>(data: unknown, key: string): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === 'object' && Array.isArray((data as Record<string, unknown>)[key])) {
    return (data as Record<string, unknown>)[key] as T[];
  }
  return [];
}

function loadAndParse(artifactPath: string, label: string): unknown | null {
  const bytes = verifiedReadOrNull(artifactPath, log, label);
  if (!bytes) return null;
  try {
    return JSON.parse(bytes.toString('utf-8')) as unknown;
  } catch (err) {
    log.error('parse failed after signature verification', {
      label,
      path: artifactPath,
      error: String(err),
    });
    return null;
  }
}

export function loadChariotAdapterCatalog(): AdapterCatalogEntry[] {
  const data = loadAndParse(chariotBundlePath(), 'adapter-catalog');
  return data ? unpackArray<AdapterCatalogEntry>(data, 'catalog') : [];
}

export function loadChariotMcpRegistry(): ChariotRegistryEntry[] {
  const data = loadAndParse(chariotBundlePath(), 'mcp-registry');
  return data ? unpackArray<ChariotRegistryEntry>(data, 'registry') : [];
}

/**
 * Native-code adapter entries for curated adapters that are authoritative
 * REST modules shipped with the package but may be absent from the published
 * bundle (bug-tracker-ref: curated adapter absent from catalog). These entries
 * mirror the static `catalog()` metadata from each class and use the same
 * `rest.module` path convention as bundle REST entries.
 */
const NATIVE_CURATED_ENTRIES: ChariotRegistryEntry[] = [
  {
    id: 'wikipedia',
    name: 'Wikipedia',
    description: 'English Wikipedia REST API: fetch article summaries, HTML content, media lists, mobile-optimised pages, revision metadata, and citation data.',
    category: 'reference',
    keywords: ['wikipedia', 'wiki', 'article', 'page', 'summary', 'content', 'encyclopedia', 'knowledge', 'reference'],
    type: 'rest',
    rest: {
      module: './dist/engine/mcp-servers/wikipedia.js',
      className: 'WikipediaMCPServer',
    },
  },
];

/**
 * Load the MCP registry and overlay native-code curated entries for adapters
 * that are absent from the published bundle. Call this instead of
 * `loadChariotMcpRegistry()` in surfaces that must surface curated adapters
 * regardless of catalog state (cmdAdd, cmdList, cmdHealth).
 */
export function loadChariotMcpRegistryWithNative(): ChariotRegistryEntry[] {
  const bundleEntries = loadChariotMcpRegistry();
  const bundleIds = new Set(bundleEntries.map((e) => e.id));
  const overlay = NATIVE_CURATED_ENTRIES.filter((e) => !bundleIds.has(e.id));
  return overlay.length > 0 ? [...bundleEntries, ...overlay] : bundleEntries;
}

export function chariotCatalogEnv(
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return {
    ...env,
    CHARIOT_ADAPTER_CATALOG_PATH: env.CHARIOT_ADAPTER_CATALOG_PATH ?? chariotBundlePath(),
    CHARIOT_MCP_REGISTRY_PATH: env.CHARIOT_MCP_REGISTRY_PATH ?? chariotBundlePath(),
  };
}

export function applyChariotCatalogEnv(): void {
  const overrides = chariotCatalogEnv();
  process.env.CHARIOT_ADAPTER_CATALOG_PATH = overrides.CHARIOT_ADAPTER_CATALOG_PATH;
  process.env.CHARIOT_MCP_REGISTRY_PATH = overrides.CHARIOT_MCP_REGISTRY_PATH;
}

