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
import { WikipediaMCPServer } from '../engine/mcp-servers/wikipedia.js';
import { readCache, writeCache } from './cache.js';

const log = createLogger('catalog.artifacts');

export interface ChariotRegistryEntry {
  id: string;
  name: string;
  description: string;
  category: string;
  keywords: string[];
  type: 'mcp' | 'rest' | 'both';
  /**
   * Authoritative tool count carried at the TOP LEVEL of every signed bundle
   * entry (CH-50). The published bundle emits `toolCount`/`toolNames` here,
   * NOT under `mcp` — surfaces that render counts MUST read this via
   * `bundleToolCount()` so `chariot search`/`list`/`health` never show
   * "0 tools" for an adapter whose bundle `toolCount` is 25 (the 3.1.2
   * paypal/grafana-api/aws gap). Optional only because the legacy
   * NATIVE_CURATED_ENTRIES overlay rows omit it.
   */
  toolCount?: number;
  toolNames?: string[];
  /**
   * Governance tier (BIEN §7a::2, FPS §15.1) — TOP LEVEL, mirroring
   * `toolCount`/`toolNames` above, not nested under `mcp`/`rest`. See
   * `AdapterEntry.tier` (ChariotState.ts) for the full citation; this is
   * the same field on the raw catalog-artifact shape this module parses.
   * Optional: absent on entries the publisher has not yet classified —
   * treated as non-official (BIEN §7a::2's closed membership test admits
   * only `tier-0-protectnil`/`tier-1-provenance-verified`).
   */
  tier?: string;
  /**
   * Vendor OAuth token-refresh endpoint declaration (CHARIOT §10.5::1,
   * rulings item 98) — TOP LEVEL, mirroring `tier`/`toolCount` above, not
   * nested under `mcp`/`rest`. See `AdapterEntry.auth` (ChariotState.ts)
   * for the full citation; this is the same field on the raw
   * catalog-artifact shape this module parses — `loadAllAdaptersWithState`
   * casts a parsed bundle entry straight to `AdapterEntry`
   * (`adapters.push(payload as unknown as AdapterEntry)`), so this
   * declaration must stay byte-identical in shape to `AdapterEntry.auth`
   * for that cast to carry the field through; no separate mapping
   * function exists to reconcile a divergence.
   */
  auth?: {
    oauth2?: {
      tokenUrl?: string;
    };
  };
  mcp?: {
    /**
     * CHARIOT::§7.2::3 — this union type declares the shapes a bundle
     * entry MAY claim, not the shapes Chariot will dispatch: only `stdio`
     * and `streamable-http` are implemented at the federation layer.
     * `JSON.parse(...) as unknown` above performs no runtime validation of
     * this field — a malformed or malicious bundle record can carry ANY
     * string here (`'sse'`, `'SSE'`, `'server-sent-events'`, garbage, or
     * the field can be absent entirely), and this loader lets it through
     * unchanged. The record is never silently dispatchable regardless: the
     * runtime allow-list enforcement lives at catalog-load time in
     * `isDispatchable()` (src/engine/server/ChariotState.ts), which
     * accepts only `stdio`+`command` (or a valid docker pin) and
     * `streamable-http`+`url` — every other value, including every alias
     * of `sse`, is dropped there and never reaches the routing index,
     * `chariot_list` output, or a customer's configured set. Dispatch
     * itself (src/engine/server/toolHandlers.ts, "MCP unsupported-
     * transport refusal") re-checks the same allow-list as defense-in-
     * depth for any adapter that reaches dispatch despite the drop.
     */
    transport: 'stdio' | 'streamable-http' | 'sse';
    command?: string;
    args?: string[];
    envKeys?: string[];
    url?: string;
    /**
     * AS §1.1 "Air-gap delivery model" (ADAPTER-STANDARD-MAY-2026.md:106-124)
     * pinning triple for a packageName-form stdio adapter — mirrors
     * `AdapterEntry.mcp.packageName`/`version`/`integrityShasum`
     * (ChariotState.ts) so callers reading a `ChariotRegistryEntry` (the
     * `chariot add`/`search`/`list` CLI surface, `src/catalog/artifacts.ts`)
     * can pin+verify identically to the engine dispatch path instead of
     * falling back to the unpinned `args[1]` bare package name (row 1.42
     * proof finding — W42-FIX). `version`/`integrityShasum` are populated
     * together by the bundle-publication pipeline (AS §1.1 sub-clause 1);
     * an entry carrying `packageName` without both is unpinned and MUST be
     * refused by any install/dispatch path that requires the air-gap
     * guarantee (`installStdioDependency`, `npmIntegrityGuard.ts`).
     */
    packageName?: string;
    version?: string;
    integrityShasum?: string;
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

/**
 * The authoritative tool count for a registry entry (CH-50). Reads the
 * top-level bundle `toolCount` first (where the publisher emits it), then
 * falls back through `mcp.toolCount` and the lengths of the name arrays.
 * Every count rendered to a user or agent (search/list/health) MUST flow
 * through this helper so the surfaced count equals the signed-bundle count.
 */
export function bundleToolCount(entry: ChariotRegistryEntry): number {
  return (
    entry.toolCount ??
    entry.mcp?.toolCount ??
    (Array.isArray(entry.toolNames) ? entry.toolNames.length : undefined) ??
    (Array.isArray(entry.mcp?.toolNames) ? entry.mcp.toolNames.length : undefined) ??
    0
  );
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

export type JoinCatalogRow = {
  id?: string;
  toolCount?: number;
  toolNames?: string[];
  mcp?: { packageName?: string; version?: string; integrityShasum?: string };
};

/**
 * Join ONE catalog[] row's fields into its matching registry[] entry,
 * mutating `r` in place. Extracted from `loadChariotMcpRegistry()` as a
 * pure, directly-unit-testable function (no disk I/O, no signature
 * verification) — the disk-loading wrapper below is the only caller in
 * production; tests call this directly with synthetic rows.
 *
 * CH-50: `toolCount`/`toolNames` are carried on the parallel `catalog[]`
 * array (keyed by id), NOT on `registry[]` entries — that split is why
 * `chariot search paypal` showed "0 tools" while the bundle `toolCount`
 * was 25.
 *
 * FIX (2026-09-30, dogfood mechanism-test-mcp, gate BLOCK
 * verdict.1.json): this join previously copied ONLY toolCount/toolNames —
 * never AS §1.1's install-critical pin triple (packageName/version/
 * integrityShasum). Reproduced live: wayback-machine's `catalog[]` row
 * carries the correct `mcp.packageName: "mcp-wayback-machine"` (a real npm
 * package at the pinned version), but its `registry[]` row — the array
 * `loadChariotMcpRegistry()` actually returns, and the ONLY array
 * `chariot add`/`installStdioDependency` consult — has no `packageName` at
 * all, so `derivePackageName()` fell through to a wrong/nonexistent `args`
 * entry and `npm install` failed. Mirror the toolCount/toolNames self-heal
 * for the pin triple: copy each FIELD independently when the registry row
 * lacks it (matches AS §1.1's requirement that `version`+`integrityShasum`
 * are populated TOGETHER — a registry row already carrying both, as
 * wayback-machine's does, is untouched; only the missing `packageName` is
 * filled in from the co-signed catalog row).
 *
 * Fail CLOSED on disagreement: both arrays are signed together as part of
 * the SAME bundle (`loadAndParse` -> `verifiedReadOrNull` verifies the
 * whole file's signature before the disk-loading wrapper ever calls this),
 * so two different values for the same pin field on the same `id` is not a
 * normal publishing gap — it is a co-signed inconsistency. Clear the
 * registry field (falls back to unpinned -> ADAPTER_UNPINNED, refused by
 * installStdioDependency/npmIntegrityGuard) rather than silently trust
 * either value; log so the publisher gap is diagnosable instead of a
 * silent air-gap-install failure.
 */
export function joinCatalogRowIntoRegistryEntry(r: ChariotRegistryEntry, c: JoinCatalogRow | undefined): void {
  const hasCount = typeof r.toolCount === 'number' || (Array.isArray(r.toolNames) && r.toolNames.length > 0);
  if (!hasCount && c) {
    if (typeof c.toolCount === 'number') r.toolCount = c.toolCount;
    if (Array.isArray(c.toolNames)) r.toolNames = c.toolNames;
  }
  // Only fill in pin fields on a row that already declares an `mcp`
  // object — never fabricate one on a REST-only (`type: 'rest'`) row
  // that has no `mcp` block at all.
  if (c?.mcp && r.mcp) {
    const rMcp = r.mcp;
    for (const field of ['packageName', 'version', 'integrityShasum'] as const) {
      const catalogValue = c.mcp[field];
      if (typeof catalogValue !== 'string' || catalogValue.length === 0) continue;
      const registryValue = rMcp[field];
      if (typeof registryValue !== 'string' || registryValue.length === 0) {
        rMcp[field] = catalogValue;
      } else if (registryValue !== catalogValue) {
        log.error('catalog<->registry pin-field disagreement — failing closed (unpinned)', {
          id: r.id,
          field,
          registryValue,
          catalogValue,
        });
        delete rMcp[field];
      }
    }
  }
}

export function loadChariotMcpRegistry(): ChariotRegistryEntry[] {
  const data = loadAndParse(chariotBundlePath(), 'mcp-registry');
  if (!data) return [];
  const registry = unpackArray<ChariotRegistryEntry>(data, 'registry');
  // Join the two arrays (signed together, same length) so
  // `bundleToolCount()`/the pin triple surface correctly for the
  // search/list/health/install surfaces — see joinCatalogRowIntoRegistryEntry.
  const catalog = unpackArray<JoinCatalogRow>(data, 'catalog');
  if (catalog.length > 0) {
    // CHARIOT::§3.1::7 — this catalog<->registry join is O(catalog + registry)
    // over the full 6-figure-entry bundle on every call; the SIGNATURE
    // VERIFICATION above (loadAndParse -> verifiedReadOrNull) always runs
    // fresh regardless of the cache (CH-01 is never skipped) — only the
    // derived JOIN result is cached, keyed to the bundle file's mtime+size,
    // under ~/.epic-ai/cache/ (safe to delete: a miss just re-runs the join
    // below against the already-verified `registry`/`catalog` arrays).
    const bundlePath = chariotBundlePath();
    const cached = readCache<ChariotRegistryEntry[]>('mcp-registry-joined', bundlePath);
    if (cached) return cached;
    const byId = new Map<string, JoinCatalogRow>();
    for (const c of catalog) if (c && typeof c.id === 'string') byId.set(c.id, c);
    for (const r of registry) joinCatalogRowIntoRegistryEntry(r, byId.get(r.id));
    writeCache('mcp-registry-joined', bundlePath, registry);
  }
  return registry;
}

/**
 * Native-code adapter entries for curated adapters that are authoritative
 * REST modules shipped with the package but may be absent from the published
 * bundle when the published catalog lags or drops them. These entries
 * mirror the static `catalog()` metadata from each class and use the same
 * `rest.module` path convention as bundle REST entries.
 */
// CHARIOT::§17.3::9 — the wikipedia overlay row shipped
// with no `toolCount`/`toolNames`, so `bundleToolCount()` fell through every
// fallback to 0 and `chariot list`/`chariot health` surfaced "wikipedia …
// 0 tools" even though WikipediaMCPServer.catalog() declares 7 real tools.
// Read the counts from the adapter class's own `catalog()` (single source
// of truth already used for the class's toolNames/description) instead of
// hand-duplicating them here, so this overlay can never drift from the
// adapter it describes.
const wikipediaCatalog = WikipediaMCPServer.catalog();

const NATIVE_CURATED_ENTRIES: ChariotRegistryEntry[] = [
  {
    id: 'wikipedia',
    name: 'Wikipedia',
    description: wikipediaCatalog.description,
    category: wikipediaCatalog.category,
    keywords: wikipediaCatalog.keywords,
    type: 'rest',
    toolCount: wikipediaCatalog.toolNames.length,
    toolNames: wikipediaCatalog.toolNames,
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

