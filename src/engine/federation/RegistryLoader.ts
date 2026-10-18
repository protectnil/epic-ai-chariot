/**
 * @epicai/chariot — Registry Loader
 * Loads mcp-registry.json and builds ServerConnection[] for the FederationManager.
 * Resolves credentials from environment variables or a SecretsProvider.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { join } from 'node:path';
import type { ServerConnection, AuthConfig, Tool } from '../types/index.js';
import type { AdapterCatalog } from './AdapterCatalog.js';
import { resolvePublishedArtifactDir } from './artifact-publication.js';
import { verifiedReadOrNull } from '../keys/verifyCatalogSignature.js';
import { createLogger } from '../logger.js';
import { isEngineInternalCredentialKey } from '../../cli/credentials.js';
import { effectiveEnvKeys } from '../types/canonical-credentialed-brands.js';
import { applyCuratedHostOverride } from '../../catalog/curated.js';

const log = createLogger('federation.registry-loader');

// ─── Registry Entry (matches generate-registry.ts output) ────────────────────

interface RegistryEntry {
  id: string;
  name: string;
  description: string;
  category: string;
  keywords: string[];
  type: 'mcp' | 'rest' | 'both';
  mcp?: {
    transport: 'stdio' | 'streamable-http';
    command?: string;
    args?: string[];
    envKeys?: string[];
    url?: string;
    requiresOAuth?: boolean;
    toolCount?: number;
    toolNames?: string[];
    recommendation?: string;
    repoUrl?: string;
    /** Supply-chain provenance fields (populated by the bundle-publication pipeline). */
    version?: string;
    integrityShasum?: string;
    packageName?: string;
  };
  rest?: {
    module: string;
    className: string;
    baseUrl: string;
    authType: string;
    envKey: string;
    toolCount: number;
    toolNames: string[];
  };
}

type RegistryPayload = RegistryEntry[] | { registry?: RegistryEntry[] };

function unpackRegistryPayload(payload: RegistryPayload): RegistryEntry[] {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.registry)) return payload.registry;
  return [];
}

// ─── CHARIOT::§7.5 wiring seams ───────────────────────────────────────────────
// Structural (not concrete-class) interfaces so this module does not need to
// import FederationManager/ToolPreFilter directly — matches the existing
// `catalog?: AdapterCatalog` seam's spirit of minimal coupling, and lets a
// test double satisfy the shape without constructing the real classes.

/** The subset of FederationManager's public surface RegistryLoader needs to
 *  "wire each adapter into the pool" (CHARIOT §7.5). */
export interface RegistryLoaderFederationTarget {
  connect(
    name: string,
    config: ServerConnection,
  ): Promise<unknown>;
  unloadAdapter(
    name: string,
    reason: string,
    options?: { maxQuiescenceMs?: number; revoked?: boolean },
  ): Promise<{ success: boolean }>;
  listTools(): Tool[];
  /**
   * CHARIOT::§7.5::1 — optional: names already connected (e.g. from
   * `FederationConfig.servers` via `connectAll()`, run BEFORE
   * `loadAndWire()` in the engine startup path). When present,
   * `loadAndWire()` skips connecting any catalog-listed entry whose
   * name is already in this list, so it never double-connects a server
   * `connectAll()` already brought up. Omit to keep pre-1.4.1 behavior
   * (always attempt `connect()`, relying on the target's own
   * idempotence, if any).
   */
  listConnectedServerNames?(): string[];
}

/** The subset of ToolPreFilter's public surface RegistryLoader needs to
 *  "register tools with ToolPreFilter" (CHARIOT §7.5). */
export interface RegistryLoaderToolIndex {
  index(tools: Tool[]): void;
}

// ─── Loader Options ──────────────────────────────────────────────────────────

export interface RegistryLoaderOptions {
  /**
   * Path to the canonical adapter artifact. Defaults to the bundled
   * adapter-bundle.json when present, otherwise the legacy
   * mcp-registry.json compatibility export.
   */
  registryPath?: string;

  /**
   * Which adapter types to load.
   * - 'mcp-only': only load adapters with vendor MCP connections
   * - 'rest-only': only load REST adapters
   * - 'all': load everything (default)
   * - 'mcp-preferred': load MCP when available, REST as fallback
   */
  strategy?: 'mcp-only' | 'rest-only' | 'all' | 'mcp-preferred';

  /**
   * Filter by category (e.g., ['cybersecurity', 'devops']).
   * If empty or undefined, all categories are included.
   */
  categories?: string[];

  /**
   * Filter by adapter ID. Only load these specific adapters.
   * If empty or undefined, all adapters are included.
   */
  include?: string[];

  /**
   * Exclude these adapter IDs.
   */
  exclude?: string[];

  /**
   * Custom credential resolver. If not provided, reads from process.env.
   * The function receives the env var name and returns the value.
   */
  resolveCredential?: (envKey: string) => string | undefined;

  /**
   * Whether to skip adapters whose credentials are not found in env.
   * Default: true (only connect adapters the customer has credentials for).
   */
  skipMissingCredentials?: boolean;

  /**
   * Optional AdapterCatalog (already loaded) used to filter revoked
   * adapters out of the ServerConnection list before the FederationManager
   * ever sees them. When set, `load()` skips any registry entry whose
   * `id` matches a revoked catalog entry and records the skip in
   * `RegistryLoadResult.skipped` with reason "revoked in catalog".
   *
   * Omit (undefined) to keep pre-1.1.0 behavior where revocation is not
   * enforced at load time.
   */
  catalog?: AdapterCatalog;

  /**
   * CHARIOT::§7.5 — when set, `loadAndWire()`/`reload()` actually
   * instantiate each catalog-listed adapter (via `federation.connect()`,
   * which builds the pool-backed adapter and registers its tools in the
   * unified ToolRegistry) rather than only returning ServerConnection[]
   * data for a caller to wire up itself. Omit to keep pre-1.4.0 `load()`
   * behavior (data only, no side effects).
   */
  federation?: RegistryLoaderFederationTarget;

  /**
   * CHARIOT::§7.5 — when set (together with `federation`), `loadAndWire()`/
   * `reload()` re-index this ToolPreFilter from `federation.listTools()`
   * after wiring, so the pre-filter's shortlist reflects the adapters this
   * loader just connected. Omit to skip pre-filter registration.
   */
  toolPreFilter?: RegistryLoaderToolIndex;
}

// ─── Loader Result ───────────────────────────────────────────────────────────

export interface LoadedAdapter {
  /** ServerConnection for the FederationManager */
  connection: ServerConnection;
  /** Whether this is an MCP or REST connection */
  connectionType: 'mcp' | 'rest';
  /** Original registry entry for reference */
  entry: RegistryEntry;
}

export interface RegistryLoadResult {
  /** Adapters that were loaded successfully (credentials found) */
  loaded: LoadedAdapter[];
  /** Adapters that were skipped (missing credentials) */
  skipped: Array<{ id: string; reason: string }>;
  /** Total entries in the registry */
  totalInRegistry: number;
}

// ─── Loader ──────────────────────────────────────────────────────────────────

export class RegistryLoader {
  private readonly options: Omit<Required<RegistryLoaderOptions>, 'catalog' | 'federation' | 'toolPreFilter'> & {
    catalog: AdapterCatalog | undefined;
    federation: RegistryLoaderFederationTarget | undefined;
    toolPreFilter: RegistryLoaderToolIndex | undefined;
  };
  private registry: RegistryEntry[] = [];
  /**
   * CHARIOT::§7.5 — names successfully wired by the most recent
   * loadAndWire()/reload() call. reload() diffs against this set to
   * decide which adapters to unloadAdapter() (no longer present, or
   * newly filtered/revoked) versus connect() (newly present). Empty
   * until loadAndWire() or reload() has run at least once.
   */
  private lastWired: Set<string> = new Set();

  constructor(options: RegistryLoaderOptions = {}) {
    const thisFile = import.meta.dirname || __dirname;
    const pkgRoot = join(thisFile, '..', '..', '..');
    const bundleDir = resolvePublishedArtifactDir(pkgRoot, 'adapter-current.json', pkgRoot);
    const bundlePath = join(bundleDir, 'adapter-bundle.json');
    this.options = {
      registryPath: options.registryPath
        || process.env.CHARIOT_MCP_REGISTRY_PATH
        || bundlePath,
      strategy: options.strategy || 'mcp-preferred',
      categories: options.categories || [],
      include: options.include || [],
      exclude: options.exclude || [],
      resolveCredential: options.resolveCredential || ((key: string) => process.env[key]),
      skipMissingCredentials: options.skipMissingCredentials ?? true,
      catalog: options.catalog,
      federation: options.federation,
      toolPreFilter: options.toolPreFilter,
    };
  }

  /**
   * Load the registry and build ServerConnection[] for all matching adapters.
   */
  load(): RegistryLoadResult {
 // this loader feeds `connection.args[0] = rest.module` to the
    // FederationManager, which downstream dynamically imports that path.
    // Same RCE shape as ChariotState/setup.ts, same gate.
    const bytes = verifiedReadOrNull(this.options.registryPath, log, 'registry');
    if (!bytes) {
      this.registry = [];
      return { loaded: [], skipped: [], totalInRegistry: 0 };
    }
    this.registry = unpackRegistryPayload(JSON.parse(bytes.toString('utf-8')) as RegistryPayload);

    const result: RegistryLoadResult = {
      loaded: [],
      skipped: [],
      totalInRegistry: this.registry.length,
    };

    for (const entry of this.registry) {
      // Apply filters
      if (this.options.include.length > 0 && !this.options.include.includes(entry.id)) continue;
      if (this.options.exclude.includes(entry.id)) continue;
      if (this.options.categories.length > 0 && !this.options.categories.includes(entry.category)) continue;

      // Revocation gate — when a catalog is provided, revoked entries
      // are excluded from the connection list before ConnectionPool
      // ever sees them. This is the first of two defense layers in
      // Chariot's runtime revocation story; the second layer is
      // FederationManager.callTool() which re-checks on every call.
      if (this.options.catalog?.isRevoked(entry.id)) {
        const details = this.options.catalog.getRevocationDetails(entry.id);
        const reasonSuffix = details?.reason ? `: ${details.reason}` : '';
        result.skipped.push({
          id: entry.id,
          reason: `revoked in catalog${reasonSuffix}`,
        });
        continue;
      }

      // Determine which connection type to use
      const connectionType = this.resolveConnectionType(entry);
      if (!connectionType) {
        result.skipped.push({ id: entry.id, reason: 'No matching connection type for strategy' });
        continue;
      }

      // Build the ServerConnection
      const loaded = connectionType === 'mcp'
        ? this.buildMCPConnection(entry)
        : this.buildRESTConnection(entry);

      if (loaded) {
        result.loaded.push(loaded);
      } else {
        result.skipped.push({ id: entry.id, reason: 'Missing credentials' });
      }
    }

    return result;
  }

  /**
   * Convenience: return just the ServerConnection[] for FederationManager.
   */
  loadConnections(): ServerConnection[] {
    return this.load().loaded.map(l => l.connection);
  }

  /**
   * CHARIOT::§7.5::1 — "instantiate each catalog-listed adapter, wire it
   * into the pool, register its tools with ToolPreFilter." Runs `load()`
   * to build the ServerConnection[] as before, then (when `federation`
   * is configured) actually connects each one — which is what builds the
   * live adapter instance and registers its tools in the unified
   * ToolRegistry — and (when `toolPreFilter` is also configured) re-indexes
   * it from the federation's now-current tool list. With neither wired,
   * behaves exactly like `load()` (no side effects), preserving pre-1.4.0
   * callers.
   */
  async loadAndWire(): Promise<RegistryLoadResult> {
    const result = this.load();
    const wired = new Set<string>();

    if (this.options.federation) {
      // CHARIOT::§7.5::1 — do not double-connect a server name the caller
      // already connected (e.g. `EpicAI.start()` runs `connectAll()`
      // against `FederationConfig.servers` before calling this). Those
      // names are already live in `adapterMap`/the tool registry;
      // reconnecting them here would be redundant at best and, for a
      // stateful transport, could tear down and race a live connection.
      const alreadyConnected = new Set(this.options.federation.listConnectedServerNames?.() ?? []);
      for (const loaded of result.loaded) {
        if (alreadyConnected.has(loaded.connection.name)) {
          wired.add(loaded.connection.name);
          continue;
        }
        await this.options.federation.connect(loaded.connection.name, loaded.connection);
        wired.add(loaded.connection.name);
      }
      if (this.options.toolPreFilter) {
        this.options.toolPreFilter.index(this.options.federation.listTools());
      }
    }

    this.lastWired = wired;
    return result;
  }

  /**
   * CHARIOT::§7.5::1 — "expose reload() for runtime adapter unload."
   * Re-reads the registry (and re-applies the catalog revocation gate)
   * and reconciles the live federation against the new result: adapters
   * present in the previous wire but absent from (or newly filtered/
   * revoked out of) this one are unloaded; adapters newly present are
   * connected. The ToolPreFilter is re-indexed once at the end so a
   * caller sees a single consistent shortlist update rather than one
   * per adapter change.
   *
   * Requires `federation` to have been configured — reload() is
   * meaningless against data-only `load()` output, since there is no
   * live adapter set to reconcile against.
   */
  async reload(): Promise<RegistryLoadResult> {
    if (!this.options.federation) {
      throw new Error(
        'RegistryLoader.reload() requires a `federation` target (RegistryLoaderOptions.federation); ' +
        'without one there is no live adapter set to reconcile against.',
      );
    }
    const federation = this.options.federation;

    const result = this.load();
    const next = new Set(result.loaded.map((l) => l.connection.name));
    const previous = this.lastWired;

    // Unload adapters no longer present in the reconciled result — covers
    // both "removed from the registry" and "newly revoked/filtered out",
    // since both cases mean the entry no longer appears in result.loaded.
    for (const name of previous) {
      if (!next.has(name)) {
        await federation.unloadAdapter(name, 'registry reload: adapter no longer present');
      }
    }

    // Connect adapters newly present.
    for (const loaded of result.loaded) {
      if (!previous.has(loaded.connection.name)) {
        await federation.connect(loaded.connection.name, loaded.connection);
      }
    }

    if (this.options.toolPreFilter) {
      this.options.toolPreFilter.index(federation.listTools());
    }

    this.lastWired = next;
    return result;
  }

  private resolveConnectionType(entry: RegistryEntry): 'mcp' | 'rest' | null {
    switch (this.options.strategy) {
      case 'mcp-only':
        return entry.mcp ? 'mcp' : null;
      case 'rest-only':
        return entry.rest ? 'rest' : null;
      case 'mcp-preferred':
        if (entry.mcp && !entry.mcp.requiresOAuth) return 'mcp';
        if (entry.rest) return 'rest';
        if (entry.mcp) return 'mcp'; // OAuth MCP as last resort
        return null;
      case 'all':
        // Prefer MCP for 'both' type
        if (entry.mcp && !entry.mcp.requiresOAuth) return 'mcp';
        if (entry.rest) return 'rest';
        return entry.mcp ? 'mcp' : null;
      default:
        return null;
    }
  }

  private buildMCPConnection(entry: RegistryEntry): LoadedAdapter | null {
    const mcp = entry.mcp;
    if (!mcp) return null;

    if (mcp.transport === 'stdio') {
      // Air-gap FAIL-CLOSED at load time: only stdio launchers that carry a
      // supply-chain integrity gate in MCPClientAdapter.connect() ('npx') may
      // be built. `mcp.command` is a free-form catalog string; a non-npx
      // launcher (uvx/docker/sh/…) has no runtime hash/offline gate and would
      // fetch+execute unpinned code, so surface it as a load failure here
      // rather than letting it fail open at first connect.
      if (mcp.command !== undefined && mcp.command !== 'npx') {
        log.warn(
          `adapter "${entry.id}": stdio launcher "${mcp.command}" has no supply-chain integrity gate; ` +
          `only npx is supported — skipping (fail-closed).`,
        );
        return null;
      }

      // Resolve env vars for stdio MCP. review V4: 1696/1777
      // entries in the published bundle today ship without `mcp.envKeys`
      // (publisher gap). Without the CANONICAL_CREDENTIALED_BRANDS
      // fallback the for-loop iterates 0 times, missingKeys=[], the
      // skipMissingCredentials bail never fires, and a credentialed
      // adapter (github/slack/stripe/…) silently builds a ServerConnection
      // with env={} — split-brain with ChariotState.getConfiguredAdapterIds
      // which correctly excludes it. Routing through effectiveEnvKeys
      // (which consults the fallback table) closes the split.
      const env: Record<string, string> = {};
      const missingKeys: string[] = [];
      const requiredKeys = effectiveEnvKeys(entry);

      for (const key of requiredKeys) {
        // Never resolve/forward a first-party engine-internal secret into an
        // adapter subprocess, even if a catalog row names it in envKeys
        // (resolveCredential reads process.env, so the load-time state.credentials
        // strip does not cover this federation path).
        if (isEngineInternalCredentialKey(key)) continue;
        const value = this.options.resolveCredential(key);
        if (value) {
          env[key] = value;
        } else {
          missingKeys.push(key);
        }
      }

      // If any required env vars are missing and we're skipping, bail
      if (missingKeys.length > 0 && this.options.skipMissingCredentials) {
        return null;
      }

      const connection: ServerConnection = {
        name: entry.id,
        transport: 'stdio',
        command: mcp.command,
        args: mcp.args,
      };

      // Store env vars in the connection for MCPClientAdapter to use.
      connection.env = env;

      // Propagate supply-chain integrity fields so MCPClientAdapter can
      // verify the npm tarball hash before spawning the subprocess.
      // Only populate when all three fields are present and the command is npx.
      if (mcp.command === 'npx' && mcp.integrityShasum && mcp.version) {
        const pkg = mcp.packageName ?? mcp.args?.find((a) => typeof a === 'string' && a.length > 0 && !a.startsWith('-'));
        if (pkg) {
          connection.integrityPkg = pkg;
          connection.integrityVersion = mcp.version;
          connection.integrityShasum = mcp.integrityShasum;
        }
      }

      return { connection, connectionType: 'mcp', entry };
    }

    if (mcp.transport === 'streamable-http' && mcp.url) {
      const connection: ServerConnection = {
        name: entry.id,
        transport: 'streamable-http',
        url: applyCuratedHostOverride(mcp.url),
      };

      // If not OAuth, try to resolve a Bearer token from env
      if (!mcp.requiresOAuth) {
        const baseKey = deriveEnvKey(entry.id);
        if (!baseKey) {
          log.warn(`adapter "${entry.id}": id cannot be sanitised to a valid env-var name; credential unresolvable — skipping`);
          return null;
        }
        const tokenKey = baseKey + '_TOKEN';
        const token = this.options.resolveCredential(tokenKey);
        if (token) {
          connection.auth = { type: 'bearer', token };
        } else {
          log.warn(`adapter "${entry.id}": credential ${tokenKey} not found in environment; adapter skipped`);
          if (this.options.skipMissingCredentials) {
            return null;
          }
        }
      }

      return { connection, connectionType: 'mcp', entry };
    }

    return null;
  }

  private buildRESTConnection(entry: RegistryEntry): LoadedAdapter | null {
    const rest = entry.rest;
    if (!rest) return null;

    // Resolve the primary credential
    const credential = this.options.resolveCredential(rest.envKey);
    if (!credential && this.options.skipMissingCredentials) {
      return null;
    }

    // REST adapters are loaded differently — they're instantiated as classes,
    // not connected via MCP protocol. The ServerConnection here is a shim
    // that tells the FederationManager to load the REST adapter module.
    const auth: AuthConfig = { type: 'bearer', token: credential || '' };

    const connection: ServerConnection = {
      name: entry.id,
      transport: 'stdio', // REST adapters are in-process, not network
      command: '__rest_adapter__', // Sentinel value for FederationManager
      args: [rest.module, rest.className, rest.envKey],
    };

    // Attach auth for credential propagation
    connection.auth = auth;

    return { connection, connectionType: 'rest', entry };
  }
}

/**
 * Derive an environment-variable name from an adapter id.
 * Converts to UPPER_SNAKE_CASE and replaces ALL non-alphanumeric characters
 * (dots, slashes, hyphens, etc.) with underscores so the result is a valid
 * POSIX env-var name. Returns undefined if the sanitised name would be
 * empty or start with a digit (both are invalid env-var names).
 */
function deriveEnvKey(adapterId: string): string | undefined {
  const sanitised = adapterId.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  if (sanitised.length === 0 || /^[0-9]/.test(sanitised)) return undefined;
  return sanitised;
}

// Test-only export — NOT part of the public API.
// Allows the adversarial eval (src/engine/audit/derive-env-key-verify-anchor.test.ts)
// to verify that adapter IDs containing dots, slashes, or hyphens are sanitised
// to valid POSIX env-var names without needing a signed registry fixture.
export { deriveEnvKey as __testOnly_deriveEnvKey };
