/**
 * @epicai/chariot — CHARIOT-SPEC §8.6a: the per-tenant OVERLAY TOOL
 * REGISTRY. Third piece of §8.6a, per MASTER/team-lead review 2026-09-05:
 * "the customer-verified tools must be DISPATCHABLE and QUERYABLE for that
 * tenant after the embed." `CustomerAuthOverlay.ts`'s connector proves the
 * live tool list and hands it to the (retrieval-side) `OverlayEmbedder` for
 * VECTOR search — but a vector embed alone does not make a tool callable
 * (`chariot_call`) or listable (`chariot_query`'s per-adapter tool array);
 * this module is the durable, tenant-scoped source of record for THAT.
 *
 * Persistence: one JSON file per tenant, `<overlayRootDir>/<tenantId>/
 * tool-registry.json` — the SAME per-tenant directory
 * `NativeOverlayEmbedder` (`src/engine/retrieval/overlay/
 * OverlayEmbedder.ts:320-322`, `tenantShardDir`) uses for that tenant's
 * `EdgeShard`, so an operator inspecting `~/.epic-ai/overlay-shards/
 * <tenantId>/` finds both the vectors and the registry describing what
 * they resolve to. `DEFAULT_OVERLAY_ROOT` below is a byte-for-byte copy of
 * `OverlayEmbedder.ts:258-262`'s (unexported) helper — same env-var
 * precedence (`HOME` then `USERPROFILE` then `.`), same `.epic-ai/
 * overlay-shards` suffix — so both modules agree on the root without one
 * importing a private symbol from the other.
 *
 * Written atomically (temp file + `renameSync` into place, same directory
 * — POSIX rename is atomic within one filesystem) so a crash mid-write
 * can never leave a half-written, unparseable file where a fully-written
 * one used to be. A file that IS malformed (truncated by a non-atomic
 * writer, hand-edited, or from a future incompatible version) fails
 * CLOSED — `TenantOverlayRegistryCorruptError` — never a silently emptied
 * registry; a corrupt registry that resolved to "no overlay tools" would
 * be indistinguishable from a tenant that legitimately has none, silently
 * demoting every customer-verified tool back to non-dispatchable.
 *
 * Cross-tenant isolation is the load-bearing security property:
 * `resolveForTenant` parses the `overlay:<tenantId>:<adapterId>:<toolName>`
 * id (format owned by `overlayToolId()`,
 * `src/engine/retrieval/overlay/OverlayEmbedder.ts:188-192`) and refuses —
 * returns `undefined`, exactly like "no such tool" — whenever the parsed
 * tenantId does not equal the REQUESTING tenant's id. Tenant B must never
 * see or dispatch tenant A's overlay tools, even if it somehow obtained
 * tenant A's toolId string.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createLogger } from '../logger.js';
import type { CustomerVerifiedTool } from '../retrieval/overlay/OverlayEmbedder.js';
import { InvalidTenantIdError } from '../retrieval/overlay/OverlayEmbedder.js';

const log = createLogger('federation.tenant-overlay-tool-registry');

/** Byte-for-byte copy of OverlayEmbedder.ts:258-262's DEFAULT_OVERLAY_ROOT — see module doc comment above for why this is a copy, not an import. */
const DEFAULT_OVERLAY_ROOT = () => join(
  process.env.HOME ?? process.env.USERPROFILE ?? '.',
  '.epic-ai',
  'overlay-shards',
);

/**
 * R4 (team-lead review 2026-09-05): `tenantId` becomes a directory path
 * segment (`tenantDir()` below) and is caller-derived on the JWT path
 * (`context.tenantId`) — an unconfined value like `../x` would be a path
 * traversal out of `overlayRootDir`. `NativeOverlayEmbedder`
 * (src/engine/retrieval/overlay/OverlayEmbedder.ts:180-201) already
 * confines its own tenantId the same way for the SAME reason; that
 * module exports `InvalidTenantIdError` (imported and reused above, so
 * both modules throw the identical error type for the identical failure)
 * but keeps its `assertValidTenantId` function private, so this is a
 * byte-for-byte mirror of that function and its `TENANT_ID_PATTERN`, not
 * an import — the pattern and the extra '.'/'..'/'..'-substring checks
 * are copied verbatim from OverlayEmbedder.ts:180/191-201.
 */
const TENANT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function assertValidTenantId(tenantId: string): void {
  if (typeof tenantId !== 'string' || !TENANT_ID_PATTERN.test(tenantId)) {
    throw new InvalidTenantIdError(tenantId);
  }
  // Belt-and-suspenders: the pattern above already excludes '/' and '.'
  // sequences long enough to traverse, but '..' alone (two dots, no
  // separator) DOES match `[A-Za-z0-9._-]{1,128}` — explicitly reject it
  // and any segment that is exactly '.' or '..' after the fact.
  if (tenantId === '.' || tenantId === '..' || tenantId.includes('..')) {
    throw new InvalidTenantIdError(tenantId);
  }
}

const REGISTRY_FILE_NAME = 'tool-registry.json';
const REGISTRY_FORMAT_VERSION = 1;

export class TenantOverlayRegistryCorruptError extends Error {
  constructor(
    public readonly tenantId: string,
    public readonly filePath: string,
    reason: string,
  ) {
    super(`tenant overlay tool registry is corrupt for tenant "${tenantId}" (${filePath}): ${reason}`);
    this.name = 'TenantOverlayRegistryCorruptError';
  }
}

interface PersistedAdapterEntry {
  tools: CustomerVerifiedTool[];
  updatedAt: string;
}

interface PersistedRegistryFile {
  version: number;
  tenantId: string;
  adapters: Record<string, PersistedAdapterEntry>;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isCustomerVerifiedTool(v: unknown): v is CustomerVerifiedTool {
  return isPlainObject(v) && typeof v.name === 'string' && typeof v.description === 'string' && 'inputSchema' in v;
}

/**
 * Validate a parsed JSON value against the persisted shape. Throws
 * `TenantOverlayRegistryCorruptError` (never returns a partially-trusted
 * object) the moment ANY field disagrees with the contract — a registry
 * file is all-or-nothing evidence, exactly like the §5.6 sealed-bundle
 * manifest fail-closed precedent this codebase already follows elsewhere.
 */
function validateRegistryFile(parsed: unknown, tenantId: string, filePath: string): PersistedRegistryFile {
  const fail = (reason: string): never => { throw new TenantOverlayRegistryCorruptError(tenantId, filePath, reason); };
  if (!isPlainObject(parsed)) return fail('top-level JSON value is not an object');
  if (parsed.version !== REGISTRY_FORMAT_VERSION) return fail(`unsupported version ${JSON.stringify(parsed.version)}`);
  if (typeof parsed.tenantId !== 'string' || parsed.tenantId !== tenantId) {
    return fail(`tenantId field ${JSON.stringify(parsed.tenantId)} does not match the directory it was read from (${tenantId})`);
  }
  if (!isPlainObject(parsed.adapters)) return fail('adapters field is not an object');
  const adapters: Record<string, PersistedAdapterEntry> = {};
  for (const [adapterId, entry] of Object.entries(parsed.adapters)) {
    if (!isPlainObject(entry)) return fail(`adapters["${adapterId}"] is not an object`);
    if (!Array.isArray(entry.tools) || !entry.tools.every(isCustomerVerifiedTool)) {
      return fail(`adapters["${adapterId}"].tools is not an array of {name,description,inputSchema}`);
    }
    if (typeof entry.updatedAt !== 'string') return fail(`adapters["${adapterId}"].updatedAt is not a string`);
    adapters[adapterId] = { tools: entry.tools, updatedAt: entry.updatedAt };
  }
  return { version: REGISTRY_FORMAT_VERSION, tenantId, adapters };
}

export interface TenantOverlayToolRegistryOptions {
  /** Test/embedder seam. Defaults to the same root `NativeOverlayEmbedder` uses. */
  rootDir?: string;
}

/**
 * One instance is expected per running Chariot process — its in-memory
 * per-tenant cache is a read-through/write-through cache over the on-disk
 * files, NOT the source of truth (the files are); a fresh instance over
 * the SAME directory (a process restart) reconstructs identical state by
 * reading what is already on disk.
 */
/**
 * Read-only surface `toolHandlers.ts` consumes (dispatch-time validation,
 * `chariot_query` listing, and — once wired — `ToolPreFilter`'s `overlay:`
 * resolution). A minimal interface rather than the concrete class so a
 * synthetic test `ChariotState` can supply a plain in-memory fake without
 * TypeScript's private-member nominal check on the real class rejecting
 * it. `TenantOverlayToolRegistry` satisfies this structurally.
 */
export interface TenantOverlayToolRegistryReader {
  getTools(tenantId: string, adapterId: string): readonly CustomerVerifiedTool[];
  hasTool(tenantId: string, adapterId: string, toolName: string): boolean;
  getTool(tenantId: string, adapterId: string, toolName: string): CustomerVerifiedTool | undefined;
  resolveForTenant(toolId: string, requestingTenantId: string): CustomerVerifiedTool | undefined;
}

export class TenantOverlayToolRegistry implements TenantOverlayToolRegistryReader {
  private readonly rootDir: string;
  private readonly cache = new Map<string, PersistedRegistryFile>();
  /** Per-tenant write serialization — two concurrent `recordTools` calls
   * for the SAME tenant (different adapters embedding at once) must not
   * race a read-modify-write cycle against each other and drop one's
   * write. Chained promises, not a real lock (single-process only, same
   * scoping as every other in-process primitive in this codebase). */
  private readonly writeQueues = new Map<string, Promise<void>>();

  constructor(options: TenantOverlayToolRegistryOptions = {}) {
    this.rootDir = options.rootDir ?? DEFAULT_OVERLAY_ROOT();
  }

  private tenantDir(tenantId: string): string {
    // R4: the single funnel every path-building entry point (load() via
    // registryPath(), writeAtomic() directly) passes through — confining
    // here confines `getTools`/`hasTool`/`getTool`/`resolveForTenant`
    // (all read via `load()`) and `recordTools` (writes via
    // `writeAtomic()`) in one place, fail-closed, before `join()` ever
    // sees an unconfined value.
    assertValidTenantId(tenantId);
    return join(this.rootDir, tenantId);
  }

  private registryPath(tenantId: string): string {
    return join(this.tenantDir(tenantId), REGISTRY_FILE_NAME);
  }

  /**
   * Read-through load. A tenant directory/file that does not exist yet is
   * a legitimate empty registry (no `requiresCustomerAuth` adapter has
   * completed its first connect for this tenant) — NOT corruption. A file
   * that exists but fails validation IS corruption and throws.
   */
  private load(tenantId: string): PersistedRegistryFile {
    const cached = this.cache.get(tenantId);
    if (cached) return cached;

    const filePath = this.registryPath(tenantId);
    if (!existsSync(filePath)) {
      const empty: PersistedRegistryFile = { version: REGISTRY_FORMAT_VERSION, tenantId, adapters: {} };
      this.cache.set(tenantId, empty);
      return empty;
    }

    let raw: string;
    try {
      raw = readFileSync(filePath, 'utf-8');
    } catch (err) {
      throw new TenantOverlayRegistryCorruptError(tenantId, filePath, `read failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new TenantOverlayRegistryCorruptError(tenantId, filePath, `JSON parse failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    const validated = validateRegistryFile(parsed, tenantId, filePath);
    this.cache.set(tenantId, validated);
    return validated;
  }

  private writeAtomic(tenantId: string, file: PersistedRegistryFile): void {
    const dir = this.tenantDir(tenantId);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const finalPath = this.registryPath(tenantId);
    const tmpPath = join(dir, `.${REGISTRY_FILE_NAME}.tmp-${randomBytes(6).toString('hex')}`);
    writeFileSync(tmpPath, JSON.stringify(file, null, 2), { mode: 0o600 });
    try {
      renameSync(tmpPath, finalPath);
    } catch (err) {
      try { unlinkSync(tmpPath); } catch { /* best-effort cleanup */ }
      throw err;
    }
    this.cache.set(tenantId, file);
  }

  /**
   * Record (or replace) the customer-verified tool set for one
   * `(tenantId, adapterId)` pair. Called by `CustomerAuthOverlayConnector`
   * immediately after a successful `embedCustomerVerifiedTools` — the
   * registry entry and the vector embed are written from the SAME
   * successful connect, so they can never disagree about which tools a
   * `requiresCustomerAuth` adapter currently exposes for a tenant. An
   * empty `tools` array is a valid write (e.g. re-recording after a
   * parity-corrected connect that returned zero live tools) — it removes
   * the adapter's dispatchability/listability, it does not throw.
   */
  async recordTools(tenantId: string, adapterId: string, tools: readonly CustomerVerifiedTool[]): Promise<void> {
    const prior = this.writeQueues.get(tenantId) ?? Promise.resolve();
    const next = prior
      .catch(() => { /* a prior failed write must not block subsequent ones */ })
      .then(() => {
        const current = this.load(tenantId);
        const updated: PersistedRegistryFile = {
          version: REGISTRY_FORMAT_VERSION,
          tenantId,
          adapters: {
            ...current.adapters,
            [adapterId]: { tools: [...tools], updatedAt: new Date().toISOString() },
          },
        };
        this.writeAtomic(tenantId, updated);
        log.info('tenant_overlay_registry_recorded', { tenantId, adapterId, toolCount: tools.length });
      });
    this.writeQueues.set(tenantId, next);
    return next;
  }

  /** All overlay tools recorded for `(tenantId, adapterId)`, `[]` if none (legitimate empty, not corrupt). Throws on a corrupt file. */
  getTools(tenantId: string, adapterId: string): readonly CustomerVerifiedTool[] {
    return this.load(tenantId).adapters[adapterId]?.tools ?? [];
  }

  /** `true` iff `toolName` is a recorded overlay tool for `(tenantId, adapterId)`. */
  hasTool(tenantId: string, adapterId: string, toolName: string): boolean {
    return this.getTools(tenantId, adapterId).some((t) => t.name === toolName);
  }

  getTool(tenantId: string, adapterId: string, toolName: string): CustomerVerifiedTool | undefined {
    return this.getTools(tenantId, adapterId).find((t) => t.name === toolName);
  }

  /**
   * Parse an `overlay:<tenantId>:<adapterId>:<toolName>` id (the format
   * `overlayToolId()` produces, OverlayEmbedder.ts:191) without resolving
   * it — used by callers that need the parts before deciding whether to
   * trust them (see `resolveForTenant` below, the trusting counterpart).
   * Returns `undefined` for any non-`overlay:`-prefixed id or one with
   * fewer than 4 colon-delimited segments.
   */
  static parseOverlayToolId(toolId: string): { tenantId: string; adapterId: string; toolName: string } | undefined {
    const parts = toolId.split(':');
    if (parts.length < 4 || parts[0] !== 'overlay') return undefined;
    const [, tenantId, adapterId, ...rest] = parts;
    if (!tenantId || !adapterId || rest.length === 0) return undefined;
    return { tenantId, adapterId, toolName: rest.join(':') };
  }

  /**
   * The tenant-scoped resolution hook for `ToolPreFilter`'s `overlay:`
   * candidate ids (composite-shard results). SECURITY-CRITICAL: refuses
   * — returns `undefined`, indistinguishable from "no such tool" — unless
   * `parseOverlayToolId(toolId).tenantId === requestingTenantId`. A
   * caller MUST pass the REQUESTING tenant's own resolved id (the same
   * `tenantId`/`dispatchTenantId` `toolHandlers.ts` already threads),
   * never a value taken from the toolId itself or from user input.
   */
  resolveForTenant(toolId: string, requestingTenantId: string): CustomerVerifiedTool | undefined {
    const parsed = TenantOverlayToolRegistry.parseOverlayToolId(toolId);
    if (!parsed) return undefined;
    if (parsed.tenantId !== requestingTenantId) {
      log.warn('tenant_overlay_registry_cross_tenant_resolve_refused', {
        requestingTenantId,
        toolIdTenantId: parsed.tenantId,
        adapterId: parsed.adapterId,
      });
      return undefined;
    }
    return this.getTool(parsed.tenantId, parsed.adapterId, parsed.toolName);
  }
}
