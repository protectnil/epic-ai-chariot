/**
 * @epicai/chariot — Progressive-auth runtime overlay: CUSTOMER-CREDENTIAL
 * CONNECT half (CHARIOT-SPEC §8.6a). RETRIEVAL half (embedding, EdgeShard
 * upsert, overlayStateHash derivation) is owned by
 * `src/engine/retrieval/overlay/OverlayEmbedder.ts` (sibling build) and is
 * consumed here only through the `OverlayEmbedder` interface below.
 *
 * Governing bytes — CHARIOT-SPEC.md:767 (§8.6a), quoted in full:
 *
 * "A `requiresCustomerAuth: true` adapter ships tool-less or with
 * `declared-registry` (search-only) tools. The overlay applies to BOTH the
 * streamable-HTTP/SSE and the `stdio` transports. On the first
 * authenticated connect the runtime obtains the live tool list with the
 * customer credential, transport-specifically: for a streamable-HTTP/SSE
 * adapter it connects to the endpoint carrying the customer credential and
 * issues `tools/list`; for a `stdio` adapter it spawns the local stdio MCP
 * server process with the customer credential supplied in that process's
 * environment (the same local-spawn path AS §3.1 G9 uses at publish for
 * non-auth stdio rows), completes the JSON-RPC `initialize` handshake, then
 * issues `tools/list`. In both cases the customer credential, the spawned
 * process (stdio), the returned tools, and the derived vectors NEVER leave
 * the host."
 *
 * The SDK's `Client.connect(transport)` performs the JSON-RPC `initialize`
 * handshake internally before returning (identical to every other call
 * site in this repo — `setup.ts`'s `defaultConnectionDispatcher` and
 * `cmdQuery`, `toolHandlers.ts` Cases 2/4) — so `connect()` then
 * `listTools()` below satisfies "completes the ... `initialize` handshake,
 * then issues `tools/list`" without hand-rolling JSON-RPC.
 *
 * Only `streamable-http` and `stdio` are handled below (any other
 * `adapter.mcp.transport` value returns the typed `{ok:false, reason:'no
 * MCP transport available for the customer-verified connect'}`). §8.6a's
 * own wording names "streamable-HTTP/SSE", but SSE never reaches this
 * code path: AS §1.3 (ADAPTER-STANDARD-MAY-2026.md:244) — "The publisher
 * MUST refuse ANY record declaring `mcp.transport: "sse"` at the intake
 * publication gate ... regardless of any URL or live-verification
 * evidence. An SSE record never enters, and never remains in, the
 * production adapter catalog." — and ADAPTER-STANDARD-MAY-2026.md:245 — "Existing
 * SSE rows are REJECTED (persisted) ... An active `mcp.transport: "sse"`
 * record is moved to `state:"rejected"` (`active:false`)". So no adapter
 * this connector is ever called with can carry `transport:'sse'`; §8.6a's
 * "streamable-HTTP/SSE" phrase resolves, at runtime, to `streamable-http`
 * alone.
 *
 * Two-phase parity (AS §3.2 G10, ADAPTER-STANDARD-MAY-2026.md:518):
 * "Live `tools/list == toolNames` parity is enforced client-side at
 * runtime, upgrading provenance to `customer-verified`. ... runtime
 * mismatch corrects the overlay."
 *
 * Credential vault (CHARIOT-SPEC §10.5, `src/iam/services/credentials.ts`
 * doc comment, CHARIOT-SPEC.md:1063): "Token refresh: background job every
 * 5 minutes finds tokens within 10 minutes of expiry, refreshes via vendor
 * refresh endpoint, updates `lastRefreshedAt`. On refresh failure (vendor
 * revoked the token), marks `status: 'expired'` and emits an alert." This
 * module is a SECOND, independent consumer of that same vault row and
 * MUST NOT dispatch on a `status !== 'active'` row nor on one whose
 * `expiresAt` has already passed (defense in depth — the refresh job
 * flips `status` on its own 5-minute cadence, so a row can be objectively
 * expired for up to that long before the flip lands).
 *
 * Auth hardening (AGENTS.md, "Auth/session/logout/verification changes
 * MUST address token revocation, refresh handling, one-time enforcement,
 * and brute-force protection"):
 *   - revocation/expiry: see above — a revoked or expired row is refused,
 *     never dispatched.
 *   - refresh handling: this module never refreshes; it reads whatever
 *     row `src/iam/services/credentials.ts`'s job most recently wrote and
 *     treats `lastRefreshedAt` (or `connectedAt` before any refresh) as
 *     the credential's version marker.
 *   - one-time enforcement: "the first-connect embed runs once per
 *     (tenant, adapter, credential version) — idempotent, no re-embed
 *     storm" — `CustomerAuthOverlayConnector` coalesces concurrent
 *     connects for the same `(tenantId, adapterId)` into one in-flight
 *     promise and skips re-embedding once a version has completed.
 *   - brute-force protection: every connect attempt (success or failure)
 *     consumes a token from a per-`(tenantId, adapterId)` `RateLimiter`
 *     bucket; a failed live connect additionally `penalize()`s that
 *     bucket so a failing customer credential cannot retry in a tight
 *     loop.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createRequire } from 'node:module';
import { getCollection } from '../../iam/db.js';
import { decryptFields } from '../../iam/crypto.js';
import * as audit from '../../iam/services/audit.js';
import { chariotEmitter } from '../../observability/emitter.js';
import { createLogger } from '../logger.js';
import type { RateLimiter } from '../resilience/RateLimiter.js';
import { confineStdioCommand } from '../keys/pathConfinement.js';
import { enforceNpxStdioGate, stripDangerousStdioEnv } from './adapters/npmIntegrityGuard.js';
import { createMcpDispatchFetch } from './mcpDispatchFetch.js';
import type { AdapterEntry } from '../server/ChariotState.js';
import type { AdapterCredentialDocument } from '../../iam/types.js';
/**
 * The connector needs only the write side of `TenantOverlayToolRegistry` —
 * a minimal interface (rather than the concrete class) so tests can supply
 * a plain in-memory fake without TypeScript's private-member nominal
 * check on the real class rejecting it. `TenantOverlayToolRegistry`
 * satisfies this structurally with no wrapper needed.
 */
export interface OverlayToolRegistryWriter {
  recordTools(tenantId: string, adapterId: string, tools: readonly CustomerVerifiedTool[]): Promise<void>;
}

const log = createLogger('federation.customer-auth-overlay');

const _require = createRequire(import.meta.url);
// Same pattern as toolHandlers.ts:164 / setup.ts — this file lives at the
// same nesting depth (src/engine/federation/) as toolHandlers.ts
// (src/engine/server/), so the same '../../../package.json' relative path
// resolves to the repo root.
const PKG_VERSION: string = (_require('../../../package.json') as { version: string }).version;

// ─── Sibling interface (build-133, RETRIEVAL half) ─────────────────────────
//
// `src/engine/retrieval/overlay/OverlayEmbedder.ts` was NOT present on disk
// when this file was first drafted; it landed on disk before this build
// finished, so the real interfaces are imported directly (no local
// restatement, no drift risk). Note the real `CustomerVerifiedTool.description`
// is a REQUIRED `string` (not optional) — `normalizeTools()` below defaults
// a missing/non-string description to `''` to satisfy that contract exactly.
export type {
  CustomerVerifiedTool,
  OverlayEmbedResult,
  OverlayEmbedder,
} from '../retrieval/overlay/OverlayEmbedder.js';
import type {
  CustomerVerifiedTool,
  OverlayEmbedder,
} from '../retrieval/overlay/OverlayEmbedder.js';

// ─── Vault read accessor ────────────────────────────────────────────────────

/**
 * Single-row read of the §10.5 credential vault for a (tenant, adapter)
 * pair. Mirrors `loadIamCredentialsForTenant`'s shared-vs-per-user
 * selection (`src/iam/credential-loader.ts:113-115`) without loading every
 * credential the tenant holds — this call site only ever needs the ONE
 * row for the adapter that just had its first authenticated connect
 * triggered.
 */
export async function fetchActiveOverlayCredential(
  tenantId: string,
  adapterId: string,
  userId?: string,
): Promise<AdapterCredentialDocument | null> {
  const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
  const filter: Record<string, unknown> = userId
    ? { tenantId, adapterId, $or: [{ shared: true }, { connectedBy: userId }] }
    : { tenantId, adapterId, shared: true };
  return col.findOne(filter);
}

// ─── Types ──────────────────────────────────────────────────────────────────

export type OverlayConnectStatus =
  | 'embedded'
  | 'already-embedded'
  | 'not-applicable'
  | 'rate-limited'
  | 'no-credential'
  | 'credential-revoked'
  | 'credential-expired'
  | 'connect-failed';

export interface OverlayConnectResult {
  status: OverlayConnectStatus;
  tenantId: string;
  adapterId: string;
  toolCount?: number;
  /** AS §3.2 G10 two-phase parity outcome, present only on a completed connect. */
  parity?: 'match' | 'mismatch';
  overlayStateHash?: string;
  reason?: string;
}

export interface CustomerAuthOverlayDeps {
  embedder: OverlayEmbedder;
  rateLimiter: RateLimiter;
  /** Durable, tenant-scoped record of which customer-verified tools an
   * adapter exposes — written on every successful embed (see `doConnect`).
   * `toolHandlers.ts`'s dispatch-time validation and `chariot_query`'s
   * tool listing both read the SAME instance a caller wires here. */
  registry: OverlayToolRegistryWriter;
  /** Test seam. Defaults to `fetchActiveOverlayCredential`. */
  fetchCredential?: (
    tenantId: string,
    adapterId: string,
    userId?: string,
  ) => Promise<AdapterCredentialDocument | null>;
  /** Test seam. Defaults to `decryptFields` from the §12.2 vault. */
  decrypt?: (
    encrypted: string,
    iv: string,
    tenantId: string,
    adapterId: string,
  ) => Promise<{ fields: Record<string, string> }>;
  /** Test seam. Defaults to a live MCP connect via the SDK. */
  connectAndListTools?: (
    adapter: AdapterEntry,
    credential: { apiKey?: string; apiSecret?: string },
  ) => Promise<{ ok: true; tools: CustomerVerifiedTool[] } | { ok: false; reason: string }>;
  now?: () => Date;
  /** Test seam. Defaults to `audit.log` (writes the §9 hash-chained tenant audit log). */
  auditLog?: typeof audit.log;
}

interface CompletedConnect {
  credentialVersion: string;
  toolCount: number;
  parity: 'match' | 'mismatch';
  overlayStateHash: string;
}

// ─── Live connect (reuses cmdQuery's / defaultConnectionDispatcher's connect primitives) ──

/**
 * §8.6a: "spawns the local stdio MCP server process with the customer
 * credential supplied in that process's environment" — env ONLY, never
 * argv, never logged. Placed under the adapter's own declared env-key
 * surface (`mcp.authEnvKey` / `mcp.envKeys`), the SAME surface
 * `credential-loader.ts` maps `apiKey`/`apiSecret` onto for ordinary
 * dispatch (credential-loader.ts:49-72), so a stdio server that reads its
 * credential from `process.env` sees it exactly where it always does —
 * the vendor-facing contract is unchanged, only the source (vault row vs.
 * `.env`) differs. Extracted as a pure function (no spawn, no I/O) so the
 * credential-placement invariant is directly unit-testable without a real
 * subprocess.
 */
export function buildStdioCredentialEnv(
  adapter: AdapterEntry,
  credential: { apiKey?: string; apiSecret?: string },
  baseEnv: Record<string, string>,
  offline: boolean,
): Record<string, string> {
  const env: Record<string, string> = { ...baseEnv };
  const primary = adapter.mcp?.authEnvKey ?? adapter.mcp?.envKeys?.[0];
  const secondary =
    adapter.mcp?.envKeys?.[1] ??
    (primary && primary.endsWith('_KEY') ? primary.replace(/_KEY$/, '_SECRET') : primary ? `${primary}_SECRET` : undefined);
  if (primary && typeof credential.apiKey === 'string' && credential.apiKey.length > 0) {
    env[primary] = credential.apiKey;
  }
  if (secondary && typeof credential.apiSecret === 'string' && credential.apiSecret.length > 0) {
    env[secondary] = credential.apiSecret;
  }
  stripDangerousStdioEnv(env);
  if (offline) {
    env.npm_config_offline = 'true';
    env.npm_config_ignore_scripts = 'true';
  }
  return env;
}

/**
 * Rulings item 106(b): "verifyAdapterConnection with an injectable
 * dispatcher reusing cmdQuery's connect primitives and calling only
 * tools/list." Same primitives, same restriction to `tools/list` only —
 * SDK `Client` + `StreamableHTTPClientTransport`/`StdioClientTransport`,
 * `confineStdioCommand`, `enforceNpxStdioGate`/`stripDangerousStdioEnv` —
 * as `setup.ts`'s `defaultConnectionDispatcher` (setup.ts:2477-2523) and
 * `toolHandlers.ts`'s Case 4 streamable-http dispatch
 * (toolHandlers.ts:2840-2890), reproduced here because neither is
 * exported and this connect additionally needs the FULL tool list (name +
 * description + inputSchema), not just a count.
 */
export async function defaultConnectAndListTools(
  adapter: AdapterEntry,
  credential: { apiKey?: string; apiSecret?: string },
): Promise<{ ok: true; tools: CustomerVerifiedTool[] } | { ok: false; reason: string }> {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');

  if (adapter.mcp?.transport === 'streamable-http' && adapter.mcp?.url) {
    const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
    const reqHeaders: Record<string, string> = {};
    // Same header-construction logic as toolHandlers.ts:2849-2857, driven
    // by the customer credential decrypted from the §10.5 vault row
    // instead of state.credentials.
    const credValue = credential.apiKey;
    if (typeof credValue === 'string' && credValue.length > 0) {
      const scheme = adapter.mcp.authScheme ?? 'bearer';
      if (scheme === 'bearer' || scheme === 'oauth2') {
        // §10.5's vendor OAuth refresh job (credentials.ts:313, `apiKey:
        // vendorResponse.access_token`) stores the OAuth access token in
        // the SAME `fields.apiKey` slot a plain api-key credential uses —
        // there is no separate OAuth field on the decrypted vault row. A
        // `requiresCustomerAuth: true` adapter with `authScheme: 'oauth2'`
        // is exactly the customer-brings-auth case §8.6a exists for, so it
        // gets the SAME `Authorization: Bearer <token>` header a plain
        // bearer credential gets. toolHandlers.ts's ordinary dispatch path
        // sends 'oauth2' with no header today, pending its own
        // OAuthClientProvider wiring — that omission is a fact about a
        // DIFFERENT call site, not a contract this overlay-connect path
        // mirrors: the vault already holds a usable bearer token
        // (`fields.apiKey`) by the time an overlay connect is triggered,
        // so there is no reason to withhold it here.
        reqHeaders['Authorization'] = `Bearer ${credValue}`;
      } else if (scheme === 'basic') {
        reqHeaders['Authorization'] = `Basic ${Buffer.from(credValue, 'utf-8').toString('base64')}`;
      } else if (scheme === 'apikey-header') {
        const headerName = adapter.mcp.authHeaderName;
        if (!headerName) {
          return { ok: false, reason: `adapter ${adapter.id} declares authScheme 'apikey-header' but no authHeaderName` };
        }
        reqHeaders[headerName] = credValue;
      }
    }
    const transport = new StreamableHTTPClientTransport(new URL(adapter.mcp.url), {
      fetch: createMcpDispatchFetch(),
      ...(Object.keys(reqHeaders).length > 0 ? { requestInit: { headers: reqHeaders } } : {}),
    });
    const client = new Client({ name: 'chariot', version: PKG_VERSION }, { capabilities: {} });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      return { ok: true, tools: normalizeTools(listed.tools) };
    } catch (err) {
      return { ok: false, reason: redactCredentialFromReason(err instanceof Error ? err.message : String(err), [credential.apiKey, credential.apiSecret]) };
    } finally {
      try { await client.close(); } catch { /* best-effort close */ }
    }
  }

  if (adapter.mcp?.transport === 'stdio' && adapter.mcp?.command) {
    const confinedCmd = confineStdioCommand(adapter.mcp.command, PACKAGE_ROOT_FOR_STDIO());
    if (!confinedCmd.ok) {
      return { ok: false, reason: `stdio command rejected (${confinedCmd.reason})` };
    }
    const gate = enforceNpxStdioGate(adapter);
    if (!gate.ok) {
      return { ok: false, reason: gate.reason ?? 'npx supply-chain gate rejected the adapter' };
    }
    const { StdioClientTransport, getDefaultEnvironment } = await import('@modelcontextprotocol/sdk/client/stdio.js');
    const env = buildStdioCredentialEnv(adapter, credential, getDefaultEnvironment(), gate.offline);
    const transport = new StdioClientTransport({ command: confinedCmd.command, args: gate.spawnArgs, env });
    const client = new Client({ name: 'chariot', version: PKG_VERSION }, { capabilities: {} });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      return { ok: true, tools: normalizeTools(listed.tools) };
    } catch (err) {
      return { ok: false, reason: redactCredentialFromReason(err instanceof Error ? err.message : String(err), [credential.apiKey, credential.apiSecret]) };
    } finally {
      try { await client.close(); } catch { /* best-effort close */ }
    }
  }

  return { ok: false, reason: 'no MCP transport available for the customer-verified connect' };
}

function PACKAGE_ROOT_FOR_STDIO(): string {
  // Mirrors setup.ts's getPackageRoot() (relative to dist/, three levels
  // up to the package root) without importing that internal helper.
  return new URL('../../../', import.meta.url).pathname;
}

/**
 * A live-connect failure's `reason` string is built from an SDK/transport
 * error message (`err.message`) that MAY echo the request it was trying to
 * send — including, for the streamable-HTTP branch, an `Authorization`
 * header built directly from the decrypted credential. That `reason` flows
 * into `log.warn`, `OverlayConnectResult.reason`, and from there into
 * whatever error envelope the dispatch call site builds — so it MUST be
 * scrubbed of the credential's plaintext AND its Basic-auth base64 form
 * before it is logged or returned. Redacts every non-empty value in
 * `secrets` (and, for values used as a Basic-auth pair, either value's
 * base64 form) wherever it appears in `text`.
 */
function redactCredentialFromReason(text: string, secrets: Array<string | undefined>): string {
  let out = text;
  const candidates = new Set<string>();
  for (const s of secrets) {
    if (typeof s === 'string' && s.length > 0) {
      candidates.add(s);
      candidates.add(Buffer.from(s, 'utf-8').toString('base64'));
    }
  }
  for (const c of candidates) {
    out = out.split(c).join('[redacted]');
  }
  return out;
}

function normalizeTools(tools: unknown): CustomerVerifiedTool[] {
  if (!Array.isArray(tools)) return [];
  const out: CustomerVerifiedTool[] = [];
  for (const t of tools) {
    if (t && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string') {
      const tt = t as { name: string; description?: unknown; inputSchema?: unknown };
      out.push({
        name: tt.name,
        description: typeof tt.description === 'string' ? tt.description : '',
        inputSchema: tt.inputSchema,
      });
    }
  }
  return out;
}

// ─── Connector ──────────────────────────────────────────────────────────────

/**
 * Owns the first-authenticated-connect trigger for `requiresCustomerAuth:
 * true` adapters. One instance is expected per running Chariot process
 * (wired alongside `FederationManager`); its in-memory maps scope
 * idempotency and in-flight coalescing to THIS process, which matches
 * every other in-process resilience primitive in `src/engine/resilience/`
 * (RateLimiter, PromptCache) — there is no cross-replica store today.
 */
export class CustomerAuthOverlayConnector {
  private readonly completed = new Map<string, CompletedConnect>();
  private readonly inflight = new Map<string, Promise<OverlayConnectResult>>();

  constructor(private readonly deps: CustomerAuthOverlayDeps) {}

  private rlKey(tenantId: string, adapterId: string): string {
    return `customer-auth-overlay:${tenantId}:${adapterId}`;
  }

  private stateKey(tenantId: string, adapterId: string): string {
    return `${tenantId}::${adapterId}`;
  }

  private async deny(
    tenantId: string,
    adapterId: string,
    reason: string,
  ): Promise<void> {
    log.warn('customer_auth_overlay_connect_denied', { tenantId, adapterId, reason });
    try {
      const auditLog = this.deps.auditLog ?? audit.log;
      await auditLog(tenantId, 'adapter_query_denied', {
        actorId: 'system:customer-auth-overlay',
        targetType: 'adapter',
        targetId: adapterId,
        detail: { reason },
      });
    } catch (err) {
      log.error('customer_auth_overlay_connect_denied audit write failed', {
        tenantId,
        adapterId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * CHARIOT-SPEC §8.6a. Called on the FIRST authenticated connect of a
   * `requiresCustomerAuth: true` adapter for a tenant. `not-applicable`
   * for any adapter that does not carry `requiresCustomerAuth: true`
   * (AS §1.2a — absent/false means the adapter's tools are already public
   * and this overlay step does not apply).
   *
   * Rate-limiter placement: `allow()` is consumed ONLY once a decrypt+live-
   * connect attempt is about to happen — NOT for the vault lookup, the
   * revoked/expired refusals, or the `already-embedded` fast path. Once
   * wired at the dispatch entry (toolHandlers.ts), EVERY dispatch to an
   * already-embedded adapter calls `connect()`; consuming a token before
   * the `already-embedded` check would mean a busy tenant's own ordinary
   * traffic drains the bucket and starts failing dispatch closed with
   * `rate-limited` — a self-inflicted denial of service, not a brute-force
   * guard. The bucket exists to bound repeated CREDENTIAL GUESSES (a
   * decrypt or a live connect actually being attempted), not cheap,
   * side-effect-free reads.
   */
  async connect(
    adapter: AdapterEntry,
    tenantId: string,
    opts: { userId?: string } = {},
  ): Promise<OverlayConnectResult> {
    if (adapter.requiresCustomerAuth !== true) {
      return { status: 'not-applicable', tenantId, adapterId: adapter.id };
    }

    const rlKey = this.rlKey(tenantId, adapter.id);

    const fetchCredential = this.deps.fetchCredential ?? fetchActiveOverlayCredential;
    const row = await fetchCredential(tenantId, adapter.id, opts.userId);
    if (!row) {
      await this.deny(tenantId, adapter.id, 'no_credential');
      return { status: 'no-credential', tenantId, adapterId: adapter.id };
    }
    if (row.status === 'revoked') {
      await this.deny(tenantId, adapter.id, 'credential_revoked');
      return { status: 'credential-revoked', tenantId, adapterId: adapter.id };
    }
    if (row.status === 'expired') {
      await this.deny(tenantId, adapter.id, 'credential_expired');
      return { status: 'credential-expired', tenantId, adapterId: adapter.id };
    }
    const now = (this.deps.now ?? (() => new Date()))();
    if (row.expiresAt && row.expiresAt.getTime() <= now.getTime()) {
      // Defense in depth: the §10.5 refresh job flips status:'expired' on
      // its own 5-minute cadence (REFRESH_JOB_INTERVAL_MS,
      // credentials.ts:79) — a row can be objectively past its
      // `expiresAt` for up to that long before the flip lands. Refuse
      // here rather than trust a status field that may not have caught
      // up yet.
      await this.deny(tenantId, adapter.id, 'credential_expired_past_expires_at');
      return { status: 'credential-expired', tenantId, adapterId: adapter.id };
    }

    const credentialVersion = (row.lastRefreshedAt ?? row.connectedAt).toISOString();
    const key = this.stateKey(tenantId, adapter.id);

    const existing = this.completed.get(key);
    if (existing && existing.credentialVersion === credentialVersion) {
      // §8.6a first-connect embed is one-time per (tenant, adapter,
      // credential version) — a subsequent connect against the SAME
      // credential is a no-op, never a re-embed storm.
      return {
        status: 'already-embedded',
        tenantId,
        adapterId: adapter.id,
        toolCount: existing.toolCount,
        parity: existing.parity,
        overlayStateHash: existing.overlayStateHash,
      };
    }

    const inflight = this.inflight.get(key);
    if (inflight) return inflight;

    // A decrypt+live-connect attempt is about to happen — consume the
    // brute-force bucket HERE, not before the cheap DB-only refusals or
    // the already-embedded fast path above (see this method's doc comment).
    if (!this.deps.rateLimiter.allow(rlKey)) {
      return { status: 'rate-limited', tenantId, adapterId: adapter.id, reason: 'brute-force guard: too many connect attempts' };
    }

    const promise = this.doConnect(adapter, tenantId, row, credentialVersion, rlKey, key);
    this.inflight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inflight.delete(key);
    }
  }

  private async doConnect(
    adapter: AdapterEntry,
    tenantId: string,
    row: AdapterCredentialDocument,
    credentialVersion: string,
    rlKey: string,
    stateKey: string,
  ): Promise<OverlayConnectResult> {
    const decrypt = this.deps.decrypt ?? decryptFields;
    let fields: Record<string, string>;
    try {
      const result = await decrypt(row.encrypted, row.iv, tenantId, adapter.id);
      fields = result.fields;
    } catch (err) {
      this.deps.rateLimiter.penalize(rlKey);
      await this.deny(tenantId, adapter.id, 'decrypt_failed');
      // Only the error CLASS is logged: a decrypt failure message can carry
      // ciphertext/iv fragments or key-derivation detail, none of which may
      // reach the log (same rule as the redacted connect-failure reasons).
      log.error('customer_auth_overlay decrypt failed', {
        tenantId,
        adapterId: adapter.id,
        error: err instanceof Error ? err.name : 'unknown_error',
      });
      return { status: 'connect-failed', tenantId, adapterId: adapter.id, reason: 'decrypt_failed' };
    }

    const connectAndListTools = this.deps.connectAndListTools ?? defaultConnectAndListTools;
    let outcome: Awaited<ReturnType<typeof connectAndListTools>>;
    try {
      outcome = await connectAndListTools(adapter, { apiKey: fields.apiKey, apiSecret: fields.apiSecret });
    } catch (err) {
      // A custom `connectAndListTools` (or a future transport branch) MAY
      // reject instead of resolving `{ok:false}` — `defaultConnectAndListTools`
      // itself never does (both its branches catch internally), but this
      // connector must not let an uncaught rejection here propagate out of
      // `connect()` as an unhandled throw, and must scrub the credential
      // out of whatever message the rejection carries before it is logged
      // or returned.
      const raw = err instanceof Error ? err.message : String(err);
      outcome = { ok: false, reason: redactCredentialFromReason(raw, [fields.apiKey, fields.apiSecret]) };
    }
    if (!outcome.ok) {
      // Defense in depth: redact again even on a normally-returned
      // `{ok:false, reason}` — `defaultConnectAndListTools` already
      // redacts its own SDK error messages, but a caller-supplied
      // `connectAndListTools` override is not guaranteed to.
      const safeReason = redactCredentialFromReason(outcome.reason, [fields.apiKey, fields.apiSecret]);
      this.deps.rateLimiter.penalize(rlKey);
      await this.deny(tenantId, adapter.id, 'connect_failed');
      log.warn('customer_auth_overlay live connect failed', {
        tenantId,
        adapterId: adapter.id,
        reason: safeReason,
      });
      return { status: 'connect-failed', tenantId, adapterId: adapter.id, reason: safeReason };
    }

    // AS §3.2 G10 two-phase parity: compare the LIVE tools/list against
    // the build-time toolNames sourced from toolProvenance.
    const declared = new Set(adapter.mcp?.toolNames ?? []);
    const live = new Set(outcome.tools.map((t) => t.name));
    const parity: 'match' | 'mismatch' =
      declared.size === live.size && [...declared].every((n) => live.has(n)) ? 'match' : 'mismatch';

    const embedResult = await this.deps.embedder.embedCustomerVerifiedTools(tenantId, adapter.id, outcome.tools);

    // §8.6a (team-lead review 2026-09-05): the vector embed alone does not
    // make a tool DISPATCHABLE (chariot_call) or QUERYABLE
    // (chariot_query's per-adapter tool array) — that durable, tenant-
    // scoped record is `TenantOverlayToolRegistry`. Written from the SAME
    // successful connect as the embed, so the two can never disagree
    // about which tools this adapter currently exposes for this tenant.
    // A registry write failure fails the WHOLE connect closed (not
    // penalized — this is an infra failure, not a credential guess) so a
    // half-embedded-but-unregistered state is never reported as success.
    try {
      await this.deps.registry.recordTools(tenantId, adapter.id, outcome.tools);
    } catch (err) {
      await this.deny(tenantId, adapter.id, 'registry_write_failed');
      log.error('customer_auth_overlay registry write failed', {
        tenantId,
        adapterId: adapter.id,
        error: err instanceof Error ? err.message : String(err),
      });
      return { status: 'connect-failed', tenantId, adapterId: adapter.id, reason: 'registry_write_failed' };
    }

    this.completed.set(stateKey, {
      credentialVersion,
      toolCount: outcome.tools.length,
      parity,
      overlayStateHash: embedResult.overlayStateHash,
    });

    // Federation event — counts + hash ONLY, never tool bodies or
    // credential material (reused `adapter.connected` type; the
    // customer-verified/parity distinction rides in `data`).
    chariotEmitter.send('adapter.connected', {
      severity: 'info',
      data: {
        tenantId,
        adapterId: adapter.id,
        customerVerified: true,
        toolCount: outcome.tools.length,
        parity,
        overlayStateHash: embedResult.overlayStateHash,
      },
      message: `Customer-verified overlay embed for ${adapter.id} (tenant ${tenantId}): ${outcome.tools.length} tool(s), parity=${parity}.`,
    });

    try {
      const auditLog = this.deps.auditLog ?? audit.log;
      await auditLog(tenantId, 'adapter_connected', {
        actorId: 'system:customer-auth-overlay',
        targetType: 'adapter',
        targetId: adapter.id,
        detail: {
          customerVerified: true,
          toolCount: outcome.tools.length,
          parity,
          overlayStateHash: embedResult.overlayStateHash,
        },
      });
    } catch (err) {
      log.error('customer_auth_overlay audit write failed', {
        tenantId,
        adapterId: adapter.id,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    if (parity === 'mismatch') {
      log.warn('customer_auth_overlay tool parity mismatch — overlay corrected to the live list', {
        tenantId,
        adapterId: adapter.id,
        declaredCount: declared.size,
        liveCount: live.size,
      });
    }

    return {
      status: 'embedded',
      tenantId,
      adapterId: adapter.id,
      toolCount: outcome.tools.length,
      parity,
      overlayStateHash: embedResult.overlayStateHash,
    };
  }
}
