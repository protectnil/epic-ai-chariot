#!/usr/bin/env node
/**
 * Epic AI® Chariot — CLI Entry Point
 * `chariot` / `npx @epicai/chariot`   — setup wizard
 * `chariot serve` / `--serve`        — MCP server mode
 * `chariot add <name>`               — add adapter and enter credentials
 * `chariot remove <name>`            — remove an adapter
 * `chariot health`                   — check adapter status
 * `chariot list`                     — show Curated + Custom adapters
 * `chariot search [term]`            — search all available adapters
 * `chariot configure`                — connect credentials and wire adapters
 * `chariot help`                     — show all commands
 *
 * Chariot is an Intelligent Virtual Assistant (IVA) — the AI classifies intent,
 * selects adapters, calls them, and synthesizes a response through your local
 * SLM or cloud LLM.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc.
 * Adapters: Elastic License 2.0 | SDK Framework: Elastic-2.0
 */

import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { loadAllAdapters, ChariotHealthEmitter, type AdapterEntry } from '../server/ChariotState.js';
import type { ResolvedMcpSession } from '../server/transports/http.js';
import {
  cmdHealthCheckAdapter,
  auditCanonicalCoverage,
  effectiveEnvKeys,
} from '../types/canonical-credentialed-brands.js';
import { getConfiguredAdapterIds } from '../federation/configuredAdapterIds.js';
import { confinePath } from '../keys/pathConfinement.js';
import { runPreInstall, readManifest } from './preinstall.js';
import {
  CREDENTIAL_VALUE_CONTROL_CHAR_RE,
  adapterTypeLabel,
  detectSystem,
  loadConfig,
  loadCredentials,
  loadCredentialsFrom,
  loadState,
  removeAdapterState,
  saveConfig,
  saveState,
  upsertAdapterState,
  withLastHealthCheck,
  writeCredential,
  writeMcpConfig,
  type AdapterState,
} from '../../cli/index.js';

const _require = createRequire(import.meta.url);
const PKG_VERSION: string = (_require('../../../package.json') as { version: string }).version;

// ─── Package root ───────────────────────────────────────────

function getPackageRoot(): string {
  // dist/engine/bin/setup.js → '..','..','..','..') → package root
  const thisFile = fileURLToPath(import.meta.url);
  return join(thisFile, '..', '..', '..', '..');
}

// Both this CLI and the gateway runtime share the bundle loader in
// ../server/ChariotState so a single signature gate covers both
// surfaces — `chariot query` does its own dynamic `import(modulePath)`
// on adapter.rest.module, same RCE shape as toolHandlers.ts.

// ─── Shared: build enriched tool descriptions for BM25 routing ──────────
// Defined before startMcpServer — also used by cmdQuery (anti-pattern 3.6 fix)

function buildToolsForRouting(adapters: AdapterEntry[]): Array<{
  name: string; description: string; parameters: Record<string, unknown>; server: string; tier: 'orchestrated' | 'direct';
}> {
  const tools: Array<{ name: string; description: string; parameters: Record<string, unknown>; server: string; tier: 'orchestrated' | 'direct' }> = [];
  for (const adapter of adapters) {
    // Anti-pattern 3.7 fix: access toolNames directly via typed field (no double cast)
    const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? [];
    const adapterDesc = adapter.description ?? adapter.id;
    // Enrich the routing-index text with category + keywords so the CLI
    // query path produces the same matches as the server path.
    const semanticContext = [adapter.category ?? '', ...(adapter.keywords ?? [])].filter(Boolean).join(' ');
    const suffix = semanticContext ? ` — ${semanticContext}` : '';
    if (toolNames.length === 0) {
      tools.push({ name: `${adapter.id}:default`, description: `${adapter.name} — ${adapterDesc}${suffix}`, parameters: { type: 'object', properties: {} }, server: adapter.id, tier: 'orchestrated' });
    } else {
      for (const t of toolNames) {
        tools.push({ name: `${adapter.id}:${t}`, description: `${adapter.name} — ${t.replace(/_/g, ' ')} — ${adapterDesc}${suffix}`, parameters: { type: 'object', properties: {} }, server: adapter.id, tier: 'orchestrated' });
      }
    }
  }
  return tools;
}

type ClackPrompts = typeof import('@clack/prompts');
interface SpinnerLike { start: (msg?: string) => void; stop: (msg?: string) => void; message: (msg?: string) => void }

// bug-tracker-ref: the @clack spinner redraws via raw ANSI cursor escapes. On a
// non-TTY stdout (a pipe, an agent capturing output, CI) those escapes flood the
// stream as literal `[1G[J` noise. Use the real animated spinner only on a TTY;
// otherwise return a plain shim that prints start/stop messages as ordinary lines.
function makeSpinner(p: ClackPrompts): SpinnerLike {
  if (process.stdout.isTTY) return p.spinner();
  return {
    start: (msg?: string) => { if (msg) console.log(msg); },
    stop: (msg?: string) => { if (msg) console.log(msg); },
    message: () => { /* no-op off-TTY */ },
  };
}

// bug-tracker-ref: singularize tool counts ("1 tool", not "1 tools").
function toolsLabel(n: number): string { return `${n} ${Number(n) === 1 ? 'tool' : 'tools'}`; }

// bug-tracker-ref: strip C0/C1 control characters (except tab/newline) from
// adapter result text before display, so a stray control byte in an upstream
// response cannot corrupt the rendered output.
function sanitizeResultText(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    const allowedWs = c === 0x09 || c === 0x0A;
    const isControl = c < 0x20 || (c >= 0x7F && c <= 0x9F);
    if (!isControl || allowedWs) out += ch;
  }
  return out;
}

// bug-tracker-ref: render an MCP tool result. When the result is flagged isError,
// throw a clean Error so the caller's catch surfaces a "✗ adapter — reason" line
// instead of printing the server's raw error body (often with control chars) as
// though it were a successful answer.
function renderMcpResult(result: unknown): string {
  const r = (result ?? {}) as { content?: unknown; isError?: unknown };
  const content = Array.isArray(r.content)
    ? (r.content as Array<{ type?: string; text?: string }>)
    : [];
  const text = sanitizeResultText(
    content.filter(c => c?.type === 'text').map(c => c?.text ?? '').join(String.fromCharCode(10)),
  );
  if (r.isError === true) {
    throw new Error(`adapter returned an error response: ${text.slice(0, 300) || '(no detail provided)'}`);
  }
  return text;
}

// single enumeration source for cmdHealth and cmdList — union of
// curated tier (no creds required) and user-added state. Deduped, stable
// order: curated first (preserving CURATED_IDS order), then state additions.
function enumerateAdapterIds(state: AdapterState): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of CURATED_IDS) {
    if (!seen.has(id)) { seen.add(id); out.push(id); }
  }
  for (const id of Object.keys(state.adapters)) {
    if (!seen.has(id)) { seen.add(id); out.push(id); }
  }
  return out;
}

// getConfiguredAdapterIds extracted to
// src/engine/federation/configuredAdapterIds.ts; both ChariotState
// (live MCP server routing) and setup.ts (cmdQuery + startMcpServer
// wiring) now share one implementation. The clone was the structural
// debt traced across earlier review rounds.

// ─── Port parsing helper ─────────────────────────────────────

function parseTransportPort(argv: string[], flag: string, envVar: string | undefined, defaultPort: number): number {
  const idx = argv.indexOf(flag);
  if (idx !== -1) {
    const next = argv[idx + 1];
    if (next !== undefined && !next.startsWith('-')) {
      const parsed = parseInt(next, 10);
      if (!isNaN(parsed)) return parsed;
    }
  }
  if (envVar !== undefined && envVar !== '') {
    const parsed = parseInt(envVar, 10);
    if (!isNaN(parsed)) return parsed;
  }
  return defaultPort;
}

// ─── MCP Server Mode (--serve) ──────────────────────────────

async function startMcpServer(): Promise<void> {
  const { loadChariotState } = await import('../server/ChariotState.js');
  const { registerChariotTools } = await import('../server/registerChariotTools.js');
  const { bindStdio } = await import('../server/transports/stdio.js');
  const { bindHttp } = await import('../server/transports/http.js');
  const { bindRest } = await import('../server/transports/rest.js');
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');

  // Parse transport flags
  const argv = process.argv.slice(2);
  const useHttp  = argv.includes('--http');
  const useRest  = argv.includes('--rest');
  const useStdio = argv.includes('--stdio') || (!useHttp && !useRest);

  const httpPort = parseTransportPort(argv, '--http', process.env.CHARIOT_HTTP_PORT, 3550);
  const restPort = parseTransportPort(argv, '--rest', process.env.CHARIOT_REST_PORT, 3551);

 // instantiate the observability emitter in this child process
  // (it cannot cross the chariot.ts → engine/bin/setup.js process boundary).
  // Wire console-logger so retry events surface to stderr by default.
  const { ObservabilityEmitter } = await import('../observability/EventEmitter.js');
  const observabilityEmitter = new ObservabilityEmitter();
  observabilityEmitter.onLog(ObservabilityEmitter.consoleLogger(['apiKey', 'credential', 'token', 'jti']));

  // Load shared state (catalog, credentials, BM25 indexes)
  const state = await loadChariotState({ observabilityEmitter });
  const getTenantId = (): string => process.env.CHARIOT_TENANT_ID ?? 'local';

  // Transport lifecycle handles (HTTP and REST only — stdio tears down on process exit)
  const handles: Array<{ port: number; close(): Promise<void> }> = [];

  try {
    if (useHttp) {
      // Per-request McpServer factory. The HTTP transport calls this on
      // every /mcp request with the derived session id (JWT jti) and
      // gets a fresh McpServer back. Stateless transport mode (SDK
      // sessionIdGenerator: undefined) requires per-request transport
      // instances; pairing each with its own McpServer also avoids the
      // SDK Protocol.connect "Already connected to a transport" exception
      // that fires on the singleton-server-with-many-transports pattern.
      const createMcpServer = (session: ResolvedMcpSession | undefined) => {
        const srv = new McpServer({ name: 'epic-ai-chariot', version: PKG_VERSION });
        // bug-tracker-ref: thread the verified per-request session into the tool
        // layer. JWT mode → real tenant + RBAC grants with localMode:false,
        // so handleCall enforces per-operation RBAC (deny-by-default) and
        // every tool reads the caller's own tenant (isolation).
        //
        // DECISION (flagged for security review): shared-bearer loopback mode
        // (CHARIOT_HTTP_TOKEN, no resolver → session undefined) stays
        // single-tenant localMode:true. That mode is documented
        // (transports/http.ts) as single-tenant loopback where the shared
        // secret IS the trust boundary; there is no cross-tenant surface to
        // isolate. bug-tracker-ref is the multi-tenant JWT path running localMode:
        // true — that is what this closes. Switching shared-bearer to
        // deny-by-default would break documented loopback deployments.
        const sec = session
          ? { tenantId: session.tenantId, auth: session.auth, localMode: false, sessionId: session.sessionId, sessionJti: session.sessionId }
          : { tenantId: getTenantId(), localMode: true, sessionId: undefined };
        registerChariotTools(srv, state, sec);
        return srv;
      };

      // Construct an Express app mounting the IAM /enterprise/oauth router so
      // the same chariot serve --http process serves both the MCP gateway
      // (/mcp) and the Resource Authorization Server surfaces
      // (/enterprise/oauth/*, /.well-known/oauth-authorization-server,
      // /health). One process is the complete RFC 8414 Resource AS.
      const express = (await import('express')).default;
      const oauthRouterMod = await import('../../iam/routes/oauth.js');
      const oauthDiscoveryHandler = oauthRouterMod.oauthAuthorizationServerMetadataHandler;
      const setDiscoveryCors = oauthRouterMod.setDiscoveryCors;
      const { createEnterpriseRoutes } = await import('../../iam/routes/index.js');
      const healthMod = await import('../../iam/routes/health.js');
      const iamSessionMod = await import('../../iam/services/session.js');

      // Bootstrap IAM Mongo + Redis before mounting the IAM router so token
      // issuance + audit writes can actually run.
      // Single-replica posture — uses local Mongo at MONGODB_URI (default
      // mongodb://127.0.0.1:27017, db 'epicai') and an in-process Redis
      // shim that satisfies the RedisClientType surface the IAM modules
      // import. Multi-replica deployments require a real Redis client
      // pointed at a shared instance — gate that in a separate fix when
      // multi-replica ships.
      let iamBootstrapOk = false;
      // Capture iamDb reference for use in getActiveUserCount below.
      // Initialized inside the bootstrap try-block; non-null by the time
      // createEnterpriseRoutes is called because iamBootstrapOk guards it.
      let _iamDb: typeof import('../../iam/db.js') | null = null;
      try {
        const { MongoClient } = await import('mongodb');
        const iamDb = await import('../../iam/db.js');
        _iamDb = iamDb;
        const iamRedis = await import('../../iam/redis.js');
        const iamJtiCache = await import('../../iam/services/jti-replay-cache.js');

        const mongoUri = process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017';
        const mongoDb = process.env.MONGODB_DB ?? 'epicai';
        const mongoClient = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 3000 });
        await mongoClient.connect();
        iamDb.setMongoClient(mongoClient, mongoDb);

        // Create the IAM/ID-JAG indexes on startup. Without this a fresh
        // deployment runs unindexed — the unique (tenantId, clientId)
        // constraint is not enforced and the POST /token client->tenant
        // lookup ({clientId, active}) COLLSCANs. createIndex is idempotent,
        // so this is a no-op once the indexes exist. Inside the bootstrap
        // try so a failure fail-stops the bind rather than serving an
        // unindexed registry.
        const { ensureEnterpriseIndexes } = await import('../../iam/indexes.js');
        const { backfillSubIdAliasCanon } = await import('../../iam/services/id-jag-issuer.js');
        const _iamDbForIndexes = await iamDb.getDb();
        // Backfill canon BEFORE index creation so the unique-canon build
        // validates corrected values (upgrade / format-change safety).
        await backfillSubIdAliasCanon(_iamDbForIndexes);
        await ensureEnterpriseIndexes(_iamDbForIndexes);

        // In-process Redis shim with proper TTL semantics. Entries carry
        // an absolute expiresAtMs (null = no expiry); reads do lazy
        // expiration on access; a background sweep evicts stale entries.
        // Critical for jti-replay-cache: the Lua-CAS for reserveOrMatch
        // depends on TTL-bounded "first-sight" → "replay" transitions.
        // Without honoring TTL, replay protection becomes permanent
        // (false-positive replays after natural assertion expiry) and the
        // kv Map grows unbounded for the process lifetime.
        interface KvEntry { value: string; expiresAtMs: number | null }
        interface SetEntry { members: Set<string>; expiresAtMs: number | null }
        const kv = new Map<string, KvEntry>();
        const sets = new Map<string, SetEntry>();
        const now = (): number => Date.now();
        const isExpired = (e: { expiresAtMs: number | null } | undefined): boolean =>
          e !== undefined && e.expiresAtMs !== null && e.expiresAtMs <= now();
        const kvGetLive = (k: string): KvEntry | undefined => {
          const e = kv.get(k);
          if (!e) return undefined;
          if (isExpired(e)) { kv.delete(k); return undefined; }
          return e;
        };
        const setGetLive = (k: string): SetEntry => {
          const e = sets.get(k);
          if (e && !isExpired(e)) return e;
          if (e) sets.delete(k);
          const fresh: SetEntry = { members: new Set<string>(), expiresAtMs: null };
          sets.set(k, fresh);
          return fresh;
        };
        const computeExpiry = (opts: { EX?: number; PX?: number } | undefined): number | null => {
          if (!opts) return null;
          if (typeof opts.PX === 'number' && opts.PX > 0) return now() + opts.PX;
          if (typeof opts.EX === 'number' && opts.EX > 0) return now() + opts.EX * 1000;
          return null;
        };
        // Background sweeper — evict expired entries every 30s so the
        // in-memory maps don't grow unbounded between accesses.
        const sweeper = setInterval((): void => {
          const t = now();
          for (const [k, e] of kv) if (e.expiresAtMs !== null && e.expiresAtMs <= t) kv.delete(k);
          for (const [k, e] of sets) if (e.expiresAtMs !== null && e.expiresAtMs <= t) sets.delete(k);
        }, 30_000);
        sweeper.unref();
        const shim = {
          async sAdd(key: string, ...members: any[]): Promise<number> {
            const s = setGetLive(key);
            let added = 0;
            for (const m of members.flat()) { if (!s.members.has(m)) { s.members.add(m); added++; } }
            return added;
          },
          async sMembers(key: string): Promise<string[]> { return [...setGetLive(key).members]; },
          async sRem(key: string, ...members: any[]): Promise<number> {
            const s = setGetLive(key);
            let removed = 0;
            for (const m of members.flat()) { if (s.members.delete(m)) removed++; }
            return removed;
          },
          async expire(key: string, seconds: number): Promise<number> {
            const kvE = kv.get(key);
            if (kvE) { kvE.expiresAtMs = now() + seconds * 1000; return 1; }
            const setE = sets.get(key);
            if (setE) { setE.expiresAtMs = now() + seconds * 1000; return 1; }
            return 0;
          },
          async set(key: string, val: string, opts?: any): Promise<string | null> {
            const existing = kvGetLive(key);
            if (opts?.NX && existing) return null;
            // Real Redis KEEPTTL preserves the existing key's TTL on
            // overwrite. session.ts:setMfaPendingTotpSecret writes with
            // { KEEPTTL: true }; without this branch the shim would drop
            // the TTL and MFA-pending entries would linger forever.
            const expiresAtMs = (opts?.KEEPTTL && existing)
              ? existing.expiresAtMs
              : computeExpiry(opts);
            kv.set(key, { value: val, expiresAtMs });
            return 'OK';
          },
          async get(key: string): Promise<string | null> { return kvGetLive(key)?.value ?? null; },
          async del(...keys: any[]): Promise<number> {
            let removed = 0;
            for (const key of keys.flat()) {
              if (kv.delete(key)) removed++;
              if (sets.delete(key)) removed++;
            }
            return removed;
          },
          async hGet(): Promise<string | null> { return null; },
          async hSet(): Promise<number> { return 1; },
          // jti-replay reserveOrMatch Lua semantics: keys[0] = replay key,
          // arguments[0] = assertion hash, arguments[1] = ttl seconds.
          async eval(_script: string, opts: any): Promise<string> {
            const key = opts.keys[0];
            const arg0 = opts.arguments[0] as string;
            const ttlSecondsStr = opts.arguments[1] as string | undefined;
            const ttlSeconds = ttlSecondsStr ? parseInt(ttlSecondsStr, 10) : 0;
            const existing = kvGetLive(key);
            if (!existing) {
              kv.set(key, {
                value: arg0,
                expiresAtMs: ttlSeconds > 0 ? now() + ttlSeconds * 1000 : null,
              });
              return 'first-sight';
            }
            if (existing.value === arg0) return 'match';
            return 'replay';
          },
          async incr(key: string): Promise<number> {
            const existing = kvGetLive(key);
            // Mirror real Redis: ERR if existing value is not an integer.
            // Without this guard a poisoned key would silently produce NaN
            // and downstream Number.isFinite() readers would fail-OPEN,
            // bypassing revocation checks.
            const cur = existing ? parseInt(existing.value, 10) : 0;
            if (existing && !Number.isFinite(cur)) {
              throw new Error(`in-process redis shim: incr on non-integer value at key "${key}"`);
            }
            const next = cur + 1;
            kv.set(key, { value: String(next), expiresAtMs: existing?.expiresAtMs ?? null });
            return next;
          },
          // node-redis v4 pipeline. session.ts:412 (revokeAllUserSessions)
          // and session.ts:664 (consumeRefreshToken) collect set/del ops
          // into a multi() chain and exec() them. Each method records the
          // op and returns the chain; exec runs them in order. The chain
          // also forwards through expire/incr/sAdd/sRem so future call
          // sites that batch additional ops do not silently drop them.
          multi(): unknown {
            const shimRef = shim;
            const ops: Array<() => Promise<unknown>> = [];
            const chain = {
              set(k: string, v: string, o?: any) { ops.push(() => shimRef.set(k, v, o)); return chain; },
              del(...keys: any[]) { ops.push(() => shimRef.del(...keys)); return chain; },
              expire(k: string, s: number) { ops.push(() => shimRef.expire(k, s)); return chain; },
              incr(k: string) { ops.push(() => shimRef.incr(k)); return chain; },
              sAdd(k: string, ...m: any[]) { ops.push(() => shimRef.sAdd(k, ...m)); return chain; },
              sRem(k: string, ...m: any[]) { ops.push(() => shimRef.sRem(k, ...m)); return chain; },
              async exec(): Promise<unknown[]> {
                const out: unknown[] = [];
                for (const op of ops) out.push(await op());
                return out;
              },
            };
            return chain;
          },
        };
        const redisUrl = process.env.REDIS_URL;
        if (redisUrl && redisUrl.length > 0) {
          // Production state path: a real, shared Redis so session /
          // jti-replay / MFA state survives process restart and is
          // visible across instances. The in-process shim above is a
          // dev/stdio convenience ONLY — it holds that state in memory,
          // so a restart wipes every session and resets the replay
          // cache, and it cannot be shared by a second instance. When
          // REDIS_URL is set we MUST use the real client and MUST NOT
          // silently fall back to the shim: a connect failure throws
          // here and is caught below, which fail-stops the bind rather
          // than degrading a production deploy to in-memory state.
          const { createClient } = await import('redis');
          const redisClient = createClient({ url: redisUrl });
          redisClient.on('error', (err: Error) => {
            // Post-connect runtime errors: log (no URL — it can carry
            // credentials) and let node-redis's own reconnect strategy
            // recover. A hard connect failure is handled by the await below.
            process.stderr.write(`Chariot Redis client error: ${err.message}\n`);
          });
          await redisClient.connect();
          iamSessionMod.setRedisClient(redisClient as any);
          iamJtiCache.setRedisClient(redisClient as any);
          iamRedis.setRedisClient(redisClient as any);
          // Never log REDIS_URL itself — it may embed a password.
          process.stderr.write(`Chariot IAM bootstrap: mongo=${mongoUri} db=${mongoDb} redis=external (REDIS_URL)\n`);
        } else {
          iamSessionMod.setRedisClient(shim as any);
          iamJtiCache.setRedisClient(shim as any);
          iamRedis.setRedisClient(shim as any);
          process.stderr.write(`Chariot IAM bootstrap: mongo=${mongoUri} db=${mongoDb} redis=in-process-shim (DEV ONLY — set REDIS_URL for a restart-surviving, shareable store)\n`);
        }
        iamBootstrapOk = true;
      } catch (e) {
        process.stderr.write(`Chariot IAM bootstrap FAILED: ${(e as Error).message}\n`);
      }

      // Fail-fast on bootstrap failure. The previous behavior swallowed
      // the error and let bindHttp succeed, after which every /mcp
      // request silently 401'd because verifyToken hit an uninitialized
      // Redis client. Operators saw 100% 401s with /health reporting OK
      // and only one stderr line at boot to diagnose.
      if (!iamBootstrapOk) {
        throw new Error(
          'Chariot startup: IAM bootstrap failed; refusing to bind /mcp with broken IAM. See preceding stderr line for the underlying error.',
        );
      }

      healthMod.configureHealth({ state, version: PKG_VERSION });
      const iamApp = express();
      iamApp.use(express.json());
      iamApp.use(express.urlencoded({ extended: true }));

      // Wire createEnterpriseRoutes() so /enterprise/oauth/token is gated
      // by requireTlsMiddleware + licenseGateMiddleware + seatGateOnTokenOnly.
      // The prior hand-mount (raw oauthRouter) bypassed all three gates.
      // getActiveUserCount counts active IAM users in iam_users; iamDb is
      // guaranteed non-null here because iamBootstrapOk is true.
      const getActiveUserCount = async (): Promise<number> => {
        const col = await _iamDb!.getCollection('iam_users');
        return col.countDocuments({ active: true });
      };
      iamApp.use('/enterprise', createEnterpriseRoutes({ getActiveUserCount }));
      // RFC 8414 §3 mandates discovery at <issuer>/.well-known/oauth-
      // authorization-server (root, no sub-path). Mount the same handler
      // here so partner conformance tooling that follows the spec
      // literally reaches it without an external rewrite. The /enterprise/
      // oauth/.well-known/oauth-authorization-server path keeps working
      // for back-compat with clients that have hard-coded that URL.
      iamApp.get('/.well-known/oauth-authorization-server', oauthDiscoveryHandler);
      // Browser-origin clients (xaa.dev, Okta playground) preflight the
      // canonical discovery path with an X-Tenant-Id header. express's
      // app.get registers GET only, so without a root OPTIONS handler the
      // preflight reaches no Access-Control-Allow-Headers and the browser
      // blocks the GET. Mirror the in-router discovery CORS headers via the
      // same shared helper so the root mount cannot drift from the router.
      iamApp.options(
        '/.well-known/oauth-authorization-server',
        (_req, res) => {
          setDiscoveryCors(res);
          res.status(204).end();
        },
      );
      iamApp.use('/health', healthMod.default);

      // Per-request session-id resolver. Calls IAM verifyToken so /mcp
      // inherits the same signature + tenant epoch + user epoch + jti
      // revocation + idle-timeout enforcement that /enterprise/oauth/*
      // applies — a revoked token can no longer carry surface state.
      // Returns null on any verification failure; bindHttp turns null
      // into 401 (fail-closed for the LLM06 surface gate).
      //
      // Startup secret validation: trigger getJwtSecret() once at bind
      // time so a missing / insecure-default / too-short
      // ENTERPRISE_JWT_SECRET surfaces as a fail-fast bind error rather
      // than every /mcp request silently returning 401 at runtime.
      // CHARIOT_PUBLIC_BASE_URL startup validation. The discovery doc
      // and issuer URLs are built from this value; bad shape (missing
      // scheme, http:// in production, embedded credentials, trailing
      // whitespace) silently produces malformed metadata that breaks
      // RFC 8414 conformance only when a client probes discovery. Fail
      // fast at bind time instead.
      const publicBaseUrl = process.env.CHARIOT_PUBLIC_BASE_URL;
      if (publicBaseUrl !== undefined) {
        try {
          const u = new URL(publicBaseUrl);
          if (u.protocol !== 'https:' && process.env.NODE_ENV === 'production') {
            throw new Error(`scheme must be https in production (got ${u.protocol})`);
          }
          if (u.username !== '' || u.password !== '') {
            throw new Error('must not contain userinfo (user:pass@)');
          }
        } catch (e) {
          throw new Error(
            `Chariot startup: CHARIOT_PUBLIC_BASE_URL validation failed — ${(e as Error).message}`,
          );
        }
      } else if (process.env.NODE_ENV === 'production') {
        throw new Error(
          'Chariot startup: CHARIOT_PUBLIC_BASE_URL must be set in production (NODE_ENV=production)',
        );
      }

      let resolveSessionId: undefined | ((req: import('node:http').IncomingMessage) => Promise<ResolvedMcpSession | null>);
      if (process.env.ENTERPRISE_JWT_SECRET) {
        // Fail-fast secret validation at bind time. The exported
        // validator runs the same checks getJwtSecret() runs on every
        // sign/verify, so a misconfigured ENTERPRISE_JWT_SECRET
        // (missing, insecure-default, <32 chars) surfaces here as a
        // startup error rather than every /mcp request silently 401'ing
        // at runtime.
        try {
          iamSessionMod.validateEnterpriseJwtSecret();
        } catch (e) {
          throw new Error(
            `Chariot startup: ENTERPRISE_JWT_SECRET validation failed — ${(e as Error).message}`,
          );
        }
        resolveSessionId = async (req: import('node:http').IncomingMessage): Promise<ResolvedMcpSession | null> => {
          const auth = req.headers['authorization'];
          if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) return null;
          const bearer = auth.slice('Bearer '.length).trim();
          if (!bearer) return null;
          try {
            // bug-tracker-ref: pin the token's tenant to THIS process's configured
            // tenant. The HTTP transport is deployed container-per-tenant under a
            // SHARED ENTERPRISE_JWT_SECRET (DEVELOPER_GUIDE §"Standalone SaaS"), so a
            // token validly signed for ANOTHER tenant would otherwise verify here and
            // drive handleCall — including per-tenant credential-vault decryption —
            // under the wrong tenant (cross-tenant escalation). expectedTenantId makes
            // verifyToken reject any token whose tenantId != this process's
            // CHARIOT_TENANT_ID. Undefined (non-enterprise / unset) → no filter, so
            // single-tenant/loopback behavior is unchanged.
            const decoded = await iamSessionMod.verifyToken(bearer, process.env.CHARIOT_TENANT_ID);
            // return the verified claims (tenant + RBAC grants), not just the jti.
            // Reject tokens missing jti OR tenantId — both key per-request security
            // (surface-state gate, tenant isolation); fail closed rather than keying
            // isolation/budget on an empty tenant.
            if (!decoded?.jti || !decoded.tenantId) return null;
            return {
              sessionId: decoded.jti,
              tenantId: decoded.tenantId,
              auth: { allowedOperations: decoded.allowedOperations, userId: decoded.userId },
            };
          } catch {
            return null;
          }
        };
      }

      const h = await bindHttp(httpPort, { createMcpServer, iamApp, resolveSessionId });
      handles.push(h);
      process.stderr.write(`Chariot HTTP MCP listening on port ${h.port}\n`);
    }

    if (useRest) {
      const h = await bindRest(state, restPort, getTenantId);
      handles.push(h);
      process.stderr.write(`Chariot REST API listening on port ${h.port}\n`);
    }

    if (useStdio) {
      const srv = new McpServer({ name: 'epic-ai-chariot', version: PKG_VERSION });
      // The MCP SDK stdio transport does not populate
      // RequestHandlerExtra.sessionId. Synthesize a stable per-process
      // id so the session-surface gate in handleCallImpl has a key to
      // record + check tuples against. Lifetime = process lifetime,
      // which matches the npx @epicai/chariot single-conversation use
      // case. Streamable-HTTP path above uses the SDK-provided uuid per
      // connection and does not need this fallback.
      const stdioSessionId = `stdio-${process.pid}-${Date.now()}`;
      // Stdio is the single-user `npx @epicai/chariot` install: the local
      // operator is the only caller and is implicitly trusted, so localMode
      // stays true (RBAC bypass opt-in) with the process tenant. bug-tracker-ref
      // only changes the multi-tenant HTTP path; stdio is unchanged.
      registerChariotTools(srv, state, { tenantId: getTenantId(), localMode: true, sessionId: stdioSessionId });
      await bindStdio(srv);
    }
  } catch (err) {
    // Startup failure: close already-bound transports in reverse order, then rethrow
    for (const h of [...handles].reverse()) await h.close().catch(() => { /* intentionally empty */ });
    throw err;
  }

  if (handles.length > 0) {
    // HTTP/REST mode: keep alive until signal
    let shuttingDown = false;
    const shutdown = async (): Promise<void> => {
      if (shuttingDown) return;
      shuttingDown = true;
      // await the audit chain flush before transport close so a
      // SIGTERM cannot drop in-flight audit rows. The audit adapter's
      // close() flushes its queue (JSONL fsync / SQLite checkpoint) and
      // releases the file handle; if it throws we still exit but with a
      // non-zero code so the operator sees the lost rows.
      let exitCode = 0;
      try {
        const maybeCloseable = state as unknown as { close?: () => Promise<void> };
        if (typeof maybeCloseable.close === 'function') {
          await maybeCloseable.close();
        }
      } catch (err) {
        process.stderr.write(
          `audit flush on shutdown failed: ${err instanceof Error ? err.message : String(err)}\n`,
        );
        exitCode = 1;
      }
      // Reverse-order sequential close to mirror the startup-failure rollback path;
      // transports are independent in practice, but tests don't cover concurrent close.
      for (const h of [...handles].reverse()) {
        try { await h.close(); } catch { /* best-effort */ }
      }
      process.exit(exitCode);
    };
    process.on('SIGTERM', () => { void shutdown(); });
    process.on('SIGINT',  () => { void shutdown(); });
    await new Promise<never>(() => { /* keep alive */ });
  }
  // stdio-only: return here; the event loop stays alive via the transport connection
}

// ─── Subcommands ────────────────────────────────────────────

async function cmdAdd(adapterName: string): Promise<void> {
  const p = await import('@clack/prompts');
  const pc = (await import('picocolors')).default;

  const all = await loadAllAdapters();

  const match = all.find(a => a.id === adapterName || a.name.toLowerCase() === adapterName.toLowerCase());
  if (!match) {
    const fuzzy = all.filter(a => a.id.includes(adapterName) || a.name.toLowerCase().includes(adapterName.toLowerCase()));
    if (fuzzy.length > 0) {
      console.log(`Adapter "${adapterName}" not found. Did you mean:`);
      fuzzy.slice(0, 5).forEach(a => console.log(`  ${pc.cyan(a.id)} — ${a.name}`));
    } else {
      console.log(`Adapter "${adapterName}" not found. Run ${pc.cyan('npx @epicai/chariot list')} to see all adapters.`);
    }
    process.exit(1);
  }

  const s = makeSpinner(p);

  // Install stdio dependency if needed
  if (match.mcp?.transport === 'stdio' && match.mcp?.packageName) {
    s.start(`Installing ${match.name}`);
    // spawnSync array form — no shell metacharacter exposure.
    const r = spawnSync('npm', ['install', '-g', '--ignore-scripts', match.mcp.packageName], {
      stdio: 'pipe', timeout: 60000,
    });
    if (r.error || (r.status !== null && r.status !== 0) || r.signal) {
      s.stop(`${pc.yellow('!')} Install failed — run manually: npm install -g ${match.mcp.packageName}`);
    } else {
      s.stop(`${pc.green('✓')} ${match.name} installed`);
    }
  }

  // Prompt for credentials. Track which required keys remain unset so we can
  // mark status accurately (cmdAdd must not lie that an adapter is
  // 'configured' when the customer never supplied the credentials it needs).
  //
// effectiveEnvKeys consults adapter.mcp.envKeys AND falls back to
  // CANONICAL_CREDENTIALED_BRANDS — so adapters whose published catalog
  // row strips envKeys (the publisher gap) still get prompted for their
  // canonical required env-vars.
  const requiredKeys: string[] = [];
  if (match.rest?.envKey) requiredKeys.push(match.rest.envKey);
  requiredKeys.push(...effectiveEnvKeys(match));

  // Two-phase: collect prompt responses + validate FIRST, then
  // writeCredential each value. A control-char throw mid-loop (bracketed-
  // paste ESC bytes, NUL/TAB, etc.) must NOT leave earlier keys persisted
  // while later keys are absent. CREDENTIAL_VALUE_CONTROL_CHAR_RE is the
  // single source of truth shared with writeCredential and
  // parseInlineCredentialFlags.
  //
// hoist loadCredentials() outside the
  // loop. The disk read used to fire N times (one per required key);
  // hoisting collapses to one read for the whole prompt phase.
  const existingCreds = loadCredentials();
  const pendingWrites: Array<[string, string]> = [];
  const rejectedKeys: string[] = [];
  for (const envKey of requiredKeys) {
    if (existingCreds[envKey]) continue;
    const key = await p.password({ message: envKey });
    if (p.isCancel(key) || !key) continue;
    if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(key)) {
      console.error(pc.red(`${envKey}: value contains a control character (NUL/CR/LF/TAB/ESC/C1). Not saved.`));
      console.error(pc.dim('  Re-run `chariot add` and paste a printable-byte credential (or base64 first).'));
      rejectedKeys.push(envKey);
      continue;
    }
    pendingWrites.push([envKey, key]);
  }
  for (const [envKey, key] of pendingWrites) {
    writeCredential(envKey, key);
  }
  // post-loop summary so the operator can
  // see which keys persisted vs which were rejected. Without this, a
  // per-key error printed mid-loop can scroll past and the operator
  // assumes either all-saved or all-failed when reality is partial.
  if (pendingWrites.length > 0) {
    const saved = pendingWrites.map(([k]) => k).join(', ');
    console.log(`${pc.green('✓')} Saved: ${saved}`);
  }
  if (rejectedKeys.length > 0) {
    console.log(`${pc.yellow('!')} Rejected: ${rejectedKeys.join(', ')} — re-run \`chariot add ${match.id}\` to retry.`);
  }

  // Recompute credential coverage after prompts to set status correctly.
  // merge process.env into the missing-keys
  // computation so the persisted status agrees with the routing path
  // (ChariotState.getConfiguredAdapterIds uses credentialStatus
  // which already merges both views). Without this, an operator who
  // exports credentials via shell env (CI, containers) gets a
  // 'credentials-pending' status sticker on an adapter that actually
  // routes correctly — cosmetic state-file lie.
  const credsNow = loadCredentials();
  const missingKeys = requiredKeys.filter(k => !credsNow[k] && !process.env[k]);
  const status = missingKeys.length === 0 ? 'configured' : 'credentials-pending';

  // Update state via immutable upsert — protects _stateCache.value from
  // mid-write corruption if saveState throws (see helper comment above).
  const state = loadState();
  const nextState = upsertAdapterState(state, match.id, {
    type: match.type || 'unknown',
    status,
    toolCount: match.rest?.toolCount ?? match.mcp?.toolCount ?? 0,
    lastVerified: null,
  });
  saveState(nextState);

  // Update config. Only add to selectedAdapters when status is fully
  // 'configured'. A pending entry present in selectedAdapters would bypass
  // the fail-closed skip in getConfiguredAdapterIds and route despite
  // missing credentials.
  const config = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };
  const alreadySelected = config.selectedAdapters.includes(match.id);
  if (status === 'configured' && !alreadySelected) {
    config.selectedAdapters.push(match.id);
  } else if (status !== 'configured' && alreadySelected) {
    // demote: an earlier add picked this up; remove it now that creds are missing
    config.selectedAdapters = config.selectedAdapters.filter(id => id !== match.id);
  }
  saveConfig(config);

  if (status === 'credentials-pending') {
    console.log(`${pc.yellow('!')} ${match.name} added in credentials-pending state — missing: ${missingKeys.join(', ')}`);
    console.log(`  ${pc.dim('Supply these env vars and re-run `chariot add ' + match.id + '` to activate.')}`);
  } else {
    console.log(`${pc.green('✓')} ${match.name} added to Chariot.`);
  }
}

async function cmdRemove(adapterName: string): Promise<void> {
  const pc = (await import('picocolors')).default;

  const state = loadState();
  const config = loadConfig();

  if (!state.adapters[adapterName]) {
    console.log(`Adapter "${adapterName}" is not configured.`);
    process.exit(1);
  }

  saveState(removeAdapterState(state, adapterName));

  if (config) {
    config.selectedAdapters = config.selectedAdapters.filter(id => id !== adapterName);
    saveConfig(config);
  }

  console.log(`${pc.green('✓')} ${adapterName} removed from Chariot.`);
  console.log(`${pc.white('  Note: credentials in ~/.epic-ai/.env and MCP client configs are not removed.')}`);
  console.log(`${pc.white('  Clean those manually if needed.')}`);
}

async function cmdHealth(): Promise<void> {
  const pc = (await import('picocolors')).default;
  const p = await import('@clack/prompts');

  const state = loadState();
  const creds = loadCredentials();
  const all = await loadAllAdapters();

  // cmdHealth and cmdList must enumerate the same universe. cmdList
  // shows CURATED_IDS + state.adapters; cmdHealth was iterating state only and
  // would say "no adapters configured" on a fresh install even though curated
  // adapters are usable out of the box. Union them and dedupe.
  const configured = enumerateAdapterIds(state);
  if (configured.length === 0) {
    console.log(`No adapters configured. Run ${pc.cyan('npx @epicai/chariot')} to set up.`);
    return;
  }

  const s = makeSpinner(p);
  s.start(`Checking ${configured.length} adapters`);

  const results: string[] = [];
  let healthy = 0;
  let issues = 0;

  for (const id of configured) {
    const adapter = all.find(a => a.id === id);
    if (!adapter) {
      // include a remediation hint so users know how to clean up
      // stale state entries left over after a bundle change.
      results.push(`${pc.red('✗')} ${id} — not found in catalog (run ${pc.cyan(`chariot remove ${id}`)} to drop)`);
      issues++;
      continue;
    }

    // cmdHealthCheckAdapter is the single
    // health-decision helper shared with src/bin/chariot.ts cmdHealth.
    // Combines REST envKey + MCP envKeys (with CANONICAL fallback) +
    // curated bypass into one call.
    const isCurated = CURATED_IDS.includes(id);
    const { healthy: hasKey, missingKey } = cmdHealthCheckAdapter(adapter, creds, isCurated);

    const stateEntry = state.adapters[id];
    const toolCount = stateEntry?.toolCount ?? adapter.rest?.toolCount ?? adapter.mcp?.toolCount ?? 0;
    if (isCurated || hasKey) {
      const label = isCurated ? 'curated' : (stateEntry?.status ?? 'configured');
      results.push(`${pc.green('✓')} ${adapter.name || id}  ${toolsLabel(toolCount)}  ${label}`);
      healthy++;
    } else {
      results.push(`${pc.yellow('!')} ${adapter.name || id}  missing ${missingKey || 'credentials'}`);
      issues++;
    }
  }

  s.stop('Health check complete');

  p.note(results.join('\n'), `${healthy} healthy, ${issues} need attention`);

  // A green health line can mean "credentials verified" OR "no
  // credentials required". Flag non-curated adapters that pass only because
  // they declare neither a REST envKey nor MCP envKeys and are absent from
  // CANONICAL_CREDENTIALED_BRANDS — likely a missing CANONICAL entry or a
  // publisher gap, not a genuinely credential-free adapter.
  const checkedAdapters = configured
    .map(id => all.find(a => a.id === id))
    .filter((a): a is AdapterEntry => !!a);
  const coverageGaps = auditCanonicalCoverage(checkedAdapters, id => CURATED_IDS.includes(id));
  if (coverageGaps.length > 0) {
    p.note(
      coverageGaps
        .map(g => `${pc.yellow('?')} ${g.id} — healthy with no declared credentials; if it needs auth, add a CANONICAL_CREDENTIALED_BRANDS entry or publisher envKeys`)
        .join('\n'),
      `${coverageGaps.length} possible credential mis-categorization(s)`,
    );
  }

  // Phase R.7: surface setup-manifest summary so users see host-install drift.
  const manifest = readManifest();
  if (manifest) {
    const totals = manifest.summary?.totals ?? {};
    const summary = Object.entries(totals).map(([k, v]) => `${k}=${v}`).join('  ');
    p.note(`Pre-install manifest (${manifest.ranAt}):\n${summary || '<empty>'}`, 'Setup state');
  }

  saveState(withLastHealthCheck(state, new Date().toISOString()));
}

// ─── Phase R.7: chariot setup --pre-install ─────────────────

async function cmdPreInstall(args: string[]): Promise<void> {
  const dryRun = args.includes('--dry-run');
  const skipPreWarm = args.includes('--skip-pre-warm');
  const onlyFlag = args.find((a) => a.startsWith('--only='));
  const only = onlyFlag ? (onlyFlag.slice('--only='.length) as 'cli' | 'npx' | 'uvx') : null;
  if (only && !['cli', 'npx', 'uvx'].includes(only)) {
    console.error(`Unknown --only group: ${only}. Valid: cli | npx | uvx`);
    process.exit(1);
  }
  await runPreInstall({ dryRun, skipPreWarm, only });
}


// Curated set: src/catalog/curated.ts. Shared with src/bin/chariot.ts.
import { CHARIOT_CURATED_IDS as CURATED_IDS } from '../../catalog/curated.js';

// ─── chariot list ────────────────────────────────────────────

async function cmdList(): Promise<void> {
  const pc = (await import('picocolors')).default;
  const all = await loadAllAdapters();
  const state = loadState();

  // Curated tier
  const curatedRows = CURATED_IDS.map(id => all.find(a => a.id === id)).filter(Boolean) as AdapterEntry[];

  // Custom tier — in state but not curated
  const customIds = Object.keys(state.adapters).filter(id => !CURATED_IDS.includes(id));
  const customRows = customIds.map(id => all.find(a => a.id === id) || { id, name: id, type: 'unknown' } as AdapterEntry);

  console.log('');

  // Curated
  console.log(`  ${pc.bold('Curated')}  ${pc.white(`(${curatedRows.length})`)}  ${pc.white('— open data, no credentials required')}`);
  console.log('');
  for (const a of curatedRows) {
    const toolCount = a.rest?.toolCount ?? a.mcp?.toolCount ?? 0;
    const typeLabel = pc.white(adapterTypeLabel(a.type));
    console.log(`    ${pc.cyan(a.id.padEnd(35))} ${typeLabel}  ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white((a.description || '').slice(0, 50))}`);
  }
  console.log('');

  // Custom
  console.log(`  ${pc.bold('Custom')}   ${pc.white(`(${customRows.length})`)}  ${pc.white('— your APIs and credentials')}`);
  console.log('');
  if (customRows.length === 0) {
    console.log(`    ${pc.white('None yet — run:')} ${pc.cyan('chariot configure')}`);
  } else {
    for (const a of customRows) {
      const toolCount = a.rest?.toolCount ?? a.mcp?.toolCount ?? 0;
      const typeLabel = pc.white(adapterTypeLabel(a.type));
      console.log(`    ${pc.cyan(a.id.padEnd(35))} ${typeLabel}  ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white((a.description || '').slice(0, 50))}`);
    }
  }
  console.log('');
}

// ─── chariot search ──────────────────────────────────────────

// bug-tracker-ref: the `search` command is owned by the chariot bin
// (src/bin/chariot.ts cmdSearch). The engine (setup.js) previously carried a
// FULL, divergent copy of search routing/render here — a drift trap: a prior
// session's CLI-output fix landed on THIS dead copy and had zero effect on
// `chariot search`. Collapsed to a single implementation: the engine no longer
// duplicates search logic; this stub redirects callers to the bin's path.
// (`chariot search` is dispatched by chariot.ts and never delegated to the
// engine, so this path is reached only by direct `setup.js search` invocation.)
async function cmdSearch(_term?: string): Promise<void> {
  console.error('`search` is handled by the chariot CLI. Run: chariot search <term>');
  process.exitCode = 1;
}

// ─── chariot configure ───────────────────────────────────────

async function cmdConfigure(): Promise<void> {
  const p = await import('@clack/prompts');
  const pc = (await import('picocolors')).default;

  // configure is fully interactive — no --config alternative exists. In
  // non-interactive mode the prompts would hang on closed stdin; exit
  // STDIN_REQUIRED(4) instead.
  const nonInteractive = process.env.CHARIOT_NON_INTERACTIVE === '1' ||
    (process.stdin && process.stdin.isTTY === false);
  if (nonInteractive) {
    console.error(pc.red('STDIN_REQUIRED: chariot configure is interactive.'));
    console.error(pc.dim('Use `chariot add <id>` per adapter with credentials in ~/.epic-ai/.env, or `chariot discover --config <file>`.'));
    process.exit(4);
  }

  console.log('');
  p.intro(pc.bgCyan(pc.black(' Chariot Configure — Connect Your APIs ')));

  const all = await loadAllAdapters();

  // Step 1: Where to look for credentials
  const scanTargets = await p.multiselect({
    message: 'Where should Chariot look for existing credentials?',
    options: [
      { value: 'epic-ai', label: '~/.epic-ai/.env', hint: 'Chariot\'s credential store' },
      { value: 'home', label: '~/.env', hint: 'home directory env file' },
      { value: 'cwd', label: '.env in current directory', hint: `${process.cwd()}/.env` },
    ],
    initialValues: ['epic-ai'],
    required: true,
  });
  if (p.isCancel(scanTargets)) { p.cancel('Cancelled.'); process.exit(0); }

  // Step 2: Scan and match
  const s = makeSpinner(p);
  s.start('Scanning for credentials');

  const foundCreds: Record<string, string> = {};

  if ((scanTargets as string[]).includes('epic-ai')) Object.assign(foundCreds, loadCredentials());
  if ((scanTargets as string[]).includes('home')) Object.assign(foundCreds, loadCredentialsFrom(join(homedir(), '.env')));
  if ((scanTargets as string[]).includes('cwd')) Object.assign(foundCreds, loadCredentialsFrom(join(process.cwd(), '.env')));

  s.stop('Scan complete');

  // Match credentials to adapters. Iterate effectiveEnvKeys (NOT
  // adapter.mcp?.envKeys directly) so adapters
  // whose published catalog row strips envKeys but whose canonical
  // brand id maps via CANONICAL_CREDENTIALED_BRANDS still match.
  // Prior code missed 1696/1777 entries on a fresh bundle.
  const matched: Array<{ adapter: AdapterEntry; key: string }> = [];
  for (const adapter of all) {
    if (CURATED_IDS.includes(adapter.id)) continue; // skip curated — already configured
    const envKey = adapter.rest?.envKey;
    if (envKey && foundCreds[envKey]) {
      matched.push({ adapter, key: envKey });
    } else {
      const mcpKeys = effectiveEnvKeys(adapter);
      for (const k of mcpKeys) {
        if (foundCreds[k]) { matched.push({ adapter, key: k }); break; }
      }
    }
  }

  if (matched.length === 0) {
    p.log.info('No matching credentials found in scanned locations.');
  } else {
    p.note(
      matched.map(m => `  ${pc.green(m.key.padEnd(30))} → ${pc.cyan(m.adapter.name)}`).join('\n'),
      `Found ${matched.length} credential${matched.length !== 1 ? 's' : ''}`
    );

    // Step 3: Confirm which to wire
    const toWire = await p.multiselect({
      message: 'Wire these adapters?',
      options: matched.map(m => ({
        value: m.adapter.id,
        label: m.adapter.name,
        hint: `${m.key} → ${m.adapter.description?.slice(0, 50) || m.adapter.id}`,
      })),
      initialValues: matched.map(m => m.adapter.id),
      required: false,
    });
    if (p.isCancel(toWire)) { p.cancel('Cancelled.'); process.exit(0); }

    // Step 4: Write to state and config via the immutable-update helper.
    //
// (cmdConfigure variant): two-phase write so a
    // bad control-char byte in any single credential value does not
    // leave prior keys persisted with state advanced to 'configured'
    // while later keys never reach disk. Validate the full set FIRST;
    // bail with a clear error before any write touches ~/.epic-ai/.env.
    // Shared CREDENTIAL_VALUE_CONTROL_CHAR_RE keeps the byte set
    // identical to writeCredential and other validators.
    type WireItem = { id: string; adapter: AdapterEntry; key: string; value: string };
    const wireItems: WireItem[] = [];
    for (const id of (toWire as string[])) {
      const m = matched.find(x => x.adapter.id === id);
      if (!m) continue;
      const value = foundCreds[m.key];
      if (typeof value !== 'string') continue;
      if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(value)) {
        console.error(pc.red(`${m.key}: source credential contains a control character (NUL/CR/LF/TAB/ESC/C1). Cannot wire ${m.adapter.id}.`));
        console.error(pc.dim('  Sanitize the source .env entry (re-encode binary data as base64) and re-run `chariot configure`.'));
        process.exit(2);
      }
      wireItems.push({ id, adapter: m.adapter, key: m.key, value });
    }
    let nextState = loadState();
    const config = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };
    for (const item of wireItems) {
      // Copy credential to ~/.epic-ai/.env if it came from elsewhere
      writeCredential(item.key, item.value);
      nextState = upsertAdapterState(nextState, item.id, {
        type: item.adapter.type || 'unknown',
        status: 'configured',
        toolCount: item.adapter.rest?.toolCount ?? item.adapter.mcp?.toolCount ?? 0,
        lastVerified: null,
      });
      if (!config.selectedAdapters.includes(item.id)) config.selectedAdapters.push(item.id);
    }
    saveState(nextState);
    saveConfig(config);

    if ((toWire as string[]).length > 0) {
      p.log.success(`${(toWire as string[]).length} adapter${(toWire as string[]).length !== 1 ? 's' : ''} configured.`);
    }
  }

  // Step 5: Add more manually?
  const addMore = await p.confirm({ message: 'Add adapters manually?', initialValue: false });
  if (!p.isCancel(addMore) && addMore) {
    const name = await p.text({ message: 'Adapter ID (run "chariot search <term>" to find one):' });
    if (!p.isCancel(name) && name) {
      await cmdAdd(name);
    }
  }

  p.outro(`${pc.green('Done.')} Run ${pc.cyan('chariot list')} to see your configured adapters.`);
}

// ─── chariot query ───────────────────────────────────────────

// per-tool input-schema fetch for cmdQuery arg extraction.
// MCP clients carry a `listTools()` method that returns full inputSchemas
// (Zod-like JSON schema). The cmdQuery router previously called every
// tool with `{ query }`, which broke any tool whose required field was
// not literally named "query" (playwright browser_navigate.url,
// pubmed search_mesh.term, etc.). We fetch the schema once per
// dispatch and feed it to extractToolArgs.
interface McpToolSchema {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string; enum?: unknown[] }>;
    required?: string[];
  };
}

interface ListToolsCapableClient {
  listTools(): Promise<{ tools: McpToolSchema[] }>;
}

// probe localhost for an OpenAI-compatible LLM endpoint.
// Order matches detectSystem's LOCAL_BACKENDS (Ollama is the common
// case). Returns the first reachable backend + the first model id it
// advertises, or null when nothing answers. Short timeouts so a missing
// service never adds more than ~2s to a CLI call.
interface LocalLLMHandle { baseUrl: string; model: string }
async function probeLocalLLM(): Promise<LocalLLMHandle | null> {
  const candidates = [
    { port: 11434, name: 'Ollama' },
    { port: 8080, name: 'llama.cpp' },
    { port: 8000, name: 'vLLM' },
  ];
  for (const c of candidates) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 1500);
    try {
      const resp = await fetch(`http://localhost:${c.port}/v1/models`, { signal: controller.signal });
      if (!resp.ok) continue;
      const ct = resp.headers.get('content-type') ?? '';
      if (!ct.includes('application/json')) continue;
      const body = (await resp.json()) as { data?: Array<{ id?: string }>; models?: Array<{ id?: string; name?: string }> };
      const id =
        body.data?.find((m) => typeof m.id === 'string')?.id ??
        body.models?.find((m) => typeof (m.id ?? m.name) === 'string')?.id ??
        body.models?.find((m) => typeof m.name === 'string')?.name;
      if (id) {
        return { baseUrl: `http://localhost:${c.port}`, model: id };
      }
    } catch {
      // fall through
    } finally {
      clearTimeout(t);
    }
  }
  return null;
}

/**
 * Resolve a tool name against the live server's tool list.
 * Returns { schema, knownAbsent, availableNames }.
 *
 * - schema         — the tool's input schema if found; null otherwise.
 * - knownAbsent    — true when listTools() succeeded AND toolName was not
 *                    in the list. Callers MUST refuse dispatch when true
 *                    to prevent -32601 Unknown tool errors from the server.
 * - availableNames — the tool names the server actually advertises, for
 *                    diagnostics. Empty when listTools() failed.
 *
 * knownAbsent is false (not true) when listTools() itself throws — we
 * cannot know whether the tool exists, so we do not block dispatch.
 */
async function resolveToolForDispatch(
  client: ListToolsCapableClient,
  toolName: string,
): Promise<{ schema: McpToolSchema | null; knownAbsent: boolean; availableNames: string[] }> {
  try {
    const listed = await client.listTools();
    // Treat a non-array tools field (null, undefined, malformed payload) as a
    // non-confirmable response — the same as a thrown error.  We cannot assert
    // the tool is absent if the server did not return a proper list.
    if (!Array.isArray(listed.tools)) {
      return { schema: null, knownAbsent: false, availableNames: [] };
    }
    const tools = listed.tools;
    const schema = tools.find((t) => t.name === toolName) ?? null;
    const availableNames = tools.map((t) => t.name);
    return { schema, knownAbsent: schema === null, availableNames };
  } catch {
    return { schema: null, knownAbsent: false, availableNames: [] };
  }
}

// extract tool arguments from a natural-language query
// against a tool's JSON-schema. Two paths:
//   1) LLM (preferred) — set CHARIOT_LLM_PROVIDER + CHARIOT_LLM_MODEL +
//      CHARIOT_LLM_API_KEY (or ANTHROPIC_API_KEY / OPENAI_API_KEY).
//      Forces tool_use against the supplied schema, returns the model's
//      arguments object verbatim.
//   2) Heuristic — always available, no API key required. Extracts
//      URLs, bare domains, and maps the residual query string onto
//      common param names (query, q, term, text, prompt, keyword,
//      question). Fills any unfilled `required` field with the raw query.
//
// Returns at minimum `{}` when no params can be mapped; never throws.
async function extractToolArgs(
  query: string,
  toolName: string,
  toolSchema: McpToolSchema | null,
): Promise<Record<string, unknown>> {
  const provider = process.env.CHARIOT_LLM_PROVIDER ?? '';
  const apiKey =
    process.env.CHARIOT_LLM_API_KEY ??
    process.env.ANTHROPIC_API_KEY ??
    process.env.OPENAI_API_KEY ??
    '';
  const model = process.env.CHARIOT_LLM_MODEL ?? '';

  // if the adapter did not surface a usable schema (transient listTools
  // failure, server with no metadata, etc.) DO NOT return {} — that's a
  // regression vs. the previous behavior, which called the tool with
  // {query} and worked for the (many) adapters whose primary tool happens
  // to take a `query` field. Fall back to {query} when no schema.
  if (!toolSchema || !toolSchema.inputSchema) {
    return { query };
  }

  // when no explicit cloud LLM config is set, probe for a
  // local OpenAI-compatible endpoint (Ollama 11434, llama.cpp 8080, vLLM
  // 8000). If one is up AND has at least one model loaded, route the
  // tool-call extraction through it with no API key. Customers on a
  // fresh Ollama install get correct arg extraction with zero config.
  let effectiveProvider = provider;
  let effectiveApiKey = apiKey;
  let effectiveModel = model;
  let effectiveBaseUrl = process.env.CHARIOT_LLM_BASE_URL;
  if (!effectiveProvider || !effectiveApiKey || !effectiveModel) {
    const local = await probeLocalLLM();
    if (local) {
      effectiveProvider = 'openai';
      effectiveApiKey = 'local';
      effectiveModel = local.model;
      effectiveBaseUrl = local.baseUrl;
    }
  }

  if (effectiveProvider && effectiveApiKey && effectiveModel && toolSchema?.inputSchema) {
    try {
      const { createGeneratorLLM } = await import('../orchestrator/GeneratorProvider.js');
      const llm = createGeneratorLLM({
        provider: effectiveProvider as 'anthropic' | 'openai' | 'ollama' | 'digitalocean' | 'custom',
        model: effectiveModel,
        apiKey: effectiveApiKey,
        baseUrl: effectiveBaseUrl,
        maxTokens: 512,
        timeoutMs: 20000,
      });
      const result = await llm({
        messages: [
          {
            role: 'system',
            content:
              'You are a tool argument extractor. Given a user question and one tool, call the tool with arguments derived from the question. Match the tool input_schema exactly. If a required field cannot be inferred, use the full user question as its value.',
          },
          { role: 'user', content: query },
        ],
        tools: [
          {
            name: toolName,
            description: toolSchema.description ?? `Call ${toolName}`,
            parameters: toolSchema.inputSchema as Record<string, unknown>,
          },
        ],
      });
      const call = result.toolCalls?.[0];
      if (call && call.name === toolName && call.arguments && typeof call.arguments === 'object') {
        return call.arguments;
      }
    } catch {
      // fall through to heuristic
    }
  }

  // ── Heuristic path ────────────────────────────────────────────────
  const args: Record<string, unknown> = {};
  const props = (toolSchema?.inputSchema?.properties ?? {}) as Record<
    string,
    { type?: string; description?: string; enum?: unknown[]; default?: unknown }
  >;
  const required: string[] = toolSchema?.inputSchema?.required ?? [];

  // Schema-aware value pick for enum-constrained fields (bug-tracker-ref: the old
  // heuristic wrote the raw query into ANY query-like key, so tavily_search
  // got topic="search wikipedia ..." and the API rejected it with
  // "Invalid topic. Must be general, news, or finance"). An enum field never
  // receives free text: use the declared default when it is a member, else
  // the first member when the field is required, else omit and let the
  // server default it.
  function pickEnumValue(prop: { enum?: unknown[]; default?: unknown }, isRequired: boolean): unknown | undefined {
    if (!Array.isArray(prop.enum) || prop.enum.length === 0) return undefined;
    if (prop.default !== undefined && prop.enum.includes(prop.default)) return prop.default;
    return isRequired ? prop.enum[0] : undefined;
  }
  function isFreeTextSafe(prop: { type?: string; enum?: unknown[] }): boolean {
    // Free text only into declared-string or untyped fields with no enum.
    return !Array.isArray(prop.enum) && (prop.type === undefined || prop.type === 'string');
  }

  const urlMatch = query.match(/\bhttps?:\/\/\S+/i);
  const domainMatch = query.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i);
  const inferredUrl = urlMatch
    ? urlMatch[0]
    : domainMatch
    ? `https://${domainMatch[0]}`
    : null;

  const QUERY_LIKE = new Set([
    'query',
    'q',
    'text',
    'question',
    'prompt',
    'search',
    'searchquery',
    'search_query',
    'keyword',
    'keywords',
    'topic',
    'subject',
    'message',
    'input',
  ]);
  const TERM_LIKE = new Set(['term', 'mesh', 'mesh_term', 'name', 'title']);

  // Strip common natural-language prefixes to derive a cleaner search term.
  function stripPrefixes(s: string): string {
    return s
      .replace(
        /^(please\s+)?(search|find|look\s*up|lookup|tell\s+me\s+about|what\s+is|who\s+is|navigate\s+to|go\s+to|fetch|get|show\s+me)\s+/i,
        '',
      )
      .replace(/\s+(on|in|using|via|from)\s+\w+(\s+for|\s+about)?\s*/i, ' ')
      .trim();
  }

  for (const key of Object.keys(props)) {
    const keyLc = key.toLowerCase();
    const prop = props[key];
    const enumValue = pickEnumValue(prop, required.includes(key));
    if (enumValue !== undefined) {
      args[key] = enumValue;
    } else if (Array.isArray(prop.enum)) {
      // enum field, not required, no usable default — let the server default it.
      continue;
    } else if (
      (keyLc === 'url' || keyLc.endsWith('url') || keyLc === 'uri' || keyLc.endsWith('_uri')) &&
      inferredUrl
    ) {
      args[key] = inferredUrl;
    } else if (QUERY_LIKE.has(keyLc) && isFreeTextSafe(prop)) {
      args[key] = query;
    } else if (TERM_LIKE.has(keyLc) && isFreeTextSafe(prop)) {
      args[key] = stripPrefixes(query);
    }
  }

  // Backfill required fields that the schema lookup did not cover —
  // pick the most-plausible value (URL for url-named requireds, the
  // raw query otherwise) so the call doesn't fail with missing-input.
  // Schema-aware: enum fields take an enum member (never free text) and
  // non-string-typed fields are left absent rather than filled with garbage.
  for (const reqKey of required) {
    if (reqKey in args) continue;
    const keyLc = reqKey.toLowerCase();
    const prop = props[reqKey] ?? {};
    const enumValue = pickEnumValue(prop, true);
    if (enumValue !== undefined) {
      args[reqKey] = enumValue;
    } else if ((keyLc === 'url' || keyLc.endsWith('url') || keyLc === 'uri') && inferredUrl) {
      args[reqKey] = inferredUrl;
    } else if (isFreeTextSafe(prop)) {
      args[reqKey] = query;
    }
  }

  return args;
}

async function cmdQuery(query: string): Promise<void> {
  const pc = (await import('picocolors')).default;
  const p = await import('@clack/prompts');

  const all = await loadAllAdapters();
  const state = loadState();
  const creds = loadCredentials();
  const config = loadConfig();

  // Anti-pattern 3.2 fix: use shared helper instead of duplicated loop
  const configuredIds = getConfiguredAdapterIds(all, creds, config, state);
  // Anti-pattern 3.4 fix: O(1) map for adapter lookup
  const adapterById = new Map(all.map(a => [a.id, a]));

  const configured = all.filter(a => configuredIds.has(a.id));
  if (configured.length === 0) {
    console.log(`\n  No adapters configured. Run ${pc.cyan('chariot')} to set up.\n`);
    process.exit(1);
  }

  // Route the query using ToolPreFilter (same engine as MCP server)
  const { ToolPreFilter } = await import('../federation/ToolPreFilter.js');
  const filter = new ToolPreFilter();
  filter.index(buildToolsForRouting(configured));

  // Phase 0 (3.1.0): vector-index.json no longer shipped/loaded — BM25-only.

  let matches = await filter.select(query, { maxTools: 5, maxPerServer: 2 });

  // brand-token pin. When the user's query contains a curated
  // adapter id as a whole-word token (case-insensitive), force that
  // adapter to win — regardless of BM25/vector ranking. Closes the gap
  // where "search wikipedia for photosynthesis" routes to pubmed because
  // "photosynthesis" outweighs "wikipedia" in BM25.
  try {
    const qTokens = query.toLowerCase().match(/[a-z][a-z0-9-]*/g) ?? [];
    const tokenSet = new Set(qTokens);
    const configuredBrandHit = configured.find((a) => tokenSet.has(a.id.toLowerCase()));
    if (!configuredBrandHit) {
      // bug-tracker-ref UX: the user named a catalog adapter that is not configured.
      // Routing will silently pick something else (e.g. a wikipedia query
      // landing on pubmed/tavily) — surface why, instead of hiding it.
      const catalogBrandHit = all.find((a) => tokenSet.has(a.id.toLowerCase()));
      if (catalogBrandHit) {
        console.log(
          `  ${pc.yellow('!')} "${catalogBrandHit.id}" matches a catalog adapter that is not configured — ` +
          `run ${pc.cyan(`chariot add ${catalogBrandHit.id}`)} to use it directly. Routing to the best configured alternative.`,
        );
      }
    }
    if (configuredBrandHit) {
      const topInExisting = matches[0]?.server === configuredBrandHit.id;
      if (!topInExisting) {
        const pinnedTool =
          (configuredBrandHit.mcp?.toolNames?.[0]) ||
          (configuredBrandHit.rest?.toolNames?.[0]) ||
          'default';
        const pinned = {
          name: `${configuredBrandHit.id}:${pinnedTool}`,
          server: configuredBrandHit.id,
          description: configuredBrandHit.description ?? configuredBrandHit.id,
          parameters: { type: 'object', properties: {} },
          tier: 'orchestrated' as const,
          score: 1,
        };
        // Splice the pinned match to the top; keep the rest as alternates.
        matches = [pinned, ...matches.filter((m) => m.server !== configuredBrandHit.id)];
      }
    }
  } catch { /* pin is a best-effort layer over BM25 — never let it crash */ }

  if (matches.length === 0) {
    console.log(`\n  No adapters matched "${query}".`);
    console.log(`  You have ${configured.length} configured adapters. Try a different query.\n`);
    process.exit(1);
  }

  const topServer = matches[0].server;
  const topToolFull = matches[0].name;
  const topToolName = topToolFull.includes(':') ? topToolFull.split(':').slice(1).join(':') : topToolFull;
  // Anti-pattern 3.4 fix: O(1) lookup
  const adapter = adapterById.get(topServer);

  if (!adapter) {
    console.log(`\n  Matched adapter "${topServer}" but it's not in the catalog.\n`);
    process.exit(1);
  }

  const s = makeSpinner(p);
  s.start(`Routing to ${adapter.name} → ${topToolName}`);

  // CLI dispatch health pings (bug-tracker-ref): the query path bypasses
  // handleCallImpl, so emit the tool-invocation ping here — including on the
  // process.exit failure branches, which would otherwise skip telemetry.
  const _healthEmitter = new ChariotHealthEmitter();
  const _healthStartMs = Date.now();
  const _emitCliPing = (outcome: 'success' | 'failure', errorCode?: string): void => {
    _healthEmitter.emit({
      adapterId: adapter.id,
      tenantId: process.env.CHARIOT_TENANT_ID ?? 'local',
      phase: 'tool-invocation',
      outcome,
      latencyMs: Math.max(0, Date.now() - _healthStartMs),
      ...(errorCode !== undefined ? { errorCode } : {}),
    });
  };

  try {
    let resultText = '';

    if (adapter.mcp?.transport === 'streamable-http' && adapter.mcp?.url) {
      const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
      const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
      const transport = new StreamableHTTPClientTransport(new URL(adapter.mcp.url));
      const client = new Client({ name: "chariot", version: PKG_VERSION }, { capabilities: {} });
      await client.connect(transport);
      try {
        const resolvedName = topToolName === 'default' ? (adapter.rest?.toolNames?.[0] ?? topToolName) : topToolName;
        const { schema: toolSchema, knownAbsent, availableNames } = await resolveToolForDispatch(client, resolvedName);
        if (knownAbsent) {
          // The catalog carried a stale tool name that the live server does not
          // recognise. Refusing here prevents MCP -32601 Unknown tool errors.
          // The catalog must be updated to remove the stale name (catalog fix
          // tracked separately; this engine gate fires fail-closed until then).
          const hint = availableNames.length > 0
            ? ` Server offers: ${availableNames.join(', ')}.`
            : '';
          throw new Error(`tool "${resolvedName}" is not available on ${adapter.name}.${hint} The catalog entry may be stale.`);
        }
        const toolArgs = await extractToolArgs(query, resolvedName, toolSchema);
        const result = await client.callTool({ name: resolvedName, arguments: toolArgs });
        resultText = renderMcpResult(result);
      } finally {
        await client.close();
      }
    } else if (adapter.mcp?.transport === 'stdio' && adapter.mcp?.command) {
      const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
      const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
      const transport = new StdioClientTransport({ command: adapter.mcp.command, args: adapter.mcp.args ?? [] });
      const client = new Client({ name: "chariot", version: PKG_VERSION }, { capabilities: {} });
      await client.connect(transport);
      try {
        const { schema: toolSchema, knownAbsent, availableNames } = await resolveToolForDispatch(client, topToolName);
        if (knownAbsent) {
          // Fail-closed: the catalog tool name was not found on the live server.
          // This prevents MCP -32601 errors and exposes the stale catalog entry.
          const hint = availableNames.length > 0
            ? ` Server offers: ${availableNames.join(', ')}.`
            : '';
          throw new Error(`tool "${topToolName}" is not available on ${adapter.name}.${hint} The catalog entry may be stale.`);
        }
        const toolArgs = await extractToolArgs(query, topToolName, toolSchema);
        const result = await client.callTool({ name: topToolName, arguments: toolArgs });
        resultText = renderMcpResult(result);
      } finally {
        await client.close();
      }
    } else if (adapter.rest?.module && adapter.rest?.className) {
 // defense-in-depth: confine to package root, including
      // realpath check against symlink escape.
      const confined = confinePath(adapter.rest.module, getPackageRoot());
      if (!confined.ok) {
        s.stop(`${pc.red('✗')} ${adapter.name}: adapter module path rejected (${confined.reason})`);
        process.exit(1);
      }
      const mod = await import(confined.resolved) as Record<string, unknown>;
      const AdapterClass = (mod[adapter.rest.className] ?? mod['default']) as new (cfg: Record<string, string>) => {
        callTool(n: string, a: Record<string, unknown>): Promise<{ content: unknown }>;
        validateInput?(n: string, a: unknown): Record<string, unknown>;
      };
      const adapterConfig: Record<string, string> = {};
      // b: source apiKey from BOTH ~/.epic-ai/.env
      // (creds arg) and process.env. Prior `creds[adapter.rest.envKey]`
      // was file-only and silently dropped credentials exported via
      // shell env (CI, containerised runs). Consistent with
      // credentialStatus and cmdHealth merged-view semantics.
      if (adapter.rest.envKey) {
        const apiKey = creds[adapter.rest.envKey] ?? process.env[adapter.rest.envKey];
        if (typeof apiKey === 'string' && apiKey.length > 0) adapterConfig['apiKey'] = apiKey;
      }
      if (adapter.rest.baseUrl) adapterConfig['baseUrl'] = adapter.rest.baseUrl;
      const instance = new AdapterClass(adapterConfig);
      // extract args from natural-language query (heuristic +
      // optional LLM); fall back to {query} for adapters whose validateInput
      // expects that shape.
      const heuristicArgs = await extractToolArgs(query, topToolName, null);
      const candidateArgs = Object.keys(heuristicArgs).length > 0 ? heuristicArgs : { query };
      const validatedArgs = typeof instance.validateInput === 'function'
        ? instance.validateInput(topToolName, candidateArgs)
        : candidateArgs;
      const result = await instance.callTool(topToolName, validatedArgs);
      resultText = typeof result.content === 'string' ? result.content : JSON.stringify(result.content);
    } else {
      _emitCliPing('failure', 'no_executable_transport');
      s.stop(`${pc.yellow('!')} No executable transport for ${adapter.name}`);
      process.exit(1);
    }

    if (resultText.trim().length === 0) {
      _emitCliPing('failure', 'empty_result');
      s.stop(`${pc.red('✗')} ${adapter.name} → ${topToolName}: no answer produced`);
      process.exit(1);
    }
    _emitCliPing('success');
    s.stop(`${pc.green('✓')} ${adapter.name} → ${topToolName}`);

    const lines = resultText.split('\n');
    if (lines.length > 30) {
      console.log('\n' + lines.slice(0, 30).join('\n'));
      console.log(pc.white(`\n  ... ${lines.length - 30} more lines. Full result returned above.`));
    } else {
      console.log('\n' + resultText);
    }
    console.log('');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    _emitCliPing('failure', 'dispatch_threw');
    s.stop(`${pc.red('✗')} ${adapter.name} — ${msg}`);
    // A failed tool call produced no answer; exit non-zero so callers/agents
    // can detect the failure instead of treating an empty run as success.
    process.exit(1);
  }
}

// ─── chariot help ────────────────────────────────────────────

async function cmdHelp(): Promise<void> {
  const pc = (await import('picocolors')).default;
  console.log('');
  console.log(`  ${pc.bold('Epic AI® Chariot')} — Intelligent Virtual Assistant (IVA)`);
  console.log('');
  console.log(`  ${pc.bold('Commands:')}`);
  console.log('');
  console.log(`    ${pc.cyan('chariot')}                      run the setup wizard`);
  console.log(`    ${pc.cyan('chariot query "<question>"')}    route a question to your adapters and return results`);
  console.log(`    ${pc.cyan('chariot list')}                  show Curated + Custom adapters`);
  console.log(`    ${pc.cyan('chariot search [term]')}         search all available adapters`);
  console.log(`    ${pc.cyan('chariot add <id>')}              add an adapter and enter credentials`);
  console.log(`    ${pc.cyan('chariot remove <id>')}           remove an adapter`);
  console.log(`    ${pc.cyan('chariot configure')}             connect your APIs and credentials`);
  console.log(`    ${pc.cyan('chariot health')}                check adapter status`);
  console.log(`    ${pc.cyan('chariot serve')}                 start MCP server over stdio (default)`);
  console.log(`    ${pc.cyan('chariot serve --http [port]')}   start Streamable-HTTP MCP (default 3550)`);
  console.log(`    ${pc.cyan('chariot serve --rest [port]')}   start REST JSON API (default 3551)`);
  console.log(`    ${pc.cyan('chariot help')}                  show this help`);
  console.log('');
  console.log(`  ${pc.white('Docs:')}  https://chariot.epic-ai.io`);
  console.log('');
}

// ─── Setup Wizard ───────────────────────────────────────────

async function runSetupWizard(): Promise<void> {
  const p = await import('@clack/prompts');
  const pc = (await import('picocolors')).default;

  // the interactive setup wizard cannot run in headless
  // environments (CI, scripted installs). When CHARIOT_NON_INTERACTIVE=1
  // or stdin is not a TTY, exit STDIN_REQUIRED(4) so callers diagnose
  // without hanging on a closed stdin prompt.
  const nonInteractive = process.env.CHARIOT_NON_INTERACTIVE === '1' ||
    process.stdin.isTTY === false;
  if (nonInteractive) {
    console.error(pc.red('STDIN_REQUIRED: chariot setup wizard is interactive.'));
    console.error(pc.dim('Run `chariot add <adapter-id>` per adapter, or set CHARIOT_NON_INTERACTIVE=0 in an interactive terminal.'));
    process.exit(4);
  }

  console.log('');
  p.note(
    `One self-hosted MCP server. Your context window only loads what the query needs.`,
    pc.bgCyan(pc.black(' Epic AI® Chariot '))
  );

  const s = makeSpinner(p);

  // Step 1: System detection
  s.start('Detecting your system');
  const system = await detectSystem();
  const allAdapters = await loadAllAdapters();
  s.stop('System detected');

  const detectedClients = system.mcpClients.filter(c => c.detected);
  const hasLocalLLM = system.localBackend !== null;

  p.note(
    [
      `${pc.green('✓')} Node.js ${system.nodeVersion}`,
      `${pc.green('✓')} ${system.platform} / ${system.arch}`,
      hasLocalLLM ? `${pc.green('✓')} ${system.localBackend} running on port ${system.localPort}` : `${pc.white('○')} No local LLM detected`,
      `${pc.green('✓')} ${allAdapters.length} adapters available`,
      `${pc.green('✓')} ${detectedClients.length} AI client${detectedClients.length !== 1 ? 's' : ''} detected`,
    ].join('\n'),
    'System'
  );

  // Step 2: AI client detection + config
  const configuredClients: string[] = [];

  if (detectedClients.length === 0 && !hasLocalLLM) {
    p.log.warning('No AI clients or local LLMs detected.');
    p.note(
      [
        'Install an MCP-compatible AI client:',
        '',
        `  ${pc.cyan('Claude Code')}   — npm install -g @anthropic-ai/claude-code`,
        `  ${pc.cyan('Cursor')}        — cursor.com`,
        `  ${pc.cyan('VS Code')}       — code.visualstudio.com + Copilot`,
        `  ${pc.cyan('Windsurf')}      — windsurf.com`,
        '',
        'Or install a local LLM:',
        '',
        `  ${pc.cyan('llama.cpp')}     — brew install llama.cpp`,
        `  ${pc.cyan('Ollama')}        — brew install ollama`,
      ].join('\n'),
      'Getting started'
    );
    const cont = await p.confirm({ message: 'Continue anyway? (you can configure clients later)', initialValue: false });
    if (p.isCancel(cont) || !cont) { p.cancel('Install an AI client and re-run.'); process.exit(0); }
  } else if (detectedClients.length > 0) {
    // Build options — detected clients pre-checked, plus local LLM option
    const clientOptions = detectedClients.map(c => ({
      value: c.id,
      label: c.name,
      hint: c.hint || c.configPath.replace(homedir(), '~'),
    }));

    if (hasLocalLLM) {
      clientOptions.push({
        value: 'local',
        label: `Local SLM (${system.localBackend} on port ${system.localPort})`,
        hint: 'No cloud LLM needed',
      });
    }

    const selectedClients = await p.multiselect({
      message: `Configure Chariot for these AI clients? (Space to toggle, Enter to confirm)`,
      options: clientOptions,
      initialValues: detectedClients.map(c => c.id), // all detected pre-selected
      required: false,
    });
    if (p.isCancel(selectedClients)) { p.cancel('Setup cancelled.'); process.exit(0); }

    // Write configs for selected clients
    const writeResults: string[] = [];
    for (const clientId of selectedClients) {
      if (clientId === 'local') continue; // handled separately
      const client = system.mcpClients.find(c => c.id === clientId);
      if (!client) continue;

      const autoWrite = await p.confirm({
        message: `Write Chariot to ${client.name} config? (${client.configPath.replace(homedir(), '~')})`,
        initialValue: true,
      });

      if (p.isCancel(autoWrite)) continue;

      if (autoWrite) {
        const result = writeMcpConfig(client, { command: 'npx', args: ['@epicai/chariot', '--serve'] });
        if (result.success) {
          if (result.error === 'already configured') {
            writeResults.push(`${pc.green('✓')} ${client.name} — already configured`);
          } else {
            writeResults.push(`${pc.green('✓')} ${client.name} — configured`);
          }
          configuredClients.push(clientId);
        } else {
          writeResults.push(`${pc.yellow('!')} ${client.name} — ${result.error}`);
        }
      } else {
        // Show the JSON for manual copy
        const serverEntry = { chariot: { command: 'npx', args: ['@epicai/chariot', '--serve'] } };
        const configStr = JSON.stringify({ [client.configKey]: serverEntry }, null, 2);
        p.note(
          [
            `Add this to ${pc.cyan(client.configPath.replace(homedir(), '~'))}:`,
            '',
            pc.white('─'.repeat(42)),
            configStr,
            pc.white('─'.repeat(42)),
          ].join('\n'),
          `${client.name} — manual config`
        );
        configuredClients.push(clientId);
      }
    }

    if (writeResults.length > 0) {
      p.note(writeResults.join('\n'), 'MCP Clients Configured');
    }

    // Handle local SLM if selected
    if (selectedClients.includes('local')) {
      p.log.success(`Using ${system.localBackend} on port ${system.localPort}`);
      configuredClients.push('local');
    }

    if (configuredClients.length === 0) {
      p.note(
        [
          `Add adapters later:  ${pc.cyan('npx @epicai/chariot add <name>')}`,
          `Check health:        ${pc.cyan('npx @epicai/chariot health')}`,
          `List all adapters:   ${pc.cyan('npx @epicai/chariot list')}`,
        ].join('\n'),
        'Quick reference'
      );
      saveConfig({ selectedAdapters: [], secretsProvider: 'manual', aiClient: 'none' });
      p.outro(`${pc.green('Done.')} Configure your AI clients and run this wizard again.\n  Your credentials never leave this machine.`);
      return;
    }
  } else if (hasLocalLLM) {
    // Only local LLM detected, no MCP clients
    p.log.success(`Using ${system.localBackend} on port ${system.localPort}`);
    configuredClients.push('local');
  }

  // Step 3: Auto-configure all curated (vetted zero-credential) adapters
  // IMPORTANT: Only add adapters to CURATED after manual vetting — confirm they
  // return real data, contain no adult/inappropriate content, and are stable.
  const CURATED = [
    {
      id: 'com-claude-mcp-pubmed-pubmed',
      name: 'PubMed',
      desc: 'Search 36 million biomedical research papers',
      tools: 7,
      demoQuery: 'Recent clinical trials on GLP-1 drugs for obesity',
      exampleQuery: 'chariot query "recent clinical trials on GLP-1 drugs for obesity"',
    },
    {
      id: 'govbase-mcp',
      name: 'Govbase',
      desc: 'Government data — legislators, bills, committees',
      tools: 10,
      demoQuery: 'Who chairs the Senate Armed Services Committee?',
      exampleQuery: 'chariot query "who chairs the Senate Armed Services Committee?"',
    },
    {
      id: 'searchcode',
      name: 'Searchcode',
      desc: 'Search 75 billion lines of open source code',
      tools: 6,
      demoQuery: 'Open source implementations of rate limiting in Go',
      exampleQuery: 'chariot query "open source implementations of rate limiting in Go"',
    },
    {
      id: 'robtex',
      name: 'Robtex',
      desc: 'Network intelligence — DNS, IP, ASN lookups',
      tools: 45,
      demoQuery: 'DNS records and ASN for cloudflare.com',
      exampleQuery: 'chariot query "DNS records and ASN for cloudflare.com"',
    },
  ];

  const s2 = makeSpinner(p);
  s2.start('Configuring curated data sources');

  let nextState = loadState();
  const curatedAdapterEntries = CURATED.map(c => allAdapters.find(a => a.id === c.id)).filter(Boolean) as AdapterEntry[];
  for (const c of CURATED) {
    const adapter = allAdapters.find(a => a.id === c.id);
    nextState = upsertAdapterState(nextState, c.id, {
      type: adapter?.type || 'mcp',
      status: 'configured',
      toolCount: c.tools,
      lastVerified: null,
    });
  }
  saveState(nextState);
  saveConfig({
    selectedAdapters: CURATED.map(c => c.id),
    secretsProvider: 'manual',
    aiClient: configuredClients.join(','),
    localBackend: system.localBackend || undefined,
  });

  s2.stop('Curated data sources configured');

  p.note(
    CURATED.map(c => `${pc.green('✓')} ${c.name.padEnd(14)} ${String(c.tools).padStart(2)} ${Number(c.tools) === 1 ? 'tool' : 'tools'}   ${pc.white(c.desc)}`).join('\n'),
    `Curated (${CURATED.length}) — no credentials required`
  );

  // Step 4: Routing demo — prove intelligence in-process, no network calls
  const { ToolPreFilter } = await import('../federation/ToolPreFilter.js');
  const demoFilter = new ToolPreFilter();
  demoFilter.index(buildToolsForRouting(curatedAdapterEntries));

  const routingLines: string[] = [];
  for (const c of CURATED) {
    const matches = await demoFilter.select(c.demoQuery, { maxTools: 3, maxPerServer: 2 });
    const topId = matches[0]?.server;
    const routed = topId === c.id;
    const arrow = routed ? pc.green('→') : pc.yellow('→');
    const adapterLabel = routed ? pc.green(c.name) : pc.yellow(topId || '?');
    routingLines.push(`  ${pc.white(`"${c.demoQuery.slice(0, 48)}${c.demoQuery.length > 48 ? '…' : ''}"`)}`);
    routingLines.push(`  ${arrow} ${adapterLabel}`);
    routingLines.push('');
  }

  p.note(routingLines.join('\n').trimEnd(), 'Routing intelligence');

  // Step 5: Outro — hand off to shell
  p.note(
    [
      pc.bold('Try these yourself:'),
      '',
      ...CURATED.map(c => `  ${pc.cyan(c.exampleQuery)}`),
    ].join('\n'),
    'Test it'
  );

  p.note(
    [
      `  ${pc.cyan('chariot configure')}   connect your APIs and credentials`,
      `  ${pc.cyan('chariot help')}        see all commands`,
    ].join('\n'),
    'When you\'re ready to connect your own APIs'
  );

  p.outro(`${pc.green('Chariot is ready.')} Your data never leaves this machine.`);
}

// ─── Main router ────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (args.includes('--serve')) {
    await startMcpServer();
    return;
  }

  // Update-availability notice (bug-tracker-ref) for interactive commands only —
  // never on query/serve paths where latency or piped output matters.
  // Runs before the command so internal process.exit() calls cannot skip it.
  if (command === undefined || ['health', 'list', 'help', '--help', '-h', 'search', 'setup', 'configure'].includes(command)) {
    const { maybeNotifyUpdate } = await import('./updateCheck.js');
    await maybeNotifyUpdate(PKG_VERSION);
  }

  switch (command) {
    case 'add':
      if (!args[1]) { console.error('Usage: chariot add <adapter-id>  (run "chariot search <term>" to find one)'); process.exit(1); }
      await cmdAdd(args[1]);
      break;
    case 'remove':
      if (!args[1]) { console.error('Usage: chariot remove <adapter-id>'); process.exit(1); }
      await cmdRemove(args[1]);
      break;
    case 'health':
      await cmdHealth();
      break;
    case 'list':
      await cmdList();
      break;
    case 'search':
      await cmdSearch(args[1]);
      break;
    case 'configure':
      await cmdConfigure();
      break;
    case 'help':
    case '--help':
    case '-h':
      await cmdHelp();
      break;
    case 'query': {
      const q = args.slice(1).join(' ');
      if (!q) { console.error('Usage: chariot query "<question>"'); process.exit(1); }
      await cmdQuery(q);
      break;
    }
    case 'serve':
      await startMcpServer();
      break;
    case 'setup':
      if (args.includes('--pre-install')) {
        await cmdPreInstall(args.slice(1));
      } else {
        await runSetupWizard();
      }
      break;
    default:
      await runSetupWizard();
      break;
  }
}

main().catch(err => {
  console.error('Chariot error:', (err as Error).message || String(err));
  process.exit(1);
});
