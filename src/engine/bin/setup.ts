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
import { redactConnectionString } from '../../iam/redactConnectionString.js';
import { existsSync, writeFileSync } from 'node:fs';
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
  restEnvKeys,
  restAllEnvKeys,
  buildRestAdapterConfig,
} from '../types/canonical-credentialed-brands.js';
import { getConfiguredAdapterIds } from '../federation/configuredAdapterIds.js';
import { confinePath, confineStdioCommand } from '../keys/pathConfinement.js';
import { findOnPath } from '../../cli/paths.js';
// `chariot query`'s cli-bridge dispatch branch reuses the SAME
// CLI-bridge subprocess primitives, DLP inspection, and injection scanner
// as the MCP/REST dispatch path (toolHandlers.ts handleCallInner Case 5) —
// one implementation of each security-critical surface, not a duplicate.
import { CLI_BASE_ENV_ALLOWLIST, CLI_STDERR_CAP_BYTES, redactStderr, spawnWithTimeout } from '../server/cliDispatch.js';
import { applyDlpInspection, applyInjectionScanner, MAX_RESPONSE_BYTES } from '../server/toolHandlers.js';
import { DlpInspector } from '../dlp/Inspector.js';
import { createLogger, validateChariotLogLevel } from '../logger.js';
// AS §1.5:334 structured-log requirement for the approval-refusal path —
// same createLogger the MCP/REST dispatch path uses (toolHandlers.ts
// `_approvalGateLogger`), a distinct component name for this CLI surface.
const _cliApprovalGateLogger = createLogger('engine.cli.query.approval');
// CHARIOT::§3.1::8 — "The system SHALL write wizard and health-check logs
// to ~/.epic-ai/logs/ (Chariot-process-owned), with Loki-style emission
// also available." (CHARIOT-SPEC.md:191). `{ logFile: true }` is the
// opt-in that makes createLogger append to <EPIC_AI_DIR>/logs/<component>.log
// in addition to the existing stderr + Loki emission; see runSetupWizard()
// and cmdHealth() below for the call sites.
const _wizardLog = createLogger('cli.wizard', undefined, { logFile: true });
const _healthLog = createLogger('cli.health', undefined, { logFile: true });
import { runPreInstall, readManifest } from './preinstall.js';
import { installStdioDependency } from '../../cli/installStdioDependency.js';
import { verifyNpmIntegrity } from '../federation/adapters/npmIntegrityGuard.js';
import { recommendModel } from '../../cli/modelRecommendation.js';
import { planLocalBackendStep } from '../../cli/localBackendStep.js';
import { filterAdapters, groupByCategory, getLicenseTierInfo } from '../../cli/adapterPicker.js';
import { renderConfigFile, validateGeneratedConfig } from '../../cli/configGenerator.js';
import { verifyAdapterConnection, type ConnectionDispatcher } from '../../cli/verifyAdapterConnection.js';
import {
  CREDENTIAL_VALUE_CONTROL_CHAR_RE,
  adapterTypeLabel,
  detectSystem,
  loadConfig,
  loadCredentials,
  loadCredentialsFrom,
  loadState,
  detectMcpClients,
  removeAdapterState,
  removeCredential,
  removeMcpConfig,
  saveConfig,
  saveState,
  upsertAdapterState,
  verifyMcpConfigLoaded,
  withLastHealthCheck,
  writeCredential,
  writeMcpConfig,
  type AdapterState,
} from '../../cli/index.js';

const _require = createRequire(import.meta.url);
const PKG_VERSION: string = (_require('../../../package.json') as { version: string }).version;

// ─── CH-31/CH-32 typed agent envelope ───────────────────────
// P9 owns the canonical src/cli/envelope.ts; it is not on this engine branch
// yet, so the query/serve paths here emit the SAME shape locally. When the CLI
// and engine branches integrate (P8), this should be replaced by an import of
// src/cli/envelope.ts — the field set is intentionally identical so the swap is
// mechanical.
interface ChariotCliEnvelope {
  ok: boolean;
  code: string;
  /** e.g. `cli:query`, `cli:serve` — the command that produced this. */
  surface: string;
  severity: 'ok' | 'info' | 'warning' | 'blocked' | 'error';
  cause?: string;
  human_message?: string;
  agent_message?: string;
  remediation?: string[];
  must_not?: string[];
  retryable: boolean;
  exit_code: number;
  data?: Record<string, unknown>;
}

/** True when the CLI is being driven by an agent and must speak JSON. */
function chariotAgentMode(argv: readonly string[] = process.argv.slice(2)): boolean {
  return argv.includes('--json') || process.env.CHARIOT_AGENT === '1';
}

/**
 * Emit a typed envelope as ONE JSON line on stdout and set process.exitCode.
 * Used only on the agent-mode query/serve paths so a real failure can never
 * present as exit-0 / human prose (CH-31). Never call this on the stdio serve
 * path — stdout there is the MCP JSON-RPC stream.
 */
function emitCliEnvelope(env: ChariotCliEnvelope): ChariotCliEnvelope {
  process.stdout.write(JSON.stringify(env) + '\n');
  process.exitCode = env.exit_code;
  return env;
}

function okEnvelope(surface: string, data?: Record<string, unknown>, human_message?: string): ChariotCliEnvelope {
  return {
    ok: true, code: 'OK', surface, severity: 'ok', retryable: false, exit_code: 0,
    ...(human_message !== undefined ? { human_message } : {}),
    ...(data !== undefined ? { data } : {}),
  };
}

function failEnvelope(
  surface: string,
  code: string,
  partial: Partial<Omit<ChariotCliEnvelope, 'ok' | 'surface' | 'code'>> = {},
): ChariotCliEnvelope {
  return {
    ok: false, code, surface,
    severity: partial.severity ?? 'error',
    retryable: partial.retryable ?? false,
    exit_code: partial.exit_code ?? 1,
    ...(partial.cause !== undefined ? { cause: partial.cause } : {}),
    ...(partial.human_message !== undefined ? { human_message: partial.human_message } : {}),
    ...(partial.agent_message !== undefined ? { agent_message: partial.agent_message } : {}),
    ...(partial.remediation !== undefined ? { remediation: partial.remediation } : {}),
    ...(partial.must_not !== undefined ? { must_not: partial.must_not } : {}),
    ...(partial.data !== undefined ? { data: partial.data } : {}),
  };
}

// ─── Package root ───────────────────────────────────────────

function getPackageRoot(): string {
  // dist/engine/bin/setup.js → '..','..','..','..') → package root
  const thisFile = fileURLToPath(import.meta.url);
  return join(thisFile, '..', '..', '..', '..');
}

// rulings item 126 (W-IAM-REDACT) — this file previously carried its OWN
// local copy of a "redact the URI" helper here, never importing the
// nominally-shared one at src/iam/redactUri.ts despite that file's own
// doc comment claiming it was extracted from exactly this local copy "so
// the two paths cannot drift." They had already drifted apart (two
// independent implementations) by the time this was caught. Both are now
// superseded by the single shared `redactConnectionString` (imported
// above) — see that module's own doc comment for the full rationale.

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
    // Include cli-bridge tool names (cli.toolSchemas[].name) so the CLI
    // query path indexes them, matching the server buildToolsForRouting.
    const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? adapter.cli?.toolSchemas?.map((s) => s.name) ?? [];
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

// The @clack spinner redraws via raw ANSI cursor escapes. On a
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

// Singularize tool counts ("1 tool", not "1 tools").
function toolsLabel(n: number): string { return `${n} ${Number(n) === 1 ? 'tool' : 'tools'}`; }

// Strip C0/C1 control characters (except tab/newline) from
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

// Render an MCP tool result. When the result is flagged isError,
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
  // MCP `instructions`: every client hands this to its model on connect, so the
  // AI itself guides first use (the AI is the interface). Both McpServer sites below use it.
  const { CHARIOT_SERVER_INSTRUCTIONS } = await import('../server/serverInstructions.js');
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

  // CH-31/CH-32: in agent mode serve emits a typed envelope. For HTTP/REST
  // stdout is free, so the "serving" envelope goes there. For stdio, stdout IS
  // the MCP JSON-RPC stream — the envelope must NOT be written to it, so the
  // stdio readiness signal goes to stderr instead (mirrors the existing
  // "listening on port" stderr convention).
  const agent = chariotAgentMode(argv);

 // instantiate the observability emitter in this child process
  // (it cannot cross the chariot.ts → engine/bin/setup.js process boundary).
  // Wire console-logger so retry events surface to stderr by default.
  const { ObservabilityEmitter } = await import('../observability/EventEmitter.js');
  const observabilityEmitter = new ObservabilityEmitter();
  observabilityEmitter.onLog(ObservabilityEmitter.consoleLogger(['apiKey', 'credential', 'token', 'jti']));

  // Load shared state (catalog, credentials, BM25 indexes)
  const state = await loadChariotState({ observabilityEmitter });
  const getTenantId = (): string => process.env.CHARIOT_TENANT_ID ?? 'local';

  // CH-45 — initialise the serve-path audit chain BEFORE binding any transport
  // so the very first tool dispatch is hash-chained to
  // ${EPIC_AI_DIR}/audit/default.jsonl. Covers stdio AND --http: the engine
  // HashChain write lives at the MCP dispatch boundary (handleCallImpl →
  // recordDispatch), the request-boundary locus §7.1/§8.4.1 prescribe. Before
  // this, AuditTrail was only reached via EpicAI.create() (orchestrator path),
  // which serve never calls — so real dispatches produced zero audit records.
  const { configureServeAudit, resolveAuditChainPath, resolveEpicAiDir, DEFAULT_CHAIN_ID } = await import('../audit/serveAuditSink.js');
  const auditTrail = await configureServeAudit();
  if (auditTrail) {
    process.stderr.write(`Chariot audit chain: ${resolveAuditChainPath()}\n`);
  }

  // §8.3–8.5: start the periodic anchor/attest cadence. Inert unless the
  // operator configured CHARIOT_TSA_URL (anchoring) and/or a ChainSigner
  // custody backend — kms/vault-transit selected, or the default
  // sealed-store already provisioned (see chainSigner.ts; there is no
  // plaintext env backend, CHARIOT::§9.8.1::1) — with a trigger interval;
  // throws loudly on a prerequisite-without-trigger misconfiguration
  // rather than silently ignoring the security config.
  const { startAuditCadence } = await import('../audit/auditCadence.js');
  startAuditCadence({
    chainId: DEFAULT_CHAIN_ID,
    packageRoot: resolveEpicAiDir(),
    chainFilePath: resolveAuditChainPath(),
  });

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
      const createMcpServer = (session: ResolvedMcpSession | undefined, req: import('node:http').IncomingMessage) => {
        const srv = new McpServer({ name: 'epic-ai-chariot', version: PKG_VERSION }, { instructions: CHARIOT_SERVER_INSTRUCTIONS });
        // Thread the verified per-request session into the tool
        // layer. JWT mode → real tenant + RBAC grants with localMode:false,
        // so handleCall enforces per-operation RBAC (deny-by-default) and
        // every tool reads the caller's own tenant (isolation).
        //
        // DECISION (flagged for security review): shared-bearer loopback mode
        // (CHARIOT_HTTP_TOKEN, no resolver → session undefined) stays
        // single-tenant localMode:true. That mode is documented
        // (transports/http.ts) as single-tenant loopback where the shared
        // secret IS the trust boundary; there is no cross-tenant surface to
        // isolate. The multi-tenant JWT path running localMode:
        // true — that is what this closes. Switching shared-bearer to
        // deny-by-default would break documented loopback deployments.
        // Audit attribution: client IP from the request socket,
        // regardless of auth mode — JWT and shared-bearer/loopback requests
        // both arrive over the same per-request node:http socket. Undefined
        // only if the socket has already been destroyed.
        const sourceIp = req.socket.remoteAddress;
        const sec = session
          ? { tenantId: session.tenantId, auth: session.auth, localMode: false, sessionId: session.sessionId, sessionJti: session.sessionId, sourceIp }
          : { tenantId: getTenantId(), localMode: true, sessionId: undefined, sourceIp };
        registerChariotTools(srv, state, sec);
        return srv;
      };

      // master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)
      // CHARIOT::§18.2::1/2 — `serve --http` gates IAM/Mongo/Redis loading
      // on CHARIOT_ENTERPRISE. "Single-user mode: `npx @epicai/chariot`
      // with no `CHARIOT_ENTERPRISE=1`. Loads only the engine (no IAM, no
      // MongoDB requirement, no Redis requirement)." / "Enterprise mode:
      // `CHARIOT_ENTERPRISE=1 npx @epicai/chariot`. Loads the IAM service,
      // requires `ENTERPRISE_MASTER_KEY`, requires MongoDB, optionally uses
      // Redis (in-process fallback if absent)." (CHARIOT-SPEC.md:1465-1469)
      //
      // Before this fix the entire IAM/Mongo/Redis bootstrap+mount block
      // below ran unconditionally for every `--http` invocation regardless
      // of CHARIOT_ENTERPRISE — a plain `chariot serve --http` (single-user,
      // no flag) still hard-required MONGODB_URI and mounted the enterprise
      // OAuth/IAM surface, directly contradicting §18.2::1's "no IAM, no
      // MongoDB requirement, no Redis requirement." isEnterpriseEnvEnabled()
      // is the same CHARIOT_ENTERPRISE=1/true parser iam/bootstrap.ts's
      // isEnterpriseModeRequested() uses, so the flag cannot mean two
      // different things across the two enterprise-startup paths.
      const { isEnterpriseEnvEnabled } = await import('../../license/loader.js');
      const enterpriseRequested = isEnterpriseEnvEnabled();
      let iamApp: import('express').Express | undefined;
      let resolveSessionId: undefined | ((req: import('node:http').IncomingMessage) => Promise<ResolvedMcpSession | null>);

      if (enterpriseRequested) {
      // CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)) —
      // fail-fast BEFORE any other enterprise bootstrap work: refuses to
      // bind CHARIOT_PROMETHEUS_EXPORTER=1 without CHARIOT_METRICS_TOKEN
      // set, rather than silently serving an unauthenticated /metrics
      // endpoint. Mirrors the existing ENTERPRISE_JWT_SECRET / IAM
      // bootstrap fail-fast pattern later in this same block.
      const {
        assertPrometheusExporterConfigValid,
        isPrometheusExporterEnabled,
        createPrometheusMetricsRouter,
      } = await import('../../observability/prometheusRoute.js');
      assertPrometheusExporterConfigValid();

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
      // Single-replica posture — uses local Mongo at MONGODB_URI (required;
      // no fallback — see the fail-closed check below, CHARIOT::§18.2::2) and
      // an in-process Redis shim that satisfies the RedisClientType surface
      // the IAM modules import. Multi-replica deployments require a real
      // Redis client pointed at a shared instance — gate that in a separate
      // fix when multi-replica ships.
      let iamBootstrapOk = false;
      // Capture iamDb reference for use in getActiveUserCount below.
      // Initialized inside the bootstrap try-block; non-null by the time
      // createEnterpriseRoutes is called because iamBootstrapOk guards it.
      let _iamDb: typeof import('../../iam/db.js') | null = null;
      try {
        // CHARIOT::§18.3::1 — "IF the master key is missing in enterprise
        // mode THEN the system SHALL fail-fast at startup (CH-19)."
        // (CHARIOT-SPEC.md:1472) requireMasterKeyForEnterpriseStartup()
        // throws synchronously with the "Enterprise startup failed: ..."
        // prefix shared with iam/bootstrap.ts's requireEnv(); letting that
        // throw propagate here (caught by this same try/catch, surfaced via
        // the iamBootstrapOk gate below) is startup fail-fast — no route is
        // mounted, no request is served, before this check runs.
        const { requireMasterKeyForEnterpriseStartup } = await import('../../iam/bootstrap.js');
        requireMasterKeyForEnterpriseStartup();
        const { MongoClient } = await import('mongodb');
        const iamDb = await import('../../iam/db.js');
        _iamDb = iamDb;
        const iamRedis = await import('../../iam/redis.js');
        const iamJtiCache = await import('../../iam/services/jti-replay-cache.js');

        // CHARIOT::§18.2::2 — enterprise mode "requires MongoDB"; fail closed
        // on an unset MONGODB_URI exactly like iam/bootstrap.ts's requireEnv()
        // rather than silently defaulting to an unauthenticated loopback
        // Mongo. The prior `?? 'mongodb://127.0.0.1:27017'` fallback let this
        // path succeed against whatever unauthenticated Mongo happened to be
        // listening on 127.0.0.1:27017 when the operator forgot to set the
        // variable — a divergent, weaker posture than bootstrapEnterprise(),
        // which throws immediately on the same unset variable.
        if (!process.env.MONGODB_URI || process.env.MONGODB_URI.trim() === '') {
          throw new Error(
            'Enterprise startup failed: MONGODB_URI is not set. ' +
            'Required for enterprise IAM data storage. ' +
            'Example: mongodb://localhost:27017/'
          );
        }
        const mongoUri = process.env.MONGODB_URI;
        const mongoDb = process.env.MONGODB_DB ?? 'chariot';
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
        // §3.5::17 (CH-12) — install the pre-dispatch hash-chained audit hook
        // now that the IAM Mongo connection is live. Attached to ChariotState
        // (installation-scoped) so every transport's dispatch path picks it up
        // without per-request wiring. Deliberately inside the enterprise-IAM
        // bootstrap: OSS / stdio installs never load src/iam at all.
        const { createDecisionAuditPort } = await import('../../iam/services/decisionAuditPort.js');
        state.decisionAudit = createDecisionAuditPort();

        const { ensureEnterpriseIndexes } = await import('../../iam/indexes.js');
        const { backfillSubIdAliasCanon } = await import('../../iam/services/id-jag-issuer.js');
        const _iamDbForIndexes = await iamDb.getDb();
        // Backfill canon BEFORE index creation so the unique-canon build
        // validates corrected values (upgrade / format-change safety).
        await backfillSubIdAliasCanon(_iamDbForIndexes);
        await ensureEnterpriseIndexes(_iamDbForIndexes);

        // CHARIOT::§18.2::2 / §18.3::4 — resolveEnterpriseRedisClient()
        // (src/iam/resolveEnterpriseRedis.ts) is also used by
        // bootstrapEnterprise() in src/iam/bootstrap.ts, so the two
        // enterprise-startup paths cannot diverge on Redis-absent/
        // unreachable semantics: unset REDIS_URL -> in-process shim
        // (silent — the documented default); set but unreachable at boot
        // -> single WARN naming the redacted host, then the same shim
        // (degrade, never a hard failure — see that module for the full
        // §18.3::4 clause quote and rationale); set and reachable -> the
        // real client. Multi-replica deployments require a real Redis
        // client pointed at a shared instance — gate that in a separate
        // fix when multi-replica ships.
        const { resolveEnterpriseRedisClient } = await import('../../iam/resolveEnterpriseRedis.js');
        const redisUrl = process.env.REDIS_URL;
        const { redisClient, redisMode, degraded: redisDegraded, reason: redisDegradedReason } = await resolveEnterpriseRedisClient(
          redisUrl,
          (message, data) => process.stderr.write(`Chariot IAM bootstrap WARN: ${message} ${data ? JSON.stringify(data) : ''}\n`),
        );
        iamSessionMod.setRedisClient(redisClient as any);
        iamJtiCache.setRedisClient(redisClient as any);
        iamRedis.setRedisClient(redisClient as any);
        // CHARIOT::§18.3 — thread the degrade state into session.ts so
        // verifyToken() knows whether a missing activity key is fail-closed
        // (normal) or ignorable (degraded — see setSessionRedisDegraded()'s
        // doc in src/iam/services/session.ts).
        iamSessionMod.setSessionRedisDegraded(redisDegraded, redisDegradedReason);
        // Never log REDIS_URL itself — it may embed a password. Redact
        // mongoUri for the same reason: it may embed admin credentials.
        process.stderr.write(
          `Chariot IAM bootstrap: mongo=${redactConnectionString(mongoUri)} db=${mongoDb} ` +
          `redis=${redisMode === 'external' ? 'external (REDIS_URL)' : 'in-process-shim (DEV/degrade — set a reachable REDIS_URL for a restart-surviving, shareable store)'}\n`,
        );
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
      iamApp = express();
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

      // CHARIOT::§16.3::1 (rulings item 91(3)) — inject the process-wide
      // ChariotMetrics instance (constructed once by loadChariotState()
      // above, the SAME instance bindRest() reads at
      // src/engine/server/transports/rest.ts:244) into the admin router's
      // GET /enterprise/:tenantId/admin/metrics route. Guarded: a
      // synthetic/test ChariotState may not carry one.
      if (state.chariotMetrics) {
        const { setChariotMetricsSource } = await import('../../iam/routes/admin.js');
        setChariotMetricsSource(state.chariotMetrics);
      }

      // CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)) — the
      // global, Prometheus-format GET /metrics, mounted only when the
      // exporter flag is set (assertPrometheusExporterConfigValid() above
      // already refused startup if the flag were set without a token).
      if (isPrometheusExporterEnabled()) {
        iamApp.use(createPrometheusMetricsRouter(() => state.chariotMetrics));
      }

      // CHARIOT::§16.2 (CHARIOT-SPEC.md:1354-1365, rulings item 91(2)/105)
      // — subscribe the process-wide channel-dispatching AlertQueue to
      // chariotEmitter, delivering through the SAME toolHandlers.handleCall
      // path chariot_call uses (src/observability/alertDispatchWiring.ts).
      {
        const {
          wireAlertDispatch,
          createFederationAlertDispatcher,
          createMongoAdminContactResolver,
          createChariotStateConnectedChannelsResolver,
        } = await import('../../observability/alertDispatchWiring.js');
        const { chariotAlertQueue } = await import('../../observability/alerts.js');
        wireAlertDispatch(
          chariotAlertQueue,
          createFederationAlertDispatcher(state),
          createMongoAdminContactResolver(),
          createChariotStateConnectedChannelsResolver(state),
        );
      }
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
            // Pin the token's tenant to THIS process's configured
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
              // CHARIOT::§16.2 step 4 (rulings item 91(2)/115(b)) — isAdmin
              // is already part of the verified JWT payload
              // (src/iam/services/session.ts:386); threaded here so the
              // pendingAlerts gate can read it from the SAME verified
              // session, not a second lookup.
              auth: { allowedOperations: decoded.allowedOperations, userId: decoded.userId, isAdmin: decoded.isAdmin },
            };
          } catch {
            return null;
          }
        };
      }

      } else {
        // CHARIOT::§18.2::1 — single-user mode: no IAM, no MongoDB
        // requirement, no Redis requirement. iamApp/resolveSessionId stay
        // undefined; bindHttp() below falls back to its existing
        // shared-bearer/loopback (CHARIOT_HTTP_TOKEN) or fully-open local
        // posture, unchanged from pre-gate behavior for this mode.
        process.stderr.write(
          'Chariot HTTP transport: single-user mode (CHARIOT_ENTERPRISE not set) — ' +
          'no IAM, no MongoDB, no Redis loaded.\n',
        );
      }


      // Optional mutual TLS for the /mcp surface. Absent (default): plain
      // node:http, unchanged from pre-mTLS behavior. Bearer-JWT/shared-
      // bearer auth above is unaffected either way — mTLS is an additional
      // transport-layer control, not a replacement for it.
      const httpTlsConfig = {
        certPath: process.env.CHARIOT_HTTP_TLS_CERT,
        keyPath: process.env.CHARIOT_HTTP_TLS_KEY,
        caPath: process.env.CHARIOT_HTTP_TLS_CA,
      };
      const h = await bindHttp(httpPort, { createMcpServer, iamApp, resolveSessionId, tlsConfig: httpTlsConfig });
      handles.push(h);
      process.stderr.write(`Chariot HTTP MCP listening on port ${h.port}\n`);
    }

    if (useRest) {
      // Optional mutual TLS for the REST surface. Separate env vars from
      // the /mcp surface (mirrors CHARIOT_REST_TOKEN vs CHARIOT_HTTP_TOKEN)
      // so the two transports can run with different certs when both are
      // enabled simultaneously. Absent (default): plain node:http.
      const restTlsConfig = {
        certPath: process.env.CHARIOT_REST_TLS_CERT,
        keyPath: process.env.CHARIOT_REST_TLS_KEY,
        caPath: process.env.CHARIOT_REST_TLS_CA,
      };
      const h = await bindRest(state, restPort, getTenantId, restTlsConfig);
      handles.push(h);
      process.stderr.write(`Chariot REST API listening on port ${h.port}\n`);
    }

    if (useStdio) {
      const srv = new McpServer({ name: 'epic-ai-chariot', version: PKG_VERSION }, { instructions: CHARIOT_SERVER_INSTRUCTIONS });
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
      // stays true (RBAC bypass opt-in) with the process tenant. This
      // only changes the multi-tenant HTTP path; stdio is unchanged.
      registerChariotTools(srv, state, { tenantId: getTenantId(), localMode: true, sessionId: stdioSessionId });
      // CH-31/CH-32: stdout is the MCP stream on stdio — emit the typed
      // readiness envelope on STDERR so an agent gets a machine-parseable
      // "serving" signal without corrupting the protocol.
      if (agent) {
        process.stderr.write(JSON.stringify(
          okEnvelope('cli:serve', { transport: 'stdio', pid: process.pid }, 'Chariot MCP serving over stdio.'),
        ) + '\n');
      }
      await bindStdio(srv);
    }
  } catch (err) {
    // Startup failure: close already-bound transports in reverse order.
    for (const h of [...handles].reverse()) await h.close().catch(() => { /* intentionally empty */ });
    if (agent) {
      // Envelope emitted + exitCode set — do NOT rethrow into main().catch() prose handler.
      emitCliEnvelope(failEnvelope('cli:serve', 'INTERNAL_ERROR', {
        cause: err instanceof Error ? err.message : String(err),
        agent_message: `chariot serve failed to bind: ${err instanceof Error ? err.message : String(err)}`,
        retryable: true,
        data: { http: useHttp ? httpPort : null, rest: useRest ? restPort : null },
      }));
      return;
    }
    throw err;
  }

  if (handles.length > 0) {
    // CH-31/CH-32: HTTP/REST stdout is free — emit the typed "serving"
    // envelope so an agent can branch on bound transports/ports.
    if (agent) {
      emitCliEnvelope(okEnvelope('cli:serve', {
        transports: handles.map((h) => h.port),
        http: useHttp ? httpPort : null,
        rest: useRest ? restPort : null,
      }, 'Chariot MCP serving.'));
      // serve is long-lived; keep the success exit code at 0 while alive.
      process.exitCode = 0;
    }
    // HTTP/REST mode: keep alive until signal
    //
    // CHARIOT §11.4::2/::3 (rulings item 88, order B2 -> B3): the license
    // loader's 60s in-memory cache (loader.ts CACHE_TTL_MS) needs a disk
    // re-read forced on two triggers besides its own TTL expiry — an
    // operator SIGHUP, and an automatic 6-hour renewal cycle. Both only
    // make sense in this long-running HTTP/REST server process (a
    // one-shot CLI invocation has no persistent cache to invalidate), so
    // both are wired here, dynamically imported like the other
    // license/IAM modules above so a plain stdio-only single-user run
    // never loads this code.
    //
    // CHARIOT-SPEC.md:1167 — "The license loader caches the parsed
    // license in process memory for 60 seconds. Disk re-read happens on
    // cache miss and on every 6-hour renewal cycle. The cache is
    // invalidated on SIGHUP for operator-driven reloads."
    const { invalidateLicenseCache, revalidateLicense, isEnterpriseEnvEnabled } = await import('../../license/loader.js');
    const { renewNow } = await import('../../license/renew-client.js');

    // §11.4::3 — SIGHUP invalidates the license cache for an
    // operator-driven reload (e.g. after `chariot license activate
    // <path>` rewrites the envelope on disk). `invalidateLicenseCache()`
    // clears EVERY tenant's cache slot (SIGHUP is a single global signal
    // with no tenant context) rather than `revalidateLicense(tenantId)`'s
    // single-slot invalidation. The next `validateLicense()` call per
    // tenant then re-reads disk on its own (this handler does not force
    // an eager re-read — the spec says "invalidated", not "re-read now";
    // the eager read is §11.4::2's job, on the renewal timer below).
    process.on('SIGHUP', () => {
      invalidateLicenseCache();
    });

    // §11.4::2 — automatic 6-hour renewal cycle. Reuses `renewNow()`
    // (src/license/renew-client.ts) unchanged — it already emits the
    // pinned `license.renewed` / `license.renew_failed` events at its one
    // return point (CHARIOT::§16.1, rulings item 91), so this timer adds
    // no new emit call, only the schedule. Ruling item 88(4): "Failed
    // 6-hour auto-renewal: emit license.renewal_failed [the canonical
    // wired name is `license.renew_failed` — see report], keep the
    // current license, retry only at the next 6-hour tick." Verified
    // against renew-client.ts source (not assumed): on a genuine HTTP
    // failure (unauthorized/network_error/jwt_stale/etc.) `renewNowInner`
    // returns early WITHOUT calling `writeLicenseEnvelopeAtomic` at all —
    // the on-disk envelope is untouched, satisfying "keep the current
    // license" directly. The one path that DOES write before failing is
    // the post-renewal-validation-failed branch (envelope verified fine,
    // but the newly renewed JWT fails `validateLicense` after being
    // written): that branch writes the NEW envelope, detects the bad
    // validation result, then writes the ORIGINAL envelope straight back
    // as a best-effort restore before returning `kind: 'invalid_response'`
    // — so the caller still ends up with "the current license" on disk
    // once the call returns, just via a write-then-restore rather than
    // never writing. "Retry only at the next tick" is exactly what a
    // plain `setInterval` (no inner retry loop) provides. After each
    // attempt (success OR failure) `revalidateLicense()` forces the
    // eager disk re-read §11.4::2's own text requires ("Disk re-read
    // happens ... on every 6-hour renewal cycle" — the cycle itself is
    // the second trigger, independent of the 60s TTL and independent of
    // whether the renewal call succeeded).
    const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
    const renewalTimer = setInterval(() => {
      void renewNow()
        .catch((err: unknown) => {
          // renewNow() itself never throws on a modeled RenewOutcome (every
          // failure path returns a RenewOutcome variant); a thrown error
          // here means something outside that contract broke (e.g. a bug
          // in the timer's own environment) — log and let the next 6h
          // tick retry rather than crashing the server process.
          process.stderr.write(
            `[license] automatic 6-hour renewal threw unexpectedly: ${err instanceof Error ? err.message : String(err)}\n`,
          );
        })
        .finally(() => {
          revalidateLicense();
        });
    }, SIX_HOURS_MS);
    // Do not hold the process open on this timer alone — SIGTERM/SIGINT
    // shutdown must still work even if the timer is mid-interval.
    renewalTimer.unref();

    // CHARIOT §10.5::1 (rulings item 88, order B2 -> B3 -> B4 -> B5): the
    // per-user OAuth vendor-token refresh job — "background job every 5
    // minutes finds tokens within 10 minutes of expiry" (CHARIOT-SPEC.md:1063).
    // Enterprise-mode only: `iam_adapter_credentials` lives in Mongo, which
    // §18.2::1 explicitly does NOT require in single-user mode — unlike
    // the license timer/SIGHUP handler above (license validation applies
    // regardless of CHARIOT_ENTERPRISE per §11.2's four modes), this timer
    // would call `getCollection()` against a Mongo connection that was
    // never bootstrapped in single-user mode. `isEnterpriseEnvEnabled()`
    // re-read here is safe: by this point in `startMcpServer()`, either it
    // is false (IAM/Mongo bootstrap block above never ran), or it is true
    // AND `iamBootstrapOk` was true (a false `iamBootstrapOk` throws and
    // aborts startup before this keep-alive block is ever reached — see
    // the fail-fast check above) — so a true result here always means
    // Mongo is live.
    if (isEnterpriseEnvEnabled()) {
      // Reuses `state.allAdapters` (the same catalog handle
      // `loadIamCredentialsForTenant` is passed at dispatch time) so
      // `resolveAdapterTokenEndpoint` can look up each credential row's
      // adapter without a second catalog load.
      const { refreshExpiringCredentials, REFRESH_JOB_INTERVAL_MS } = await import('../../iam/services/credentials.js');
      const credentialRefreshTimer = setInterval(() => {
        void refreshExpiringCredentials(state.allAdapters).catch((err: unknown) => {
          // refreshExpiringCredentials only throws on a genuine unexpected
          // write failure (VaultUpgradePersistFailedError) — every modeled
          // per-row outcome (skip/fail/refresh) is caught and counted
          // internally. Log and let the next 5-minute tick retry, matching
          // the license renewal timer's own failure posture above.
          process.stderr.write(
            `[credentials] 5-minute OAuth refresh cycle threw unexpectedly: ${err instanceof Error ? err.message : String(err)}\n`,
          );
        });
      }, REFRESH_JOB_INTERVAL_MS);
      credentialRefreshTimer.unref();
    }

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

/**
 * Resolve a customer-typed adapter argument (`chariot add <arg>`) against
 * the full adapter list. An exact `id` match ALWAYS wins over a `name`
 * match, checked across the WHOLE collection first — never picked by
 * array order.
 *
 * FIX (2026-09-30, dogfood mechanism-test-mcp, gate BLOCK
 * verdict.1.json): the prior single linear
 * `all.find(a => a.id === adapterName || a.name.toLowerCase() === ...)`
 * evaluated the OR per-element in array order, so a row that matched only
 * by `name` — earlier in `all` than the row whose `id` matched the typed
 * argument exactly — shadowed it. Reproduced live: `chariot add
 * tavily-mcp` resolved to catalog id `runno` (a malformed duplicate row
 * that also happens to have `name: "tavily-mcp"`, at array index 5051)
 * instead of id `tavily-mcp` (array index 5542), because `runno` was
 * reached first. `runno`'s bogus `DEFAULT_PARAMETERS` credential and the
 * customer-facing `human_message` naming adapter "runno" instead of
 * "tavily-mcp" both trace to this bug, not to the catalog row.
 *
 * When several rows match only by NAME (no exact `id` match exists) this
 * is now a genuine ambiguity, not a silent array-order pick: return
 * `{ kind: 'ambiguous', ids }` and let the caller ask the customer to
 * re-run with the exact `id`.
 */
function resolveAdapterByIdOrName(
  all: readonly AdapterEntry[],
  adapterName: string,
): { kind: 'found'; adapter: AdapterEntry } | { kind: 'ambiguous'; ids: readonly string[] } | { kind: 'not-found' } {
  const exactId = all.find(a => a.id === adapterName);
  if (exactId) return { kind: 'found', adapter: exactId };
  const nameMatches = all.filter(a => a.name.toLowerCase() === adapterName.toLowerCase());
  if (nameMatches.length === 1) return { kind: 'found', adapter: nameMatches[0] };
  if (nameMatches.length > 1) return { kind: 'ambiguous', ids: nameMatches.map(a => a.id) };
  return { kind: 'not-found' };
}

async function cmdAdd(adapterName: string): Promise<void> {
  const p = await import('@clack/prompts');
  const pc = (await import('picocolors')).default;

  const all = await loadAllAdapters();

  const resolved = resolveAdapterByIdOrName(all, adapterName);
  if (resolved.kind === 'ambiguous') {
    console.log(`Adapter "${adapterName}" matches multiple catalog entries by name: ${resolved.ids.join(', ')}. Re-run with the exact id, e.g. ${pc.cyan(`chariot add ${resolved.ids[0]}`)}.`);
    process.exit(1);
  }
  if (resolved.kind === 'not-found') {
    const fuzzy = all.filter(a => a.id.includes(adapterName) || a.name.toLowerCase().includes(adapterName.toLowerCase()));
    if (fuzzy.length > 0) {
      console.log(`Adapter "${adapterName}" not found. Did you mean:`);
      fuzzy.slice(0, 5).forEach(a => console.log(`  ${pc.cyan(a.id)} — ${a.name}`));
    } else {
      console.log(`Adapter "${adapterName}" not found. Run ${pc.cyan('npx @epicai/chariot list')} to see all adapters.`);
    }
    process.exit(1);
  }
  const match = resolved.adapter;

  const s = makeSpinner(p);

  // Install stdio dependency if needed — CHARIOT::§17.2::10, shared with
  // the setup wizard's step 4 (runSetupWizard) via installStdioDependency.
  //
  // W42-FIX (row 1.42 proof, gap 1 of 3): gating on `mcp.packageName` here
  // silently skipped this whole block for virtually every real catalog
  // row — a direct read of the signed bundle (chariot-adapter-bundle.json)
  // shows `mcp.packageName` is ABSENT on real stdio/npx entries; the
  // package spec lives in `mcp.args` instead. `installStdioDependency()`
  // derives the name internally (packageName, else first non-flag `args`
  // entry) and returns `'not-applicable'` when nothing resolves, so gate
  // on transport alone and let it decide.
  if (match.mcp?.transport === 'stdio') {
    s.start(`Installing ${match.name}`);
    const result = installStdioDependency(
      match,
      (bin, argv, timeoutMs) => {
        // spawnSync array form — no shell metacharacter exposure.
        const r = spawnSync(bin, argv, { stdio: 'pipe', timeout: timeoutMs });
        return { error: r.error, status: r.status, signal: r.signal };
      },
      verifyNpmIntegrity,
    );
    if (result.status === 'failed') {
      s.stop(
        result.reason === 'unpinned'
          ? `${pc.yellow('!')} ${match.name}: catalog entry is unpinned (no version/integrityShasum) — cannot install air-gap-safe`
          : `${pc.yellow('!')} Install failed — run manually: ${result.manualCommand}`,
      );
    } else if (result.status === 'installed') {
      s.stop(`${pc.green('✓')} ${match.name} installed`);
    } else {
      s.stop(`${pc.green('✓')} ${match.name} — no install needed`);
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
  // hoist loadCredentials() BEFORE requiredKeys so restEnvKeys can see
  // which alternative (if any) is already satisfied — e.g. an operator who
  // already has SERVICENOW_GRC_USERNAME+PASSWORD on disk must not also be
  // prompted for SERVICENOW_GRC_BEARER_TOKEN just because it's
  // alternatives[0]. Also collapses the disk read that used to fire N
  // times (once per required key) to one read for the whole prompt phase.
  const existingCreds = loadCredentials();

  const requiredKeys: string[] = [];
  if (match.rest?.envKey) requiredKeys.push(match.rest.envKey);
  requiredKeys.push(...effectiveEnvKeys(match));
  // restEnvKeys covers REST adapters whose constructor needs MORE than a
  // single rest.envKey -> apiKey (e.g. paypal clientId+clientSecret;
  // acumatica clientId+clientSecret+username+password+instanceUrl) — see
  // REST_CREDENTIAL_MAP (rest-credential-map.generated.ts). Without this
  // `chariot add` never prompts for these fields and the adapter lands at
  // status='configured' while dispatch still throws "<field> is required".
  for (const { envVar } of restEnvKeys(match, existingCreds)) {
    if (!requiredKeys.includes(envVar)) requiredKeys.push(envVar);
  }

  // Two-phase: collect prompt responses + validate FIRST, then
  // writeCredential each value. A control-char throw mid-loop (bracketed-
  // paste ESC bytes, NUL/TAB, etc.) must NOT leave earlier keys persisted
  // while later keys are absent. CREDENTIAL_VALUE_CONTROL_CHAR_RE is the
  // single source of truth shared with writeCredential and
  // parseInlineCredentialFlags.
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

  // CH-38: purge the adapter's credential from ~/.epic-ai/.env (no residue),
  // keeping keys still needed by other configured adapters.
  let removedCreds: string[] = [];
  const all = await loadAllAdapters();
  const match = all.find(a => a.id === adapterName);
  if (match) {
    // restAllEnvKeys (not restEnvKeys): purge must catch every field this
    // adapter COULD have received a credential for — including a satisfied
    // alternatives[] group other than alternatives[0], and optional fields
    // the operator supplied — not just the current prompt-facing subset.
    const keys = [...effectiveEnvKeys(match), ...restAllEnvKeys(match).map(f => f.envVar)];
    const remainingIds = Object.keys(loadState().adapters);
    const stillNeeded = new Set<string>();
    for (const otherId of remainingIds) {
      const other = all.find(a => a.id === otherId);
      if (other) {
        for (const k of effectiveEnvKeys(other)) stillNeeded.add(k);
        for (const { envVar } of restAllEnvKeys(other)) stillNeeded.add(envVar);
      }
    }
    const safeToRemove = keys.filter(k => !stillNeeded.has(k));
    if (safeToRemove.length > 0) {
      try { removedCreds = removeCredential(safeToRemove); } catch { /* best-effort */ }
    }
  }

  // CH-38/CH-48: remove the Chariot MCP server entry from every AI-client
  // config that the wizard may have written. Best-effort; errors do not abort.
  const mcpClients = detectMcpClients();
  const removedMcpClients: string[] = [];
  for (const client of mcpClients) {
    try {
      const r = removeMcpConfig(client);
      if (r.removed) removedMcpClients.push(client.id);
    } catch { /* best-effort */ }
  }

  console.log(`${pc.green('✓')} ${adapterName} removed from Chariot.`);
  if (removedCreds.length > 0) {
    console.log(`${pc.green('✓')} purged credential${removedCreds.length === 1 ? '' : 's'}: ${removedCreds.join(', ')}`);
  } else {
    console.log(`${pc.white('  No adapter-specific credentials remained in ~/.epic-ai/.env.')}`);
  }
  if (removedMcpClients.length > 0) {
    console.log(`${pc.green('✓')} removed Chariot MCP entry from: ${removedMcpClients.join(', ')}`);
  }
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

  // CHARIOT::§3.1::8 health-check log — see _healthLog declaration above.
  _healthLog.info('health.check_completed', { healthy, issues, configuredCount: configured.length });

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

// The `search` command is owned by the chariot bin
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
      let hit = false;
      for (const k of mcpKeys) {
        if (foundCreds[k]) { matched.push({ adapter, key: k }); hit = true; break; }
      }
      if (!hit) {
        for (const { envVar } of restAllEnvKeys(adapter)) {
          if (foundCreds[envVar]) { matched.push({ adapter, key: envVar }); break; }
        }
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

  // Schema-aware value pick for enum-constrained fields (the old
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
  //
  // FIX (2026-09-30, dogfood mechanism-test-3/4): "list my wikipedia
  // summary for Detroit" previously survived this function UNCHANGED (its
  // leading verb "list" and its "for Detroit" tail were both outside what
  // the original two regexes covered) and was passed whole as the `title`
  // arg to get_page_summary, which then 404'd/errored instead of resolving
  // to "Detroit". Two additions:
  //   1. "list"/"give me" added to the leading-verb alternation.
  //   2. A trailing "for/about/of/on <subject>" extraction — natural
  //      English very often puts the real subject LAST ("... summary FOR
  //      Detroit", "... article ABOUT the Eiffel Tower", "History OF the
  //      Turing Award"). Applied ONLY when every word before that
  //      preposition is generic filler (an adapter/format noun or
  //      determiner — FILLER_WORDS below), never when real content
  //      precedes it — e.g. a PubMed-style term like "clinical trials on
  //      GLP-1 drugs for obesity" must NOT collapse to just "obesity";
  //      "drugs" is not filler, so the rule does not fire and the full
  //      term passes through unchanged, exactly as before this fix.
  const FILLER_WORDS = /^(my|the|a|an|wikipedia|summary|article|page|info|information|details|overview|results?|data|list)$/i;
  function stripPrefixes(s: string): string {
    const afterPrefix = s
      .replace(
        /^(please\s+)?(list|give\s+me|search|find|look\s*up|lookup|tell\s+me\s+about|what\s+is|who\s+is|navigate\s+to|go\s+to|fetch|get|show\s+me)\s+/i,
        '',
      )
      .replace(/\s+(on|in|using|via|from)\s+\w+(\s+for|\s+about)?\s*/i, ' ')
      .trim();
    const trailingMatch = afterPrefix.match(/^(.*?)\b(?:for|about|of|on)\s+(.+)$/i);
    if (trailingMatch) {
      const before = trailingMatch[1].trim();
      const beforeWords = before.length > 0 ? before.split(/\s+/) : [];
      const subject = trailingMatch[2].trim();
      if (subject.length > 0 && beforeWords.every(w => FILLER_WORDS.test(w))) {
        return subject;
      }
    }
    return afterPrefix;
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
  // CH-31/CH-32: in agent mode the query path speaks the typed envelope on
  // stdout, never human prose, and every terminal outcome flows through it.
  const agent = chariotAgentMode();

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
    if (agent) {
      emitCliEnvelope(failEnvelope('cli:query', 'NOT_CONFIGURED', {
        cause: 'No adapters configured.',
        agent_message: 'No adapters are configured. Configure one before querying.',
        remediation: ['Run: chariot add <adapter-id>'],
        must_not: ['treat exit 0 as success', 'fabricate a tool result'],
        data: { query, configuredCount: 0 },
      }));
      return;
    }
    console.log(`\n  No adapters configured. Run ${pc.cyan('chariot')} to set up.\n`);
    process.exit(1);
  }

  // Route the query using ToolPreFilter (same engine as MCP server)
  const { ToolPreFilter } = await import('../federation/ToolPreFilter.js');
  const filter = new ToolPreFilter();
  filter.index(buildToolsForRouting(configured));
  filter.setCatalogKeywords(configured); // CHARIOT::§4.6::1

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
      // UX: the user named a catalog adapter that is not configured.
      // Routing will silently pick something else (e.g. a wikipedia query
      // landing on pubmed/tavily) — surface why, instead of hiding it.
      const catalogBrandHit = all.find((a) => tokenSet.has(a.id.toLowerCase()));
      if (catalogBrandHit && !agent) {
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
    if (agent) {
      emitCliEnvelope(failEnvelope('cli:query', 'NO_MATCH', {
        severity: 'warning',
        cause: `No configured adapter matched the query.`,
        agent_message: `No configured adapter matched "${query}". Do not invent a tool — tell the user the catalog has no tool for this task.`,
        remediation: ['Try a different query', 'Run: chariot search <term>'],
        must_not: ['fabricate a tool result', 'invent a tool name'],
        data: { query, configuredCount: configured.length, matched: 0 },
      }));
      return;
    }
    console.log(`\n  No adapters matched "${query}".`);
    console.log(`  You have ${configured.length} configured adapters. Try a different query.\n`);
    process.exit(1);
  }

  const topServer = matches[0].server;
  const topToolFull = matches[0].name;
  // FIX (2026-09-30, release-blocking): `topToolFull` is
  // `${adapter.id}:${toolName}`. The prior `split(':').slice(1).join(':')`
  // assumed adapter.id itself contains NO colon — true for every catalog
  // adapter, but FALSE for a discovered adapter (`discovered:<serviceId>`,
  // an operational-namespace prefix — see
  // src/engine/federation/configuredAdapterIds.ts). For
  // "discovered:server-abc123:get_widgets", the naive split dropped only
  // the FIRST segment ("discovered"), leaving topToolName =
  // "server-abc123:get_widgets" instead of "get_widgets" — dispatch then
  // failed "Unknown tool" even though routing had picked the correct
  // adapter+tool. `topServer` (matches[0].server) already carries the
  // EXACT adapter id boundary; stripping that known prefix is correct
  // regardless of how many colons the id itself contains.
  const topToolName = topToolFull.startsWith(`${topServer}:`)
    ? topToolFull.slice(topServer.length + 1)
    : (topToolFull.includes(':') ? topToolFull.split(':').slice(1).join(':') : topToolFull);
  // Anti-pattern 3.4 fix: O(1) lookup
  const adapter = adapterById.get(topServer);

  if (!adapter) {
    if (agent) {
      emitCliEnvelope(failEnvelope('cli:query', 'INTERNAL_ERROR', {
        cause: `Matched adapter "${topServer}" is not present in the catalog.`,
        agent_message: `Router matched "${topServer}" but it is absent from the catalog; the catalog entry may be stale.`,
        data: { query, matchedServer: topServer },
      }));
      return;
    }
    console.log(`\n  Matched adapter "${topServer}" but it's not in the catalog.\n`);
    process.exit(1);
  }

  // Agent mode keeps stdout clean for the final JSON envelope — the animated
  // spinner is suppressed (the shim already no-ops on a non-TTY, but an agent
  // may run with an attached TTY).
  const s = agent
    ? { start: () => {}, stop: () => {}, message: () => {} }
    : makeSpinner(p);
  s.start(`Routing to ${adapter.name} → ${topToolName}`);

  // CLI dispatch health pings: the query path bypasses
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
      const { createMcpDispatchFetch } = await import('../federation/mcpDispatchFetch.js');
      // Suppress the SDK's standalone GET SSE listening stream, which
      // otherwise starves the tools/list + tools/call POSTs and hangs curated
      // streamable-http adapters (e.g. pubmed) until DISPATCH_TIMEOUT.
      const transport = new StreamableHTTPClientTransport(new URL(adapter.mcp.url), { fetch: createMcpDispatchFetch() });
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
      // A bare PATH-resolved launcher must NOT be confinePath'd against
      // the package root — resolve(root,'npx') is a non-existent path and
      // rejected every stdio adapter fail-closed. Confine ONLY a package-relative
      // script path; allowlist the ONE bare launcher whose supply-chain integrity
      // is enforced by its own downstream gate — `npx` (node/uvx removed, they
      // had no target gate; see STDIO_LAUNCHER_ALLOWLIST). Same classification as
      // the serve dispatch path so both boundaries match.
      const confinedCmd = confineStdioCommand(adapter.mcp.command, getPackageRoot());
      if (!confinedCmd.ok) {
        // Under the no-silent-false-success rule, in agent mode this
        // confinement rejection must emit a typed failure envelope like every
        // other terminal branch — a bare process.exit(1) left stdout empty and
        // gave the calling agent zero bytes to branch on.
        _emitCliPing('failure', 'stdio_command_rejected');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
            cause: `stdio command rejected (${confinedCmd.reason}).`,
            agent_message: `Adapter "${adapter.id}" stdio launch command was rejected by path confinement (${confinedCmd.reason}); it cannot be dispatched.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, reason: confinedCmd.reason },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: stdio command rejected (${confinedCmd.reason})`);
        process.exit(1);
      }
        // Apply the same npx supply-chain gate the serve
      // path uses, via the shared enforceNpxStdioGate — the two boundaries are
      // now provably identical (they were NOT: this path previously spawned npx
      // with raw catalog argv and no package/integrity/pin gate, so a row like
      // `{command:"npx", args:["-y","evil-pkg"]}` reached spawn unpinned and npx
      // re-resolved it from the registry). On rejection, speak a typed failure
      // envelope in agent mode like every other terminal branch — never a
      // silent spawn (CH-31 typed-outcome / no-silent-false-success —
      // CHARIOT::§23.2::44-45).
      const { enforceNpxStdioGate, stripDangerousStdioEnv } = await import('../federation/adapters/npmIntegrityGuard.js');
      const _npxGate = enforceNpxStdioGate(adapter);
      if (!_npxGate.ok) {
        _emitCliPing('failure', 'supply_chain_integrity_failure');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
            cause: _npxGate.reason ?? 'stdio supply-chain gate rejected the adapter.',
            agent_message: `Adapter "${adapter.id}" failed the npx supply-chain integrity gate: ${_npxGate.reason ?? 'unpinned/ungated npm stdio launcher'}. It cannot be dispatched.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, reason: _npxGate.reason },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: npx supply-chain gate rejected (${_npxGate.reason ?? 'unpinned/ungated'})`);
        process.exit(1);
      }
      const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
      const { StdioClientTransport, getDefaultEnvironment } = await import('@modelcontextprotocol/sdk/client/stdio.js');
      // Mirror the serve path: the SDK default env is getDefaultEnvironment()
      // (the same safe base this branch already got implicitly when `env` was
      // omitted); add npm_config_offline so npx resolves ONLY from the
      // integrity-verified local cache and fails closed when the pin is absent.
      const _stdioEnv: Record<string, string> = { ...getDefaultEnvironment() };
      // Strip any preload/exec/npm_config_* channel BEFORE the engine sets its
        // own npm_config_offline — identical to the serve path.
      stripDangerousStdioEnv(_stdioEnv);
      if (_npxGate.offline) {
        _stdioEnv.npm_config_offline = 'true';
        // Disable npm lifecycle scripts at dispatch —
        // identical to the serve path (no preinstall/postinstall code-exec).
        _stdioEnv.npm_config_ignore_scripts = 'true';
      }
      const transport = new StdioClientTransport({ command: confinedCmd.command, args: _npxGate.spawnArgs, env: _stdioEnv });
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
        // Under the no-silent-false-success rule, mirror the stdio branch —
        // a rejected REST module path must speak a typed failure envelope in
        // agent mode instead of exiting silently with an empty stdout.
        _emitCliPing('failure', 'module_path_rejected');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
            cause: `adapter module path rejected (${confined.reason}).`,
            agent_message: `Adapter "${adapter.id}" module path was rejected by path confinement (${confined.reason}); it cannot be dispatched.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, reason: confined.reason },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: adapter module path rejected (${confined.reason})`);
        process.exit(1);
      }
      // eslint-disable-next-line local/no-dynamic-module-specifier -- DYNAMIC_LOADER_SITES: adapter package path resolved from the signed catalog and confined by confinePath() to the package root before this import
      const mod = await import(confined.resolved) as Record<string, unknown>;
      const AdapterClass = (mod[adapter.rest.className] ?? mod['default']) as new (cfg: Record<string, string>) => {
        callTool(n: string, a: Record<string, unknown>): Promise<{ content: unknown }>;
        validateInput?(n: string, a: unknown): Record<string, unknown>;
        // Every REST adapter module (1106/1108 at time of writing) exposes
        // its real per-tool schema via this getter — see e.g.
        // WikipediaMCPServer.tools / RedshiftMCPServer.tools. Optional so a
        // hypothetical adapter without one still type-checks; handled with
        // a runtime fallback below (never assumed present).
        readonly tools?: ReadonlyArray<{ name: string; description?: string; inputSchema?: McpToolSchema['inputSchema'] }>;
      };
      // FIX (2026-09-30, dogfood mechanism-test-mcp, gate BLOCK
      // verdict.1.json): this block previously built adapterConfig from
      // ONLY apiKey/baseUrl/endpointsJson/authType via `adapter.rest.envKey`
      // and never consulted REST_CREDENTIAL_MAP — so a multi-field or
      // alternatives-shaped adapter (redshift, paypal, acumatica, every
      // mapped adapter) dispatched here with an empty/incomplete config and
      // the constructor threw, even with every required key present in
      // ~/.epic-ai/.env. CHARIOT-SPEC.md:438 "configured … Ready to be
      // dispatched" was violated. Now calls the SAME shared builder
      // toolHandlers.ts's REST dispatch uses (canonical-credentialed-
      // brands.ts buildRestAdapterConfig) so the two surfaces can never
      // diverge again, and fails CLOSED with a typed envelope naming the
      // missing env var(s) instead of letting the constructor throw.
      const restConfigResult = buildRestAdapterConfig(adapter, creds);
      if (!restConfigResult.ok) {
        const missingRestFields = restConfigResult.missing;
        _emitCliPing('failure', 'credentials_pending');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CREDENTIALS_PENDING', {
            cause: `missing credential(s): ${missingRestFields.join(', ')}.`,
            agent_message: `Adapter "${adapter.id}" is missing credential(s) ${missingRestFields.join(', ')}. Run \`chariot add ${adapter.id} --token ${missingRestFields[0]}=<value>\` (repeat --token per key) to configure.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, missing: missingRestFields },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: missing credential(s) ${missingRestFields.join(', ')}`);
        process.exit(1);
      }
      const adapterConfig: Record<string, string> = restConfigResult.config;
      const instance = new AdapterClass(adapterConfig);
      // extract args from natural-language query (heuristic +
      // optional LLM); fall back to {query} for adapters whose validateInput
      // expects that shape.
      //
      // FIX (2026-09-30, dogfood mechanism-test-3/4): this call previously
      // passed a HARDCODED `null` for toolSchema. extractToolArgs's very
      // first line is `if (!toolSchema || !toolSchema.inputSchema) return
      // { query }` — passing null made it return `{query: <full sentence>}`
      // UNCONDITIONALLY for every REST-dispatched adapter reached through
      // `chariot query`, skipping BOTH the LLM path and the deterministic
      // heuristic path entirely, regardless of what the tool's real schema
      // required. Reproduced live: "list my wikipedia summary for Detroit"
      // routed correctly to wikipedia/get_page_summary (a SEPARATE fix,
      // curated-adapter routing) but then dispatched with {query: "list my
      // wikipedia..."} against a tool whose schema requires `title`, not
      // `query` — the adapter correctly rejected it ("title is required").
      // Now reads the adapter's own `.tools` getter (the same ToolDefinition[]
      // every REST module publishes) to find the REAL schema for topToolName,
      // so extractToolArgs's schema-aware heuristic (TERM_LIKE field
      // detection, enum handling, required-field backfill) actually runs.
      const realToolSchema: McpToolSchema | null =
        instance.tools?.find(t => t.name === topToolName)
          ? { name: topToolName, description: instance.tools.find(t => t.name === topToolName)!.description, inputSchema: instance.tools.find(t => t.name === topToolName)!.inputSchema }
          : null;
      const heuristicArgs = await extractToolArgs(query, topToolName, realToolSchema);
      const candidateArgs = Object.keys(heuristicArgs).length > 0 ? heuristicArgs : { query };
      const validatedArgs = typeof instance.validateInput === 'function'
        ? instance.validateInput(topToolName, candidateArgs)
        : candidateArgs;
      const result = await instance.callTool(topToolName, validatedArgs);
      resultText = typeof result.content === 'string' ? result.content : JSON.stringify(result.content);
    } else if (adapter.type === 'cli-bridge') {
      // cmdQuery previously had no branch for cli-bridge
      // adapters at all, so a matched cli-bridge tool fell all the way
      // through to the generic "No executable transport" branch below —
      // a real dispatch bug reported as a routing failure. This branch
      // mirrors toolHandlers.ts handleCallInner Case 5 (AS §1.5).
      //
      // Q-2.5 parity: guard a malformed cli-bridge entry (missing
      // cli.binary) BEFORE anything else, so it surfaces its own error
      // instead of silently falling through to "no executable transport"
      // and obscuring the catalog defect (toolHandlers.ts:2549-2568).
      if (!adapter.cli?.binary) {
        _emitCliPing('failure', 'cli_binary_missing');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CLI_BINARY_MISSING', {
            cause: `cli-bridge adapter "${adapter.id}" missing required cli.binary.`,
            agent_message: `Adapter "${adapter.id}" is a malformed cli-bridge catalog entry (no cli.binary); it cannot be dispatched.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: malformed cli-bridge entry (no cli.binary)`);
        process.exit(1);
      }
      const cli = adapter.cli;

      // AS §1.5 approval gate. Reuses the SAME approval-state helpers
      // (src/cli/approval.ts) the MCP/REST dispatch path uses
      // (toolHandlers.ts:2570-2628) — one approval record and one
      // shape-hash algorithm govern both surfaces, so `chariot approve
      // <id>` covers this query path too, and a post-approval
      // binary/argv mutation is refused here exactly as on the MCP
      // surface (TOCTOU close). Runs BEFORE the schema lookup, PATH
      // resolution, and any subprocess spawn — no side effects until
      // approval is confirmed AND the shape matches.
      const { readAdapterApproval, computeAdapterShapeHash, renderToolArgv } = await import('../../cli/approval.js');
      const selectedSchema = cli.toolSchemas.find((sch) => sch.name === topToolName);
      let currentShapeHash: string | null;
      try {
        currentShapeHash = computeAdapterShapeHash({ binary: cli.binary, args: cli.args, toolSchemas: cli.toolSchemas });
      } catch {
        // Q-3.2 parity: a malformed catalog entry (non-string args
        // member, etc.) refuses as CLI_APPROVAL_REQUIRED rather than
        // throwing an unhandled TypeError out of cmdQuery.
        currentShapeHash = null;
      }
      const approval = readAdapterApproval(adapter.id);
      const shapeMatches = currentShapeHash !== null && approval?.approvedShapeHash === currentShapeHash;
      if (!approval || !shapeMatches) {
        const failureKind = !approval ? 'unapproved' : 'shape_mismatch';
        const effectiveArgv = renderToolArgv(cli.args, selectedSchema);
        _emitCliPing('failure', 'cli_approval_required');
        // AS §1.5:334 — the refusal MUST "write a structured log line
        // naming the adapter id + binary + argv." Fires in BOTH agent and
        // human mode (unlike the envelope below, which is agent-mode
        // only), mirroring toolHandlers.ts's
        // `_approvalGateLogger.warn('cli_approval_required', {...})`
        // (toolHandlers.ts:2600-2609) field-for-field.
        _cliApprovalGateLogger.warn('cli_approval_required', {
          adapter_id: adapter.id,
          binary: cli.binary,
          argv: effectiveArgv,
          base_args: cli.args,
          tool: topToolName,
          failure: failureKind,
          approved_shape_hash: approval?.approvedShapeHash ?? null,
          current_shape_hash: currentShapeHash,
        });
        // The dispatcher MUST NOT prompt the AI client to approve on the
        // user's behalf (AS §1.5) — both envelope paths below only ever
        // point at the human-operator `chariot approve` command.
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CLI_APPROVAL_REQUIRED', {
            severity: 'blocked',
            cause: failureKind === 'unapproved'
              ? 'CLI adapter requires interactive approval before first use.'
              : "CLI adapter's binary or argv template has changed since approval.",
            agent_message: 'This CLI adapter requires interactive approval before first use. Run `chariot approve <adapter-id>` to review and accept.',
            remediation: [`chariot approve ${adapter.id}`],
            must_not: ['claim the tool ran', 'fabricate the tool output', "approve on the user's behalf"],
            data: { query, adapter: adapter.id, tool: topToolName, binary: cli.binary, argv: effectiveArgv, failure: failureKind },
          }));
          return;
        }
        s.stop(
          `${pc.yellow('!')} ${adapter.name}: This CLI adapter requires interactive approval before first use. ` +
          `Run ${pc.cyan(`chariot approve ${adapter.id}`)} to review and accept.`,
        );
        process.exit(1);
      }

      if (!selectedSchema) {
        _emitCliPing('failure', 'cli_tool_not_registered');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CLI_TOOL_NOT_REGISTERED', {
            cause: `cli-bridge adapter "${adapter.id}" has no schema for tool "${topToolName}".`,
            agent_message: `Adapter "${adapter.id}" has no CLI tool schema for "${topToolName}"; it cannot be dispatched. The catalog entry may be stale.`,
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: no CLI schema for tool "${topToolName}"`);
        process.exit(1);
      }

      const resolvedBinary = findOnPath(cli.binary);
      if (!resolvedBinary) {
        _emitCliPing('failure', 'cli_binary_missing');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CLI_BINARY_MISSING', {
            cause: `CLI binary "${cli.binary}" not on PATH.`,
            agent_message: `Adapter "${adapter.id}" binary "${cli.binary}" is not on PATH — run \`chariot setup --pre-install\` to install it.`,
            remediation: ['chariot setup --pre-install'],
            must_not: ['claim the tool ran', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, binary: cli.binary },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: binary "${cli.binary}" not on PATH`);
        process.exit(1);
      }

      // Extract tool args from the query against the CLI tool's OWN
      // inputSchema, via the same extractToolArgs helper the MCP/stdio
      // branches use above — so positional/flag params are filled the
      // same way a JSON-Schema-driven MCP tool call would be.
      const cliToolSchema: McpToolSchema | null = selectedSchema.inputSchema
        ? { name: topToolName, description: selectedSchema.description, inputSchema: selectedSchema.inputSchema as McpToolSchema['inputSchema'] }
        : null;
      const toolArgs = await extractToolArgs(query, topToolName, cliToolSchema);

      // Build argv — array-form only, no shell. Mirrors the dispatcher's
      // spawn contract exactly (toolHandlers.ts Case 5): cli.args, then
      // schema.subcommand, then positional params in schema order, then
      // flag params.
      const argv: string[] = [...(Array.isArray(cli.args) ? cli.args : [])];
      if (selectedSchema.subcommand) argv.push(selectedSchema.subcommand);
      for (const param of selectedSchema.positional ?? []) {
        const v = toolArgs[param];
        if (v !== undefined && v !== null) argv.push(String(v));
      }
      for (const [param, flag] of Object.entries(selectedSchema.flags ?? {})) {
        const v = toolArgs[param];
        if (v !== undefined && v !== null) argv.push(flag, String(v));
      }

      // Subprocess env — named allowlist + per-adapter credentials only.
      // No spread of process.env; nothing else from this CLI's parent env
      // leaks into the subprocess. CLI_BASE_ENV_ALLOWLIST is imported from
      // src/engine/server/cliDispatch.ts — the SAME constant the MCP/REST
      // dispatch path uses, not a second copy.
      const subprocessEnv: Record<string, string> = {};
      for (const k of CLI_BASE_ENV_ALLOWLIST) {
        const v = process.env[k];
        if (typeof v === 'string') subprocessEnv[k] = v;
      }
      const credValues: string[] = [];
      for (const k of cli.envKeys ?? []) {
        const v = creds[k] ?? process.env[k];
        if (typeof v === 'string' && v.length > 0) {
          subprocessEnv[k] = v;
          credValues.push(v);
        }
      }

      // OWASP LLM02 / R.9(a): every byte a CLI-bridge subprocess produces
      // flows through the SAME DLP inspector + injection scanner as the
      // MCP/REST dispatch path (toolHandlers.ts applyDlpInspection /
      // applyInjectionScanner) before it becomes the query result or an
      // error message — DLP first (so a secret is redacted/blocked before
      // anything else touches the content), then the injection scanner,
      // exactly the order toolHandlers.ts Case 5 uses. cmdQuery has no
      // ChariotState (it is a lightweight one-shot CLI invocation), so a
      // DlpInspector is constructed here with the SAME default config
      // ChariotState.ts wires for the MCP surface (defaultDecision:
      // 'redact', no per-tenant overrides in the OSS build) — same policy,
      // same functions, an independent instance for this one dispatch.
      const _dlpCtx = {
        inspector: new DlpInspector({ defaultConfig: { rules: new Map(), defaultDecision: 'redact', alwaysAudit: false } }),
        tenantId: process.env.CHARIOT_TENANT_ID ?? 'local',
      };
      const _scanCtx = { adapterId: adapter.id, toolName: topToolName };
      const runCliDlp = (raw: string): { blocked: boolean; content: string } => {
        const verdict = applyDlpInspection(raw, { adapterId: adapter.id, toolName: topToolName, dlp: _dlpCtx });
        return verdict.kind === 'block'
          ? { blocked: true, content: verdict.errorContent }
          : { blocked: false, content: verdict.content };
      };

      // Spawn — reuses toolHandlers.ts's own spawnWithTimeout (SIGTERM
      // then SIGKILL after a 2s grace; MAX_RESPONSE_BYTES / CLI_STDERR_CAP_BYTES
      // are the SAME budgets the MCP/REST dispatch path enforces).
      const timeoutMs = Math.min(cli.timeoutMs ?? 30_000, 300_000);
      let spawnResult: { stdout: string; stderr: string; exitCode: number };
      try {
        spawnResult = await spawnWithTimeout(
          resolvedBinary,
          argv,
          subprocessEnv,
          timeoutMs,
          MAX_RESPONSE_BYTES,
          CLI_STDERR_CAP_BYTES,
        );
      } catch (spawnErr: unknown) {
        // spawnWithTimeout rejects with Error('CLI_TIMEOUT') after the
        // SIGTERM-then-SIGKILL escalation. Surface it as its OWN typed
        // envelope — distinct from the generic dispatch-threw catch below
        // — instead of collapsing a timeout and an arbitrary spawn error
        // into one undifferentiated DISPATCH_FAILED.
        if (spawnErr instanceof Error && spawnErr.message === 'CLI_TIMEOUT') {
          _emitCliPing('failure', 'cli_timeout');
          if (agent) {
            emitCliEnvelope(failEnvelope('cli:query', 'CLI_TIMEOUT', {
              cause: `CLI tool exceeded ${timeoutMs}ms.`,
              agent_message: `Adapter "${adapter.id}" tool "${topToolName}" exceeded its ${timeoutMs}ms timeout; the subprocess was killed.`,
              must_not: ['claim the tool ran to completion', 'fabricate the tool output'],
              data: { query, adapter: adapter.id, tool: topToolName, binary: cli.binary, timeoutMs },
            }));
            return;
          }
          s.stop(`${pc.red('✗')} ${adapter.name}: tool "${topToolName}" exceeded ${timeoutMs}ms and was killed`);
          process.exit(1);
        }
        throw spawnErr;
      }
      const { stdout, stderr, exitCode } = spawnResult;
      if (exitCode !== 0) {
        const _dlp = runCliDlp(redactStderr(stderr, credValues).slice(0, 4096));
        const _stderrExcerpt = applyInjectionScanner(_dlp.content, _scanCtx);
        _emitCliPing('failure', 'cli_nonzero_exit');
        if (agent) {
          emitCliEnvelope(failEnvelope('cli:query', 'CLI_NONZERO_EXIT', {
            cause: `cli-bridge subprocess exited non-zero (${exitCode}).`,
            agent_message: `Adapter "${adapter.id}" tool "${topToolName}" exited with code ${exitCode}: ${_stderrExcerpt}`,
            must_not: ['claim the tool ran successfully', 'fabricate the tool output'],
            data: { query, adapter: adapter.id, tool: topToolName, binary: cli.binary, exitCode, stderr: _stderrExcerpt },
          }));
          return;
        }
        s.stop(`${pc.red('✗')} ${adapter.name}: tool "${topToolName}" exited with code ${exitCode}: ${_stderrExcerpt}`);
        process.exit(1);
      }
      // Parse stdout per declared format, then redact credentials from any
      // text that leaves this process — vendor CLIs may echo credentials
      // in successful output (e.g. `gh auth status` prints the token).
      // Mirrors toolHandlers.ts Case 5 stdout handling exactly.
      let rawResult: string;
      if (cli.stdoutFormat === 'json') {
        const parsed: unknown = JSON.parse(stdout);
        rawResult = redactStderr(JSON.stringify(parsed), credValues);
      } else if (cli.stdoutFormat === 'json-rpc') {
        const parsed = JSON.parse(stdout) as { result?: unknown; error?: unknown };
        if (parsed.error !== undefined) {
          const _dlp = runCliDlp(redactStderr(JSON.stringify(parsed.error), credValues));
          throw new Error(`cli-bridge JSON-RPC error: ${applyInjectionScanner(_dlp.content, _scanCtx)}`);
        }
        rawResult = redactStderr(JSON.stringify(parsed.result ?? null), credValues);
      } else {
        rawResult = redactStderr(stdout.trim(), credValues);
      }
      const _dlpResult = runCliDlp(rawResult);
      if (_dlpResult.blocked) {
        throw new Error(applyInjectionScanner(_dlpResult.content, _scanCtx));
      }
      resultText = applyInjectionScanner(_dlpResult.content, _scanCtx);
    } else {
      _emitCliPing('failure', 'no_executable_transport');
      if (agent) {
        emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
          cause: `No executable transport for adapter "${adapter.id}".`,
          agent_message: `Adapter "${adapter.id}" has no executable transport; it cannot be dispatched.`,
          data: { query, adapter: adapter.id, tool: topToolName },
        }));
        return;
      }
      s.stop(`${pc.yellow('!')} No executable transport for ${adapter.name}`);
      process.exit(1);
    }

    if (resultText.trim().length === 0) {
      _emitCliPing('failure', 'empty_result');
      if (agent) {
        emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
          cause: 'Tool produced no answer.',
          agent_message: `${adapter.id} → ${topToolName} returned an empty result; no answer was produced.`,
          must_not: ['treat the empty result as success', 'fabricate the tool output'],
          data: { query, adapter: adapter.id, tool: topToolName, empty: true },
        }));
        return;
      }
      s.stop(`${pc.red('✗')} ${adapter.name} → ${topToolName}: no answer produced`);
      process.exit(1);
    }
    _emitCliPing('success');
    if (agent) {
      emitCliEnvelope(okEnvelope('cli:query', {
        query,
        adapter: adapter.id,
        tool: topToolName,
        result: resultText,
      }));
      return;
    }
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
    if (agent) {
      emitCliEnvelope(failEnvelope('cli:query', 'DISPATCH_FAILED', {
        cause: msg,
        agent_message: `Dispatch to ${adapter.id} → ${topToolName} failed: ${msg}`,
        retryable: true,
        must_not: ['claim the tool ran', 'fabricate the tool output'],
        data: { query, adapter: adapter.id, tool: topToolName },
      }));
      return;
    }
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
  // Render the command list from the single-source-of-truth capability
  // registry (CH-32) so `--help`/`help` can never drift out of sync with the
  // dispatcher. Every dispatched command is listed with its usage + summary.
  const { buildManifest } = await import('../../cli/capabilities.js');
  const cmds = buildManifest(PKG_VERSION).commands;
  const col = Math.min(40, Math.max(...cmds.map((c) => c.usage.length)));
  for (const cmd of cmds) {
    console.log(`    ${pc.cyan(cmd.usage.padEnd(col))}  ${cmd.summary}`);
  }
  console.log('');
  console.log(`  ${pc.white('Docs:')}  https://chariot.epic-ai.io`);
  console.log('');
}

// CHARIOT::§17.2::13 default live dispatcher — reuses the SAME connect
// primitives cmdQuery's streamable-http/stdio branches use (SDK Client,
// confineStdioCommand, enforceNpxStdioGate, stripDangerousStdioEnv), but
// calls ONLY client.listTools() — never a tool invocation. tools/list IS
// the "light read-only call" the clause asks for; no separate
// "cheapest read-only tool" call is needed on the two MCP transports.
// REST-module adapters (adapter.rest?.module) are reported ok:false with
// an explicit reason rather than attempting a real method call — the
// catalog does not carry a readOnlyHint for REST tools to pick one
// safely, and this pass's budget did not extend to building that lookup;
// see the report for this unit.
const defaultConnectionDispatcher: ConnectionDispatcher = async (adapter, _timeoutMs) => {
  if (adapter.mcp?.transport === 'streamable-http' && adapter.mcp?.url) {
    const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
    const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
    const { createMcpDispatchFetch } = await import('../federation/mcpDispatchFetch.js');
    const transport = new StreamableHTTPClientTransport(new URL(adapter.mcp.url), { fetch: createMcpDispatchFetch() });
    const client = new Client({ name: 'chariot', version: PKG_VERSION }, { capabilities: {} });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      return { ok: true, toolCount: Array.isArray(listed.tools) ? listed.tools.length : 0 };
    } catch (err) {
      return { ok: false, reason: err instanceof Error ? err.message : String(err) };
    } finally {
      try { await client.close(); } catch { /* best-effort close */ }
    }
  }

  if (adapter.mcp?.transport === 'stdio' && adapter.mcp?.command) {
    const confinedCmd = confineStdioCommand(adapter.mcp.command, getPackageRoot());
    if (!confinedCmd.ok) {
      return { ok: false, reason: `stdio command rejected (${confinedCmd.reason})` };
    }
    const { enforceNpxStdioGate, stripDangerousStdioEnv } = await import('../federation/adapters/npmIntegrityGuard.js');
    const gate = enforceNpxStdioGate(adapter);
    if (!gate.ok) {
      return { ok: false, reason: gate.reason ?? 'npx supply-chain gate rejected the adapter' };
    }
    const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
    const { StdioClientTransport, getDefaultEnvironment } = await import('@modelcontextprotocol/sdk/client/stdio.js');
    const env: Record<string, string> = { ...getDefaultEnvironment() };
    stripDangerousStdioEnv(env);
    if (gate.offline) {
      env.npm_config_offline = 'true';
      env.npm_config_ignore_scripts = 'true';
    }
    const transport = new StdioClientTransport({ command: confinedCmd.command, args: gate.spawnArgs, env });
    const client = new Client({ name: 'chariot', version: PKG_VERSION }, { capabilities: {} });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      return { ok: true, toolCount: Array.isArray(listed.tools) ? listed.tools.length : 0 };
    } catch (err) {
      return { ok: false, reason: err instanceof Error ? err.message : String(err) };
    } finally {
      try { await client.close(); } catch { /* best-effort close */ }
    }
  }

  return { ok: false, reason: 'no MCP transport to verify (REST-module adapters are not yet live-verified)' };
};

// ─── Setup Wizard ───────────────────────────────────────────

export async function runSetupWizard(): Promise<void> {
  // Test hook (W35-10) — a scripted-answers test double for the whole
  // @clack/prompts surface (select/confirm/multiselect/text/password/
  // note/log/isCancel/spinner/outro/cancel), set ONLY by
  // setup.wizard-integration.test.ts before calling this function. Absent
  // in every real invocation, where the real module is always used.
  const p = (globalThis as { __chariotTestClack?: ClackPrompts }).__chariotTestClack
    ?? await import('@clack/prompts');
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

  // CHARIOT::§3.1::8 wizard log — see _wizardLog declaration above.
  _wizardLog.info('wizard.started', {});

  console.log('');
  p.note(
    `One self-hosted MCP server. Your context window only loads what the query needs.`,
    pc.bgCyan(pc.black(' Epic AI® Chariot '))
  );

  const s = makeSpinner(p);

  // Step 1: System detection
  s.start('Detecting your system');
  const system = await detectSystem();
  // Test hook (W35-10) — a fixture catalog, set ONLY by
  // setup.wizard-integration.test.ts, so the integration test is hermetic
  // (no dependency on the real signed bundle being present/current) and
  // fast. Absent in every real invocation.
  const allAdapters = (globalThis as { __chariotTestAdapters?: AdapterEntry[] }).__chariotTestAdapters
    ?? await loadAllAdapters();
  s.stop('System detected');

  const detectedClients = system.mcpClients.filter(c => c.detected);
  const hasLocalLLM = system.localBackend !== null;

  // CHARIOT::§17.2::1 — the version line reflects the ACTUAL >=20 check,
  // not an unconditional checkmark.
  const nodeVersionLine = system.nodeVersionSupported
    ? `${pc.green('✓')} Node.js ${system.nodeVersion}`
    : `${pc.red('✗')} Node.js ${system.nodeVersion} — Chariot requires >=20`;
  // CHARIOT::§17.2::2 — Python/Go/Rust runtime report.
  const runtimeLine = `${pc.white('○')} Runtimes: ` + [
    ['Python', system.runtimes.python],
    ['Go', system.runtimes.go],
    ['Rust', system.runtimes.rust],
  ].map(([label, v]) => v ? `${label} (${v})` : `${label} not found`).join(', ');
  // CHARIOT::§17.2::3 — CPU/RAM/GPU report.
  const gpuLabel = system.hardware.gpu
    ? `${system.hardware.gpu.vendor === 'apple-silicon' ? 'Apple Silicon' : 'NVIDIA'} — ${system.hardware.gpu.name}`
    : `none (${system.hardware.gpuAbsentReason ?? 'none-detected'})`;
  const hardwareLine = `${pc.white('○')} Hardware: ${system.hardware.cpuCores}-core ${system.hardware.cpuModel}, ` +
    `${Math.round(system.hardware.ramTotalBytes / (1024 * 1024 * 1024))} GiB RAM, GPU: ${gpuLabel}`;

  p.note(
    [
      nodeVersionLine,
      `${pc.green('✓')} ${system.platform} / ${system.arch}`,
      runtimeLine,
      hardwareLine,
      hasLocalLLM ? `${pc.green('✓')} ${system.localBackend} running on port ${system.localPort}` : `${pc.white('○')} No local LLM detected`,
      `${pc.green('✓')} ${allAdapters.length} adapters available`,
      `${pc.green('✓')} ${detectedClients.length} AI client${detectedClients.length !== 1 ? 's' : ''} detected`,
    ].join('\n'),
    'System'
  );

  // Step 1b: Local AI backend — CHARIOT::§17.2::5, ::6. Exactly three
  // options (auto-download / "I have one running" / skip); the decision
  // logic lives entirely in planLocalBackendStep/recommendModel (pure,
  // tested in modelRecommendation.test.ts / localBackendStep.test.ts) —
  // this block is a thin @clack/prompts wrapper around it.
  const recommendation = recommendModel(system.hardware);
  if (recommendation) {
    p.log.info(`Recommended local backend: ${recommendation.backend} (${recommendation.sizeClass}) — ${recommendation.reason}`);
  }
  const localBackendChoice = await p.select({
    message: 'Local AI backend:',
    options: [
      { value: 'auto-download' as const, label: 'Auto-download', hint: recommendation ? `${recommendation.backend} (${recommendation.sizeClass})` : 'no recommendation for this hardware' },
      { value: 'have-one-running' as const, label: "I have one running", hint: hasLocalLLM ? `${system.localBackend} detected on port ${system.localPort}` : 'no backend detected on standard ports' },
      { value: 'skip' as const, label: 'Skip', hint: 'configure a local backend later' },
    ],
    initialValue: hasLocalLLM ? ('have-one-running' as const) : ('skip' as const),
  });
  if (p.isCancel(localBackendChoice)) { p.cancel('Setup cancelled.'); process.exit(0); }

  const localBackendAction = planLocalBackendStep(
    hasLocalLLM ? { backend: system.localBackend as string, port: system.localPort as number } : null,
    localBackendChoice,
    recommendation,
    system.platform as NodeJS.Platform,
  );
  let localBackendLabel: string | null = null;
  switch (localBackendAction.kind) {
    case 'download': {
      const cmd = localBackendAction.command;
      if (cmd.manualInstructionsOnly) {
        p.note(`No single install command for ${localBackendAction.backend} on this platform — install it manually, then re-run setup.`, 'Manual install required');
      } else {
        const s3 = makeSpinner(p);
        s3.start(`Installing ${localBackendAction.backend}`);
        const r = spawnSync(cmd.bin, cmd.argv, { stdio: 'pipe', timeout: 180_000 });
        if (r.error || (r.status !== null && r.status !== 0) || r.signal) {
          s3.stop(`${pc.yellow('!')} Install failed — run manually: ${cmd.bin} ${cmd.argv.join(' ')}`);
        } else {
          s3.stop(`${pc.green('✓')} ${localBackendAction.backend} installed`);
          localBackendLabel = localBackendAction.backend;
        }
      }
      break;
    }
    case 'download-unavailable':
      p.log.warning(localBackendAction.reason);
      break;
    case 'use-detected':
      localBackendLabel = localBackendAction.backend;
      break;
    case 'prompt-custom-url': {
      const url = await p.text({ message: 'Local backend URL (OpenAI-compatible /v1):', placeholder: 'http://localhost:8000' });
      if (!p.isCancel(url) && url) localBackendLabel = url;
      break;
    }
    case 'skip':
      break;
  }

  // Step 2: AI client detection + config
  const configuredClients: string[] = [];
  if (localBackendLabel) configuredClients.push('local');

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
    // Build options — detected clients pre-checked. Local-backend selection
    // is handled explicitly in Step 1b above (CHARIOT::§17.2::6); it is no
    // longer offered as a checkbox here.
    const clientOptions = detectedClients.map(c => ({
      value: c.id,
      label: c.name,
      hint: c.hint || c.configPath.replace(homedir(), '~'),
    }));

    const selectedClients = await p.multiselect({
      // CH-38: explicit opt-in — never pre-select live client configs.
      message: `Select AI clients to register Chariot in (Space to toggle — none selected by default):`,
      options: clientOptions,
      initialValues: [],
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
        // Supply-chain pin (zero-day fix): pin the exact running release and
        // forbid a registry fetch at AI-client launch (--no-install). An
        // unpinned `npx @epicai/chariot` re-resolves at every client start —
        // a compromised/newer npm publish would execute on next launch, and
        // an air-gapped deploy would emit outbound registry traffic.
        const result = writeMcpConfig(client, { command: 'npx', args: ['--no-install', `@epicai/chariot@${PKG_VERSION}`, '--serve'] });
        if (result.success) {
          // CH-48: verify-load before claiming ✓ (a write to a path the
          // client never reads is a silent no-op).
          const verify = verifyMcpConfigLoaded(client);
          if (verify.loaded) {
            writeResults.push(result.error === 'already configured'
              ? `${pc.green('✓')} ${client.name} — already configured (verified)`
              : `${pc.green('✓')} ${client.name} — configured + verified`);
            configuredClients.push(clientId);
          } else {
            writeResults.push(`${pc.red('✗')} ${client.name} — wrote ${client.configPath.replace(homedir(), '~')} but verify-load failed: ${verify.reason}`);
          }
        } else {
          writeResults.push(`${pc.yellow('!')} ${client.name} — ${result.error}`);
        }
      } else {
        // Show the JSON for manual copy
        const serverEntry = { chariot: { command: 'npx', args: ['--no-install', `@epicai/chariot@${PKG_VERSION}`, '--serve'] } };
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

    // Local-backend bookkeeping already applied in Step 1b above
    // (configuredClients.push('local') when localBackendLabel is set).

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

  // Step 3b: Additional adapters — CHARIOT::§17.2::7, ::8, ::9. An
  // interactive, categorized, searchable picker over the FULL signed-bundle
  // catalog (loadAllAdapters()), beyond the zero-credential CURATED set
  // above. Tier prompts (rulings item 92): the license PLAN tier and its
  // seat allowance are shown for context; they do not gate selection (the
  // license carries no per-adapter entitlement list to gate against).
  const tierInfo = getLicenseTierInfo();
  const tierLabel = tierInfo.tier
    ? `${tierInfo.tier}${tierInfo.totalSeats != null ? ` (${tierInfo.totalSeats} seats)` : ''}`
    : `unlicensed — free tier (1 seat)`;
  const browseMore = await p.confirm({ message: `Browse more adapters? (License: ${tierLabel})`, initialValue: false });
  const additionalAdapters: AdapterEntry[] = [];
  if (!p.isCancel(browseMore) && browseMore) {
    const searchTerm = await p.text({ message: 'Search adapters (name/description/keyword, blank for all):', placeholder: '' });
    const search = p.isCancel(searchTerm) ? '' : (searchTerm ?? '');
    const remaining = allAdapters.filter(a => !curatedAdapterEntries.some(c => c.id === a.id));
    const filtered = filterAdapters(remaining, { search });
    const groups = groupByCategory(filtered);
    const pickerOptions = [...groups.entries()].flatMap(([category, entries]) =>
      entries.map(a => ({ value: a.id, label: a.name, hint: `${category}${a.description ? ' — ' + a.description : ''}` })),
    );
    if (pickerOptions.length === 0) {
      p.log.warning('No adapters match that search.');
    } else {
      const picked = await p.multiselect({
        message: `Select adapters to add (Space to toggle, ${pickerOptions.length} match${pickerOptions.length !== 1 ? 'es' : ''}):`,
        options: pickerOptions,
        initialValues: [],
        required: false,
      });
      if (!p.isCancel(picked)) {
        for (const id of picked as string[]) {
          const a = allAdapters.find(x => x.id === id);
          if (a) additionalAdapters.push(a);
        }
      }
    }
  }

  // Step 3c: dependency install (CHARIOT::§17.2::10) + credential
  // configuration (CHARIOT::§17.2::11, ::12) for each additionally
  // selected adapter — reuses the SAME installStdioDependency helper and
  // writeCredential/effectiveEnvKeys primitives cmdAdd uses, so a
  // wizard-added adapter and a `chariot add`-added adapter end up in
  // identical, correctly-audited state.
  if (additionalAdapters.length > 0) {
    let addState = loadState();
    const existingCreds0 = loadCredentials();
    for (const adapter of additionalAdapters) {
      // W42-FIX (row 1.42 proof, gap 1 of 3): see the matching comment at
      // cmdAdd's install block above — gate on transport alone, not
      // `packageName` (absent on real catalog rows); installStdioDependency()
      // derives the name internally and no-ops when nothing resolves.
      if (adapter.mcp?.transport === 'stdio') {
        const s4 = makeSpinner(p);
        s4.start(`Installing ${adapter.name}`);
        const result = installStdioDependency(
          adapter,
          (bin, argv, timeoutMs) => {
            const r = spawnSync(bin, argv, { stdio: 'pipe', timeout: timeoutMs });
            return { error: r.error, status: r.status, signal: r.signal };
          },
          verifyNpmIntegrity,
        );
        s4.stop(result.status === 'failed'
          ? `${pc.yellow('!')} Install failed — run manually: ${result.manualCommand}`
          : `${pc.green('✓')} ${adapter.name} — ready`);
      }
      const requiredKeys: string[] = [];
      if (adapter.rest?.envKey) requiredKeys.push(adapter.rest.envKey);
      requiredKeys.push(...effectiveEnvKeys(adapter));
      // See the matching comment at interactive cmdAdd — REST_CREDENTIAL_MAP
      // covers adapters whose constructor needs more than a single
      // rest.envKey -> apiKey.
      for (const { envVar } of restEnvKeys(adapter, existingCreds0)) {
        if (!requiredKeys.includes(envVar)) requiredKeys.push(envVar);
      }
      for (const envKey of requiredKeys) {
        if (existingCreds0[envKey]) continue;
        const value = await p.password({ message: `${adapter.name} — ${envKey}:` });
        if (p.isCancel(value) || !value) continue;
        if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(value)) {
          console.error(pc.red(`${envKey}: value contains a control character. Not saved.`));
          continue;
        }
        writeCredential(envKey, value);
      }
      const credsNow0 = loadCredentials();
      const missing0 = requiredKeys.filter(k => !credsNow0[k] && !process.env[k]);
      addState = upsertAdapterState(addState, adapter.id, {
        type: adapter.type || 'unknown',
        status: missing0.length === 0 ? 'configured' : 'credentials-pending',
        toolCount: adapter.tools?.length ?? adapter.rest?.toolCount ?? adapter.mcp?.toolCount ?? 0,
        lastVerified: null,
      });
    }
    saveState(addState);
  }

  // Step 6: Connection verification — CHARIOT::§17.2::13. A light
  // read-only call per configured adapter (curated + additionally
  // selected), reporting tools discovered. --skip-verify / CHARIOT_SKIP_VERIFY=1
  // is the escape hatch (offline/air-gapped setup, or a slow network).
  const skipVerify = process.argv.includes('--skip-verify') || process.env.CHARIOT_SKIP_VERIFY === '1';
  if (!skipVerify) {
    const toVerify = [...curatedAdapterEntries, ...additionalAdapters];
    const s5 = makeSpinner(p);
    s5.start(`Verifying ${toVerify.length} adapter connection${toVerify.length !== 1 ? 's' : ''}`);
    const verifyLines: string[] = [];
    for (const adapter of toVerify) {
      const result = await verifyAdapterConnection(adapter, defaultConnectionDispatcher, 5000);
      if (!result.ok) {
        verifyLines.push(`${pc.yellow('!')} ${adapter.name} — not verified (${result.reason}, ${result.latencyMs}ms)`);
      } else if (result.countMismatch) {
        // CH-50 — the count shown to the user/agent must be the bundle
        // count, never a stale/empty runtime tally; a live-vs-catalog
        // disagreement is surfaced, not silently accepted.
        verifyLines.push(`${pc.yellow('!')} ${adapter.name} — ${result.toolCount} tools discovered (catalog declares ${result.declaredToolCount}), ${result.latencyMs}ms`);
      } else {
        verifyLines.push(`${pc.green('✓')} ${adapter.name} — ${result.toolCount} tools discovered, ${result.latencyMs}ms`);
      }
    }
    s5.stop('Connection verification complete');
    p.note(verifyLines.join('\n'), 'Connection verification');
  } else {
    p.log.info('Connection verification skipped (--skip-verify).');
  }

  // Step 4: Routing demo — prove intelligence in-process, no network calls
  const { ToolPreFilter } = await import('../federation/ToolPreFilter.js');
  const demoFilter = new ToolPreFilter();
  demoFilter.index(buildToolsForRouting(curatedAdapterEntries));
  demoFilter.setCatalogKeywords(curatedAdapterEntries); // CHARIOT::§4.6::1

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

  // Step 3d/7: epic-ai.config.ts generation — CHARIOT::§17.2::14. Written
  // to process.cwd() (a per-PROJECT file — distinct from the per-machine
  // ~/.epic-ai/* state written above). Validated with ts.transpileModule
  // before writing (rulings item 92); an existing file is never silently
  // overwritten.
  {
    const configPath = join(process.cwd(), 'epic-ai.config.ts');
    const allSelected = [...curatedAdapterEntries, ...additionalAdapters];
    const rendered = renderConfigFile(allSelected, { pkgVersion: PKG_VERSION });
    const diagnostics = validateGeneratedConfig(rendered);
    if (diagnostics.length > 0) {
      p.log.warning(`epic-ai.config.ts generation produced invalid TypeScript — skipped writing it. Diagnostics: ${diagnostics.join('; ')}`);
    } else if (existsSync(configPath)) {
      const overwrite = await p.confirm({ message: 'epic-ai.config.ts already exists — overwrite?', initialValue: false });
      if (!p.isCancel(overwrite) && overwrite) {
        writeFileSync(configPath, rendered);
        p.log.success(`${pc.green('✓')} epic-ai.config.ts updated`);
      }
    } else {
      writeFileSync(configPath, rendered);
      p.log.success(`${pc.green('✓')} epic-ai.config.ts written`);
    }
  }

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
  // CHARIOT::§3.1::8 wizard log — see _wizardLog declaration above.
  _wizardLog.info('wizard.completed', { configuredClients: configuredClients.length });
}

// ─── Main router ────────────────────────────────────────────

async function main(): Promise<void> {
  // CHARIOT::§20::8 — validate CHARIOT_LOG_LEVEL once, before any command
  // (including --serve) does real work, so an invalid value fails fast at
  // startup rather than silently falling back to a different level deep in
  // some component's logger.
  validateChariotLogLevel();

  const args = process.argv.slice(2);
  const command = args[0];

  if (args.includes('--serve')) {
    await startMcpServer();
    return;
  }

  // Update-availability notice for interactive commands only —
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
      // Strip agent flags so they are not folded into the question text.
      const q = args.slice(1).filter((a) => a !== '--json').join(' ');
      if (!q) {
        if (chariotAgentMode()) {
          emitCliEnvelope(failEnvelope('cli:query', 'USAGE_ERROR', {
            severity: 'error', exit_code: 2,
            cause: 'Missing query text.',
            agent_message: 'chariot query requires a question argument.',
            remediation: ['Run: chariot query "<question>" --json'],
          }));
          break;
        }
        console.error('Usage: chariot query "<question>"'); process.exit(1);
      }
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
  if (chariotAgentMode()) {
    emitCliEnvelope(failEnvelope('cli', 'INTERNAL_ERROR', {
      cause: (err as Error).message || String(err),
      agent_message: `Chariot failed: ${(err as Error).message || String(err)}`,
    }));
  } else {
    console.error('Chariot error:', (err as Error).message || String(err));
  }
  process.exit(1);
});
