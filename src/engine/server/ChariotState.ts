/**
 * @epicai/chariot — Chariot State
 * Shared runtime state loaded once at startup, used by all transports.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendFileSync } from 'node:fs';
import { isValidDockerPin } from './dockerIntegrity.js';
import { randomUUID } from 'node:crypto';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import { resolvePublishedArtifactDir } from '../federation/artifact-publication.js';
import { verifiedReadOrNull } from '../keys/verifyCatalogSignature.js';
import { createLogger } from '../logger.js';
import { loadConfig, loadCredentials, loadState } from '../../cli/index.js';
import type { ObservabilityEmitterContract } from '../types/index.js';
import type { SessionSurfaceState } from './sessionSurfaceState.js';
import { createSessionSurfaceState } from './sessionSurfaceState.js';
import { DlpInspector } from '../dlp/Inspector.js';
import { getConfiguredAdapterIds } from '../federation/configuredAdapterIds.js';
import { PersistentMemory } from '../memory/PersistentMemory.js';
import { InMemoryStore } from '../memory/adapters/InMemoryStore.js';

const log = createLogger('server.chariot-state');

// =============================================================================
// ChariotHealthEmitter
//
// Writes one JSONL line per adapter dispatch event to
// CHARIOT_HEALTH_FILE (default /tmp/chariot-health-pings.jsonl).
// An external consumer may poll this file by byte-offset and process
// each newline-delimited JSON object independently.
//
// Wire format (ChariotHealthPing):
//   adapter_id, tenant_id, call_id, phase, outcome, error_code,
//   latency_ms, emitted_at
// All fields are optional in the interface; the emitter populates all
// of them on every dispatch event.
// =============================================================================

export const CHARIOT_HEALTH_FILE_DEFAULT = '/tmp/chariot-health-pings.jsonl';

export interface ChariotHealthPing {
  adapter_id?: string;
  tenant_id?: string;
  call_id?: string;
  phase?: string;
  outcome?: string;
  error_code?: string;
  latency_ms?: number;
  emitted_at?: string;
}

export interface ChariotHealthEmitArgs {
  adapterId: string;
  tenantId: string;
  phase: 'dispatch-after-load' | 'first-call-success' | 'tool-invocation';
  outcome: 'success' | 'failure';
  latencyMs: number;
  errorCode?: string;
}

/**
 * Emits one ChariotHealthPing JSONL line per adapter dispatch event.
 * Writing is synchronous and best-effort: errors are swallowed so a
 * filesystem issue never interrupts dispatch.
 */
export class ChariotHealthEmitter {
  private readonly filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? process.env.CHARIOT_HEALTH_FILE ?? CHARIOT_HEALTH_FILE_DEFAULT;
  }

  emit(args: ChariotHealthEmitArgs): void {
    const ping: ChariotHealthPing = {
      adapter_id: args.adapterId,
      tenant_id: args.tenantId,
      call_id: randomUUID(),
      phase: args.phase,
      outcome: args.outcome,
      latency_ms: args.latencyMs,
      emitted_at: new Date().toISOString(),
    };
    if (args.errorCode !== undefined) {
      ping.error_code = args.errorCode;
    }
    try {
      appendFileSync(this.filePath, JSON.stringify(ping) + '\n', 'utf-8');
    } catch (err) {
      // Best-effort — never interrupt dispatch on a filesystem error.
      log.warn('chariot_health_emitter_write_failed', { error: String(err) });
    }
  }
}

// =============================================================================
// Adapter catalog type (engine-specific shape — distinct from ChariotRegistryEntry)
// =============================================================================

export interface AdapterEntry {
  id: string;
  name: string;
  description?: string;
  category?: string;
  /**
   * Semantic search keywords authored by the catalog publisher enricher. Used by
   * buildToolsForRouting to broaden the BM25 indexed text beyond
   * id+toolNames+description so domain queries (e.g. "photosynthesis"
   * for a reference adapter whose toolNames carry no domain terms)
   * reach the right adapter. bug-tracker-ref.
   */
  keywords?: string[];
  type?: string;
  rest?: {
    module?: string;
    className?: string;
    baseUrl?: string;
    authType?: string;
    envKey?: string;
    toolCount?: number;
    toolNames?: string[];
    /**
 * per-tool metadata including JSON-Schema inputSchema.
     * Populated by the publisher materializer (mapDocToCatalogEntry /
     * mapDocToRegistryEntry) from upstream mcp.tools[] / rest.tools[]
     * arrays. validateForHandlerInner reads `adapter.rest?.tools` to look up
     * a tool's inputSchema before adapter dispatch on the REST branch.
     * Absent when the source document has no per-tool schema data; in that
     * case the validator emits warn-once and lets the call proceed.
     */
    tools?: Array<{
      name: string;
      description?: string;
      inputSchema?: Record<string, unknown>;
    }>;
  };
  mcp?: {
    transport?: string;
    packageName?: string;
    command?: string;
    args?: string[];
    serverUrl?: string;
    url?: string;
    envKeys?: string[];
    /**
     * Phase R (v4 spec §R.1): env var name in `state.credentials` whose value
     * becomes the Authorization header value for streamable-http dispatch
     * (Case 4 in toolHandlers.ts). Absent on adapters that target public,
     * unauthenticated MCP endpoints.
     */
    authEnvKey?: string;
    /**
     * Phase R (v4 spec §R.1): how to format the credential as an HTTP header.
     * 'bearer' → Authorization: Bearer <v>. 'basic' → Authorization: Basic <base64(v)>.
     * 'apikey-header' → vendor-specific header name from sibling `authHeaderName`.
     * 'oauth2' → defer to existing SDK OAuthClientProvider (not wired in v4).
     */
    authScheme?: 'bearer' | 'basic' | 'apikey-header' | 'oauth2';
    /**
     * Phase R (v4 spec §R.1): REQUIRED when `authScheme === 'apikey-header'`.
     * Vendor-specific HTTP header name (e.g. 'X-API-Key', 'X-Auth-Token').
     */
    authHeaderName?: string;
    toolNames?: string[];
    toolCount?: number;
    /**
 * Pinned version for npx/uvx stdio adapters. When set,
     * preinstall installs THIS version (not @latest). Required whenever
     * `integrityShasum` is set — the two fields are populated together by
     * the bundle-publication pipeline. For npx rows the version comes from
     * `npm view <pkg> dist-tags.latest`. For uvx rows it is parsed from
     * the wheel filename (PEP 427) produced by `uv pip download --no-deps`.
     */
    version?: string;
    /**
 * SHA-512 hex digest of the tarball (npm) or wheel (uvx)
     * for the pinned `version`. When set, preinstall verifies the on-disk
     * artifact's digest matches before reporting WARMED; mismatch yields
     * INTEGRITY_MISMATCH and fail-closed refusal to install.
     */
    integrityShasum?: string;
    /**
     * Git-commit pin for `github:`-sourced stdio adapters (bug-tracker-ref). A
     * 40-hex commit SHA. npm tarball pins (version + integrityShasum) do
     * not exist for github: specs, so this is their integrity contract:
     * preinstall clones the repo, checks out exactly this commit, and
     * verifies `git rev-parse HEAD` matches before reporting WARMED.
     * github: rows without a gitRef are refused (INTEGRITY_UNPINNED),
     * mirroring the fail-closed npm/uvx behavior. Populated by the
     * catalog publication pipeline (its demotion gate stops
     * demoting a github: row once this field is present).
     */
    gitRef?: string;
    /**
     * Docker-run dispatch path. Container adapters that have been digest-pinned
     * by the catalog publication pipeline carry both fields in the published
     * catalog entry. When present together, the engine spawns
     * `docker run --rm -i --pull=never <dockerImage>@<dockerDigest>`
     * and bridges MCP over stdio — the container analog of the npm stdio path.
     *
     * `dockerImage` — lower-case registry/repo/image ref WITHOUT a tag or
     * digest suffix (e.g. "mcp/github"). Validated against the safe-image
     * pattern before any subprocess spawn so a malformed ref cannot inject
     * flags into the docker argv.
     *
     * `dockerDigest` — immutable sha256 content digest ("sha256:<64 hex chars>").
     * The container's integrity pin — analogous to npm `integrityShasum`. Absent
     * or malformed → dispatch refused (fail-closed), same posture as unpinned npm.
     */
    dockerImage?: string;
    /**
     * sha256 content-addressable digest for the image named in `dockerImage`.
     * Format: "sha256:" followed by exactly 64 lowercase hex characters.
     * Required for dispatch; absent → DOCKER_INTEGRITY_UNPINNED refusal.
     */
    dockerDigest?: string;
    /**
 * per-tool metadata including JSON-Schema inputSchema.
     * Populated by the publisher materializer (mapDocToCatalogEntry /
     * mapDocToRegistryEntry) from upstream mcp.tools[] arrays.
     * validateForHandlerInner reads `adapter.mcp?.tools` to look up a
     * tool's inputSchema before adapter dispatch on the 4 non-REST
     * transports (stdio, SSE, streamable-http, CLI). Absent when the
     * source document has no per-tool schema data; in that case the
     * validator emits warn-once and lets the call proceed.
     */
    tools?: Array<{
      name: string;
      description?: string;
      inputSchema?: Record<string, unknown>;
    }>;
  };
  /**
   * Phase R (v4 spec §R.1): CLIBridge adapter block. Present when
   * `type === 'cli-bridge'` — defines how to spawn a vendor CLI as a tool call
   * (Case 5 in toolHandlers.ts). Each CLIBridge adapter has a `cli` block
   * instead of `mcp` or `rest`.
   */
  cli?: {
    /** Binary name to spawn (e.g. 'gh', 'aws', 'stripe'). Looked up on PATH at dispatch. */
    binary: string;
    /** Static argument prefix before the tool-call-derived args (e.g. ['repo', 'list']). */
    args: string[];
    /** Whitelist of env var names from state.credentials injected into the subprocess. */
    envKeys?: string[];
    /** How to parse subprocess stdout. */
    stdoutFormat: 'json' | 'json-rpc' | 'text';
    /** Per-tool argument schemas — defines the tool-name → CLI subcommand/flag mapping. */
    toolSchemas: Array<{
      name: string;
      description?: string;
      /**
 * per-tool JSON-Schema validation contract. Populated by
       * the publisher materializer alongside the dispatch metadata
       * (subcommand/flags/positional). validateForHandlerInner with
       * source='cli' looks up `adapter.cli.toolSchemas[i].inputSchema`
 * for the gate before the CLI subprocess spawns. Absent
       * when the source document has no per-tool inputSchema data; in
       * that case the validator emits warn-once and lets the call proceed.
       */
      inputSchema?: Record<string, unknown>;
      /** Static subcommand inserted between cli.args and the per-call argv (e.g. 'list'). */
      subcommand?: string;
      /** Mapping from tool-call parameter name to CLI flag (e.g. {limit: '--limit'}). */
      flags?: Record<string, string>;
      /** Tool-call parameters injected as positional args, in order. */
      positional?: string[];
    }>;
    /** Per-call timeout in milliseconds. Defaults to 30000 (30s). */
    timeoutMs?: number;
    /**
     * Phase R.7 (v4): per-host install map for `chariot setup --pre-install`.
     * Optional — the setup wizard falls through to a hardcoded fallback for
     * the 5 GT-anchored CLIs (gh, aws, gcloud, az, stripe) when this field is
     * absent. Each per-host entry is either a package-manager invocation
     * (`{ manager, package }`) or a manual hint (`{ manager: 'manual', hint }`).
     */
    installTargets?: {
      darwin?: { manager: 'brew'; package: string } | { manager: 'manual'; hint: string };
      debian?: { manager: 'apt'; package: string } | { manager: 'manual'; hint: string };
      rhel?: { manager: 'dnf'; package: string } | { manager: 'manual'; hint: string };
      arch?: { manager: 'pacman'; package: string } | { manager: 'manual'; hint: string };
      win32?: { manager: 'winget'; package: string } | { manager: 'manual'; hint: string };
    };
  };
  /** Maps the adapter's native severity strings to the normalized vocabulary used by downstream consumers.
   *  Missing key defaults to 'info'. */
  severityMap?: Record<string, 'info' | 'low' | 'medium' | 'high' | 'critical'>;
  /**
 * per-adapter timeout in milliseconds. Authored by the
   * publisher (heuristic per tool class), consumed by Chariot's retry
   * layer in place of the legacy 30 s global default. Optional;
   * absence falls back to MCPAdapterBase.DEFAULT_RETRY.timeoutMs.
   * Note: cli-bridge dispatch additionally caps the effective timeout
   * at 300 000 ms (5 minutes) — values above are silently clamped.
   */
  timeoutMs?: number;
  /**
 * EFFICIENCY #2: Pre-built Set<string> for O(1) tool-name
   * validation in handleCall. Populated by loadAllAdapters() from the
   * combined rest.toolNames ?? mcp.toolNames arrays at catalog-load time.
   * Absent on synthetic/test stubs that don't go through loadAllAdapters().
   */
  toolNamesSet?: Set<string>;
  /**
   * draft-04 §4.3 — Chariot-as-Client ID-JAG fan-out manifest. When
   * present on an adapter, MCP-dispatch obtains a per-audience ID-JAG
   * from the user's enterprise IdP via exchangeForIdJag() and presents
   * it at the downstream Resource AS instead of (or alongside) the
   * static credential. Absent → adapter uses static credentials only.
   */
  idJagAuth?: {
    /** Downstream Resource AS issuer URL (RFC 8414). Becomes the audience parameter. */
    audience: string;
    /** Optional RFC 8707 resource indicator. */
    resource?: string;
    /** Optional space-delimited scope to request. */
    scope?: string;
    /**
     * Behaviour when the IdP token exchange fails:
     *   'static' → fall back to the existing credential path so the
     *              tool call still proceeds with a vendor-managed key.
     *   'reject' → return an error to the caller; no static fallback.
     */
    fallback: 'static' | 'reject';
  };
}

// =============================================================================
// ChariotState interface
// =============================================================================

export interface ChariotState {
  /** All adapters from the catalog. */
  allAdapters: AdapterEntry[];
  /** Indexed by adapter id for O(1) lookup. */
  adapterById: Map<string, AdapterEntry>;
  /** BM25 pre-filter over configured adapters (default search scope). */
  toolPreFilter: ToolPreFilter;
  /** BM25 pre-filter over full catalog (discover mode). */
  fullCatalogFilter: ToolPreFilter;
  /** ISO timestamp of when the catalog was last loaded. */
  loadedAt: string;
  /**
   * Returns adapters the given tenant is authorized to search and call.
   *
   * In Chariot 3.0.0 single-user mode: the tenantId parameter is ignored.
   * The function always returns the globally-configured adapter set built
   * from ~/.epic-ai/.env at startup. All callers see the same set.
   *
   * This is the injection point for Chariot's enterprise build, which
   * replaces this function with an IAM credential-store lookup keyed on
   * tenantId.
   */
  getConfiguredAdapters(tenantId: string): AdapterEntry[];
  /** Adapter IDs that are configured in the OSS single-user build. */
  configuredAdapterIds: Set<string>;
  /** Credentials loaded from ~/.epic-ai/.env at startup. */
  credentials: Record<string, string>;
  /** Absolute path to the package root (directory containing package.json). */
  packageRoot: string;
  /**
 * optional observability emitter wired through to
   * handleCallInner's REST branch so adapter retries surface as
   * 'tool-call-retry' StreamEvents. Instantiated in the child process
   * by setup.ts:startMcpServer; embedders may also supply their own.
   */
  observabilityEmitter?: ObservabilityEmitterContract;
  /**
   * Per-MCP-session memory of tool tuples that chariot_query has surfaced.
   * Populated in handleQueryImpl after a matched response is built.
   * Read in handleCallImpl to fail-closed (TOOL_NOT_SURFACED_IN_SESSION)
   * when the agent invokes chariot_call on a tool that was never
   * returned by a chariot_query in this session. Optional so embedders
   * with their own state management can opt out; the MCP/stdio runtime
   * always installs one in setup.ts:startMcpServer.
   */
  sessionSurfaceState?: SessionSurfaceState;
  /**
   * OWASP LLM02 Sensitive Information Disclosure — gateway DLP.
   *
   * Inspector runs against every MCP tool-call response body before the
   * payload reaches the orchestrator / model context (see
   * extractAndScanMcpTextResult + the REST branch of handleCallInner in
   * toolHandlers.ts). Built-in rules cover credit-card, ssn-us, AWS
   * access-key id/secret, PEM private keys, JWTs, GitHub PATs, generic
   * API keys, GCP service-account JSON, Azure connection strings, Slack
   * tokens, Twilio credentials, npm tokens. Decision is redact-by-
   * default: matches are replaced with `[REDACTED-<rule-id>]` markers in
   * place rather than blocking the response. Operators that prefer hard-
   * block semantics can replace this inspector with one whose
   * defaultDecision is 'block'. Optional so embedders / tests can opt
   * out; the MCP/stdio runtime installs the default inspector below.
   */
  dlpInspector?: DlpInspector;
  /**
   * Health-ping emitter. Writes one JSONL line per adapter dispatch event
   * to CHARIOT_HEALTH_FILE (default /tmp/chariot-health-pings.jsonl).
   * An external consumer may poll this file for dispatch telemetry.
   * Optional — absent in embedder contexts that manage their own telemetry.
   * The MCP/stdio runtime installs a default instance in loadChariotState.
   */
  healthEmitter?: ChariotHealthEmitter;
  /**
   * Adapter ids that have completed at least one successful tool invocation
   * this process lifetime. Backs the one-shot `first-call-success` health
   * phase (bug-tracker-ref): the first success per adapter emits an extra ping with
   * that phase; later successes emit only `tool-invocation`.
   */
  firstCallSuccessSeen?: Set<string>;
  /**
   * Per-process persistent memory service. Exposes etch/recall/forget to the
   * three user-facing memory tools (chariot_remember / chariot_recall /
   * chariot_forget) registered in registerChariotTools. Backed by
   * InMemoryStore in the OSS single-user build; enterprise deployments may
   * swap in a RedisMongoAdapter-backed instance without changing the tool
   * layer. Optional so embedders that manage their own memory layer can opt out.
   */
  memory?: PersistentMemory;
  /**
   * Optional LLM function wired to chariot_validate_claim for higher-fidelity
   * grounding.  When absent the claim validator falls back to a deterministic
   * heuristic path (lexical overlap + negation detection).  Embedders supply
   * this by setting `state.claimValidatorLlm`; the OSS single-user build
   * leaves it undefined so no outbound LLM call is made.
   */
  claimValidatorLlm?: import('./ClaimValidator.js').ClaimValidatorLlm;
}

// =============================================================================
// Internal helpers
// =============================================================================

function getPackageRoot(): string {
  // dist/engine/server/ChariotState.js → '..','..','..','..') → package root
  const thisFile = fileURLToPath(import.meta.url);
  return join(thisFile, '..', '..', '..', '..');
}

/**
 * Bridge the catalog publisher publisher field names to the dispatcher's canonical field names.
 * the catalog publisher emits `mcp.serverUrl` (HTTP/SSE) and `mcp.packageName` (stdio); dispatch
 * sites in setup.ts and toolHandlers.ts read `mcp.url` and `mcp.command`/`mcp.args`.
 * This function is the single field-name reconciliation point. Both legacy and
 * canonical fields are preserved so emitter-side code that reads either still works.
 */
export function normalizeAdapter(adapter: AdapterEntry): AdapterEntry {
  if (!adapter.mcp) return adapter;
  if (!adapter.mcp.url && adapter.mcp.serverUrl) {
    adapter.mcp.url = adapter.mcp.serverUrl;
  }
  if (!adapter.mcp.command && adapter.mcp.packageName) {
    adapter.mcp.command = 'npx';
    if (!adapter.mcp.args) {
      // Air-gap: NEVER `npx -y` — that fetches and executes an unpinned
      // package from the registry at runtime, which breaks the air-gap
      // guarantee. `--no-install` runs the package only if it is already
      // present locally and fails closed (no network fetch) otherwise.
      // Pinned/bundled packages are provided by the publisher; integrity
      // verification against the pinned manifest is layered on top.
      adapter.mcp.args = ['--no-install', adapter.mcp.packageName];
    }
  }
  return adapter;
}

/**
 * True when an adapter resolves to at least one dispatcher branch in
 * setup.ts (CLI query path) or toolHandlers.ts (server runtime path).
 * Call AFTER normalizeAdapter so serverUrl/packageName have been bridged.
 *
 * An adapter is dispatchable iff:
 *   - streamable-http or sse transport with a url, OR
 *   - stdio transport with a command, OR
 *   - docker-run: stdio transport with a valid dockerImage + dockerDigest, OR
 *   - rest with module+className, OR
 *   - cli with binary + toolSchemas.
 *
 * Undispatchable entries are dropped at load time so they never reach the
 * routing index or the configured set; the customer cannot select an
 * adapter that would 100% fail at dispatch time with
 * "No executable transport".
 */
export function isDispatchable(adapter: AdapterEntry): boolean {
  if (adapter.mcp) {
    if ((adapter.mcp.transport === 'streamable-http' || adapter.mcp.transport === 'sse') && adapter.mcp.url) {
      return true;
    }
    if (adapter.mcp.transport === 'stdio' && adapter.mcp.command) {
      return true;
    }
    // digest-pinned docker container adapters. transport='stdio', no
    // command, but dockerImage + dockerDigest are both present and valid. The
    // engine synthesizes `docker run --rm -i --pull=never <image>@<digest>`.
    if (
      adapter.mcp.transport === 'stdio' &&
      !adapter.mcp.command &&
      isValidDockerPin(adapter.mcp.dockerImage, adapter.mcp.dockerDigest)
    ) {
      return true;
    }
  }
  if (adapter.rest?.module && adapter.rest?.className) return true;
  if (adapter.cli?.binary && Array.isArray(adapter.cli.toolSchemas)) return true;
  return false;
}

export async function loadAllAdapters(): Promise<AdapterEntry[]> {
  try {
    const pkgRoot = getPackageRoot();
    const bundleDir = resolvePublishedArtifactDir(pkgRoot, 'chariot-current.json', pkgRoot);
    const bundlePath = join(bundleDir, 'chariot-adapter-bundle.json');
    const catalogPath = process.env.CHARIOT_ADAPTER_CATALOG_PATH ?? bundlePath;

    const bytes = verifiedReadOrNull(catalogPath, log, 'adapter-catalog');
    if (!bytes) return [];

    let parsed: AdapterEntry[] | { catalog?: AdapterEntry[]; registry?: AdapterEntry[] };
    try {
      parsed = JSON.parse(bytes.toString('utf-8')) as AdapterEntry[] | { catalog?: AdapterEntry[]; registry?: AdapterEntry[] };
    } catch (err) {
      log.error('adapter catalog parse failed after signature verification', {
        path: catalogPath,
        error: String(err),
      });
      return [];
    }

    // Prefer bundle.registry[] over bundle.catalog[]: both carry the same
    // 1,788 rows, but registry[] is the field-rich projection the MCP-server
    // dispatch path (RegistryLoader) consumes — it retains rest.toolNames for
    // ~690 REST adapters that catalog[] drops. Reading catalog[] here made the
    // CLI query path build `<id>:default` routing tools for those adapters,
    // so brand-pinned queries dispatched a non-existent `default` tool
    // ("Unknown tool: default"). Falling back to catalog[] then a bare array
    // keeps older single-collection bundles working. (bug-tracker-ref)
    const adapters: AdapterEntry[] = Array.isArray(parsed) ? parsed
      : (parsed && Array.isArray(parsed.registry)) ? parsed.registry
      : (parsed && Array.isArray(parsed.catalog)) ? parsed.catalog
      : [];

    // Overlay native-code curated adapters that are absent from the published
    // bundle. The catalog publication pipeline may lag or drop curated
    // open-data adapters (bug-tracker-ref: wikipedia removed by catalog purge).
    // These entries are code-authoritative: the class lives at
    // dist/engine/mcp-servers/<id>.js; the module field uses the same
    // relative-to-pkgRoot pattern as other REST entries in the bundle.
    const bundleIds = new Set(adapters.map((a) => a.id));
    const nativeCurated: AdapterEntry[] = [
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
          toolCount: 7,
          toolNames: ['get_page_summary', 'get_page_html', 'get_page_media_list', 'get_page_mobile_html', 'get_revision_metadata', 'get_citation', 'get_mobile_css'],
        },
      },
    ];
    for (const native of nativeCurated) {
      if (!bundleIds.has(native.id)) {
        adapters.push(native);
      }
    }

    // Overlay verified discovered adapters from ~/.epic-ai/discovered-adapters/.
    // loadVerifiedDiscoveredAdapters rejects any envelope whose signature
    // does not verify against the per-host public key — closing the
    // tamper boundary the disk layout otherwise opened.
    try {
      const { loadVerifiedDiscoveredAdapters } = await import('../../discovery/envelope.js');
      const verified = loadVerifiedDiscoveredAdapters();
      for (const payload of verified) {
        // The discover-write path produces a minimal REST-style adapter
        // shape; coerce into AdapterEntry. Skip ones missing an id.
        const id = typeof payload.id === 'string' ? payload.id : undefined;
        if (!id) continue;
        adapters.push(payload as unknown as AdapterEntry);
      }
    } catch (err) {
      log.warn('loadVerifiedDiscoveredAdapters skipped', { error: String(err) });
    }

    const loadStartMs = Date.now();
    const kept: AdapterEntry[] = [];
    let droppedTransportless = 0;
    let droppedMismatch = 0;
    // dispatch-after-load (bug-tracker-ref): one ping per adapter recording the
    // load-time dispatchability verdict. Emitted ONLY when CHARIOT_HEALTH_FILE
    // is explicitly set — telemetry-wired deployments opt in via env; default
    // CLI invocations must not append a catalog-sized JSONL block per run.
    const loadEmitter = process.env.CHARIOT_HEALTH_FILE ? new ChariotHealthEmitter() : undefined;
    const loadTenantId = process.env.CHARIOT_TENANT_ID ?? 'local';
    for (const adapter of adapters) {
      normalizeAdapter(adapter);
      if (!isDispatchable(adapter)) {
        const hasAnyTransportKey = !!(adapter.mcp?.serverUrl || adapter.mcp?.packageName || adapter.rest || adapter.cli);
        if (hasAnyTransportKey) droppedMismatch++; else droppedTransportless++;
        loadEmitter?.emit({
          adapterId: adapter.id,
          tenantId: loadTenantId,
          phase: 'dispatch-after-load',
          outcome: 'failure',
          latencyMs: Math.max(0, Date.now() - loadStartMs),
          errorCode: hasAnyTransportKey ? 'undispatchable_mismatch' : 'undispatchable_transportless',
        });
        continue;
      }
      const names = adapter.rest?.toolNames ?? adapter.mcp?.toolNames;
      if (names && names.length > 0) {
        adapter.toolNamesSet = new Set<string>(names);
      }
      kept.push(adapter);
      loadEmitter?.emit({
        adapterId: adapter.id,
        tenantId: loadTenantId,
        phase: 'dispatch-after-load',
        outcome: 'success',
        latencyMs: Math.max(0, Date.now() - loadStartMs),
      });
    }
    if (droppedTransportless > 0 || droppedMismatch > 0) {
      // bug-tracker-ref: routine catalog filtering — not an error
      // condition for the customer. Demoted to debug so it does not
      // leak into customer-facing CLI stderr on every invocation.
      log.debug('adapter catalog: dropped undispatchable entries at load', {
        droppedTransportless,
        droppedMismatch,
        kept: kept.length,
        total: adapters.length,
      });
    }
    return kept;
  } catch (err) {
    log.error('loadAllAdapters failed', { error: String(err) });
    return [];
  }
}

// getConfiguredAdapterIds extracted to
// src/engine/federation/configuredAdapterIds.ts as the single canonical
// implementation. Both ChariotState (live MCP server routing) and
// setup.ts (cmdQuery + startMcpServer wiring) now import the same
// function. The earlier review rounds traced split-brain bugs
// back to this clone being maintained by hand in two files — extracting
// it eliminates the divergence surface permanently.

/**
 * bug-tracker-ref: an adapter is description-quality-disqualified when its
 * description is missing, too short, or matches one of the auto-generated
 * boilerplate templates the catalog publisher emits when it failed to
 * scrape a real description. These records have no semantic specificity
 * and pollute BM25 by matching generic CRUD tokens (e.g. id="decern-crm"
 * with description "Set your ship colors" matched "hotel occupancy" queries
 * in eval-01). They are kept in the bundle for dispatch but excluded from
 * the routing index so they cannot win top-1 over an adapter whose
 * description actually describes its domain.
 *
 * Whitelist: canonical brand-name adapters (amplitude, datadog, etc.) whose
 * bundle records sometimes ship with an empty description because the
 * publisher couldn't scrape one from the vendor's documentation. Those
 * brands have unambiguous user intent (the query literally names them) and
 * should never be filtered out of routing on quality grounds — the
 * canonical-vendor pin needs them present in `sortedCandidates` to fire.
 */
const QUALITY_FILTER_WHITELIST = new Set<string>([
  'amplitude', 'mixpanel', 'pendo', 'hotjar',
  'datadog', 'datadog-observability', 'datadog-rum', 'new-relic', 'sentry',
  'pagerduty', 'opsgenie', 'rootly',
  'okta', 'microsoft-entra', 'auth0', 'crowdstrike-identity',
  'salesforce', 'hubspot', 'pipedrive', 'marketo',
  'github', 'gitlab', 'bitbucket', 'github-actions', 'argocd',
  'slack', 'discord', 'microsoft-teams', 'twilio', 'zoom',
  'stripe', 'paypal', 'square', 'quickbooks', 'accounting',
  'gmail', 'sendgrid', 'mailchimp', 'emailmcp',
  'notion', 'linear', 'jira', 'atlassian-jira', 'asana', 'monday',
  'aws', 'azure', 'gcp', 'kubernetes',
  'wiz', 'snyk', 'crowdstrike', 'agentsec', 'sentinelone',
  'shopify', 'zendesk', 'intercom', 'freshdesk',
  'bamboohr', 'workday', 'greenhouse', 'lever', 'adp',
  'drata', 'vanta', 'secureframe',
  'playwright', 'tavily', 'wayback-machine', 'pubmed',
  'epic-fhir', 'cerner',
  'impala-travel-hotels', 'nelly-elephant', 'opera-pms', 'mews', 'cloudbeds',
  'concur', 'expensify', 'navan',
  'public',  // queueing-theory adapter (legit answer to ER-wait-times queries)
  'acumatica', 'netsuite', 'sage',
  'ambianic',  // legitimate niche adapter occasionally surfaces
]);

const COHESION_STOPWORDS = new Set<string>([
  'the', 'a', 'an', 'and', 'or', 'of', 'for', 'to', 'in', 'on', 'at',
  'by', 'with', 'from', 'is', 'are', 'be', 'this', 'that', 'these',
  'those', 'it', 'its', 'as', 'mcp', 'server', 'api', 'tool', 'tools',
  'set', 'get', 'list', 'create', 'update', 'delete', 'find', 'search',
  'use', 'used', 'using', 'service', 'data', 'info', 'name', 'id',
]);

function tokensOf(s: string): Set<string> {
  return new Set(
    s.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3 && !COHESION_STOPWORDS.has(t)),
  );
}

function descriptionIsLowQuality(adapter: AdapterEntry): boolean {
  if (QUALITY_FILTER_WHITELIST.has(adapter.id)) return false;
  const d = (adapter.description ?? '').trim();
  if (d.length < 20) return true;
  if (/^Health check\b/i.test(d)) return true;
  if (/^Returns server (?:status|info)/i.test(d)) return true;
  if (/^MCP server by /i.test(d)) return true;
  if (/^MCP server exposing \d+ tools:/i.test(d)) return true;
  if (/^Check whether a model ID/i.test(d)) return true;
  if (/^Echo the input/i.test(d)) return true;
  // bug-tracker-ref langsmith case: description is just a markdown image
  // alt-text + URL with no actual prose. Strip markdown images / URLs / inline
  // markup and re-check length; if what remains is below 20 chars of real text,
  // the description has no semantic content for BM25 to weigh.
  const stripped = d
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')  // markdown images
    .replace(/\[[^\]]*\]\([^)]*\)/g, '')   // markdown links
    .replace(/https?:\/\/\S+/g, '')         // bare URLs
    .replace(/`[^`]*`/g, '')                // inline code
    .replace(/\s+/g, ' ')
    .trim();
  if (stripped.length < 20) return true;
  // bug-tracker-ref spacemolt case (was decern-crm): description tokens
  // do not match the adapter's actual tool surface. Description "Set your
  // ship colors" describes ONE tool; the adapter has 172 game tools
  // (mine, attack, dock, jump, scan, etc.). Such adapters dominate BM25
  // via tool-name token volume against queries whose intent the
  // description does not reflect. Filter when the adapter has a wide
  // tool surface (>=16 tools) and effectively zero token overlap
  // between description and tools. Threshold deliberately conservative
  // so legitimate adapters with concise descriptions aren't filtered.
  const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? [];
  if (toolNames.length >= 16) {
    const descTokens = tokensOf(stripped);
    const toolTokens = tokensOf(toolNames.join(' '));
    if (toolTokens.size > 0) {
      let overlap = 0;
      for (const t of toolTokens) if (descTokens.has(t)) overlap += 1;
      const coverage = overlap / toolTokens.size;
      if (coverage < 0.05) return true;
    }
  }
  return false;
}

export function buildToolsForRouting(adapters: AdapterEntry[]): Array<{
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  server: string;
  tier: 'orchestrated' | 'direct';
}> {
  const tools: Array<{
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    server: string;
    tier: 'orchestrated' | 'direct';
  }> = [];

  for (const adapter of adapters) {
    if (descriptionIsLowQuality(adapter)) continue;
    const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? [];
    const adapterDesc = adapter.description ?? adapter.id;
    // bug-tracker-ref / bug-tracker-ref: enrich the routing-index text with the
    // catalog publisher-published `keywords` and `category` so domain queries
    // (e.g. "photosynthesis", "biomedical") reach adapters whose
    // toolNames carry no domain terms (e.g. `search_mesh`).
    const semanticContext = [
      adapter.category ?? '',
      ...(adapter.keywords ?? []),
    ].filter(Boolean).join(' ');
    if (toolNames.length === 0) {
      tools.push({
        name: `${adapter.id}:default`,
        description: `${adapter.name} — ${adapterDesc}${semanticContext ? ` — ${semanticContext}` : ''}`,
        parameters: { type: 'object', properties: {} },
        server: adapter.id,
        tier: 'orchestrated',
      });
    } else {
      for (const t of toolNames) {
        tools.push({
          name: `${adapter.id}:${t}`,
          description: `${adapter.name} — ${t.replace(/_/g, ' ')} — ${adapterDesc}${semanticContext ? ` — ${semanticContext}` : ''}`,
          parameters: { type: 'object', properties: {} },
          server: adapter.id,
          tier: 'orchestrated',
        });
      }
    }
  }
  return tools;
}

// =============================================================================
// loadChariotState
// =============================================================================

export async function loadChariotState(
  opts: { observabilityEmitter?: ObservabilityEmitterContract } = {},
): Promise<ChariotState> {
  const allAdapters = await loadAllAdapters();
  const credentials = loadCredentials();
  const adapterState = loadState();
  const config = loadConfig();
  const packageRoot = getPackageRoot();

  const configuredAdapterIds = getConfiguredAdapterIds(allAdapters, credentials, config, adapterState);
  const configuredAdapters = allAdapters.filter(a => configuredAdapterIds.has(a.id));

  const toolPreFilter = new ToolPreFilter();
  const fullCatalogFilter = new ToolPreFilter();
  toolPreFilter.index(buildToolsForRouting(configuredAdapters));
  fullCatalogFilter.index(buildToolsForRouting(allAdapters));

  // Phase 0 (3.1.0): vector-index.json is no longer shipped or loaded.
  // Retrieval is BM25-only (ToolPreFilter.select); no signed-index step here.

  const adapterById = new Map(allAdapters.map(a => [a.id, a]));

  return {
    allAdapters,
    adapterById,
    toolPreFilter,
    fullCatalogFilter,
    loadedAt: new Date().toISOString(),
    getConfiguredAdapters(_tenantId: string): AdapterEntry[] {
      // OSS build: tenantId ignored. Chariot enterprise injects a different implementation.
      return configuredAdapters;
    },
    configuredAdapterIds,
    credentials,
    packageRoot,
    observabilityEmitter: opts.observabilityEmitter,
    // OWASP LLM02 — gateway DLP inspector applied to every MCP/REST tool
    // response body before it reaches the orchestrator. Built-in rule
    // set covers PII (credit-card, SSN) and credentials (AWS keys, PEM,
    // JWT, GitHub PAT, Stripe, generic API keys, GCP service account,
    // Azure conn str, Slack, Twilio, npm). Redact-by-default: matches
    // are replaced with `[REDACTED-<rule-id>]` rather than blocking. No
    // per-tenant overrides in the OSS build — enterprise injects its own
    // ChariotState with a per-tenant config map.
    dlpInspector: new DlpInspector({
      defaultConfig: {
        rules: new Map(),
        defaultDecision: 'redact',
        alwaysAudit: false,
      },
    }),
    // Per-process session-surface tracker. Populated by handleQueryImpl
    // when an MCP sessionId is present; read by handleCallImpl to gate
    // chariot_call against tuples that were actually surfaced to this
    // conversation. Single-process store; horizontal scaling moves this
    // to a shared backend later.
    sessionSurfaceState: createSessionSurfaceState(),
    // Health-ping emitter. One JSONL line per dispatch event →
    // /tmp/chariot-health-pings.jsonl (or CHARIOT_HEALTH_FILE env var).
    healthEmitter: new ChariotHealthEmitter(),
    // One-shot first-call-success tracking per adapter (bug-tracker-ref).
    firstCallSuccessSeen: new Set<string>(),
    // Memory service — InMemoryStore in the OSS build. Enterprise injects a
    // RedisMongoAdapter-backed PersistentMemory via its own loadChariotState
    // override. cacheTTLMs is unused by InMemoryStore (adapter-specific) but
    // required by MemoryConfig; set to a reasonable default.
    memory: new PersistentMemory({ store: new InMemoryStore(), cacheTTLMs: 0 }),
  };
}
