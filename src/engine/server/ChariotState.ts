/**
 * @epicai/chariot — Chariot State
 * Shared runtime state loaded once at startup, used by all transports.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  fstatSync,
  fsyncSync,
  closeSync,
  readFileSync,
  lstatSync,
  statSync,
  writeSync,
  renameSync,
  linkSync,
  rmSync,
  constants as fsConstants,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isValidDockerPin } from './dockerIntegrity.js';
import { randomUUID, createHash } from 'node:crypto';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import type { DecisionAuditPort } from '../ports/DecisionAuditPort.js';
import { resolvePublishedArtifactDir } from '../federation/artifact-publication.js';
import { verifiedReadFailClosed, verifyAndReadArtifact } from '../keys/verifyCatalogSignature.js';
import { CHARIOT_CATALOG_PUBLIC_KEYS } from '../keys/chariot-catalog-public.js';
// CHARIOT::§16.1 Catalog (rulings item 91/105) — direct import, matching
// this repo's established pattern (VerifiedCatalog.ts, mfa.ts, loader.ts,
// FederationManager.ts, TieredAutonomy.ts).
import { chariotEmitter } from '../../observability/emitter.js';
import { wireHybridRetrieval, type ArtifactSource } from '../retrieval/loadRetrieval.js';
import type { AdmissionCode } from '../retrieval/VectorIndexVerifier.js';
import { loadNativeEdge } from '../retrieval/nativeEdge.js';
import {
  loadSealedShardDescriptor,
  resolveSealedShardDescriptorPath,
  SEALED_SHARD_DESCRIPTOR_ENV,
  type SealedShardConfig,
} from '../retrieval/sealedShardConfig.js';
import type { NativeEdgeShard } from '../retrieval/nativeEdge.js';
import type { BundleEnvelope } from '../retrieval/VectorIndexVerifier.js';
import { loadPersistedEpoch, persistEpoch, type CatalogEpochState, MAX_CATALOG_BYTES } from '../federation/AdapterCatalog.js';
import {
  computeCatalogState,
  effectiveCatalogEntries,
  type CatalogWideState,
} from '../../catalog/VerifiedCatalog.js';
import { DEFAULT_CATALOG_TRUST_CONFIG } from '../../catalog/types.js';
import { createLogger } from '../logger.js';
import { loadConfig, loadCredentials, loadState } from '../../cli/index.js';
import type { ObservabilityEmitterContract } from '../types/index.js';
import type { SessionSurfaceState } from './sessionSurfaceState.js';
import { createSessionSurfaceState } from './sessionSurfaceState.js';
import { DlpInspector } from '../dlp/Inspector.js';
import { getConfiguredAdapterIds } from '../federation/configuredAdapterIds.js';
import { PersistentMemory } from '../memory/PersistentMemory.js';
import { FileStore } from '../memory/adapters/FileStore.js';
import { EPIC_AI_DIR, MEMORY_FILE, MODELS_DIR, QDRANT_DATA_DIR } from '../../cli/paths.js';
import { ChariotMetrics } from '../../observability/index.js';
import { WikipediaMCPServer } from '../mcp-servers/wikipedia.js';
import { DnsMCPServer } from '../mcp-servers/dns.js';
import { CustomerAuthOverlayConnector } from '../federation/CustomerAuthOverlay.js';
import { RateLimiter } from '../resilience/RateLimiter.js';
import { NativeOverlayEmbedder } from '../retrieval/overlay/OverlayEmbedder.js';
import type { OverlayEmbedder, OverlayEncoderIdentity } from '../retrieval/overlay/OverlayEmbedder.js';
import type { NativeDenseEncoder, NativeSpladeEncoder } from '../retrieval/nativeEdge.js';
import { TenantOverlayToolRegistry } from '../federation/TenantOverlayToolRegistry.js';
import type { TenantOverlayToolRegistryReader } from '../federation/TenantOverlayToolRegistry.js';

const log = createLogger('server.chariot-state');

// =============================================================================
// ChariotHealthEmitter
//
// Writes one JSONL line per adapter dispatch event to
// CHARIOT_HEALTH_FILE (default: a per-uid 0700 state dir, see
// CHARIOT_HEALTH_FILE_DEFAULT). An external consumer may poll this file by
// byte-offset and process each newline-delimited JSON object independently.
//
// Wire format (ChariotHealthPing):
//   adapter_id, tenant_id, call_id, phase, outcome, error_code,
//   latency_ms, emitted_at
// All fields are optional in the interface; the emitter populates all
// of them on every dispatch event.
// =============================================================================

/**
 * CWE-377 hardening: the ping stream previously defaulted to a PREDICTABLE
 * world-readable path in shared /tmp (/tmp/chariot-health-pings.jsonl),
 * exposing tenant_id/adapter/error/latency metadata to any local user and
 * opening a symlink/pre-creation clobber vector on non-hardened kernels.
 * Default is now a per-uid directory created 0700 (XDG_STATE_HOME when set),
 * and the emitter opens the file O_NOFOLLOW with an ownership check.
 */
function defaultHealthFilePath(): string {
  const stateHome = process.env.XDG_STATE_HOME;
  if (stateHome && stateHome.length > 0) {
    return join(stateHome, 'chariot', 'health-pings.jsonl');
  }
  const uidSuffix = typeof process.getuid === 'function' ? `-${process.getuid()}` : '';
  return join(tmpdir(), `chariot${uidSuffix}`, 'health-pings.jsonl');
}

export const CHARIOT_HEALTH_FILE_DEFAULT = defaultHealthFilePath();

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
  private fd: number | null = null;
  private disabled = false;

  constructor(filePath?: string) {
    this.filePath = filePath ?? process.env.CHARIOT_HEALTH_FILE ?? CHARIOT_HEALTH_FILE_DEFAULT;
  }

  /**
   * Open the ping file once, hardened against tmp-dir attacks: the parent
   * dir is created 0700, the file is opened O_NOFOLLOW (never follow a
   * planted symlink) with mode 0600, and the resulting fd is verified to be
   * a regular file owned by this process's uid. Applies equally to the
   * CHARIOT_HEALTH_FILE operator override. On any failure the emitter
   * disables itself (one warn) — telemetry is best-effort, dispatch never
   * blocks, and we never write through an attacker-controlled path.
   */
  private ensureFd(): number | null {
    if (this.disabled) return null;
    if (this.fd !== null) return this.fd;
    try {
      mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
      const flags = fsConstants.O_WRONLY
        | fsConstants.O_APPEND
        | fsConstants.O_CREAT
        | (fsConstants.O_NOFOLLOW ?? 0);
      const fd = openSync(this.filePath, flags, 0o600);
      const st = fstatSync(fd);
      const uidOk = typeof process.getuid !== 'function' || st.uid === process.getuid();
      if (!st.isFile() || !uidOk) {
        closeSync(fd);
        throw new Error('health ping path is not a process-owned regular file');
      }
      this.fd = fd;
      return fd;
    } catch (err) {
      this.disabled = true;
      log.warn('chariot_health_emitter_disabled', { file: this.filePath, error: String(err) });
      return null;
    }
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
    const fd = this.ensureFd();
    if (fd === null) return;
    try {
      appendFileSync(fd, JSON.stringify(ping) + '\n', 'utf-8');
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
  /**
   * Retrieval-oriented adapter description (CH-34/CH-35). Authored freeze-side
   * for the agent surface; surfaced by chariot_query for the top-k. Falls back
   * to `description` until the freeze-side producer emits it (sequenced P5).
   */
  descriptionForRetrieval?: string;
  category?: string;
  /**
   * Semantic search keywords authored by the catalog publisher enricher. Used by
   * buildToolsForRouting to broaden the BM25 indexed text beyond
   * id+toolNames+description so domain queries (e.g. "photosynthesis"
   * for a reference adapter whose toolNames carry no domain terms)
   * reach the right adapter.
   */
  keywords?: string[];
  type?: string;
  /**
   * Governance tier (BIEN §7a::2, FPS §15.1). Derived exclusively by the
   * catalog publisher's G17-03/G17-04 pipeline (AS §3.5) and stamped onto
   * every shipped catalog/registry entry, tamper-covered by the bundle's
   * signature. Chariot consumes this value ONLY to look up an adapter's
   * official/non-official status for the retrieval result partition
   * (`src/engine/retrieval/OfficialPartition.ts`, BIEN §7a::1/5/6) — it is
   * read at re-sort time from catalog metadata, never re-derived here
   * (BIEN §7a::3), and MUST NOT be added to any embedding/serializer
   * input or ToolRecord-shaped retrieval type (BIEN §7a::10).
   */
  tier?: string;
  tools?: Array<{
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
    dispatchMechanisms: Array<'rest' | 'mcp'>;
  }>;
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
    /**
     * Discovered-REST adapters only (src/discovery/DiscoveredRestAdapter.ts,
     * src/bin/chariot.ts discover writer). JSON.stringify'd
     * `DiscoveredEndpoint[]` ({method, path, handlerName?}) — the ONE piece
     * of per-adapter data no hand-written REST adapter class ever needed
     * before (its endpoint list is fixed at authoring time; a discovered
     * service's is dynamic, scanned from an arbitrary customer codebase).
     * Read by the two REST-dispatch call sites (toolHandlers.ts,
     * setup.ts cmdQuery) into `adapterConfig['endpointsJson']` before
     * constructing the adapter instance — DiscoveredRestAdapter's
     * constructor parses it to build both its `tools` list and its
     * `callTool` routing table.
     */
    discoveredEndpointsJson?: string;
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
     * Git-commit pin for `github:`-sourced stdio adapters. A
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
     * tool's inputSchema before adapter dispatch on the 3 non-REST
     * transports (stdio, streamable-http, CLI) — CHARIOT::§7.2::3, SSE is
     * refused before dispatch and never reaches this gate. Absent when the
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
  /**
   * Supply-chain trust signal set by the catalog publication pipeline's
   * verification gate (see the chariot-adapter-bundle.json rows).
   * true when the adapter passed the gate's verification checks at
   * publication time. Absent on synthetic/test stubs and on rows from
   * older bundle formats that predate the field — treated as unverified
   * (not fabricated as true) when computing the supply-chain integrity
   * percentage (see loadChariotState's ChariotMetrics wiring below).
   */
  catalogVerified?: boolean;
  /**
   * AS §1.2a: true when the adapter's tools are gated behind a customer
   * credential we never hold (auth-walled streamable-HTTP/SSE or stdio MCP).
   * OPTIONAL; default false when absent. CHARIOT-SPEC §4.5 requires the
   * routing proof-artifact gold set to include adapters carrying this flag
   * and to report Recall@8 for that class SEPARATELY (see
   * eval/proof/auth-segment.ts) — auth-walled discovery reliability must be
   * a measured, bounded number, never a silently-folded-in assumption.
   */
  requiresCustomerAuth?: boolean;
  /**
   * CHARIOT §10.5::1 (rulings item 98) — vendor OAuth token-refresh
   * declaration for the per-user OAuth credential vault. Populated by
   * the catalog publisher where the vendor documents a token-refresh endpoint;
   * ABSENT means the adapter's per-user OAuth credentials (if any) are
   * non-refreshable — `src/iam/services/credentials.ts`'s background
   * refresh job skips them and audits the skip, it never fabricates a
   * default. Distinct from `idJagAuth` (RFC 8693 token-exchange for
   * Resource-AS-facing scopes, §4.3) and from `mcp.authScheme ===
   * 'oauth2'` (documented as "defer to existing SDK OAuthClientProvider
   * (not wired in v4)") — this is specifically the vendor's OAuth 2.0
   * token endpoint (RFC 6749 §3.2) used for the refresh_token grant.
   * Top-level (mirrors `tier`/`toolCount` above, not nested under
   * `rest`/`mcp`) because it describes the adapter's vendor identity, not
   * a per-dispatch-mechanism detail — a vendor has one token endpoint
   * regardless of whether Chariot reaches it via REST or MCP.
   * AS §1.x field definition: proposed in a separate spec-amendment unit
   * (this build does not edit specs) — see the build report for the
   * byte-exact proposal.
   */
  auth?: {
    oauth2?: {
      /** Absolute https:// URL. AAD/type validation happens at the call site (resolveAdapterTokenEndpoint), not here — this type only declares the shape the catalog MAY carry. */
      tokenUrl?: string;
    };
  };
}

// =============================================================================
// ChariotState interface
// =============================================================================

/**
 * Effective Tier-1 retrieval mode decided at startup (§4.3/§4.4). 'hybrid'
 * means the four-signal stack (BM25 + dense + SPLADE + rerank) is live;
 * 'bm25-only' means the lexical steady state (legacy bundle, or hybrid
 * artifacts not yet shipped — P5/P8/BIEN M10). A fail-closed bundle rejection
 * never yields a state at all (loadChariotState throws). Exposed so
 * certification/release harnesses can assert the shipped mode
 * machine-checkably instead of trusting the build label.
 */
export type RetrievalMode = 'hybrid' | 'bm25-only';

export interface ChariotState {
  /**
   * §3.5::17 (CH-12) — pre-dispatch hash-chained audit hook, installed once at
   * startup by the enterprise IAM bootstrap. Installation-scoped (the port is
   * stateless), so it lives here rather than being rebuilt at every transport's
   * per-request CallContext. Absent on OSS / single-user installs.
   */
  decisionAudit?: DecisionAuditPort;
  /**
   * CHARIOT::§5.2 catalog-wide Ed25519-gated trust state (CH-02), computed
   * by the SAME `computeCatalogState()` (src/catalog/VerifiedCatalog.ts)
   * the federation `AdapterCatalog` class uses — the single shared
   * implementation of the §5.2 state machine. `allAdapters`/`adapterById`
   * below, and both `toolPreFilter`/`fullCatalogFilter`, are already the
   * EFFECTIVE catalog for this state (empty when `invalid`, per CH-02
   * "never a partial one") — this field exists so a caller can observe
   * WHY, not to be re-applied by the caller. Optional so embedders/tests
   * that construct a synthetic ChariotState (matching the pattern already
   * used by `chariotMetrics`/`healthEmitter` below) can opt out.
   */
  catalogState?: CatalogWideState;
  /** Human-readable trigger for {@link catalogState}. */
  catalogStateReason?: string;
  /** All adapters from the catalog — the EFFECTIVE catalog (empty when `catalogState === 'invalid'`, CH-02). */
  allAdapters: AdapterEntry[];
  /** Indexed by adapter id for O(1) lookup — same effective-catalog guarantee as {@link allAdapters}. */
  adapterById: Map<string, AdapterEntry>;
  /** BM25 pre-filter over configured adapters (default search scope). */
  toolPreFilter: ToolPreFilter;
  /** BM25 pre-filter over full catalog (discover mode). */
  fullCatalogFilter: ToolPreFilter;
  /** ISO timestamp of when the catalog was last loaded. */
  loadedAt: string;
  /** Effective Tier-1 retrieval mode decided at startup (see RetrievalMode). */
  retrievalMode: RetrievalMode;
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
   * to CHARIOT_HEALTH_FILE (default: per-uid state dir, see
   * CHARIOT_HEALTH_FILE_DEFAULT).
   * An external consumer may poll this file for dispatch telemetry.
   * Optional — absent in embedder contexts that manage their own telemetry.
   * The MCP/stdio runtime installs a default instance in loadChariotState.
   */
  healthEmitter?: ChariotHealthEmitter;
  /**
   * CHARIOT-SPEC §8.6a progressive-auth runtime overlay — the customer-
   * credential connect step. `toolHandlers.ts`'s shared
   * `runCustomerAuthOverlayGate` helper calls
   * `customerAuthOverlayConnector.connect(adapter, tenantId, {userId})`
   * from TWO call sites — `handleCallImpl`, BEFORE tool-name validation
   * (team-lead review R1: the connect must precede validation for a
   * tool-less adapter, or its overlay registry can never be populated),
   * and `handleCallInner`, again, deeper, as defense-in-depth immediately
   * before dispatch — before trusting a `requiresCustomerAuth: true` MCP
   * adapter's tools as dispatchable, and fails the call closed when this
   * is undefined (see that helper's doc comment). Constructed in
   * `loadChariotState` from
   * the RETRIEVAL-side `OverlayEmbedder` (src/engine/retrieval/overlay/
   * OverlayEmbedder.ts's `NativeOverlayEmbedder`): the injected
   * `opts.customerAuthOverlayEmbedder` seam when supplied, otherwise the live
   * embedder `wireRetrievalForState` builds on the full-admission ('hybrid')
   * path from the SAME dense/sparse encoder instances the HybridRetriever
   * uses (`makeDiskArtifactSource`'s memoized loaders — BIEN::§9::13).
   * Undefined on a BM25-only (manifest-less, legacy) bundle, where no vector
   * space exists to embed into. Optional so embedders/tests that construct
   * a synthetic ChariotState can opt out, same as `healthEmitter`.
   */
  customerAuthOverlayConnector?: CustomerAuthOverlayConnector;
  /**
   * CHARIOT-SPEC §8.6a — the durable, tenant-scoped record of which
   * customer-verified tools a `requiresCustomerAuth` adapter exposes for a
   * tenant (see `TenantOverlayToolRegistry`'s module doc comment). Read by
   * `toolHandlers.ts` at BOTH the dispatch-time tool-name validation and
   * `handleQueryImpl`'s per-adapter tool listing, and written by
   * `customerAuthOverlayConnector` on every successful embed — the SAME
   * instance is threaded into both, so a tool the connector just embedded
   * is immediately dispatchable/listable without a restart. Always
   * constructed (unlike `customerAuthOverlayConnector`, which needs a
   * retrieval-side embedder to do anything): the registry itself has no
   * embedder dependency, and an empty/never-written registry correctly
   * resolves every lookup to "no overlay tools for this tenant" — the
   * right answer for a tenant no `requiresCustomerAuth` adapter has ever
   * completed a connect for. Optional only so a synthetic test
   * `ChariotState` can opt out entirely, same as `healthEmitter`.
   */
  tenantOverlayToolRegistry?: TenantOverlayToolRegistryReader;
  /**
   * Supply-chain integrity metrics (Wiz practice 7 — feed #23). Fed once at
   * catalog load time from the loaded bundle's per-adapter `catalogVerified`
   * flag: verified = count of adapters with `catalogVerified === true`,
   * total = allAdapters.length. Re-fed every time loadChariotState() runs
   * (the only "catalog reload" point in the OSS single-process build —
   * there is no live file-watch reload here). Optional so embedders/tests
   * that construct a synthetic ChariotState can opt out.
   */
  chariotMetrics?: ChariotMetrics;
  /**
   * Adapter ids that have completed at least one successful tool invocation
   * this process lifetime. Backs the one-shot `first-call-success` health
   * phase: the first success per adapter emits an extra ping with
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
 *   - streamable-http transport with a url, OR
 *   - stdio transport with a command, OR
 *   - docker-run: stdio transport with a valid dockerImage + dockerDigest, OR
 *   - rest with module+className, OR
 *   - cli with binary + toolSchemas.
 *
 * CHARIOT::§7.2::3 — the `adapter.mcp` branch above is an ALLOW-LIST of the
 * two implemented federation-layer transports (`streamable-http` with a
 * `url`, `stdio` with a `command` or a valid docker pin), not a denylist of
 * `'sse'`. Any other transport value — `'sse'`, a case-variant/alias such as
 * `'SSE'`/`'server-sent-events'`/`'eventsource'`, an empty string, or
 * `undefined` — falls through every `if` and hits `return false` at the
 * bottom, so it is NEVER dispatchable regardless of what value it carries.
 * This is what keeps an unsupported transport from being advertised — it
 * never reaches the routing index, chariot_list output, or a customer's
 * configured set. Note this function returns `false` for BOTH failure
 * shapes toolHandlers.ts distinguishes at dispatch time — a transport
 * value outside the two implemented ones, AND a `stdio`/`streamable-http`
 * value with its required field missing — because at catalog-load time
 * there is nothing useful to distinguish; either way the adapter cannot
 * dispatch. toolHandlers.ts's two defense-in-depth refusals (the "MCP
 * unsupported-transport refusal" block, errorClass `transport_not_supported`,
 * and the "MCP incomplete-record refusal" block right after it, errorClass
 * `adapter_config_invalid`) make that distinction ONLY if a caller reaches
 * dispatch despite this drop — a customer never sees it, since this
 * function already removed both shapes from the configured set.
 *
 * Undispatchable entries are dropped at load time so they never reach the
 * routing index or the configured set; the customer cannot select an
 * adapter that would 100% fail at dispatch time with
 * "No executable transport".
 */
export function isDispatchable(adapter: AdapterEntry): boolean {
  if (adapter.mcp) {
    if (adapter.mcp.transport === 'streamable-http' && adapter.mcp.url) {
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

/** Result of {@link loadAllAdaptersWithState} — the effective adapter list plus the CHARIOT::§5.2 state that produced it. */
export interface AdapterCatalogLoadResult {
  /** The EFFECTIVE catalog (CH-02: empty when `state === 'invalid'`, never a partial one). */
  adapters: AdapterEntry[];
  state: CatalogWideState;
  stateReason: string;
}

/**
 * `materializedAt` sibling field on the bundle envelope, when the publisher
 * stamps it. Mirrors `extractMaterializedAt` in
 * `src/engine/federation/AdapterCatalog.ts` — same field, same shape, kept
 * as a small local copy here rather than importing a non-exported helper
 * across files for one three-line function.
 */
function extractMaterializedAt(parsed: unknown): number | undefined {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const v = (parsed as { materializedAt?: unknown }).materializedAt;
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/**
 * CHARIOT::§5.2::1-4 (CH-02) — the production adapter-load path (every
 * caller of `loadAllAdapters()` below runs through this). Classifies the
 * bundle signature check via the SAME `computeCatalogState()` /
 * `effectiveCatalogEntries()` (`src/catalog/VerifiedCatalog.ts`) the
 * federation `AdapterCatalog` class uses, so this — the path that
 * actually drives `ChariotState.allAdapters`/`adapterById` and every
 * `toolHandlers.ts` reader — reports the identical state semantics
 * instead of the ad hoc bytes-or-null check this replaces. Returns the
 * EFFECTIVE catalog: empty on `invalid`, full (with a WARN already
 * logged) on `stale`, full on `verified` — CH-02 "never a partial one".
 */
export async function loadAllAdaptersWithState(): Promise<AdapterCatalogLoadResult> {
  try {
    const pkgRoot = getPackageRoot();
    const bundleDir = resolvePublishedArtifactDir(pkgRoot, 'chariot-current.json', pkgRoot);
    const bundlePath = join(bundleDir, 'chariot-adapter-bundle.json');
    const catalogPath = process.env.CHARIOT_ADAPTER_CATALOG_PATH ?? bundlePath;

    // CHARIOT::§5.2::3 (CH-02) — call the lower-level verifier directly
    // (rather than `verifiedReadOrNull`, which collapses every failure
    // reason to a bare null) so an ABSENT bundle (fresh install, nothing
    // published yet — CHARIOT-SPEC.md's own artifact-not-found precedent,
    // silent by design) can be told apart from a PRESENT-but-invalid one
    // (tamper, wrong key, corrupt .sig — a CH-02 "signature mismatch or
    // missing" integrity failure). Both still yield an empty effective
    // catalog; only the log noise and the reported `state`/`stateReason`
    // differ.
    const verifyResult = verifyAndReadArtifact(catalogPath, CHARIOT_CATALOG_PUBLIC_KEYS, MAX_CATALOG_BYTES);
    if (!verifyResult.ok) {
      if (verifyResult.reason !== 'artifact-not-found') {
        log.error('catalog signature gate failed', {
          label: 'adapter-catalog',
          reason: verifyResult.reason,
          path: catalogPath,
          detail: verifyResult.detail,
        });
      }
      const result = computeCatalogState({ signatureValid: false });
      return {
        adapters: effectiveCatalogEntries(result.state, []),
        state: result.state,
        stateReason: `${result.reason} (${verifyResult.reason})`,
      };
    }
    const bytes = verifyResult.bytes;

    let parsed: AdapterEntry[] | { catalog?: AdapterEntry[]; registry?: AdapterEntry[] };
    try {
      parsed = JSON.parse(bytes.toString('utf-8')) as AdapterEntry[] | { catalog?: AdapterEntry[]; registry?: AdapterEntry[] };
    } catch (err) {
      log.error('adapter catalog parse failed after signature verification', {
        path: catalogPath,
        error: String(err),
      });
      // Signature-valid but unparseable: still an integrity failure
      // distinct from "mismatched signature" — CH-02 governs it the same
      // way (empty effective catalog, not a throw).
      const result = computeCatalogState({ signatureValid: false });
      return {
        adapters: effectiveCatalogEntries(result.state, []),
        state: result.state,
        stateReason: `${result.reason} (json parse failed: ${String(err)})`,
      };
    }

    const catalogStateResult = computeCatalogState({
      signatureValid: true,
      materializedAtMs: extractMaterializedAt(parsed),
      maxAgeMs: DEFAULT_CATALOG_TRUST_CONFIG.staleDetection.maxAgeMs,
    });
    if (catalogStateResult.state === 'stale') {
      log.warn('adapter-catalog.state_stale', { reason: catalogStateResult.reason });
      // CHARIOT::§16.1 Catalog (CHARIOT-SPEC.md:1350, rulings item
      // 91/105) — the customer-facing counterpart to the WARN log
      // directly above (CHARIOT::§5.2::2's own "Full catalog with WARN
      // log" row), not a replacement for it.
      chariotEmitter.send('catalog.stale_warning', {
        severity: 'warning',
        data: { reason: catalogStateResult.reason },
      });
    }

    // Prefer bundle.registry[] over bundle.catalog[]: both carry the same
    // 1,788 rows, but registry[] is the field-rich projection the MCP-server
    // dispatch path (RegistryLoader) consumes — it retains rest.toolNames for
    // ~690 REST adapters that catalog[] drops. Reading catalog[] here made the
    // CLI query path build `<id>:default` routing tools for those adapters,
    // so brand-pinned queries dispatched a non-existent `default` tool
    // ("Unknown tool: default"). Falling back to catalog[] then a bare array
    // keeps older single-collection bundles working.
    const adapters: AdapterEntry[] = Array.isArray(parsed) ? parsed
      : (parsed && Array.isArray(parsed.registry)) ? parsed.registry
      : (parsed && Array.isArray(parsed.catalog)) ? parsed.catalog
      : [];

    // Overlay native-code curated adapters that are absent from the published
    // bundle. The catalog publication pipeline may lag or drop curated
    // open-data adapters (e.g. wikipedia removed by a catalog purge).
    // These entries are code-authoritative: the class lives at
    // dist/engine/mcp-servers/<id>.js; the module field uses the same
    // relative-to-pkgRoot pattern as other REST entries in the bundle.
    const bundleIds = new Set(adapters.map((a) => a.id));
    const nativeCurated: AdapterEntry[] = process.env.CHARIOT_DISABLE_NATIVE_CURATED_OVERLAY === '1' ? [] : [
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
    //
    // TRUST BOUNDARY: discovered adapters are host-TOFU-signed (a tamper
    // seal, NOT a central-authority attestation) and rank strictly BELOW the
    // Ed25519-signed bundle + code-authoritative native-curated entries. The
    // overlay is strictly additive: adapterById is built last-writer-wins, so
    // without this guard a discovered payload reusing an authoritative id
    // (e.g. 'stripe' with an attacker baseUrl) would silently shadow the
    // bundle adapter at dispatch time and receive its injected credential.
    const authoritativeIds = new Set(adapters.map((a) => a.id));
    try {
      const { loadVerifiedDiscoveredAdapters } = await import('../../discovery/envelope.js');
      const { adapters: verified, rejected } = loadVerifiedDiscoveredAdapters();
      if (rejected.length > 0) {
        // Structured rejection signal (Loki-visible) — a tampered/rolled-back
        // envelope must be distinguishable from a clean load, not a bare
        // stderr line.
        log.warn('discovered-adapter envelopes rejected', { count: rejected.length, rejected });
      }
      for (const payload of verified) {
        // The discover-write path produces a minimal REST-style adapter
        // shape; coerce into AdapterEntry. Skip ones missing an id.
        //
        // FIX (2026-09-30, dogfood mechanism-test-routes): `payload.id` is
        // now the BARE serviceId — it is the SIGNED identity, which must
        // equal the envelope's filename stem (src/bin/chariot.ts's writer;
        // envelope.ts docstring lines 6-13 + the :227-228 check). The
        // `discovered:` operational-namespace prefix is applied HERE, at
        // read time, never baked into the signed bytes.
        //
        // This also fixes a second, latent bug the same prefix
        // inconsistency caused: the collision guard below used to compare
        // the (previously prefixed) `id` against `authoritativeIds`, a set
        // of BARE catalog ids like "stripe" — "discovered:stripe" can never
        // equal "stripe", so a discovered service actually named "stripe"
        // would NEVER have collided and the guard was dead code. Comparing
        // the bare id (before prefixing) against authoritativeIds is what
        // makes the guard's own stated purpose — "a discovered payload
        // reusing an authoritative id ... would silently shadow the bundle
        // adapter" — actually reachable.
        const bareId = typeof payload.id === 'string' ? payload.id : undefined;
        if (!bareId) continue;
        if (authoritativeIds.has(bareId)) {
          // Surface the collision loudly and reject the lower-authority row —
          // never silently override a centrally-signed catalog entry.
          log.warn('discovered adapter shadows authoritative catalog id; rejecting', { id: bareId });
          continue;
        }
        const id = `discovered:${bareId}`;
        adapters.push({ ...(payload as unknown as AdapterEntry), id });
      }
    } catch (err) {
      log.warn('loadVerifiedDiscoveredAdapters skipped', { error: String(err) });
    }

    // Curated per-tool schema backfill. The catalog
    // publisher stamps curated adapters (CHARIOT_CURATED in
    // src/catalog/curated.ts: pubmed, wikipedia, dns) with terse
    // `rest.toolNames`/`mcp.toolNames` only. chariot_query {discover:true}
    // (handleQueryImpl in toolHandlers.ts) surfaces per-tool
    // `{name, description, inputSchema}` by reading `adapter.rest?.tools` /
    // `adapter.mcp?.tools`; absent that field, every curated tool entry came
    // back `description: ''`, `inputSchema.properties: {}` even though the
    // adapter's own class already carries the real ToolDefinition[] (see
    // WikipediaMCPServer.tools / DnsMCPServer.tools). Backfill from the local
    // class for the two curated adapters that dispatch through an in-repo
    // rest.module (wikipedia, dns). pubmed dispatches to a remote-hosted MCP
    // endpoint (mcp.olyport.com) with no local adapter class — there is
    // genuinely no local schema to backfill for it, so it is intentionally
    // left out of this map and stays name-only (CONFIGURED-adapter
    // "where available" rule; never fabricate a schema).
    const CURATED_LOCAL_TOOL_SOURCES: Record<
      string,
      () => Array<{ name: string; description?: string; inputSchema?: Record<string, unknown> }>
    > = {
      wikipedia: () => new WikipediaMCPServer().tools,
      dns: () => new DnsMCPServer().tools,
    };
    for (const adapter of adapters) {
      const loadTools = CURATED_LOCAL_TOOL_SOURCES[adapter.id];
      if (!loadTools) continue;
      try {
        const defs = loadTools();
        if (adapter.rest && (!adapter.rest.tools || adapter.rest.tools.length === 0)) {
          adapter.rest.tools = defs;
        } else if (adapter.mcp && (!adapter.mcp.tools || adapter.mcp.tools.length === 0)) {
          adapter.mcp.tools = defs;
        }
      } catch (err) {
        log.warn('curated adapter local tool-schema backfill failed', { id: adapter.id, error: String(err) });
      }
    }

    const loadStartMs = Date.now();
    const kept: AdapterEntry[] = [];
    let droppedTransportless = 0;
    let droppedMismatch = 0;
    // dispatch-after-load: one ping per adapter recording the
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
      const names = adapter.tools?.map((tool) => tool.name)
        ?? [...new Set([...(adapter.rest?.toolNames ?? []), ...(adapter.mcp?.toolNames ?? [])])];
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
      // Routine catalog filtering — not an error
      // condition for the customer. Demoted to debug so it does not
      // leak into customer-facing CLI stderr on every invocation.
      log.debug('adapter catalog: dropped undispatchable entries at load', {
        droppedTransportless,
        droppedMismatch,
        kept: kept.length,
        total: adapters.length,
      });
    }
    // CHARIOT::§5.2::1-3 (CH-02) — gate the FULLY assembled list (bundle +
    // native-curated overlay + verified-discovered overlay, post
    // dispatchability filter) through the same effective-catalog function,
    // not just the raw bundle bytes. `stale`/`verified` both pass `kept`
    // through unchanged; `invalid` cannot occur past this point (both
    // earlier signature/parse failures already returned above), so this is
    // a no-op today but keeps every exit of this function routed through
    // one shared rule rather than two different "what does empty mean"
    // implementations.
    // CHARIOT::§16.1 Catalog (CHARIOT-SPEC.md:1350, rulings item 91/105)
    // — the shared return point every successful catalog load (initial
    // boot or a future re-invocation) routes through; the `invalid`
    // state cannot reach here (both signature/parse failures already
    // returned above), so this only fires for a genuinely usable catalog
    // ('verified' or 'stale' — 'stale' already ALSO got its own warning
    // above, both still represent a completed refresh).
    chariotEmitter.send('catalog.refresh_completed', {
      data: { state: catalogStateResult.state, adapterCount: kept.length },
    });
    return {
      adapters: effectiveCatalogEntries(catalogStateResult.state, kept),
      state: catalogStateResult.state,
      stateReason: catalogStateResult.reason,
    };
  } catch (err) {
    log.error('loadAllAdapters failed', { error: String(err) });
    return { adapters: [], state: 'invalid', stateReason: `unexpected load failure: ${String(err)}` };
  }
}

/**
 * Backward-compatible wrapper for the ~10 existing call sites (setup.ts,
 * preinstall.ts, eval/proof/catalog.ts) that only need the adapter list,
 * not the CHARIOT::§5.2 state. `loadChariotState()` below calls
 * {@link loadAllAdaptersWithState} directly so it can expose `catalogState`/
 * `catalogStateReason` on the returned `ChariotState`.
 */
export async function loadAllAdapters(): Promise<AdapterEntry[]> {
  return (await loadAllAdaptersWithState()).adapters;
}

// getConfiguredAdapterIds extracted to
// src/engine/federation/configuredAdapterIds.ts as the single canonical
// implementation. Both ChariotState (live MCP server routing) and
// setup.ts (cmdQuery + startMcpServer wiring) now import the same
// function. The earlier review rounds traced split-brain bugs
// back to this clone being maintained by hand in two files — extracting
// it eliminates the divergence surface permanently.

/**
 * An adapter is description-quality-disqualified when its
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
  // langsmith case: description is just a markdown image
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
  // spacemolt case (was decern-crm): description tokens
  // do not match the adapter's actual tool surface. Description "Set your
  // ship colors" describes ONE tool; the adapter has 172 game tools
  // (mine, attack, dock, jump, scan, etc.). Such adapters dominate BM25
  // via tool-name token volume against queries whose intent the
  // description does not reflect. Filter when the adapter has a wide
  // tool surface (>=16 tools) and effectively zero token overlap
  // between description and tools. Threshold deliberately conservative
  // so legitimate adapters with concise descriptions aren't filtered.
  const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? adapter.cli?.toolSchemas?.map((s) => s.name) ?? [];
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
    // cli-bridge adapters (AS §1.5) carry their tool surface in
    // cli.toolSchemas[].name, not rest/mcp toolNames. Without this the whole
    // cli-bridge slice indexes only a `:default` entry and its real tools never
    // reach the BM25 index → unreachable via query.
    const toolNames = adapter.rest?.toolNames ?? adapter.mcp?.toolNames ?? adapter.cli?.toolSchemas?.map((s) => s.name) ?? [];
    const adapterDesc = adapter.description ?? adapter.id;
    // Enrich the routing-index text with the
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

/**
 * The five files fastembed needs for any user-defined model: the ONNX graph
 * plus the four tokenizer files. Read from an operator-supplied plaintext
 * directory — the same mechanism `loadShard()` already uses via
 * CHARIOT_EDGE_SHARD_DIR. The signed-bundle delivery of these bytes rides the
 * P5 seal-envelope schema, which is defined freeze-side and is NOT invented
 * here; when it ships it becomes an additional source, not a replacement.
 *
 * Throws on any missing/unreadable file so the caller degrades to null (and the
 * load path to BM25-only) rather than constructing a half-initialized encoder.
 */
/**
 * §4.1::4 — the cross-encoder reranker is LOCKED by BIEN §7 (BIEN SPEC.md)
 * line 7 locks `cross-encoder/ms-marco-MiniLM-L6-v2` as the SHIPPED reranker
 * base; `cross-encoder/ms-marco-MiniLM-L12-v2` is the build-time distillation
 * TEACHER and must never be loaded at runtime.
 */
export const SHIPPED_RERANKER_MODEL = 'cross-encoder/ms-marco-MiniLM-L6-v2';

/**
 * §4.1::4 — fail closed unless the on-disk reranker declares the locked model.
 * CHARIOT_RERANKER_DIR is operator-supplied, so without this check any ONNX
 * cross-encoder could be substituted for the locked one. Exported for the
 * prove-on-revert test, which must not need the real ~90MB artifacts.
 */
export function assertShippedRerankerModel(configFile: Buffer): void {
  let config: unknown;
  try {
    config = JSON.parse(configFile.toString('utf8'));
  } catch {
    throw new Error('reranker config.json is not valid UTF-8 JSON');
  }

  const modelId =
    typeof config === 'object' &&
    config !== null &&
    '_name_or_path' in config &&
    typeof (config as { _name_or_path: unknown })._name_or_path === 'string'
      ? (config as { _name_or_path: string })._name_or_path
      : null;

  if (modelId !== SHIPPED_RERANKER_MODEL) {
    throw new Error(
      `reranker model identity mismatch: expected "${SHIPPED_RERANKER_MODEL}", ` +
        `got ${JSON.stringify(modelId)}`,
    );
  }
}

function readModelDir(dir: string): {
  onnx: Buffer;
  tokenizerFiles: {
    tokenizerFile: Buffer;
    configFile: Buffer;
    specialTokensMapFile: Buffer;
    tokenizerConfigFile: Buffer;
  };
} {
  const read = (name: string) => readFileSync(join(dir, name));
  return {
    onnx: read('model.onnx'),
    tokenizerFiles: {
      tokenizerFile: read('tokenizer.json'),
      configFile: read('config.json'),
      specialTokensMapFile: read('special_tokens_map.json'),
      tokenizerConfigFile: read('tokenizer_config.json'),
    },
  };
}

/**
 * Read a REQUIRED positive-integer env var, or null when absent/malformed.
 *
 * Every encoder here takes a `max_length` that MUST match the length the model
 * was exported with: it sets tokenizer truncation, therefore the tensor width,
 * therefore every score the model produces. A wrong value does not error — it
 * silently changes results. So it is never defaulted: it is stated
 * explicitly or read from the export's own configuration
 * (`resolveModelMaxLength`, CHARIOT §23.2), or the encoder stays off.
 */
function requiredPositiveIntEnv(name: string): number | null {
  const raw = process.env[name];
  if (raw === undefined) return null;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}

export type ModelParamResolution<T> =
  | { ok: true; value: T; source: 'env' | 'artifact' | 'spec' }
  | { ok: false; reason: string };

/**
 * The export's own maximum sequence length (CHARIOT §23.2::145/146/181:
 * sourced from the artifact's configuration, never assumed):
 * `config.json` `max_position_embeddings` and `tokenizer_config.json`
 * `model_max_length` in the model directory being loaded, which must be the
 * same positive safe integer.
 */
export function exportMaxLength(dir: string): { ok: true; value: number } | { ok: false; reason: string } {
  const field = (file: string, key: string): unknown => {
    try {
      const parsed = JSON.parse(readFileSync(join(dir, file), 'utf8')) as unknown;
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>)[key] : undefined;
    } catch {
      return undefined;
    }
  };
  const fromConfig = field('config.json', 'max_position_embeddings');
  const fromTokenizer = field('tokenizer_config.json', 'model_max_length');
  if (typeof fromConfig !== 'number' || !Number.isSafeInteger(fromConfig) || fromConfig <= 0 || fromConfig !== fromTokenizer) {
    return {
      ok: false,
      reason: `${dir}: config.json max_position_embeddings and tokenizer_config.json model_max_length are not one positive integer`,
    };
  }
  return { ok: true, value: fromConfig };
}

/**
 * Resolve an encoder `max_length` for the model in `dir` (CHARIOT
 * §23.2::145/146/181). The value must trace to the export's own
 * configuration, so an unreadable or self-inconsistent export disables the
 * leg whatever the env var says. When the env var is set it must be a
 * positive integer equal to the export's value (a disagreeing value silently
 * changes every score). When unset, the export's value is published to the
 * env var, so the running process carries the traced value.
 */
export function resolveModelMaxLength(envName: string, dir: string): ModelParamResolution<number> {
  const envHint = `${envName} must be a positive integer matching the model export`;
  const exported = exportMaxLength(dir);
  if (!exported.ok) return { ok: false, reason: `${envHint}; ${exported.reason}` };
  if (process.env[envName] !== undefined) {
    const n = requiredPositiveIntEnv(envName);
    if (n === null) return { ok: false, reason: `${envHint} (it is set but invalid)` };
    if (exported.value !== n) {
      return { ok: false, reason: `${envHint} (it is ${n}; the export in ${dir} declares ${exported.value})` };
    }
    return { ok: true, value: n, source: 'env' };
  }
  process.env[envName] = String(exported.value);
  return { ok: true, value: exported.value, source: 'artifact' };
}

/**
 * Resolve dense pooling. CHARIOT §23.2::182 fixes the value: the delivery
 * "SHALL set CHARIOT_DENSE_POOLING to `mean`, the pooling the export bakes
 * into its graph". Any other explicit value disables the dense leg; when
 * unset, `mean` is applied and published to the env var.
 */
export function resolveDensePooling(): ModelParamResolution<'mean'> {
  const raw = process.env.CHARIOT_DENSE_POOLING;
  if (raw !== undefined) {
    return raw === 'mean'
      ? { ok: true, value: 'mean', source: 'env' }
      : { ok: false, reason: "CHARIOT_DENSE_POOLING must be exactly 'mean', the pooling the 4.0 export bakes into its graph (CHARIOT §23.2)" };
  }
  process.env.CHARIOT_DENSE_POOLING = 'mean';
  return { ok: true, value: 'mean', source: 'spec' };
}

/**
 * ONNX Runtime default (dogfood-ready 4.0 contract). The native encoders are
 * built with `ort/load-dynamic`; `native/src/ort_dylib.rs::
 * ensure_ort_dylib_available` and `ort` itself read `ORT_DYLIB_PATH` from
 * the process environment at the first encoder load (Node's `process.env`
 * assignment calls the C `setenv`, so the native side sees it). When
 * `ORT_DYLIB_PATH` is unset — or empty, which the native guard also treats
 * as unset — and `<EPIC_AI_DIR>/lib/libonnxruntime.so` is a regular file
 * (symlinks followed, like Rust's `Path::is_file`), set it to that file.
 * An operator-set value always wins. Returns the path it set, else null.
 * Must run before the first `DenseEncoder`/`SpladeEncoder`/
 * `CrossEncoderScorer` load; `makeDiskArtifactSource` calls it first.
 */
export function applyDefaultOrtDylibPath(baseDir: string = EPIC_AI_DIR): string | null {
  const current = process.env.ORT_DYLIB_PATH;
  if (current !== undefined && current !== '') return null;
  const candidate = join(baseDir, 'lib', 'libonnxruntime.so');
  try {
    if (!statSync(candidate).isFile()) return null;
  } catch {
    return null;
  }
  process.env.ORT_DYLIB_PATH = candidate;
  log.info('retrieval.ort_dylib_default_applied', { path: candidate });
  return candidate;
}

/**
 * Disk-backed artifact source for the hybrid retrieval load path. Each accessor
 * returns null when its artifact is absent so the load path degrades to
 * BM25-only with a WARN (§4.4) rather than failing.
 *
 * Every accessor is fail-closed and independent: a missing directory, a missing
 * file, a native build without the required surface, an unset/malformed
 * length, or a load failure disables THAT leg only, and `wireHybridRetrieval`
 * decides the resulting mode. Nothing here guesses a model parameter.
 */
/** Fixed names inside a §5.7 sealed-shard staging directory (gate findings
 * F1/F2, 2026-09-04) — a fresh, private (`mkdtemp`, mode 0700) directory
 * per unseal attempt, so a fixed filename within it carries no TOCTOU risk
 * from OTHER processes; `O_EXCL|O_NOFOLLOW` below is defense-in-depth for a
 * caller-injected (e.g. test) staging-dir factory that might not be private. */
const SEALED_SHARD_STAGING_ARCHIVE_NAME = 'plaintext.archive';
const SEALED_SHARD_STAGING_UNPACK_DIRNAME = 'unpacked';
/** Prefix for an orphaned backup of the PREVIOUS devDir contents, created
 * during promotion (gate round 2 finding, 2026-09-04). `<devDir>.stale-<uuid>`. */
/**
 * Thrown ONLY when a §5.7 sealed-shard promotion failure could NOT be
 * recovered — the original devDir was moved to a `.stale-` backup and the
 * attempt to move it back also failed (gate round 2 finding, 2026-09-04).
 * `unsealSealedShardIntoDevDir`'s outer catch re-throws this specific type
 * instead of swallowing it into a `null` return, because at that point
 * automated recovery is not possible and a silent `null` would hide a
 * missing-or-misplaced shard from the operator. Also thrown by
 * `ensureTrustedMetaDir`/`readStaleRegistry` (gate round 4 finding F3) when
 * the meta directory or the registry file itself fails provenance
 * validation — an untrusted object at either path is never read through,
 * written through, or overwritten; the whole sealed load fails closed.
 */
export class SealedShardUnrecoverableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SealedShardUnrecoverableError';
  }
}

export interface SealedShardStagingOptions {
  /**
   * Factory returning a fresh, caller-created private staging directory
   * (the production default: `mkdtempSync(join(dirname(devDir),
   * '.chariot-sealed-staging-'))`, mode 0700 — SAME FILESYSTEM as devDir's
   * parent, so every promotion rename below is same-filesystem and cannot
   * hit EXDEV). Overridable ONLY so tests can inject a directory they
   * control — e.g. to pre-seed a symlink at the would-be archive path and
   * prove F2's refusal, or to simulate a cross-filesystem staging dir.
   */
  mkStagingDir?: () => string;
  /**
   * Test-only override for the `stat(...).dev` device-number lookup the
   * cross-filesystem preflight (gate round 2 finding) uses. Defaults to the
   * real `statSync(path).dev`. Lets a test simulate an EXDEV-prone setup
   * deterministically without depending on the sandbox's actual mount
   * layout (which may or may not put tmpdir on a separate filesystem).
   */
  statDev?: (path: string) => number;
  /**
   * Test-only override for the promotion `renameSync` calls. Defaults to
   * the real `renameSync`. Lets a test simulate an EXDEV (or any other)
   * failure on a SPECIFIC promotion rename deterministically — e.g. the
   * second rename (staging → devDir) after the first (devDir → stale
   * backup) has already succeeded, which is exactly the gate round 2
   * scenario.
   */
  renameSync?: (oldPath: string, newPath: string) => void;
  /**
   * Test-only override for the `process.getuid()` lookup the gate round 4
   * F4 root-refusal check uses. Defaults to the real `process.getuid()`
   * (or `undefined` when unavailable). Lets a test deterministically
   * simulate running as root (return `0`) or on a platform without
   * `getuid` (return `undefined`) without needing actual root privileges.
   */
  uidOverride?: () => number | undefined;
}

const SEALED_SHARD_STALE_DIR_INFIX = '.stale-';
/** Strict UUID v4-shaped suffix `randomUUID()` produces — anchors the name
 * pattern the gate round 3 registry validates registered paths against. */
const SEALED_SHARD_STALE_UUID_RE = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
/** Private meta directory (gate round 4 finding F3, 2026-09-04) holding the
 * stale-backup registry AND its interprocess lock file — sibling of devDir,
 * created 0700 and provenance-checked on every use so an untrusted object
 * at this path is never read through or overwritten. */
const SEALED_SHARD_META_DIRNAME = '.chariot-sealed-meta';
/** Registry of stale-backup directories THIS installation created (gate
 * round 3 finding, 2026-09-04), under the meta dir. */
const SEALED_SHARD_STALE_REGISTRY_FILENAME = '.chariot-sealed-stale-registry.json';
/** Interprocess lock guarding the registry's read → decide → atomic-replace
 * critical section (gate round 4 finding F1, 2026-09-04). */
const SEALED_SHARD_REGISTRY_LOCK_FILENAME = '.registry.lock';
const REGISTRY_LOCK_RETRY_MS = 50;
const REGISTRY_LOCK_RETRY_COUNT = 100;
const REGISTRY_LOCK_STALE_MS = 60_000;

/** One dedup flag per process — `retrieval.sealed_shard_stale_cleanup_unavailable`
 * is logged ONCE (F2, 2026-09-04) rather than on every retry while the
 * loaded native binary lacks `removeStaleDirValidated` (e.g. before the
 * operator re-signs the binary after this native export ships). */
let loggedStaleCleanupUnavailableOnce = false;

function metaDirFor(devDir: string): string {
  return join(dirname(devDir), SEALED_SHARD_META_DIRNAME);
}

/**
 * Ensure the private meta directory exists and is trustworthy (gate round 4
 * finding F3, 2026-09-04). Creates it fresh (mode 0700) if absent. If it
 * already exists, it MUST be a real directory, owned by `expectedUid`, mode
 * EXACTLY 0700 — any mismatch is treated as untrusted and this function
 * THROWS `SealedShardUnrecoverableError` naming the path rather than ever
 * reading through, writing through, or overwriting it.
 */
function ensureTrustedMetaDir(devDir: string, expectedUid: number): string {
  const dir = metaDirFor(devDir);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
  }
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(dir);
  } catch (err) {
    throw new SealedShardUnrecoverableError(
      `sealed-shard meta directory ${dir} could not be inspected: ${String(err)}`,
    );
  }
  const mode = st.mode & 0o777;
  if (!st.isDirectory() || st.uid !== expectedUid || mode !== 0o700) {
    throw new SealedShardUnrecoverableError(
      `sealed-shard meta directory ${dir} is untrusted (isDirectory=${st.isDirectory()}, ` +
        `uid=${st.uid} expected=${expectedUid}, mode=${mode.toString(8)} expected=700) — refusing ` +
        'to read or write through it; inspect and fix or remove it manually before retrying',
    );
  }
  return dir;
}

// ── gate round 4 F1: interprocess registry lock (pure TS) ─────────────────

interface RegistryLockContents {
  pid: number;
  createdAt: string;
}

/** Test-only override knobs for `acquireRegistryLock`/`tryTakeoverStaleLock`
 * — production callers (`withRegistryLock`) never pass these, so real
 * behavior always uses the module constants (100×50ms retry, 60s stale
 * threshold). Lets tests exercise "exhausts and throws" / "takes over a
 * stale lock" deterministically and quickly, without waiting on the real
 * 60-second threshold or a real ~5-second exhaustion. */
interface RegistryLockTuning {
  retryCount?: number;
  retryMs?: number;
  staleMs?: number;
}

function sleepSyncMs(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    // Atomics.wait unavailable in this runtime — busy-wait so the bounded
    // retry/backoff contract still holds regardless.
    const until = Date.now() + ms;
    while (Date.now() < until) {
      /* spin */
    }
  }
}

/** `true` iff `pid` is a live process THIS user can at least query the
 * existence of. `ESRCH` is the only outcome that proves it is dead; every
 * other outcome (alive, or "alive but owned by someone else" via `EPERM`,
 * or any other ambiguous error) is conservatively treated as "still alive"
 * — a stale-lock takeover only ever fires on a PROVEN-dead pid. */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/**
 * Decide whether `lockPath` is eligible for a stale-lock takeover and, if
 * so, PERFORM the takeover atomically (gate round 5 finding, 2026-09-04):
 * rename it aside to `<lockPath>.stale-<random>` — never unlink it in
 * place — so that if a DIFFERENT racing process wins the identical
 * decision concurrently, only ONE of them succeeds at the rename (the
 * loser's `renameSync` sees `ENOENT`, since the winner already moved it,
 * and simply reports "no takeover happened" so its caller retries the
 * link from the top rather than assuming it owns anything). The renamed
 * -aside file is then deleted; nothing about this path ever writes
 * through or truncates the object at `lockPath` itself.
 *
 * Eligibility:
 *   - a PARSEABLE `{pid, createdAt}` record: stale when `createdAt` is
 *     older than `REGISTRY_LOCK_STALE_MS` AND `pid` is provably dead
 *     (`isProcessAlive` false) — the pre-existing rule, unchanged.
 *   - UNPARSEABLE / unreadable content (gate round 5: the exact scenario a
 *     crash between an old-style `O_EXCL` create and a SEPARATE write of
 *     the owner record could leave — the NEW `acquireRegistryLock` below
 *     no longer has that gap, but a leftover from before this fix, or any
 *     other corruption, must still be recoverable): stale when the file's
 *     OWN `lstat` mtime is older than `REGISTRY_LOCK_STALE_MS`. A fresh
 *     (young) malformed file is NOT eligible — it might be a legitimate
 *     holder's temp file mid-publish under a future code path, or simply
 *     too new to safely assume abandoned.
 *
 * Returns `true` only when a takeover actually happened (the caller may
 * retry acquisition immediately); `false` for every other case (missing
 * file, not-yet-stale, live holder, or lost a takeover race) — the caller
 * backs off and retries instead.
 */
function tryTakeoverStaleLock(lockPath: string, staleMs: number = REGISTRY_LOCK_STALE_MS): boolean {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(lockPath);
  } catch {
    return false; // already gone — nothing to take over; the next link attempt decides
  }

  let raw: string | null;
  try {
    raw = readFileSync(lockPath, 'utf8');
  } catch {
    raw = null;
  }

  let eligible = false;
  if (raw !== null) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = null;
    }
    const rec = parsed as Partial<RegistryLockContents> | null;
    if (rec && typeof rec.pid === 'number' && typeof rec.createdAt === 'string') {
      const ageMs = Date.now() - Date.parse(rec.createdAt);
      eligible = Number.isFinite(ageMs) && ageMs >= staleMs && !isProcessAlive(rec.pid);
    } else {
      // Malformed/empty content — fall back to the FILE's own mtime.
      eligible = Date.now() - st.mtimeMs >= staleMs;
    }
  } else {
    // Unreadable for a reason other than "gone" (e.g. a transient error) —
    // same mtime-based fallback.
    eligible = Date.now() - st.mtimeMs >= staleMs;
  }
  if (!eligible) return false;

  const asidePath = `${lockPath}.stale-${randomUUID()}`;
  try {
    renameSync(lockPath, asidePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return false; // lost the race — another process already took over or released it
    }
    throw err;
  }
  log.error('retrieval.sealed_shard_registry_lock_takeover', { path: lockPath, asidePath });
  try {
    rmSync(asidePath, { force: true });
  } catch (err) {
    log.error('retrieval.sealed_shard_registry_lock_takeover_cleanup_failed', {
      path: asidePath,
      error: String(err),
    });
  }
  return true;
}

/**
 * Acquire the interprocess registry lock under `metaDir` (gate round 4
 * finding F1, 2026-09-04; gate round 5 finding, 2026-09-04 — crash-safe
 * publication). Bounded retry with backoff (`REGISTRY_LOCK_RETRY_COUNT` ×
 * `REGISTRY_LOCK_RETRY_MS`). Returns a release function the caller MUST
 * invoke in a `finally`.
 *
 * GATE ROUND 5 — the lock file NEVER exists without its `{pid, createdAt}`
 * owner record: that record is written to a fresh, randomly-suffixed temp
 * file FIRST (`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` 0600, `writeSync` +
 * `fsyncSync` + `closeSync` — durable on disk before anything else
 * happens), and the lock is then published by `linkSync`ing that temp file
 * onto `lockPath` — `link(2)` is atomic and fails with `EEXIST` exactly
 * when a lock already exists, exactly like the old `O_EXCL`-on-the-real-
 * path approach did, but WITHOUT the two-step "create empty, then write"
 * window a crash between those two steps used to leave open (an empty
 * lock file that `tryTakeoverStaleLock`'s PARSEABLE branch could never
 * recognize as stale, permanently blocking every future acquisition until
 * an operator intervened). The temp file is removed afterward either way
 * (a stray extra hardlink is not the lock itself and must not linger).
 */
function acquireRegistryLock(metaDir: string, tuning: RegistryLockTuning = {}): () => void {
  const retryCount = tuning.retryCount ?? REGISTRY_LOCK_RETRY_COUNT;
  const retryMs = tuning.retryMs ?? REGISTRY_LOCK_RETRY_MS;
  const staleMs = tuning.staleMs ?? REGISTRY_LOCK_STALE_MS;
  const lockPath = join(metaDir, SEALED_SHARD_REGISTRY_LOCK_FILENAME);
  for (let attempt = 0; attempt < retryCount; attempt++) {
    const tmpPath = join(
      metaDir,
      `${SEALED_SHARD_REGISTRY_LOCK_FILENAME}.tmp-${process.pid}-${randomUUID()}`,
    );
    const contents: RegistryLockContents = { pid: process.pid, createdAt: new Date().toISOString() };
    const fd = openSync(
      tmpPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    try {
      writeSync(fd, JSON.stringify(contents));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }

    try {
      linkSync(tmpPath, lockPath);
    } catch (err) {
      try {
        rmSync(tmpPath, { force: true });
      } catch {
        /* best-effort: an orphaned .tmp-* file next to the lock is inert */
      }
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw err;
      }
      if (tryTakeoverStaleLock(lockPath, staleMs)) {
        continue; // retry the link immediately — we may now win it
      }
      sleepSyncMs(retryMs);
      continue;
    }

    // We now hold the lock (as `lockPath`); the temp hardlink that
    // published it is redundant.
    try {
      rmSync(tmpPath, { force: true });
    } catch {
      /* best-effort: does not affect lock ownership, which is `lockPath` */
    }
    return () => {
      try {
        rmSync(lockPath, { force: true });
      } catch (err) {
        log.error('retrieval.sealed_shard_registry_lock_release_failed', { path: lockPath, error: String(err) });
      }
    };
  }
  throw new Error(
    `could not acquire the §5.7 registry lock at ${lockPath} after ${retryCount} attempts`,
  );
}

function withRegistryLock<T>(metaDir: string, fn: () => T): T {
  const release = acquireRegistryLock(metaDir);
  try {
    return fn();
  } finally {
    release();
  }
}

// ── gate round 3/4: the stale-backup registry itself ───────────────────────

interface StaleRegistryEntry {
  path: string;
  createdAt: string;
  pid: number;
}

/**
 * Read the stale-backup registry from `registryPath` (must already be
 * inside a trusted meta dir — see `ensureTrustedMetaDir`). A MISSING file is
 * the normal "no backups recorded yet" state and returns `[]` silently.
 *
 * GATE ROUND 4 F3 — every read FIRST validates the registry FILE's own
 * provenance via `lstat` (never follows a symlink): it must be a regular
 * file, owned by `expectedUid`, mode EXACTLY 0600. A mismatch here is NOT
 * treated as "corrupt, fall back to empty" — it THROWS
 * `SealedShardUnrecoverableError`, because an object at this path that
 * fails provenance may not be OUR registry at all, and reading (or later
 * overwriting) it would not be safe. A file that PASSES provenance but
 * contains corrupt/malformed JSON is a lesser concern (routine corruption,
 * not a provenance/tampering signal) and is logged + treated as empty, per
 * gate round 3.
 */
function readStaleRegistry(registryPath: string, expectedUid: number): StaleRegistryEntry[] {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(registryPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw new SealedShardUnrecoverableError(
      `sealed-shard stale registry ${registryPath} could not be inspected: ${String(err)}`,
    );
  }
  const mode = st.mode & 0o777;
  if (!st.isFile() || st.uid !== expectedUid || mode !== 0o600) {
    throw new SealedShardUnrecoverableError(
      `sealed-shard stale registry ${registryPath} is untrusted (isFile=${st.isFile()}, ` +
        `uid=${st.uid} expected=${expectedUid}, mode=${mode.toString(8)} expected=600) — refusing ` +
        'to read or overwrite it; inspect and fix or remove it manually before retrying',
    );
  }

  let raw: string;
  try {
    raw = readFileSync(registryPath, 'utf8');
  } catch (err) {
    log.error('retrieval.sealed_shard_stale_registry_unreadable', { path: registryPath, error: String(err) });
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    log.error('retrieval.sealed_shard_stale_registry_corrupt', { path: registryPath, error: String(err) });
    return [];
  }
  if (!Array.isArray(parsed)) {
    log.error('retrieval.sealed_shard_stale_registry_corrupt', {
      path: registryPath,
      reason: 'registry content is not a JSON array',
    });
    return [];
  }
  const entries: StaleRegistryEntry[] = [];
  for (const item of parsed as unknown[]) {
    const rec = item as Partial<StaleRegistryEntry> | null;
    if (
      rec &&
      typeof rec === 'object' &&
      typeof rec.path === 'string' &&
      typeof rec.createdAt === 'string' &&
      typeof rec.pid === 'number'
    ) {
      entries.push({ path: rec.path, createdAt: rec.createdAt, pid: rec.pid });
    } else {
      log.error('retrieval.sealed_shard_stale_registry_corrupt', {
        path: registryPath,
        reason: 'malformed registry entry',
        entry: item,
      });
    }
  }
  return entries;
}

/**
 * Atomic registry rewrite (gate round 4 F3): a fresh temp file, NEVER an
 * open-with-truncate of the existing path — `O_EXCL` on a randomly-suffixed
 * temp name, mode 0600, `writeSync` + `fsyncSync` + `closeSync`, then
 * `renameSync` over the target (same directory, same filesystem, atomic).
 * Because we always create a brand-new file and swap it in, an untrusted
 * object at the destination is replaced wholesale, never written-through.
 */
function writeStaleRegistryAtomic(registryPath: string, entries: StaleRegistryEntry[]): void {
  const dir = dirname(registryPath);
  const tmpPath = join(dir, `${basename(registryPath)}.tmp-${process.pid}-${randomUUID()}`);
  const fd = openSync(
    tmpPath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeSync(fd, JSON.stringify(entries, null, 2));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmpPath, registryPath);
}

/**
 * Record a stale-backup directory THIS process just created — the locked
 * read → append → atomic-write critical section (gate round 4 F1). A write
 * failure is logged and swallowed (not thrown): the promotion itself must
 * not fail just because the registry could not be updated — the untracked
 * backup simply becomes unreachable to automated cleanup, which is a
 * strictly safer outcome than either blocking promotion or deleting
 * without a record. A registry PROVENANCE failure (from the read half) is
 * NOT swallowed — see `readStaleRegistry`.
 */
function addStaleRegistryEntry(metaDir: string, staleDir: string, expectedUid: number): void {
  withRegistryLock(metaDir, () => {
    const registryPath = join(metaDir, SEALED_SHARD_STALE_REGISTRY_FILENAME);
    const entries = readStaleRegistry(registryPath, expectedUid);
    entries.push({ path: staleDir, createdAt: new Date().toISOString(), pid: process.pid });
    try {
      writeStaleRegistryAtomic(registryPath, entries);
    } catch (err) {
      log.error('retrieval.sealed_shard_stale_registry_write_failed', { path: registryPath, error: String(err) });
    }
  });
}

/** Remove one entry (e.g. after a successful restore-on-failure rename put
 * the directory back at devDir, so `staleDir` no longer exists). Same
 * locking / best-effort-write contract as `addStaleRegistryEntry`. */
function removeStaleRegistryEntry(metaDir: string, staleDir: string, expectedUid: number): void {
  withRegistryLock(metaDir, () => {
    const registryPath = join(metaDir, SEALED_SHARD_STALE_REGISTRY_FILENAME);
    const entries = readStaleRegistry(registryPath, expectedUid).filter((e) => e.path !== staleDir);
    try {
      writeStaleRegistryAtomic(registryPath, entries);
    } catch (err) {
      log.error('retrieval.sealed_shard_stale_registry_write_failed', { path: registryPath, error: String(err) });
    }
  });
}

/**
 * Remove ONE registered stale-backup directory via the descriptor-based,
 * TOCTOU-safe native primitive (gate round 4 finding F2, 2026-09-04) —
 * NEVER a path-based `rmSync` fallback. When the loaded native binary does
 * not yet expose `removeStaleDirValidated` (the runtime binary stays
 * whatever was last signed until an operator re-signs it after this native
 * export ships), the entry simply stays registered and is retried on the
 * next successful load; the unavailability is logged exactly ONCE per
 * process, not on every retry.
 *
 * Returns whether the removal succeeded (`true`) so the caller can decide
 * whether to keep retrying (`false`/unavailable → registry entry kept) or
 * drop the entry (removed, or an ENOENT reported by native as `false`
 * transparently — see `validateAndCleanupStaleEntry`, which distinguishes
 * these outcomes from the thrown-error ones native also produces).
 */
function cleanupStaleDir(
  native: NonNullable<ReturnType<typeof loadNativeEdge>>,
  parent: string,
  name: string,
  expectedUid: number,
): 'removed' | 'missing' | 'unavailable' | 'validation_failed' | 'io_failed' {
  if (typeof native.removeStaleDirValidated !== 'function') {
    if (!loggedStaleCleanupUnavailableOnce) {
      loggedStaleCleanupUnavailableOnce = true;
      log.error('retrieval.sealed_shard_stale_cleanup_unavailable', {
        reason: 'the loaded native binary does not expose removeStaleDirValidated — stale-backup ' +
          'cleanup is disabled until the operator rebuilds/re-signs it; entries remain registered ' +
          'and are retried on every subsequent successful load',
      });
    }
    return 'unavailable';
  }
  let removed: boolean;
  try {
    removed = native.removeStaleDirValidated(parent, name, expectedUid);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('REMOVE_VALIDATION_FAILED')) {
      log.error('retrieval.sealed_shard_stale_registry_mismatch', { path: join(parent, name), reason: message });
      return 'validation_failed';
    }
    log.error('retrieval.sealed_shard_stale_cleanup_failed', { path: join(parent, name), error: message });
    return 'io_failed';
  }
  return removed ? 'removed' : 'missing';
}

/**
 * Validate ONE registered entry's PATH SHAPE (cheap, no syscalls) before
 * ever calling into native removal — this is a fast filter, not the
 * security-critical check (that lives entirely inside
 * `remove_stale_dir_validated`'s descriptor-relative validation, which is
 * immune to the TOCTOU gap a separate TS-side `lstat`-then-remove would
 * have — gate round 4 F2, 2026-09-04):
 *   - located DIRECTLY in `parent` (`dirname(devDir)`);
 *   - basename matches the STRICT `<basename(devDir)>.stale-<uuid>` pattern.
 * Either failing is logged as a mismatch and the entry is dropped WITHOUT
 * calling into native at all.
 */
function validateAndCleanupStaleEntry(
  native: NonNullable<ReturnType<typeof loadNativeEdge>>,
  entry: StaleRegistryEntry,
  parent: string,
  namePattern: RegExp,
  expectedUid: number,
): 'removed' | 'dropped_missing' | 'dropped_mismatch' | 'keep' {
  const parentOk = dirname(entry.path) === parent;
  const nameOk = namePattern.test(basename(entry.path));
  if (!parentOk || !nameOk) {
    log.error('retrieval.sealed_shard_stale_registry_mismatch', {
      path: entry.path,
      reason: !parentOk
        ? "registered path is not located directly in devDir's parent directory"
        : 'registered path does not match the strict stale-dir name pattern',
    });
    return 'dropped_mismatch';
  }

  const outcome = cleanupStaleDir(native, parent, basename(entry.path), expectedUid);
  switch (outcome) {
    case 'removed':
      return 'removed';
    case 'missing':
      return 'dropped_missing';
    case 'validation_failed':
      return 'dropped_mismatch';
    case 'unavailable':
    case 'io_failed':
      return 'keep';
    default:
      return 'keep';
  }
}

/**
 * Attempt cleanup of every REGISTERED stale-backup directory (gate round 2
 * "re-attempted on next successful load", tightened by gate round 3 to
 * registry-only, tightened again by gate round 4 to descriptor-based
 * removal — NEVER a directory scan, NEVER a path-based `rmSync`,
 * 2026-09-04). F1: the ENTIRE read → validate/cleanup → atomic-replace
 * sequence runs under ONE `withRegistryLock` acquisition, so a concurrent
 * promotion on another process cannot interleave a read-modify-write and
 * lose an update. F4: refuses to run at all when `expectedUid` is 0/root —
 * enforced by the caller (`unsealSealedShardIntoDevDir`) before this
 * function is ever reached.
 */
function cleanupOrphanedStaleDirs(
  native: NonNullable<ReturnType<typeof loadNativeEdge>>,
  devDir: string,
  metaDir: string,
  expectedUid: number,
): void {
  withRegistryLock(metaDir, () => {
    const registryPath = join(metaDir, SEALED_SHARD_STALE_REGISTRY_FILENAME);
    const entries = readStaleRegistry(registryPath, expectedUid);
    if (entries.length === 0) return;
    const parent = dirname(devDir);
    const namePattern = new RegExp(
      `^${basename(devDir).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${SEALED_SHARD_STALE_DIR_INFIX.replace('.', '\\.')}${SEALED_SHARD_STALE_UUID_RE}$`,
    );
    const remaining: StaleRegistryEntry[] = [];
    for (const entry of entries) {
      const outcome = validateAndCleanupStaleEntry(native, entry, parent, namePattern, expectedUid);
      if (outcome === 'keep') remaining.push(entry);
    }
    writeStaleRegistryAtomic(registryPath, remaining);
  });
}

/**
 * CHARIOT::§5.7 sealed-shard unseal → stage → unpack → promote, fail-closed
 * end to end (gate findings F1 High, F2 High, 2026-09-04; gate round 2
 * finding, 2026-09-04 — cross-filesystem promotion safety).
 *
 * F1 — the ENTIRE staged tree (plaintext archive AND the unpacked target) is
 * owned by ONE try/finally from staging-directory creation to removal:
 * unseal → write → unpack all happen inside a private staging directory that
 * is deleted on ANY failure, so a failing/partial write or a
 * failing/partial `edgeUnpackSnapshot` can never leave plaintext, or a
 * half-unpacked tree, sitting in `devDir` or anywhere else persistent.
 * `devDir` itself is only ever touched by the FINAL promotion step, after
 * `edgeUnpackSnapshot` has already fully succeeded.
 *
 * F2 (TOCTOU) — the staging directory is created via `mkdtempSync` (private,
 * mode 0700, cryptographically-unpredictable name), and the archive file
 * inside it is opened with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` — it refuses
 * to write through a pre-existing file OR a pre-existing symlink at that
 * path, rather than following it.
 *
 * FILE-REFERENCE FORM (CHARIOT §5.7 envelope fields, AMENDED 2026-10-14):
 * when the descriptor names a ciphertext FILE (`cfg.descriptor.
 * ciphertextPath`), the staging directory and its same-filesystem preflight
 * are created BEFORE unsealing, and `native.unsealAndVerifySnapshotToFile`
 * writes the plaintext archive straight into it with the same F2 open flags
 * (O_CREAT|O_EXCL|O_NOFOLLOW, 0600, fsync) — no base64 string crosses the
 * JS boundary. The inline (`ciphertextB64`) branch is unchanged.
 *
 * GATE ROUND 2 (cross-filesystem promotion safety) — the prior
 * implementation staged under the SHARED `os.tmpdir()`, which is commonly a
 * separate filesystem (e.g. tmpfs) from wherever `devDir` lives; the final
 * `renameSync(unpackDir, devDir)` could then hit EXDEV AFTER the original
 * devDir had already been renamed away, leaving the service with no devDir
 * and an orphaned PLAINTEXT copy outside the private staging directory.
 * Three changes close this:
 *   1. The staging directory is created under `dirname(devDir)` by default
 *      (SAME filesystem as devDir), so the promotion renames are ordinary
 *      same-filesystem renames, not cross-filesystem ones, in the normal
 *      case.
 *   2. A PREFLIGHT device check (`statSync(...).dev`) compares the staging
 *      directory against `dirname(devDir)` and ABORTS — before devDir is
 *      touched at all — if they differ (covers a caller-injected
 *      `mkStagingDir` that violates the same-filesystem contract, or an
 *      unusual mount layout).
 *   3. If the final promotion rename fails ANYWAY (any reason, not just
 *      EXDEV) AFTER the original devDir was already moved to a `.stale-`
 *      backup, that backup is renamed BACK to devDir before this function
 *      returns — the original shard is restored, not left in `.stale-`. If
 *      the RESTORE itself also fails, this function THROWS (never returns
 *      null silently) with a distinct message naming both paths, because at
 *      that point automated recovery is not possible and silence would hide
 *      a missing/misplaced shard from the operator.
 * A `.stale-` backup that DID clean up successfully, or that is left behind
 * because cleanup itself failed, is never treated as "inert" — see
 * `cleanupStaleDir`/`cleanupOrphanedStaleDirs`.
 *
 * Returns `null` on a normal failure (unseal, write, unpack, or a
 * promotion failure that was fully recovered by restoring the backup) — the
 * caller (`makeDiskArtifactSource.loadShard`) treats that as "sealed load
 * failed, do not fall back to plaintext." THROWS only for the
 * restore-also-failed case described above, which is not a normal failure
 * mode and must not be swallowed into a silent `null`.
 */
export function unsealSealedShardIntoDevDir(
  native: NonNullable<ReturnType<typeof loadNativeEdge>>,
  cfg: SealedShardConfig,
  devDir: string,
  opts: SealedShardStagingOptions = {},
): NativeEdgeShard | null {
  const mkStagingDir =
    opts.mkStagingDir ??
    (() => {
      mkdirSync(dirname(devDir), { recursive: true });
      return mkdtempSync(join(dirname(devDir), '.chariot-sealed-staging-'));
    });
  const statDev = opts.statDev ?? ((path: string) => statSync(path).dev);
  const rename = opts.renameSync ?? renameSync;

  // GATE ROUND 4 F4: a uid-based ownership check (the stale-backup
  // registry's provenance validation, the meta directory's provenance
  // validation, and the native descriptor-based removal's own uid check)
  // is not a security boundary against root, which bypasses ownership
  // checks entirely. Refuse the WHOLE sealed-shard path — not merely
  // cleanup — rather than silently running with a meaningless check.
  const getUid = opts.uidOverride ?? (() => (typeof process.getuid === 'function' ? process.getuid() : undefined));
  const uid = getUid();
  if (uid === undefined || uid === 0) {
    log.error('retrieval.sealed_shard_root_refused', {
      reason:
        uid === 0
          ? 'refusing to run the §5.7 sealed-shard path as root — its ownership-based provenance ' +
            'checks are not a security boundary for root; run this service as a non-root user'
          : "refusing to run the §5.7 sealed-shard path — process.getuid() is unavailable, so " +
            'ownership-based provenance checks cannot be performed',
      devDir,
    });
    return null;
  }

  let stagingDir: string | null = null;
  try {
    // GATE ROUND 4 F3: resolve (creating if absent, or validating if
    // present) the private meta directory BEFORE any registry/lock file is
    // touched. Throws SealedShardUnrecoverableError on a provenance
    // mismatch — caught by the outer handler below, which re-throws it
    // rather than returning null silently.
    const metaDir = ensureTrustedMetaDir(devDir, uid);

    // GATE ROUND 2 preflight: abort BEFORE devDir is touched at all if the
    // staging directory is not on the same filesystem as devDir's parent —
    // the promotion renames below are only safe (same-filesystem, atomic,
    // no EXDEV) when this holds.
    const preflightSameFilesystem = (dir: string): void => {
      mkdirSync(dirname(devDir), { recursive: true });
      const stagingDev = statDev(dir);
      const devDirParentDev = statDev(dirname(devDir));
      if (stagingDev !== devDirParentDev) {
        throw new Error(
          `sealed-shard staging directory ${dir} (dev=${stagingDev}) is on a different ` +
            `filesystem than devDir's parent ${dirname(devDir)} (dev=${devDirParentDev}); refusing ` +
            'before touching devDir — the promotion rename below requires the same filesystem',
        );
      }
    };

    let archivePath: string;
    let receipt: string;
    if (cfg.descriptor.ciphertextPath !== undefined) {
      // CHARIOT §5.7 file-reference form (AMENDED 2026-10-14): a real shard
      // exceeds V8's maximum string length, so neither ciphertext nor
      // plaintext crosses the JS boundary. The native call WRITES the
      // plaintext into the staging tree, so the staging directory and its
      // same-filesystem preflight come FIRST. F2 is enforced natively: the
      // archive path is created O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, and
      // fsync'd (`unseal_and_verify_snapshot_to_file`), refusing a
      // pre-existing file or symlink exactly like the inline branch below.
      if (typeof native.unsealAndVerifySnapshotToFile !== 'function') {
        throw new Error(
          'native binary does not expose unsealAndVerifySnapshotToFile; a file-reference sealed ' +
            'descriptor cannot be unsealed by this binary',
        );
      }
      stagingDir = mkStagingDir();
      preflightSameFilesystem(stagingDir);
      archivePath = join(stagingDir, SEALED_SHARD_STAGING_ARCHIVE_NAME);
      receipt = native.unsealAndVerifySnapshotToFile(
        cfg.descriptor.ciphertextPath,
        archivePath,
        cfg.descriptor.ivB64,
        cfg.descriptor.signatureB64,
        cfg.publicKeyPem,
        cfg.secretRootB64,
        cfg.descriptor.salt,
        cfg.descriptor.aad,
        cfg.licenseJwt,
        devDir,
      ).receipt;
    } else {
      if (cfg.descriptor.ciphertextB64 === undefined) {
        throw new Error('sealed-shard descriptor carries neither a ciphertext file reference nor an inline ciphertext');
      }
      const unsealed = native.unsealAndVerifySnapshot(
        cfg.descriptor.ciphertextB64,
        cfg.descriptor.ivB64,
        cfg.descriptor.signatureB64,
        cfg.publicKeyPem,
        cfg.secretRootB64,
        cfg.descriptor.salt,
        cfg.descriptor.aad,
        cfg.licenseJwt,
        devDir,
      );

      stagingDir = mkStagingDir();
      preflightSameFilesystem(stagingDir);
      archivePath = join(stagingDir, SEALED_SHARD_STAGING_ARCHIVE_NAME);

      // F2: refuse a pre-existing path (file OR symlink) at the staging
      // archive location — O_EXCL fails if ANYTHING already exists there;
      // O_NOFOLLOW additionally refuses to follow a symlink at the final path
      // component even without O_EXCL. Written via the descriptor
      // (writeSync + fsyncSync + closeSync), not writeFileSync, so the file
      // is durable on disk before `edgeUnpackSnapshot` ever reads it.
      const fd = openSync(
        archivePath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
        0o600,
      );
      try {
        writeSync(fd, Buffer.from(unsealed.plaintextB64, 'base64'));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      receipt = unsealed.receipt;
    }

    // F1: unpack into a FRESH subdirectory of the STAGING tree, never
    // devDir directly — if this throws (partial/failed unpack), devDir (any
    // prior valid shard) is completely untouched; only the staging tree
    // (removed in the outer `finally`) is affected.
    const unpackDir = join(stagingDir, SEALED_SHARD_STAGING_UNPACK_DIRNAME);
    native.edgeUnpackSnapshot(archivePath, unpackDir, receipt);

    // Promote only after a FULLY successful unpack. Back the existing
    // devDir up under a throwaway name FIRST (both renames are near-instant
    // same-filesystem syscalls, not a recursive copy — the preflight above
    // guarantees "same filesystem" for both), THEN rename the freshly
    // unpacked tree into devDir's place.
    const hadExistingDevDir = existsSync(devDir);
    const staleDir = hadExistingDevDir ? `${devDir}${SEALED_SHARD_STALE_DIR_INFIX}${randomUUID()}` : null;
    if (staleDir) {
      rename(devDir, staleDir);
      // GATE ROUND 3: register the backup THIS process just created BEFORE
      // attempting the second rename — cleanup only ever touches paths this
      // registry names, so a directory that exists but was never recorded
      // here (e.g. an unrelated sibling from another user/process) can
      // never be reached by `cleanupOrphanedStaleDirs`.
      addStaleRegistryEntry(metaDir, staleDir, uid);
    }
    try {
      rename(unpackDir, devDir);
    } catch (promoteErr) {
      // GATE ROUND 2: the promotion rename failed. If we moved the ORIGINAL
      // devDir away above, we MUST restore it — returning null here would
      // silently leave the service with no devDir while the original shard
      // sits at `staleDir`.
      if (staleDir) {
        try {
          rename(staleDir, devDir);
          // Restored — staleDir no longer exists; deregister it.
          removeStaleRegistryEntry(metaDir, staleDir, uid);
        } catch (restoreErr) {
          throw new SealedShardUnrecoverableError(
            `sealed-shard promotion failed (${String(promoteErr)}) AND restoring the original ` +
              `shard from ${staleDir} back to ${devDir} ALSO failed (${String(restoreErr)}); devDir ` +
              `may now be missing, and the original shard may be stuck at ${staleDir} — manual ` +
              'recovery required',
          );
        }
      }
      throw promoteErr;
    }

    // Promotion fully succeeded. Clean up THIS run's backup (if any) plus
    // any orphans a PRIOR run's failed cleanup left behind — "re-attempted
    // on next successful load" (gate round 2 finding).
    cleanupOrphanedStaleDirs(native, devDir, metaDir, uid);

    // Load AFTER promotion, from the final stable path — never from the
    // staging tree. A handle constructed against a path that is then
    // renamed away could retain stale internal path state and misbehave on
    // a later flush/upsert; loading fresh from the promoted, permanent path
    // avoids that class of bug entirely.
    return native.EdgeShardHandle.load(devDir);
  } catch (err) {
    if (err instanceof SealedShardUnrecoverableError) {
      // GATE ROUND 2: never swallow this into a silent `null` — the caller
      // (and ultimately the operator) MUST see it.
      throw err;
    }
    log.error('retrieval.sealed_shard_load_failed', { error: String(err) });
    return null;
  } finally {
    if (stagingDir) {
      try {
        rmSync(stagingDir, { recursive: true, force: true });
      } catch {
        /* best-effort cleanup of the transient staging tree */
      }
    }
  }
}

/**
 * TEST-ONLY (gate round 4 finding F1, 2026-09-04): exercises the exact
 * locked read → append → atomic-write path `addStaleRegistryEntry` uses,
 * for concurrency tests that need two SEPARATE processes/threads racing on
 * the SAME registry file — proving the interprocess lock actually
 * serializes them — without driving the entire unseal→promote pipeline
 * (which would additionally race on the devDir rename itself, a distinct
 * concern this helper deliberately does not exercise). Not part of the
 * public retrieval-loading contract; `__testOnly`-prefixed to match the
 * existing convention (`nativeEdge.ts::__resetNativeEdgeCacheForTests`).
 */
export function __testOnlyAddStaleRegistryEntry(devDir: string, staleDir: string, uid: number): void {
  const metaDir = ensureTrustedMetaDir(devDir, uid);
  addStaleRegistryEntry(metaDir, staleDir, uid);
}

/** TEST-ONLY: reads back what `__testOnlyAddStaleRegistryEntry` (or the
 * production path) recorded, for the same concurrency tests. */
export function __testOnlyReadStaleRegistry(devDir: string, uid: number): { path: string; createdAt: string; pid: number }[] {
  const metaDir = ensureTrustedMetaDir(devDir, uid);
  return readStaleRegistry(join(metaDir, SEALED_SHARD_STALE_REGISTRY_FILENAME), uid);
}

/**
 * TEST-ONLY (gate round 5, 2026-09-04): drives `acquireRegistryLock`
 * directly, with the optional tuning overrides, so tests can exercise
 * stale-lock takeover / mutual-exclusion-preserved / live-holder-never-
 * taken-over deterministically and quickly (bounded retry counts/intervals,
 * or a real 60s `createdAt`/`mtime` backdated via `utimesSync` — the
 * default `staleMs` is left at the real 60s threshold specifically so a
 * test proves the REAL threshold, not a shortened stand-in for it). Returns
 * the same release function `acquireRegistryLock` returns.
 */
export function __testOnlyAcquireRegistryLock(
  devDir: string,
  uid: number,
  tuning?: { retryCount?: number; retryMs?: number; staleMs?: number },
): () => void {
  const metaDir = ensureTrustedMetaDir(devDir, uid);
  return acquireRegistryLock(metaDir, tuning);
}

/** TEST-ONLY: the lock file path a test needs to pre-seed/inspect directly
 * (e.g. writing a malformed or backdated lock file before acquiring). */
export function __testOnlyRegistryLockPath(devDir: string, uid: number): string {
  const metaDir = ensureTrustedMetaDir(devDir, uid);
  return join(metaDir, SEALED_SHARD_REGISTRY_LOCK_FILENAME);
}

// Exported (was module-private) so CHARIOT::§3.1::5/6 default-directory
// resolution — dense/splade/reranker under MODELS_DIR, the EdgeShard dir
// under QDRANT_DATA_DIR — is independently testable without a working
// native binary: every accessor below returns null before ever touching
// `native` when its resolved directory doesn't exist, so a caller can pass
// a minimal/fake `native` binding and observe only the path-resolution +
// existsSync gate.
/**
 * The disk-backed `ArtifactSource` plus the §8.6a on-device overlay embedder
 * built from the SAME encoder instances the query side loads (BIEN §3
 * constraint 4 / BIEN::§9::13 — one shared encoder object, never a second
 * independently loaded one; see `overlay/OverlayEmbedder.ts`'s class header).
 */
export interface DiskArtifactSource extends ArtifactSource {
  /**
   * The lazily constructed `NativeOverlayEmbedder`, or null when the dense
   * encoder is unavailable or no admitted manifest encoder block was
   * supplied (an overlay can only be embedded into the vector space of an
   * ADMITTED sealed bundle). Construction throws
   * `OverlayEncoderIdentityMismatchError` on an identity mismatch — never
   * caught here: the same fail-closed class as `encoder_load_failed`.
   */
  overlayEmbedder(): NativeOverlayEmbedder | null;
}

export function makeDiskArtifactSource(
  native: NonNullable<ReturnType<typeof loadNativeEdge>>,
  overlay?: { manifestEncoder: OverlayEncoderIdentity },
): DiskArtifactSource {
  // Memoized so the query-side HybridRetriever and the §8.6a overlay
  // embedder share ONE dense encoder and ONE sparse encoder instance
  // (BIEN::§9::13's structural half). `undefined` = not yet attempted;
  // `null` = attempted and unavailable (the warn was already logged once).
  let denseMemo: NativeDenseEncoder | null | undefined;
  let spladeNativeMemo: NativeSpladeEncoder | null | undefined;
  let overlayMemo: NativeOverlayEmbedder | null | undefined;
  // Every native encoder this gateway loads is loaded through the accessors
  // below, so this is ahead of the first `ort` dynamic load on this path.
  applyDefaultOrtDylibPath();
  return {
    loadShard() {
      // CHARIOT::§3.1::6 — "The system SHALL use ~/.epic-ai/qdrant/
      // (customer-owned) as the bundled local Qdrant data directory, optional
      // but required for persistence." (CHARIOT-SPEC.md:189). CHANGELOG.md's
      // 4.0.0 "Changed" section documents `CHARIOT_QDRANT_DATA_DIR` as the
      // repurposed in-process shard directory env var, but this accessor has
      // only ever read `CHARIOT_EDGE_SHARD_DIR` — a different name never
      // mentioned in the CHANGELOG. Both are honored here (env wins over the
      // new customer-owned default, `CHARIOT_EDGE_SHARD_DIR` wins when both
      // are set, matching its pre-existing precedence as the accessor's
      // original variable) so neither promise is broken.
      const devDir = process.env.CHARIOT_EDGE_SHARD_DIR ?? process.env.CHARIOT_QDRANT_DATA_DIR ?? QDRANT_DATA_DIR;

      // CHARIOT::§5.7 sealed path. `resolveSealedShardDescriptorPath()` is
      // the switch: `SEALED_SHARD_DESCRIPTOR_ENV` when set, else the default
      // `<EPIC_AI_DIR>/edgeshard/catalog.edgeshard.sealed` when present.
      // Either way this installation is DECLARING a sealed deployment and
      // MUST go through unseal → unpack → load, failing closed on ANY step's
      // failure (never falling through to the plaintext `devDir` branch
      // below — that fallback exists only for an installation that never
      // configured the sealed path at all). The resolved path is passed to
      // the loader so the predicate and the load use ONE resolution.
      const sealedDescriptorPath = resolveSealedShardDescriptorPath();
      if (sealedDescriptorPath !== null) {
        const cfg = loadSealedShardDescriptor(sealedDescriptorPath);
        if (!cfg) {
          log.error('retrieval.sealed_shard_config_invalid', {
            reason: `a sealed-shard descriptor is configured (${sealedDescriptorPath}; ` +
              `${SEALED_SHARD_DESCRIPTOR_ENV} or the Epic AI dir default) but the sealed-shard ` +
              'configuration could not be resolved; refusing to fall back to a plaintext shard directory',
          });
          return null;
        }
        // The unseal entry point the descriptor's ciphertext form needs:
        // file-reference → unsealAndVerifySnapshotToFile; inline →
        // unsealAndVerifySnapshot (CHARIOT §5.7 envelope fields).
        const fileForm = cfg.descriptor.ciphertextPath !== undefined;
        const unsealEntry = fileForm ? native.unsealAndVerifySnapshotToFile : native.unsealAndVerifySnapshot;
        if (typeof unsealEntry !== 'function' || typeof native.edgeUnpackSnapshot !== 'function') {
          log.error('retrieval.sealed_shard_surface_absent', {
            reason: `native binary does not expose ${fileForm ? 'unsealAndVerifySnapshotToFile' : 'unsealAndVerifySnapshot'}/edgeUnpackSnapshot`,
          });
          return null;
        }
        // Fail closed (CHARIOT::§5.7::23/24) is enforced INSIDE
        // unsealSealedShardIntoDevDir (gate findings F1/F2, 2026-09-04): it
        // returns null on every ORDINARY failure at any step, and the
        // plaintext dev-dir fallback below is NOT reached regardless.
        // EXCEPTION (gate round 2, 2026-09-04): it intentionally THROWS
        // `SealedShardUnrecoverableError`, uncaught here, when a promotion
        // failure could not even be rolled back (devDir may now be missing
        // or the prior shard stuck in a `.stale-` backup) — that is a
        // startup-fatal condition this codebase's existing §4.4 row 2
        // "fail-closed, no BM25 fallback" posture treats as loud-not-silent,
        // and it must not be laundered into an ordinary `null`.
        return unsealSealedShardIntoDevDir(native, cfg, devDir);
      }

      // Plaintext dev path — only reached when no sealed descriptor is
      // configured (env unset AND no default descriptor on disk), i.e. this
      // installation never declared a sealed deployment.
      if (existsSync(devDir)) {
        try {
          return native.EdgeShardHandle.load(devDir);
        } catch (err) {
          log.warn('retrieval.shard_load_failed', { error: String(err) });
          return null;
        }
      }
      return null;
    },
    // §8.6 step 2: the BIEN 768-d dense encoder, in-process via fastembed's
    // user-defined path (`DenseEncoder` in native/src/encoder.rs).
    //
    // Pooling is REQUIRED and never defaulted. §17 bakes mean-pooling + L2 into
    // the exported ONNX graph so the graph output IS the final embedding, but
    // fastembed's `UserDefinedEmbeddingModel` still applies a pooling mode of
    // its own — picking the wrong one silently produces a different vector
    // space from the freeze side, which breaks the lockstep invariant (BIEN §3
    // constraint 4) without any error. The operator states which mode matches
    // the export, or the dense leg stays off.
    loadDenseEncoder() {
      if (denseMemo !== undefined) return denseMemo;
      denseMemo = loadDenseEncoderOnce();
      return denseMemo;
    },
    loadSparseEncoder() {
      const encoder = loadSpladeNativeOnce();
      if (!encoder) return null;
      return {
        embedSparse: (texts: string[]) =>
          encoder.embed(texts).map((v) => ({ indices: v.indices, values: v.values })),
      };
    },
    // CHARIOT-SPEC §8.6a / BIEN::§9::10/13/14 — the on-device overlay
    // embedder, built once from the memoized encoders above and the
    // admitted manifest's encoder block, so overlay vectors land in the
    // sealed catalog's vector space (queryable together, BIEN::§9::14).
    overlayEmbedder() {
      if (overlayMemo !== undefined) return overlayMemo;
      if (!overlay) {
        overlayMemo = null;
        return overlayMemo;
      }
      const denseEncoder = this.loadDenseEncoder();
      if (!denseEncoder) {
        overlayMemo = null;
        return overlayMemo;
      }
      overlayMemo = new NativeOverlayEmbedder({
        native,
        denseEncoder,
        sparseEncoder: loadSpladeNativeOnce(),
        manifestEncoder: overlay.manifestEncoder,
      });
      return overlayMemo;
    },
    overlayShardFor(tenantId: string) {
      const embedder = this.overlayEmbedder();
      return embedder ? embedder.getOverlayShard(tenantId) : null;
    },
    overlayStateHash(tenantId: string) {
      const embedder = this.overlayEmbedder();
      if (!embedder || !embedder.getOverlayShard(tenantId)) return undefined;
      return embedder.overlayStateHash(tenantId);
    },
    // AS §3.2 G10 "runtime mismatch corrects the overlay": the LIVE overlay
    // tool ids for the tenant (from its persisted manifest). CompositeEdgeShard
    // drops any overlay point outside this set before ranking, so a tool a
    // vendor removed can never resurface from a stale vector (the native
    // shard exposes no delete). null = the tenant never had an overlay.
    overlayLiveToolIds(tenantId: string) {
      const embedder = this.overlayEmbedder();
      return embedder ? embedder.liveOverlayToolIds(tenantId) : null;
    },
    // §8.6 step 7 / BIEN §7: the fused shortlist is reranked by the LLM-free
    // cross-encoder. The in-process scorer is `CrossEncoderScorer` in
    // `native/src/reranker.rs`; this accessor supplies it with model bytes.
    //
    // Fail-closed like the legs above: without the directory, the native
    // surface, or an explicit max-length, this returns null and
    // `loadRetrieval.ts:155` leaves `reranker` null, so the stage does not run.
    loadRerankScorer() {
      return loadRerankScorerImpl();
    },
    querySerializer() {
      return querySerializerImpl();
    },
  };

  function loadDenseEncoderOnce(): NativeDenseEncoder | null {
      // CHARIOT::§3.1::5 — "The system SHALL stage locally the retrieval
      // artifacts (ONNX encoder, tokenizer, serializer corpus, manifest)
      // under ~/.epic-ai/models/ (customer-owned, optional)."
      // (CHARIOT-SPEC.md:188). The env var, when set, still wins.
      const dir = process.env.CHARIOT_DENSE_MODEL_DIR ?? join(MODELS_DIR, 'dense');
      if (!existsSync(dir)) return null;
      // Parameters: env (checked against the export), else the export's own
      // configuration — see resolveModelMaxLength / resolveDensePooling.
      const maxLengthR = resolveModelMaxLength('CHARIOT_DENSE_MAX_LENGTH', dir);
      if (!maxLengthR.ok) {
        log.warn('retrieval.dense_max_length_invalid', {
          reason: `${maxLengthR.reason}; dense leg disabled rather than run at a guessed width`,
        });
        return null;
      }
      const maxLength = maxLengthR.value;
      const poolingR = resolveDensePooling();
      if (!poolingR.ok) {
        log.warn('retrieval.dense_pooling_invalid', {
          reason: `${poolingR.reason}; dense leg disabled rather than run in a guessed vector space`,
        });
        return null;
      }
      const pooling = poolingR.value;
      try {
        const { onnx, tokenizerFiles } = readModelDir(dir);
        return native.DenseEncoder.load(onnx, tokenizerFiles, pooling === 'mean', maxLength);
      } catch (err) {
        log.warn('retrieval.dense_load_failed', { error: String(err) });
        return null;
      }
  }
    // §8.6 step 3: SPLADE sparse (`Splade_PP_en_v1`) via `SpladeEncoder` in
    // native/src/splade.rs — driven through ort + tokenizers directly, because
    // fastembed 5.17.2's SparseTextEmbedding has no user-defined load path
    // (per the pinned sparse-encoder decision).
    //
    // The native method is `embed`; the retrieval stack's `SparseQueryEncoder`
    // contract is `embedSparse`. The two are adapted in `loadSparseEncoder`
    // above — deliberately at the one place that knows both shapes, rather
    // than renaming either side. This loader returns the NATIVE encoder
    // (memoized) so the §8.6a overlay embedder can share the same instance.
  function loadSpladeNativeOnce(): NativeSpladeEncoder | null {
      if (spladeNativeMemo !== undefined) return spladeNativeMemo;
      spladeNativeMemo = loadSpladeNative();
      return spladeNativeMemo;
  }
  function loadSpladeNative(): NativeSpladeEncoder | null {
      // CHARIOT::§3.1::5 — see loadDenseEncoder above; env var still wins.
      const dir = process.env.CHARIOT_SPLADE_MODEL_DIR ?? join(MODELS_DIR, 'splade');
      if (!existsSync(dir)) return null;
      if (typeof native.SpladeEncoder?.load !== 'function') {
        log.warn('retrieval.splade_surface_absent', {
          reason: 'native binary carries no SpladeEncoder; sparse leg disabled',
        });
        return null;
      }
      const maxLengthR = resolveModelMaxLength('CHARIOT_SPLADE_MAX_LENGTH', dir);
      if (!maxLengthR.ok) {
        log.warn('retrieval.splade_max_length_invalid', {
          reason: `${maxLengthR.reason}; sparse leg disabled rather than run at a guessed width`,
        });
        return null;
      }
      const maxLength = maxLengthR.value;
      try {
        const { onnx, tokenizerFiles } = readModelDir(dir);
        return native.SpladeEncoder.load(onnx, tokenizerFiles, maxLength);
      } catch (err) {
        log.warn('retrieval.splade_load_failed', { error: String(err) });
        return null;
      }
  }
  function loadRerankScorerImpl() {
      // CHARIOT::§3.1::5 — the reranker is an ONNX+tokenizer retrieval
      // artifact like the dense/splade encoders above, so it nests under
      // the same ~/.epic-ai/models/ root; env var still wins.
      const dir = process.env.CHARIOT_RERANKER_DIR ?? join(MODELS_DIR, 'reranker');
      if (!existsSync(dir)) return null;
      if (typeof native.CrossEncoderScorer?.load !== 'function') {
        log.warn('retrieval.rerank_surface_absent', {
          reason: 'native binary carries no CrossEncoderScorer; rerank stage disabled',
        });
        return null;
      }
      const maxLengthR = resolveModelMaxLength('CHARIOT_RERANKER_MAX_LENGTH', dir);
      if (!maxLengthR.ok) {
        log.warn('retrieval.rerank_max_length_invalid', {
          reason: `${maxLengthR.reason}; rerank stage disabled rather than run at a guessed width`,
        });
        return null;
      }
      const maxLength = maxLengthR.value;
      try {
        const { onnx, tokenizerFiles } = readModelDir(dir);
        // §4.1::4 — the BIEN §7 model is LOCKED; refuse any substitute.
        assertShippedRerankerModel(tokenizerFiles.configFile);
        return native.CrossEncoderScorer.load(onnx, tokenizerFiles, maxLength);
      } catch (err) {
        // §4.1::4 — a WRONG model must abort startup, never degrade quietly:
        // returning null here leaves `reranker` null and the rerank stage
        // simply does not run (§4.4 row 2), which is exactly the silent
        // substitution the LOCK exists to prevent. Only genuine
        // absence/IO/native-load failures may fall through to the warn+null
        // path below.
        if (err instanceof Error && err.message.startsWith('reranker model identity mismatch:')) {
          throw err;
        }
        log.warn('retrieval.rerank_load_failed', { error: String(err) });
        return null;
      }
  }
  function querySerializerImpl() {
      // Lockstep query serialization via the native serializer (CH-23). The
      // exact query-record field contract is owned by BIEN's serialize_query and
      // finalized at P8 integration; this path is dormant until the dense
      // encoder above is non-null, so it is never exercised at runtime today.
      return (q: string) => native.serializeQuery('nomic', JSON.stringify({ query: q }));
  }
}

/**
 * CHARIOT::§5.2::5 / §4.4 — thrown by `wireRetrievalForState` on every
 * fail-closed retrieval-bundle rejection (both the file-level Ed25519 gate
 * failure and every `VectorIndexVerifier.admit()` rejection).
 *
 * §4.4 (CHARIOT-SPEC.md): "no routing begins" — that abort IS this throw;
 * `loadChariotState()` never returns a `ChariotState` object on this path,
 * so there is no returned object left to read a state transition off of.
 * §5.2::5: "Any of these three 4.0.0 conditions yields state invalid
 * (empty catalog)." Because the throw is the only channel back to the
 * caller, the transition is carried ON this error: `catalogState` /
 * `catalogStateReason` are set to `'invalid'` / the trigger reason when
 * `code` classifies as one of the three §5.2::5 conditions (see
 * `classifySealedBundleFailure`); both stay `undefined` for a fail-closed
 * rejection §5.2::5 doesn't name (§5.6 replay/downgrade, CH-35
 * dispatch-identity) — §4.4 still aborts, but the adapter catalog was
 * never claimed invalid, so nothing here should claim it either.
 */
export class RetrievalBundleRejectedError extends Error {
  readonly code: AdmissionCode;
  readonly catalogState?: CatalogWideState;
  readonly catalogStateReason?: string;
  constructor(
    message: string,
    opts: { code: AdmissionCode; catalogState?: CatalogWideState; catalogStateReason?: string },
  ) {
    super(message);
    this.name = 'RetrievalBundleRejectedError';
    this.code = opts.code;
    this.catalogState = opts.catalogState;
    this.catalogStateReason = opts.catalogStateReason;
  }
}

/**
 * CHARIOT::§5.2::5 — "In 4.0.0 the `invalid` state SHALL also be produced
 * by retrieval-manifest mismatch, encoder mismatch, and any sealed-bundle
 * signature failure." Classifies a `VectorIndexVerifier.admit()` /
 * `wireHybridRetrieval()` `AdmissionCode` into which of those three 4.0.0
 * triggers it is, or `null` when the code is a §5.6 anti-rollback
 * (`epoch_replay_rejected`, `version_downgrade_rejected`) or CH-35/§3.5a
 * dispatch-identity rejection — neither of which §5.2::5 names, so neither
 * forces the ADAPTER catalog invalid (the §4.4 retrieval abort below still
 * fires for every fail-closed code regardless of this classification; only
 * the ADDITIONAL adapter-catalog-emptying consequence is code-specific).
 * Exported so the mapping is directly unit-testable against every
 * `AdmissionCode` without needing a live bundle fixture per case.
 */
export function classifySealedBundleFailure(
  code: AdmissionCode,
): 'retrieval_manifest_mismatch' | 'encoder_mismatch' | 'sealed_bundle_signature_failed' | null {
  switch (code) {
    case 'manifest_missing':
    case 'manifest_mismatch':
    case 'serializer_mismatch':
      return 'retrieval_manifest_mismatch';
    case 'encoder_load_failed':
      return 'encoder_mismatch';
    case 'signature_invalid':
      return 'sealed_bundle_signature_failed';
    default:
      return null;
  }
}

/**
 * CHARIOT::§5.2::5 — the CH-02 side of a sealed-bundle fail-closed
 * rejection: when `code` classifies as one of the three 4.0.0 triggers
 * (see {@link classifySealedBundleFailure}), empties `allAdapters` /
 * `adapterById` (by reference, in place) and re-indexes both pre-filters
 * to empty — the effective catalog becomes empty for every reader sharing
 * these objects. A no-op (returns `null`, touches nothing) for any other
 * fail-closed code (§5.6 replay/downgrade, CH-35 dispatch-identity —
 * neither of which §5.2::5 names). Extracted from `wireRetrievalForState`
 * so this side effect is directly unit-testable against real
 * `ToolPreFilter` instances without needing a bundle fixture signed by the
 * production key (the file-level Ed25519 gate that precedes this in
 * `wireRetrievalForState` cannot be satisfied by a test key). Returns the
 * classification for the caller's own logging.
 */
export function applySealedBundleFailure(
  code: AdmissionCode,
  reason: string,
  allAdapters: AdapterEntry[],
  adapterById: Map<string, AdapterEntry>,
  toolPreFilter: ToolPreFilter,
  fullCatalogFilter: ToolPreFilter,
): 'retrieval_manifest_mismatch' | 'encoder_mismatch' | 'sealed_bundle_signature_failed' | null {
  const kind = classifySealedBundleFailure(code);
  if (kind) {
    // `state: 'invalid'` is included explicitly (not just `kind`/`code`) so
    // this log line — the telemetry-side observable for this transition —
    // names the literal CHARIOT::§5.2 state value, not just the trigger.
    log.error('adapter-catalog.state_invalid', { state: 'invalid', kind, code, reason });
    allAdapters.length = 0;
    adapterById.clear();
    toolPreFilter.index([]);
    fullCatalogFilter.index([]);
  }
  return kind;
}

/**
 * CHARIOT-SPEC §8.6a / BIEN::§9::13 — the sealed bundle's encoder identity,
 * read from the envelope's retrieval manifest for the overlay embedder's
 * constructor-time identity gate. Returns null when the envelope carries no
 * manifest (legacy bundle → BM25-only, no overlay) or the encoder block is
 * malformed; a malformed block is ALSO refused by `VectorIndexVerifier.admit()`
 * on the same envelope, so this never admits what the verifier rejects.
 */
function overlayEncoderIdentityFromEnvelope(envelope: BundleEnvelope): OverlayEncoderIdentity | null {
  const manifest = envelope.manifest;
  if (!manifest || typeof manifest !== 'object') return null;
  const m = manifest as { encoder?: unknown; serializer_hash?: unknown };
  const enc = m.encoder;
  if (!enc || typeof enc !== 'object') return null;
  const e = enc as { denseModelId?: unknown; denseModelVersion?: unknown; denseDims?: unknown; sparseModelId?: unknown };
  if (
    typeof e.denseModelId !== 'string' ||
    typeof e.denseModelVersion !== 'string' ||
    typeof e.denseDims !== 'number' ||
    typeof m.serializer_hash !== 'string'
  ) {
    return null;
  }
  return {
    denseModelId: e.denseModelId,
    denseModelVersion: e.denseModelVersion,
    denseDims: e.denseDims,
    ...(typeof e.sparseModelId === 'string' ? { sparseModelId: e.sparseModelId } : {}),
    serializerHash: m.serializer_hash,
  };
}

/**
 * Resolve + fail-closed-verify the retrieval manifest and attach the hybrid
 * retriever to both pre-filters when the 4.0.0 artifacts are present. Throws on
 * a present-but-invalid manifest so no routing begins (§4.4). No-ops to
 * BM25-only when the bundle carries no manifest (today's steady state).
 *
 * CHARIOT::§5.2::5 — on a retrieval-manifest mismatch, encoder mismatch, or
 * sealed-bundle signature failure, `allAdapters`/`adapterById` (passed BY
 * REFERENCE and cleared in place) and both pre-filters are emptied FIRST —
 * CH-02's "empty effective catalog, never a partial one" — and the §4.4
 * abort below still throws immediately after. Both hold; this function
 * does not choose one over the other.
 */
export function wireRetrievalForState(
  toolPreFilter: ToolPreFilter,
  fullCatalogFilter: ToolPreFilter,
  packageRoot: string,
  allAdapters: AdapterEntry[],
  adapterById: Map<string, AdapterEntry>,
  /**
   * CHARIOT-SPEC §8.6a — out-parameter filled with the on-device overlay
   * embedder on the full-admission ('hybrid') path only; left null on
   * BM25-only and on every fail-closed path. Optional so the existing
   * callers/tests that only need the mode are unchanged.
   */
  overlayOut?: { embedder: OverlayEmbedder | null },
): RetrievalMode {
  const bundleDir = resolvePublishedArtifactDir(packageRoot, 'chariot-current.json', packageRoot);
  const bundlePath = join(bundleDir, 'chariot-adapter-bundle.json');
  const catalogPath = process.env.CHARIOT_ADAPTER_CATALOG_PATH ?? bundlePath;

  // §4.2/§5.6 fail-closed: absent manifest → BM25-only; present-but-invalid → throw.
  // verifiedReadFailClosed distinguishes the two cases so a tampered or stale
  // bundle never silently degrades to BM25 routing.
  //
  // CHARIOT-SPEC.md:525 ("Trust anchor", CH-52): "The Ed25519 verifying key
  // SHALL be pinned to the compiled-in accepted key set
  // (`native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM`). A caller-supplied
  // key outside that rotation set SHALL be rejected, so neither a caller
  // nor an attacker controlling the caller's configuration can substitute a
  // signing key." This function therefore takes NO key parameter at all —
  // `verifiedReadFailClosed` below always verifies against its own
  // production default, `CHARIOT_CATALOG_PUBLIC_KEYS`, with no seam any
  // caller (test or production) can widen or override.
  //
  // CHARIOT::§5.2::5 — this file IS the sealed bundle (chariot-adapter-
  // bundle.json carries the adapter catalog AND the retrieval manifest in
  // one signed envelope); a failure of THIS gate is a "sealed-bundle
  // signature failure" exactly as much as an admit()-level `signature_invalid`
  // is, so it gets the same CH-02 treatment: empty the adapter catalog
  // (applySealedBundleFailure) before the §4.4 abort re-throws.
  let bytes: Buffer | null;
  try {
    bytes = verifiedReadFailClosed(catalogPath, log, 'retrieval-manifest');
  } catch (err) {
    applySealedBundleFailure('signature_invalid', String(err), allAdapters, adapterById, toolPreFilter, fullCatalogFilter);
    throw new RetrievalBundleRejectedError(`retrieval bundle rejected (signature_invalid): ${String(err)}`, {
      code: 'signature_invalid',
      catalogState: 'invalid',
      catalogStateReason: `sealed-bundle Ed25519 envelope signature failed (CHARIOT::§5.2::5): ${String(err)}`,
    });
  }
  if (!bytes) return 'bm25-only'; // legitimately absent (artifact-not-found) → BM25-only

  let envelope: BundleEnvelope;
  try {
    const parsed = JSON.parse(bytes.toString('utf-8')) as unknown;
    if (Array.isArray(parsed) || !parsed || typeof parsed !== 'object') return 'bm25-only'; // legacy array
    envelope = parsed as BundleEnvelope;
  } catch (err) {
    log.error('retrieval.bundle_parse_failed', { error: String(err) });
    throw new Error(`retrieval bundle parse failed: ${String(err)}`);
  }

  const native = loadNativeEdge();
  // The retrieval bundle's §5.6 high-water mark is keyed to its OWN artifact
  // file. It MUST NOT share `.chariot-catalog-epoch.json` with
  // AdapterCatalog's independent adapter-bundle mark — the two artifacts
  // carry independent monotonic counters, and multiplexing them onto one
  // unkeyed record lets either side's accept falsely epoch_replay_reject the
  // other on the next boot (permanent fail-closed startup failure).
  const epochPath =
    process.env.CHARIOT_RETRIEVAL_EPOCH_PATH ?? join(packageRoot, '.chariot-retrieval-epoch.json');
  // CHARIOT-SPEC §8.6a / BIEN::§9::13 — the overlay embedder must embed into
  // the vector space of the ADMITTED sealed bundle, so its encoder identity
  // is read from this envelope's manifest (the same block
  // `VectorIndexVerifier.admit()` checks below). `wireHybridRetrieval` only
  // reaches the artifact source's overlay accessors on the full-admission
  // ('hybrid') path, so a rejected bundle never seeds an embedder.
  const manifestEncoder = overlayEncoderIdentityFromEnvelope(envelope);
  const artifacts = native ? makeDiskArtifactSource(native, manifestEncoder ? { manifestEncoder } : undefined) : null;
  const result = wireHybridRetrieval({
    envelope,
    signatureVerified: true, // verifiedReadOrNull only returns bytes on a verified signature
    // §5.6 identity binding: hash of the exact signature-verified bytes, so a
    // restart re-admitting the identical bundle is idempotent, never a brick.
    bundleSha256: createHash('sha256').update(bytes).digest('hex'),
    persisted: loadPersistedEpoch(epochPath),
    persist: (s: CatalogEpochState) => persistEpoch(epochPath, s),
    native,
    artifacts,
    logger: log,
  });
  if (result.mode === 'hybrid' && artifacts && overlayOut) {
    // Hand the embedder (same encoder instances as the retriever just built)
    // to loadChariotState so the §8.6a connector can be constructed from it.
    overlayOut.embedder = artifacts.overlayEmbedder();
  }

  if (result.mode === 'hybrid') {
    toolPreFilter.setHybridRetriever(result.retriever);
    fullCatalogFilter.setHybridRetriever(result.retriever);
    // CHARIOT::§4.1::14 — the pre-filter (not the retriever) owns the
    // once-per-query degraded-pass WARN; wire the same logger used above.
    toolPreFilter.setLogger(log);
    fullCatalogFilter.setLogger(log);
    log.info('retrieval.hybrid_enabled', {});
  } else if (result.mode === 'fail-closed') {
    // CHARIOT::§5.2::5 — "Any of these three 4.0.0 conditions yields state
    // invalid (empty catalog)." Runs BEFORE the §4.4 abort below so the
    // catalog-wide emptying is not skipped by the throw that follows it.
    const kind = applySealedBundleFailure(result.code, result.reason, allAdapters, adapterById, toolPreFilter, fullCatalogFilter);
    // §4.4: a manifest mismatch fails closed — no routing begins.
    log.error('retrieval.bundle_fail_closed', { code: result.code, reason: result.reason });
    throw new RetrievalBundleRejectedError(`retrieval bundle rejected (${result.code}): ${result.reason}`, {
      code: result.code,
      ...(kind ? { catalogState: 'invalid' as const, catalogStateReason: `${kind} (CHARIOT::§5.2::5): ${result.reason}` } : {}),
    });
  } else {
    log.debug('retrieval.bm25_only', { reason: result.reason });
  }
  return result.mode;
}

// =============================================================================
// loadChariotState
// =============================================================================

export async function loadChariotState(
  opts: {
    observabilityEmitter?: ObservabilityEmitterContract;
    /**
     * CHARIOT-SPEC §8.6a — the retrieval-side embedder the customer-auth
     * overlay connector hands newly customer-verified tools to. Injectable
     * test/embedder seam that takes precedence over the live
     * `NativeOverlayEmbedder` `wireRetrievalForState` builds on the
     * full-admission path (see `ChariotState.customerAuthOverlayConnector`).
     */
    customerAuthOverlayEmbedder?: OverlayEmbedder;
  } = {},
): Promise<ChariotState> {
  const { adapters: allAdapters, state: catalogState, stateReason: catalogStateReason } = await loadAllAdaptersWithState();
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
  // CHARIOT::§4.6::1 — wire the same adapter lists as the query-expansion
  // catalog so QueryExpander's abbreviation rewrites are loaded from each
  // adapter's catalog `keywords` field per CHARIOT-SPEC.md §4.6.
  toolPreFilter.setCatalogKeywords(configuredAdapters);
  fullCatalogFilter.setCatalogKeywords(allAdapters);
  // BIEN::§7a::2/10 — wire the same adapter lists so the official/
  // non-official partition step (`ToolPreFilter.selectInternal`) can look
  // up each candidate's governance tier from catalog metadata; the tier
  // value itself is derived exclusively upstream (AS §3.5 G17-03/G17-04)
  // and never re-computed here (BIEN::§7a::3).
  toolPreFilter.setAdapterTiers(configuredAdapters);
  fullCatalogFilter.setAdapterTiers(allAdapters);

  // adapterById is built BEFORE wireRetrievalForState so the SAME Map
  // reference can be handed in and cleared by it (CHARIOT::§5.2::5, see
  // below) — building it after, as before, would mean a retrieval-triggered
  // invalidation could never reach it.
  const adapterById = new Map(allAdapters.map(a => [a.id, a]));

  // 4.0.0 retrieval load path (§4.3/§4.4/§8.6). Reads the sealed bundle's
  // retrieval manifest, fail-closed-verifies it (VectorIndexVerifier: contract +
  // §5.6 anti-rollback + CH-35 gate), and — when the native Edge module + BIEN
  // dense encoder are available — attaches the HybridRetriever so Tier-1 fuses
  // BM25 + dense + SPLADE → RRF → rerank. Today's adapter bundle carries no
  // manifest, so this resolves to BM25-only (the lexical path above) without
  // changing runtime behavior; the hybrid path activates when the tool-granular
  // signed bundle + EdgeShard snapshot ship (P5/P8). A manifest that is present
  // but does NOT satisfy the contract throws here — no routing begins (§4.4).
  // CHARIOT::§5.2::5 — a retrieval-manifest mismatch / encoder mismatch /
  // sealed-bundle signature failure ALSO forces the adapter catalog's
  // effective set empty (allAdapters/adapterById/both pre-filters, passed
  // by reference so wireRetrievalForState can clear them) BEFORE the §4.4
  // abort throw below runs — both hold, per CH-02 and §4.4 respectively.
  // CHARIOT-SPEC §8.6a — receives the on-device overlay embedder on the
  // full-admission path; null on BM25-only (legacy bundle) and on every
  // fail-closed path (which throws below anyway).
  const overlayOut: { embedder: OverlayEmbedder | null } = { embedder: null };
  const retrievalMode = wireRetrievalForState(toolPreFilter, fullCatalogFilter, packageRoot, allAdapters, adapterById, overlayOut);
  // Test/embedder seam wins when supplied; otherwise the live embedder built
  // from the admitted bundle's encoder instances (same objects the retriever
  // uses — BIEN::§9::13).
  const customerAuthOverlayEmbedder: OverlayEmbedder | undefined =
    opts.customerAuthOverlayEmbedder ?? overlayOut.embedder ?? undefined;

  // Supply-chain integrity feed (Wiz practice 7 — feed #23). Count against
  // the catalog just loaded above; verified = adapters whose bundle row
  // carries `catalogVerified === true` from the publication gate. Absence
  // of the field (older bundle rows / synthetic stubs) counts as
  // unverified — never fabricated as verified.
  const chariotMetrics = new ChariotMetrics();
  chariotMetrics.setSupplyChainIntegrity(
    allAdapters.filter((a) => a.catalogVerified === true).length,
    allAdapters.length,
  );

  // CHARIOT-SPEC §8.6a — constructed unconditionally (see the field's doc
  // comment): shared by `customerAuthOverlayConnector` (writer, when
  // wired) and toolHandlers.ts (reader, always) below.
  const tenantOverlayToolRegistry = new TenantOverlayToolRegistry();
  // CHARIOT-SPEC §8.6a — the pre-filters resolve an `overlay:<tenant>:…`
  // candidate returned by the tenant-scoped composite shard into the
  // registered Tool for the REQUESTING tenant only (ToolPreFilter's
  // `setOverlayToolRegistry`; `resolveForTenant` refuses a mismatched tenant).
  toolPreFilter.setOverlayToolRegistry(tenantOverlayToolRegistry);
  fullCatalogFilter.setOverlayToolRegistry(tenantOverlayToolRegistry);

  return {
    catalogState,
    catalogStateReason,
    allAdapters,
    adapterById,
    toolPreFilter,
    fullCatalogFilter,
    loadedAt: new Date().toISOString(),
    retrievalMode,
    chariotMetrics,
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
    // CHARIOT_HEALTH_FILE_DEFAULT (per-uid state dir) or the
    // CHARIOT_HEALTH_FILE env var override.
    healthEmitter: new ChariotHealthEmitter(),
    // CHARIOT-SPEC §8.6a. Constructed whenever an OverlayEmbedder exists:
    // the injected seam, or the live NativeOverlayEmbedder that
    // wireRetrievalForState hands back on the full-admission path. Absent
    // only on a BM25-only (legacy, manifest-less) bundle, where no vector
    // space exists to embed into and the dispatch gate fails closed with
    // CUSTOMER_AUTH_OVERLAY_NOT_WIRED. The 5-per-60s per-(tenant,adapter)
    // bucket is generous for what is a rare, once-per-credential-version
    // operation (see CustomerAuthOverlayConnector's own one-time-enforcement
    // cache) — it exists purely as the AGENTS.md-required brute-force guard
    // on a failing customer credential, not as a normal-traffic throttle.
    customerAuthOverlayConnector: customerAuthOverlayEmbedder
      ? new CustomerAuthOverlayConnector({
          embedder: customerAuthOverlayEmbedder,
          rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 60_000 }),
          registry: tenantOverlayToolRegistry,
        })
      : undefined,
    tenantOverlayToolRegistry,
    // One-shot first-call-success tracking per adapter.
    firstCallSuccessSeen: new Set<string>(),
    // Memory service — file-backed FileStore in the OSS build so
    // chariot_remember data survives a `serve` restart (CHARIOT §8.5:
    // "memory persists across restarts"). FileStore inherits all of
    // InMemoryStore's capacity / high-importance / eviction / tenant-scoping
    // logic and adds durability under ${EPIC_AI_DIR}/memory.json (honors
    // EPIC_AI_DIR_OVERRIDE). Enterprise injects a RedisMongoAdapter-backed
    // PersistentMemory via its own loadChariotState override. cacheTTLMs is
    // unused by FileStore (adapter-specific) but required by MemoryConfig.
    memory: new PersistentMemory({ store: new FileStore(MEMORY_FILE), cacheTTLMs: 0 }),
  };
}
