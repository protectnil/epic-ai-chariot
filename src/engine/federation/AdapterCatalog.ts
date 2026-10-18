/**
 * @epicai/chariot — Adapter Catalog
 * Static registry of all known adapters. Loaded from npm bundle
 * or signed registry. Powers Tier 1 domain classification.
 *
 * 1.3.0: Signature verification is ON BY DEFAULT on both the bundled
 * and remote load paths. See `CatalogSourceConfig.verifySignature`
 * and the class docs below for the enforcement model and the opt-out.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync, existsSync, writeFileSync, copyFileSync, renameSync, chmodSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve, join as pathJoin } from 'node:path';
import { verify as cryptoVerify, createHash } from 'node:crypto';
import { createLogger } from '../logger.js';
import {
  CHARIOT_CATALOG_PUBLIC_KEYS,
  type ChariotCatalogPublicKey,
} from '../keys/chariot-catalog-public.js';
// CHARIOT-SPEC.md:383 (§5.4, amended) / :523 (§5.7 trust anchor) — the
// same choke point the catalog/bundle fast path (`verifyCatalogSignature.ts`)
// routes every caller-supplied key through. Importing it here does NOT
// create a cycle: `verifyCatalogSignature.ts` reads its own byte cap from
// `artifact-limits.ts` directly rather than from this file (see that
// file's own note).
import { intersectWithRotationSet } from '../keys/verifyCatalogSignature.js';
import { ARTIFACT_LIMITS } from '../keys/artifact-limits.js';
import { resolvePublishedArtifactDir } from './artifact-publication.js';
import { classifyCatalogAdmission } from './catalogAdmission.js';
import { stripInvisibleChars } from '../persona/injection-defense.js';
import { DEFAULT_CATALOG_TRUST_CONFIG } from '../../catalog/types.js';
import {
  computeCatalogState,
  type CatalogWideState,
} from '../../catalog/VerifiedCatalog.js';
import { recordLoadedCatalogEpoch } from '../../observability/operational-telemetry/runtime-context.js';

const log = createLogger('federation.catalog');

// =============================================================================
// Types
// =============================================================================

export type AdapterCategory =
  | 'aerospace' | 'agriculture' | 'ai' | 'ai-ml' | 'automotive'
  | 'blockchain' | 'category' | 'cloud' | 'climate' | 'collaboration'
  | 'commerce' | 'communication' | 'compliance' | 'construction' | 'crm'
  | 'cybersecurity' | 'data' | 'design' | 'devops' | 'ecommerce'
  | 'education' | 'employment' | 'energy' | 'engineering' | 'environment'
  | 'erp' | 'finance' | 'food' | 'gaming' | 'government' | 'healthcare'
  | 'hospitality' | 'housing' | 'hr' | 'identity' | 'insurance' | 'iot'
  | 'legal' | 'logistics' | 'manufacturing' | 'marketing' | 'media'
  | 'misc' | 'music' | 'observability' | 'politics' | 'productivity'
  | 'real-estate' | 'reference' | 'sales' | 'science' | 'social' | 'sports'
  | 'telecom' | 'test' | 'travel';

export interface AdapterCatalogEntry {
  /**
   * Short kebab-case slug used as the federation server name and as
   * the `entry.id` in mcp-registry.json. When both `id` and `name` are
   * present the catalog indexes by both so revocation lookups work
   * whether the caller has the slug (federation/runtime side) or the
   * package name (classifier/retrieval side). Optional because older
   * catalog bundles did not include it; production bundles generated
   * from upstream tooling always do.
   */
  id?: string;
  /**
   * Canonical name, typically the npm package identifier
   * (e.g. `@stripe/mcp-server`). Primary key for `byName` lookups
   * and the historical revocation index.
   */
  name: string;
  displayName: string;
  version: string;
  category: AdapterCategory;
  keywords: string[];
  toolNames: string[];
  tools?: Array<{
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
    dispatchMechanisms: Array<'rest' | 'mcp'>;
  }>;
  /**
 * EFFICIENCY #2 — Pre-built Set for O(1) tool-name lookup.
   * Populated by AdapterCatalog.buildIndex() from the `toolNames` array.
   * Absent on raw bundle entries before indexing; always present on
   * entries returned by catalog queries (entries(), byName(), etc.).
   */
  toolNamesSet?: Set<string>;
  description: string;
  author: 'protectnil' | 'vendor' | 'community';
  cosignBundle?: string;
  revoked?: boolean;
  revokedAt?: string;
  revokedReason?: string;
}

type AdapterCatalogPayload = AdapterCatalogEntry[] | { catalog?: unknown; epoch?: unknown; catalogVersion?: unknown };

/**
 * / Bundle envelope monotonicity fields.
 *
 * Every published bundle MUST carry both `epoch` (Unix milliseconds,
 * strictly monotonic across publishes) and `catalogVersion` (integer,
 * non-decreasing across publishes). Chariot persists the highest
 * accepted pair to <packageRoot>/.chariot-catalog-epoch.json and
 * rejects any subsequent bundle that violates the order. This blocks
 * replay of a previously-signed-but-stale bundle and
 * downgrade to an older catalogVersion.
 */
export interface CatalogEpochState {
  epoch: number;
  catalogVersion: number;
  /**
   * SHA-256 (hex) of the exact signed bundle bytes that were accepted at
   * this high-water mark. Binds the persisted (epoch, catalogVersion) pair
   * to a concrete artifact so re-admitting the IDENTICAL bundle across a
   * restart is an idempotent no-op, while a DIFFERENT bundle at the same
   * epoch is still rejected as a replay (§5.6). Optional for backward
   * compatibility with legacy epoch files written before identity binding;
   * a legacy record is treated as hash-unknown and upgraded once.
   */
  bundleSha256?: string;
}

const EPOCH_FILE_BASENAME = '.chariot-catalog-epoch.json';

/**
 * Structured error class for catalog-integrity failures. Throwing this
 * (rather than a bare Error) lets callers distinguish security-relevant
 * rejections (collisions, malformed envelope, oversized bundle) from
 * generic I/O or signature failures.
 */
export class CatalogIntegrityError extends Error {
  public readonly details?: Record<string, unknown>;
  constructor(message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'CatalogIntegrityError';
    this.details = details;
  }
}

/**
 * Fail closed on missing/invalid `catalog` key.
 *
 * The previous behavior silently returned `[]` if the bundle envelope
 * was missing `catalog` or had a non-array value. That caused production
 * Chariot instances to boot with zero adapters and no signal that the
 * bundle was malformed. The catalog-loss path is indistinguishable from
 * an attacker substituting an empty bundle, so we now throw.
 *
 * Accepted shapes:
 *   - Bare array (legacy flat catalog file)
 *   - Object with `catalog: AdapterCatalogEntry[]`
 * Anything else throws CatalogIntegrityError.
 */
function unpackCatalogPayload(payload: AdapterCatalogPayload): AdapterCatalogEntry[] {
  if (Array.isArray(payload)) return payload;
  if (payload === null || typeof payload !== 'object') {
    throw new CatalogIntegrityError(
      'adapter-catalog payload is not an array and not an object — refusing to load',
    );
  }
  if (!('catalog' in payload)) {
    throw new CatalogIntegrityError(
      'adapter-catalog payload object is missing required "catalog" key — refusing to load',
    );
  }
  const catalogField = (payload as { catalog?: unknown }).catalog;
  if (!Array.isArray(catalogField)) {
    throw new CatalogIntegrityError(
      `adapter-catalog payload "catalog" key is ${
        catalogField === null ? 'null' : typeof catalogField
      }, expected array — refusing to load`,
    );
  }
  return catalogField as AdapterCatalogEntry[];
}

/**
 * / Parse the envelope just enough to extract the
 * monotonicity fields. Throws CatalogIntegrityError when either field
 * is missing or non-integer. Bare-array (legacy) payloads fail here:
 * the spec requires the envelope shape going forward, and a publisher
 * that did not stamp epoch/catalogVersion is by definition speaking
 * the old protocol — refuse to load.
 */
function extractEnvelopeMonotonicity(parsed: unknown): CatalogEpochState {
  if (Array.isArray(parsed) || parsed === null || typeof parsed !== 'object') {
    throw new CatalogIntegrityError(
      'adapter-catalog bundle is missing the envelope object — refusing to load: ' +
        'every bundle MUST carry top-level "epoch" and "catalogVersion" fields. ' +
        'Re-publish the bundle with a publisher build that stamps the envelope.',
    );
  }
  const obj = parsed as { epoch?: unknown; catalogVersion?: unknown };
  if (!('epoch' in obj) || !Number.isInteger(obj.epoch)) {
    throw new CatalogIntegrityError(
      'adapter-catalog bundle envelope "epoch" is missing or not an integer — ' +
        'refusing to load. The publisher must stamp epoch:Date.now() ' +
        'before signing.',
      { epoch: obj.epoch },
    );
  }
  if (!('catalogVersion' in obj) || !Number.isInteger(obj.catalogVersion)) {
    throw new CatalogIntegrityError(
      'adapter-catalog bundle envelope "catalogVersion" is missing or not an integer — ' +
        'refusing to load. The publisher must stamp a non-decreasing ' +
        'catalogVersion before signing.',
      { catalogVersion: obj.catalogVersion },
    );
  }
  return {
    epoch: obj.epoch as number,
    catalogVersion: obj.catalogVersion as number,
  };
}

/**
 * CHARIOT::§3.6::1 — "The system SHALL set staleDetection.maxAgeMs =
 * 7*24*60*60*1000 (seven days) and SHALL treat a catalog older than seven
 * days from its `materializedAt` timestamp as stale, producing a startup
 * warning." (CHARIOT-SPEC.md:283, restated in CHARIOT-SPEC.md:371 §5.2's
 * `stale` state row and independently corroborated by this repo's
 * integrator-facing `docs/product/CHARIOT-SPEC.md` §4.3/§9.1, which names
 * the exact event `catalog.stale_warning`).
 *
 * `materializedAt` is NOT one of §5.6's REQUIRED envelope fields
 * (CHARIOT-SPEC.md:421 lists only catalog/registry/manifest/epoch/
 * catalogVersion) and no publisher stamps it today — a repo-wide grep for
 * `materializedAt` outside this change returns zero hits. Its extraction is
 * therefore lenient (unlike `extractEnvelopeMonotonicity` above, which
 * THROWS on a missing/malformed `epoch`/`catalogVersion` because those ARE
 * required): a missing or non-numeric `materializedAt` yields `undefined`
 * and never blocks catalog load. Type is `number` (Unix ms), matching
 * `epoch`'s established convention in this same envelope (§5.6: the
 * publisher MUST stamp `epoch = Date.now()`) — the only wall-clock-timestamp
 * convention already pinned at this schema level.
 */
function extractMaterializedAt(parsed: unknown): number | undefined {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const v = (parsed as { materializedAt?: unknown }).materializedAt;
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/**
 * CHARIOT::§3.6::1 boundary check, pure and independently testable.
 * Mirrors `VerifiedCatalog.isStaleTimestamp`'s strict `age > maxAgeMs`
 * convention (src/catalog/VerifiedCatalog.ts) so the two staleness gates
 * in this codebase — the existing per-adapter `lastVerifiedAt` check and
 * this whole-catalog `materializedAt` check — apply the same boundary
 * semantics (exactly 7 days old is NOT yet stale; one ms past 7 days IS).
 *
 * Returns `false` (not stale) when `materializedAt` is absent. This is a
 * deliberate exception to the "ABSENT ≠ FALSE" rule: a startup WARNING is
 * an affirmative claim ("this catalog IS stale") the code must not make
 * about a field no publisher stamps yet, so silence — not a false warning
 * — is correct until a publisher begins emitting the field. This differs from
 * `isStaleTimestamp`'s fail-CLOSED handling of a present-but-malformed or
 * future timestamp (which REJECTS the catalog, a security-relevant
 * admission decision): this function only gates a WARN log, never
 * admission, so a future `materializedAt` naturally evaluates as "not
 * stale" (a large negative age) rather than needing its own clock-skew
 * rule — the consequence of getting a warning-only check wrong is a
 * missing/incorrect log line, not a bad catalog reaching the effective set.
 */
export function isCatalogStaleFromMaterializedAt(
  materializedAt: number | undefined,
  maxAgeMs: number,
  now: number = Date.now(),
): boolean {
  if (materializedAt === undefined) return false;
  return now - materializedAt > maxAgeMs;
}

/**
 * / Read the persisted high-water-mark for this
 * Chariot install. Returns null when no prior bundle has been
 * accepted (fresh install). Any read or parse error is treated as
 * "no prior state" — fail OPEN on the first bundle, fail CLOSED on
 * monotonicity once a baseline exists.
 */
export function loadPersistedEpoch(epochPath: string): CatalogEpochState | null {
  try {
    if (!existsSync(epochPath)) return null;
    const raw = readFileSync(epochPath, 'utf-8');
    const parsed = JSON.parse(raw) as { epoch?: unknown; catalogVersion?: unknown; bundleSha256?: unknown };
    if (!Number.isInteger(parsed.epoch) || !Number.isInteger(parsed.catalogVersion)) {
      log.warn('adapter-catalog.persisted_epoch_malformed', { epochPath, raw });
      return null;
    }
    return {
      epoch: parsed.epoch as number,
      catalogVersion: parsed.catalogVersion as number,
      // Legacy files carry no bundleSha256 — treated as hash-unknown.
      ...(typeof parsed.bundleSha256 === 'string' && parsed.bundleSha256.length > 0
        ? { bundleSha256: parsed.bundleSha256 }
        : {}),
    };
  } catch (err) {
    log.warn('adapter-catalog.persisted_epoch_read_failed', {
      epochPath,
      error: String(err),
    });
    return null;
  }
}

/**
 * / Persist the freshly-accepted (epoch,
 * catalogVersion) pair. Atomic via write-temp + rename with mode
 * 0o600. The file lives under <packageRoot> — when running under a
 * sandboxed service manager, the host operator is responsible for
 * adding <packageRoot> to the service's writable-paths allowlist.
 */
export function persistEpoch(epochPath: string, state: CatalogEpochState): void {
  const tmp = `${epochPath}.${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.tmp`;
  const body = JSON.stringify({
    epoch: state.epoch,
    catalogVersion: state.catalogVersion,
    ...(state.bundleSha256 !== undefined ? { bundleSha256: state.bundleSha256 } : {}),
  }) + '\n';
  writeFileSync(tmp, body, { encoding: 'utf-8', mode: 0o600 });
  try {
    chmodSync(tmp, 0o600);
  } catch {
    // best-effort — writeFileSync's mode arg already covers this on
    // POSIX; chmod is a belt-and-braces call for filesystems that
    // ignore the open(2) mode bits.
  }
  try {
    renameSync(tmp, epochPath);
  } catch (err) {
    // EFFICIENCY #7: EXDEV fires when tmp and epochPath are on different
    // filesystems (common in containerised / bind-mount setups). Fall back
    // to copy+unlink — atomicity is best-effort across filesystems.
    if ((err as NodeJS.ErrnoException).code === 'EXDEV') {
      try {
        copyFileSync(tmp, epochPath);
        try { unlinkSync(tmp); } catch { /* best-effort */ }
      } catch (copyErr) {
        try { unlinkSync(tmp); } catch { /* best-effort */ }
        throw copyErr;
      }
    } else {
      try { unlinkSync(tmp); } catch { /* best-effort */ }
      throw err;
    }
  }
}

// =============================================================================
// Catalog hardening constants & sanitization (, , )
// =============================================================================

/**
 * Maximum byte length accepted on the adapter bundle file
 * BEFORE JSON.parse runs. The cap is sized above the full production bundle
 * while still bounding memory and parse cost on a hostile input. Rejects
 * oversized payloads at the envelope before structural recursion happens.
 */
// Sourced from the central artifact-limits policy so the
// module-import invariant in artifact-limits.ts guards this cap against
// drift past ABSOLUTE_MAX_ARTIFACT_BYTES.
export const MAX_CATALOG_BYTES = ARTIFACT_LIMITS.catalog;

/**
 * Per-text-field cap. Adapter descriptions, names, and
 * displayNames flow into LLM system context for Tier 1 classification —
 * every byte is paid for in token budget AND attack surface. 2048
 * chars is enough for legitimate descriptive copy and short of any
 * prompt-injection payload of meaningful sophistication.
 */
const MAX_TEXT_FIELD_CHARS = 2048;

/**
 * Lower bound for the publishedAt validity window. MCP did
 * not exist before 2024; 2020-01-01 is a generous floor that still
 * rejects "1970-01-01" placeholders and obviously-bogus epoch=0
 * timestamps that indicate a mis-stamped bundle entry.
 */
const PUBLISHED_AT_MIN_MS = Date.UTC(2020, 0, 1);

/**
 * Tolerance on the upper bound. One day forward of `now`
 * covers clock skew between the bundle producer and this Chariot host
 * without admitting "year 2999" payloads.
 */
const PUBLISHED_AT_MAX_FUTURE_MS = 24 * 60 * 60 * 1000;

// Conservative HTML/XML tag stripper. Not a parser — by design. Any
// `<...>` token in an adapter description is either prompt injection,
// accidental LLM output that shipped into the bundle, or an email
// artifact. None of those belong in the model context.
const HTML_TAG_RE = /<[^>]*>/g;

/**
 * Sanitize a free-text field that flows into the LLM system context
 *. Defense-in-depth, NOT an HTML parser. Returns the
 * sanitized string (possibly empty if input was non-string or fully
 * stripped).
 *
 * REUSE #1: delegates invisible-char stripping to stripInvisibleChars()
 * from injection-defense.ts, which composes C0 controls + Unicode tag
 * block + zero-width + bidi controls (U+200E/200F/202A-202E) + NFC.
 * The previous local version omitted the bidi controls strip, leaving a
 * bypass surface that injection-defense.ts closed.
 */
function sanitizeFreeText(input: unknown): string {
  if (typeof input !== 'string') return '';
  // 1. Strip all invisible characters (C0, Unicode tags, zero-width, bidi)
  //    and NFC-normalize via the shared pipeline.
  let s = stripInvisibleChars(input);
  // 2. Strip HTML/XML-shaped substrings.
  s = s.replace(HTML_TAG_RE, '');
  // 3. Cap length.
  if (s.length > MAX_TEXT_FIELD_CHARS) {
    s = s.slice(0, MAX_TEXT_FIELD_CHARS);
  }
  return s;
}

/**
 * Validate that a publishedAt string is parseable AND falls
 * inside [2020-01-01, now + 1 day]. Returns true when the timestamp is
 * valid OR absent (publishedAt is optional). Returns false when present
 * but malformed or out-of-range — the caller should skip + log the
 * entry without rejecting the whole bundle.
 */
function isPublishedAtAcceptable(publishedAt: unknown, nowMs: number = Date.now()): boolean {
  if (publishedAt === undefined || publishedAt === null) return true;
  if (typeof publishedAt !== 'string') return false;
  const parsed = Date.parse(publishedAt);
  if (Number.isNaN(parsed)) return false;
  if (parsed < PUBLISHED_AT_MIN_MS) return false;
  if (parsed > nowMs + PUBLISHED_AT_MAX_FUTURE_MS) return false;
  return true;
}

export interface CatalogSourceConfig {
  source: 'bundle' | 'registry';
  /**
   * Absolute path to a local adapter artifact. Defaults to the bundled
   * adapter-bundle.json, or CHARIOT_ADAPTER_CATALOG_PATH when set.
   * The loader accepts both the legacy array shape and the canonical
   * bundle shape. The bundle is the preferred source; the flat catalog
   * file remains as a compatibility export.
   */
  catalogPath?: string;
  registryUrl?: string;
  /**
   * Verify the Ed25519 signature on the catalog. **Defaults to `true`
   * as of Chariot 3.0.0.** Setting this to `false` opts out of the
   * signature check on both the bundled and remote load paths, and
   * emits a loud startup warning every boot. Opting out is an
   * explicit acknowledgment that the adapter catalog is being loaded
   * without cryptographic verification.
   *
   * BREAKING CHANGE from 1.2.0 → 1.3.0: in prior versions the default
   * was `false` (verification off) and consumers had to explicitly
   * opt in. The default is now on. Consumers running against a custom
   * catalog that isn't signed must either sign the catalog (see
   * `scripts/sign-catalog.mjs`) or set `verifySignature: false`.
   */
  verifySignature?: boolean;
  /**
   * PEM-encoded Ed25519 public key used to verify the catalog
   * signature. When omitted, Chariot falls back to the bundled default
   * key in `keys/chariot-catalog-public.ts`. Consumers running against
   * a custom signed catalog must supply their own key here.
   */
  publicKeyPem?: string;
  /**
   * Polling interval for the signed-catalog refresh loop, in
   * milliseconds. Only applies when `source === 'registry'` and
   * `registryUrl` is set. Default 1 hour (3_600_000). The refresh
   * loop is started explicitly via `startRefresh()` and cancelled via
   * `stopRefresh()`; it is not started automatically by `load()`.
   */
  refreshIntervalMs?: number;
  revocationListUrl?: string;
  /**
 * / Override the default persistence path for the
   * (epoch, catalogVersion) high-water-mark. When omitted, defaults to
   * `<packageRoot>/.chariot-catalog-epoch.json`, or
   * `process.env.CHARIOT_CATALOG_EPOCH_PATH` when set. Tests use this
   * to point at a hermetic tmp dir.
   */
  epochPath?: string;
  /**
 * cross-instance closure — Explicit epoch store injection.
   * When omitted, the store is selected from env (`CHARIOT_EPOCH_STORE`)
   * with file mode the default. Multi-replica deployments set
   * `CHARIOT_EPOCH_STORE=mongo` to share the high-water-mark across
   * replicas via the IAM Mongo client. Tests pass an explicit store
   * to verify cross-instance rejection (eval 08 Test 14) by sharing
   * one MongoEpochStore between two AdapterCatalog instances.
   */
  epochStore?: import('./CatalogEpochStore.js').CatalogEpochStore;
  /**
   * CHARIOT::§5.2::2 freshness-boundary testability. Clock used by the
   * catalog-wide state machine's age computation (`computeCatalogState`'s
   * `now`). Defaults to `Date.now`. Tests use this to assert the exact
   * 7-day boundary deterministically instead of racing the real clock.
   */
  now?: () => number;
}

export interface RevocationEntry {
  adapterName: string;
  affectedVersions: string[];
  reason: string;
  revokedAt: string;
}

// =============================================================================
// Catalog
// =============================================================================

export class AdapterCatalog {
  private entries_: AdapterCatalogEntry[] = [];
  private categoryIndex = new Map<AdapterCategory, AdapterCatalogEntry[]>();
  private keywordIndex = new Map<string, Set<string>>();
  private nameIndex = new Map<string, AdapterCatalogEntry>();
  private revocationSet = new Set<string>();
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private refreshInFlight = false;
  /**
   * CHARIOT::§7.5::1 / §7.6::1 — subscribers notified every time
   * `buildIndex()` runs (initial `load()` AND every refresh/refresh-fallback
   * cycle that reaches a successful rebuild — see the `startRefresh()` call
   * sites of `buildIndex`). This is the single hook point: FederationManager
   * uses it to re-seed its revocation set from the catalog's freshly
   * rebuilt `revocationSet` (§7.6::1) and to run the runtime-revocation
   * teardown path for any currently-connected adapter newly marked
   * `revoked: true`; RegistryLoader-driven callers can use it to trigger
   * `reload()` so a signed-catalog refresh reconciles the live adapter set.
   */
  private readonly changeListeners: Array<() => void> = [];
  private readonly config: CatalogSourceConfig;
  private readonly verifyEnabled: boolean;
  /**
   * EFFICIENCY #11 — In-process cache of the last accepted (epoch,
   * catalogVersion) pair. Avoids a disk read on every call to
   * enforceMonotonicityAndPersist when the same instance processes
   * multiple loads (e.g. the refresh loop). Set on every successful
   * accept; null until first load or after explicit reset.
   */
  private _lastAcceptedEpoch: CatalogEpochState | null = null;
  /**
   * Ed25519 public keys accepted for catalog signature verification.
   *
   * CHARIOT-SPEC.md:383 (§5.4, amended): "`publicKeyPem?: string, //
   * optional additional caller-supplied key; SHALL be validated as a
   * member of the compiled-in CHARIOT_CATALOG_PUBLIC_KEYS rotation set
   * (§5.1 trust anchor) before use — a supplied key outside that set
   * SHALL be rejected, never substituted for it`." CHARIOT-SPEC.md:523
   * (§5.7 "Trust anchor"), the same principle stated for the sealed
   * EdgeShard's native key: "A caller-supplied key outside that rotation
   * set SHALL be rejected." A caller-supplied `publicKeyPem` is therefore
   * an ADDITIONAL candidate, never a substitute: it is intersected
   * against `CHARIOT_CATALOG_PUBLIC_KEYS` via `intersectWithRotationSet`
   * (`verifyCatalogSignature.ts`) — the identical choke point the
   * catalog/bundle fast path routes every caller-supplied key through.
   * The default (no `publicKeyPem`) intersects the compiled-in set
   * against itself, which is always the full set unchanged, so a rotation
   * overlap still accepts both old and new signing keys with no
   * behavior change from before this field existed.
   */
  private readonly acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey>;
  /**
   * CHARIOT-SPEC.md:383 / :523 — true only when the caller supplied a
   * `publicKeyPem` AND it intersected to ZERO members of the compiled-in
   * rotation set (never true for the default, unconfigured case — see
   * `acceptedKeys` above). Consulted by `loadFromBundle`/`loadFromRegistry`
   * so a load lands in `invalid` with the dedicated
   * `accepted-keys-outside-rotation-set` reason instead of attempting a
   * signature check against zero keys and misreporting a generic
   * signature mismatch. Set once, at construction — never throws, and
   * never silently falls back to the compiled-in set.
   */
  private readonly acceptedKeysOutsideRotationSet: boolean;

  /**
   * CHARIOT::§5.2::4 — catalog-wide Ed25519-gated trust state (CH-01/CH-02),
   * distinct from the per-adapter `AdapterVerificationRecord` bookkeeping in
   * `src/catalog/VerifiedCatalog.ts`. Starts `invalid` — fail-closed before
   * any load has run (there is no verified catalog yet, so there is no
   * effective catalog yet either; `entries_` starts `[]` to match).
   */
  private _state: CatalogWideState = 'invalid';
  private _stateReason = 'catalog not yet loaded';

  /** CHARIOT::§5.2 catalog-wide state: `verified` | `stale` | `invalid`. */
  get state(): CatalogWideState {
    return this._state;
  }

  /** Human-readable trigger for the current {@link state}. */
  get stateReason(): string {
    return this._stateReason;
  }

  constructor(config: CatalogSourceConfig) {
    this.config = config;
    this.verifyEnabled = config.verifySignature !== false;
    // CHARIOT-SPEC.md:383 / :523 — intersect BEFORE storing. Never throws
    // here (construction never fails-closed by throwing) and never falls
    // back to the compiled-in set silently on an empty result — an empty
    // intersection is recorded in `acceptedKeysOutsideRotationSet` and
    // surfaces as the catalog-wide `invalid` state the next time a load
    // is attempted (see `loadFromBundle`/`loadFromRegistry` below).
    const candidateKeys: ReadonlyArray<ChariotCatalogPublicKey> = config.publicKeyPem
      ? [{ id: 'caller-supplied', pem: config.publicKeyPem }]
      : CHARIOT_CATALOG_PUBLIC_KEYS;
    this.acceptedKeys = intersectWithRotationSet(candidateKeys);
    this.acceptedKeysOutsideRotationSet = config.publicKeyPem !== undefined && this.acceptedKeys.length === 0;

    if (!this.verifyEnabled) {
      // Every startup when verification is disabled emits a loud
      // warning so operators cannot forget the catalog is unverified.
      log.warn(
        'adapter-catalog.signature_verification_disabled ' +
          '— catalog signature verification is OPT-OUT in 1.3.0+. ' +
          'This Chariot instance is loading an UNVERIFIED adapter catalog. ' +
          'Set verifySignature: true (the default) or remove the explicit ' +
          'opt-out to enable signature enforcement. This warning fires on ' +
          'every startup by design.',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Loading
  // ---------------------------------------------------------------------------

  async load(): Promise<void> {
    let raw: AdapterCatalogEntry[];

    if (this.config.source === 'registry' && this.config.registryUrl) {
      // CHARIOT::§5.4::5 — "WHEN source is `registry` the system SHALL read
      // the operator-configured registryUrl and SHALL fall back to bundle
      // when refresh fails." An initial (load-time) registry failure is a
      // refresh-failure case too — without this fallback the error
      // propagated uncaught and the service never came up, even though a
      // usable bundle was on disk.
      try {
        raw = await this.loadFromRegistry();
      } catch (err) {
        log.error('adapter-catalog.load.registry_failed', {
          error: String(err),
          note: 'falling back to bundle catalog',
        });
        raw = await this.loadFromBundle();
      }
    } else {
      raw = await this.loadFromBundle();
    }

    this.buildIndex(raw);
    log.info('catalog loaded', { entries: raw.length, categories: this.categoryIndex.size });
  }

  /**
 * / Resolve the persistence path for the
   * monotonicity high-water-mark. Resolution order:
   *   1. Explicit `config.epochPath` (used by tests).
   *   2. `process.env.CHARIOT_CATALOG_EPOCH_PATH`.
   *   3. `<packageRoot>/.chariot-catalog-epoch.json` next to the
   *      package.json. Operators running under sandboxed service
   *      managers must include `<packageRoot>` in the service's
   *      writable-paths allowlist.
   */
  private resolveEpochPath(): string {
    if (this.config.epochPath) return this.config.epochPath;
    if (process.env.CHARIOT_CATALOG_EPOCH_PATH) {
      return process.env.CHARIOT_CATALOG_EPOCH_PATH;
    }
    const thisFile = fileURLToPath(import.meta.url);
    const pkgRoot = pathResolve(dirname(thisFile), '..', '..', '..');
    return pathJoin(pkgRoot, EPOCH_FILE_BASENAME);
  }

  /**
   * Cached store handle. Resolved lazily on first
   * enforceMonotonicityAndPersist call.
   */
  private _epochStore: import('./CatalogEpochStore.js').CatalogEpochStore | null = null;

  private async resolveEpochStore(): Promise<import('./CatalogEpochStore.js').CatalogEpochStore> {
    if (this._epochStore) return this._epochStore;
    if (this.config.epochStore) {
      this._epochStore = this.config.epochStore;
      return this._epochStore;
    }
    // Dynamic import keeps the Mongo module surface (and its transitive
    // mongodb driver references) out of file-mode startup paths.
    const mod = await import('./CatalogEpochStore.js');
    this._epochStore = mod.createEpochStore({ epochPath: this.resolveEpochPath() });
    return this._epochStore;
  }

  /**
 * / Enforce envelope monotonicity. Called from
   * both bundle and registry load paths after byte-size / signature
   * checks but before parsing the full catalog payload. Throws
   * CatalogIntegrityError on missing/invalid envelope, replay
   * (epoch below or equal to persisted), or downgrade
   * (catalogVersion < persisted).
   * On accept, persists the new pair BEFORE returning so a subsequent
   * load in the same process sees the bumped baseline.
   *
   * IDENTITY BINDING (§5.6): `bundleSha256` is the SHA-256 of the exact
   * signed bytes being admitted. It supplements, but does not replace, the
   * strictly-increasing epoch requirement: even identical bytes cannot be
   * republished at an already-consumed epoch.
   */
  private async enforceMonotonicityAndPersist(
    parsed: unknown,
    source: 'bundle' | 'registry',
    bundleSha256?: string,
  ): Promise<void> {
    const envelope = extractEnvelopeMonotonicity(parsed);
    const store = await this.resolveEpochStore();
    // EFFICIENCY #11 — in-process cache short-circuits a store read for
    // back-to-back loads in the same instance. The cache reflects the
    // last value THIS instance accepted; for cross-instance correctness
    // the store itself is consulted on first load and any path where the
    // cache was reset.
    const persisted = this._lastAcceptedEpoch ?? (await store.load());
    const epochPath = this.resolveEpochPath();

    // §5.6 admission — the SINGLE shared classifier (CHARIOT-SPEC.md:436).
    // This site MUST NOT restate the comparison locally; the local copy that
    // used to live here rejected every equal epoch and bricked boot on the
    // second start.
    const admission = classifyCatalogAdmission({
      epoch: envelope.epoch,
      catalogVersion: envelope.catalogVersion,
      ...(bundleSha256 !== undefined ? { bundleSha256 } : {}),
      persisted,
    });

    if (admission.kind === 'rejection') {
      log.warn('catalog.epoch_replay_rejected', {
        bundleEpoch: envelope.epoch,
        persistedEpoch: persisted?.epoch ?? null,
        reason: admission.reason,
        source,
      });
      throw new CatalogIntegrityError(`adapter-catalog ${admission.message}`, {
        envelopeEpoch: envelope.epoch,
        persistedEpoch: persisted?.epoch ?? null,
        envelopeCatalogVersion: envelope.catalogVersion,
        persistedCatalogVersion: persisted?.catalogVersion ?? null,
        bundleSha256: bundleSha256 ?? null,
        persistedBundleSha256: persisted?.bundleSha256 ?? null,
        admissionReason: admission.reason,
        source,
        epochStore: store.describe(),
      });
    }

    // CHARIOT::§3.6::1 — computed on every accepted load (advance AND
    // re-admission), matching §5.2's "state transition is computed on
    // every catalog load and on every refresh cycle" (CHARIOT-SPEC.md:373).
    // A rejection above already threw, so this only runs for a catalog that
    // IS going to be served.
    const materializedAt = extractMaterializedAt(parsed);
    if (isCatalogStaleFromMaterializedAt(materializedAt, DEFAULT_CATALOG_TRUST_CONFIG.staleDetection.maxAgeMs)) {
      log.warn('catalog.stale_warning', {
        materializedAt,
        ageMs: Date.now() - (materializedAt as number),
        maxAgeMs: DEFAULT_CATALOG_TRUST_CONFIG.staleDetection.maxAgeMs,
        source,
      });
    }

    const accepted: CatalogEpochState = {
      epoch: envelope.epoch,
      catalogVersion: envelope.catalogVersion,
      ...(bundleSha256 !== undefined ? { bundleSha256 } : {}),
    };
    // A re-admission is NOT a publication: the high-water mark SHALL NOT be
    // rewritten (CHARIOT-SPEC.md:431, :457). Only an advance persists. The
    // values are unchanged by definition on a re-admission, so skipping the
    // write is also the correct no-op — but the reason it is skipped is the
    // clause, not an equality test.
    if (admission.kind === 'advance') {
      await store.persist(accepted);
    }
    // EFFICIENCY #11: update the in-process cache so subsequent loads in
    // the same process lifetime skip the disk read.
    this._lastAcceptedEpoch = accepted;
    // C4AMD §8 closed field set: the loaded signed catalog's epoch rides on
    // every telemetry event as `catalogEpoch` (local state only; no I/O).
    recordLoadedCatalogEpoch(accepted.epoch);
    log.info('adapter-catalog.envelope_accepted', {
      source,
      epoch: accepted.epoch,
      catalogVersion: accepted.catalogVersion,
      epochPath,
      hadPriorBaseline: persisted !== null,
    });
  }

  private async loadFromBundle(): Promise<AdapterCatalogEntry[]> {
    try {
      // Resolve the bundle path from this module's location. We use
      // readFileSync (synchronous, raw bytes) rather than dynamic
      // JSON import because the signature verifier must see the EXACT
      // bytes on disk — `import` reparses and may normalize, which
      // would break the detached signature.
      const thisFile = fileURLToPath(import.meta.url);
      const pkgRoot = pathResolve(dirname(thisFile), '..', '..', '..');
      const bundleDir = resolvePublishedArtifactDir(pkgRoot, 'adapter-current.json', pkgRoot);
      const bundlePath = pathResolve(bundleDir, 'adapter-bundle.json');
      const catalogPath = this.config.catalogPath
        ?? process.env.CHARIOT_ADAPTER_CATALOG_PATH
        ?? bundlePath;
      const sigPath = `${catalogPath}.sig`;

      if (!existsSync(catalogPath)) {
        log.warn(
          'adapter-catalog.json not found — catalog will be empty until adapters implement static catalog()',
          { catalogPath },
        );
        return [];
      }

      const catalogBytes = readFileSync(catalogPath);

 // Pre-parse oversize check. Reject before JSON.parse
      // touches the bytes — bounds memory and parse cost on hostile
      // input, and avoids "billion laughs"-style amplification at the
      // envelope size.
      if (catalogBytes.length > MAX_CATALOG_BYTES) {
        throw new CatalogIntegrityError(
          `adapter-catalog file at ${catalogPath} is ${catalogBytes.length} bytes, ` +
            `exceeds MAX_CATALOG_BYTES=${MAX_CATALOG_BYTES} — refusing to parse`,
          { bytes: catalogBytes.length, limit: MAX_CATALOG_BYTES, path: catalogPath },
        );
      }

      // 1.3.0: bundled catalog signature enforcement.
      //
      // CHARIOT::§5.2::3 (CH-02): "A catalog whose signature fails
      // verification produces an empty effective catalog, never a partial
      // one." A missing/mismatched signature on this — the TERMINAL load
      // path (there is no further fallback once the local bundle itself
      // fails; `registry` failures fall back to here per §5.4, but a
      // bundle failure has nowhere left to fall back to) — MUST NOT throw
      // and crash startup. It sets the catalog-wide state to `invalid` and
      // resolves with an empty entry list so `load()` completes normally
      // with "no adapters available" (CHARIOT-SPEC.md:1477), matching the
      // documented failure-mode row. This replaces the pre-4.0.0 behavior
      // of throwing here, which brought the whole process down instead.
      if (this.verifyEnabled) {
        // CHARIOT-SPEC.md:383 / :523 — checked BEFORE any file I/O, same
        // ordering rationale as `verifyAndReadArtifact`'s own gate: a
        // caller-supplied `publicKeyPem` outside the compiled-in rotation
        // set is a CONFIGURATION error, independent of whether the
        // catalog/.sig files even exist, and must be diagnosed with its
        // own reason rather than misreported as a signature mismatch
        // against a file that was never actually checked.
        if (this.acceptedKeysOutsideRotationSet) {
          this.applyLoadedState({ signatureValid: false, acceptedKeysOutsideRotationSet: true }, {
            note: 'publicKeyPem override contained no member of the compiled-in CHARIOT_CATALOG_PUBLIC_KEYS rotation set (CHARIOT-SPEC.md:383, :523)',
            catalogPath,
          });
          return [];
        }
        if (!existsSync(sigPath)) {
          this.applyLoadedState({ signatureValid: false }, {
            note: 'adapter-catalog.json.sig not found alongside adapter-catalog.json',
            catalogPath,
            sigPath,
          });
          return [];
        }
        const sigB64 = readFileSync(sigPath, 'utf-8').trim();
        const verifyResult = this.verifyAgainstAnyKey(catalogBytes, sigB64);
        if (!verifyResult.matched) {
          const acceptedIds = this.acceptedKeys.map((k) => k.id).join(', ');
          this.applyLoadedState({ signatureValid: false }, {
            note: 'adapter-catalog.json signature verification failed against any accepted key',
            triedKeys: acceptedIds,
            catalogPath,
          });
          return [];
        }
        log.info('adapter-catalog.signature_verified', {
          source: 'bundle',
          keyId: verifyResult.keyId,
          bytes: catalogBytes.length,
        });
      }

      const parsed = JSON.parse(catalogBytes.toString('utf-8')) as AdapterCatalogPayload;
 // / Envelope monotonicity. Runs AFTER signature
      // verification so we never persist an unsigned envelope's claims,
      // and BEFORE unpackCatalogPayload so a stale-but-signed bundle
      // never reaches the index. Persists on accept. The SHA-256 of the
      // exact verified bytes identity-binds the high-water mark so the
      // unchanged on-disk bundle re-admits across restarts (§5.6).
      await this.enforceMonotonicityAndPersist(
        parsed,
        'bundle',
        createHash('sha256').update(catalogBytes).digest('hex'),
      );
      // CHARIOT::§5.2::1/2/4 — state recomputed on every accepted load.
      // `enforceMonotonicityAndPersist` already threw on a rejected
      // (replayed/downgraded) envelope above, so reaching here means this
      // catalog IS going to be served; `verifyEnabled === false` (opt-out,
      // its own loud startup warning fires in the constructor) is treated
      // as `signatureValid: true` — there is no meaningful "signature
      // valid" fact to gate on when verification itself was disabled by
      // the operator, and §5.2 has no fourth state for "unverified."
      this.applyLoadedState(
        { signatureValid: true, materializedAtMs: extractMaterializedAt(parsed) },
        { source: 'bundle' },
      );
      return unpackCatalogPayload(parsed);
    } catch (err) {
      log.error('loadFromBundle failed', { error: String(err) });
      throw err;
    }
  }

  /**
   * CHARIOT::§5.2::1-4 — apply `computeCatalogState`'s result to this
   * instance and log it. Centralizes state assignment so `loadFromBundle`
   * and `loadFromRegistry` (both success and the bundle's terminal
   * signature-failure path) share one code path to the `state`/
   * `stateReason` getters. Does not touch `entries_` — callers that need
   * the CH-02 empty-effective-catalog consequence of `invalid` call
   * `this.buildIndex([])` (or rely on the bundle-failure caller returning
   * `[]`, which `load()`/`startRefresh()` then index).
   */
  private applyLoadedState(
    input: { signatureValid: boolean; materializedAtMs?: number; acceptedKeysOutsideRotationSet?: boolean },
    logContext: Record<string, unknown>,
  ): CatalogWideState {
    const result = computeCatalogState({
      signatureValid: input.signatureValid,
      ...(input.materializedAtMs !== undefined ? { materializedAtMs: input.materializedAtMs } : {}),
      ...(input.acceptedKeysOutsideRotationSet ? { acceptedKeysOutsideRotationSet: true } : {}),
      maxAgeMs: DEFAULT_CATALOG_TRUST_CONFIG.staleDetection.maxAgeMs,
      now: (this.config.now ?? Date.now)(),
    });
    this._state = result.state;
    this._stateReason = result.reason;
    if (result.state === 'invalid') {
      log.error('adapter-catalog.state_invalid', { reason: result.reason, ...logContext });
    } else if (result.state === 'stale') {
      log.warn('adapter-catalog.state_stale', { reason: result.reason, ...logContext });
    } else {
      log.info('adapter-catalog.state_verified', { reason: result.reason, ...logContext });
    }
    return result.state;
  }

  /**
   * CHARIOT::§5.2::5 — 4.0.0: the `invalid` state SHALL also be produced
   * by a retrieval-manifest mismatch, an encoder mismatch, or any
   * sealed-bundle signature failure. Those three conditions are detected
   * by `VectorIndexVerifier.admit()` (`src/engine/retrieval/
   * VectorIndexVerifier.ts`) against the SAME sealed bundle envelope this
   * catalog's `catalog` array is drawn from, not by this class's own
   * Ed25519 check — a caller that observes one of those `AdmissionResult`
   * failures on this catalog's envelope reports it here so the
   * catalog-wide state and effective (adapter) catalog stay CH-02
   * compliant even though the failing gate lives outside this file.
   * Forces the effective catalog empty, per CH-02, and never throws.
   */
  markInvalidFromSealedBundleFailure(
    kind: 'retrieval_manifest_mismatch' | 'encoder_mismatch' | 'sealed_bundle_signature_failed',
    reason: string,
  ): void {
    const result = computeCatalogState({
      signatureValid: true,
      retrievalManifestMismatch: kind === 'retrieval_manifest_mismatch',
      encoderMismatch: kind === 'encoder_mismatch',
      sealedBundleSignatureFailed: kind === 'sealed_bundle_signature_failed',
    });
    this._state = result.state;
    this._stateReason = `${result.reason} — ${reason}`;
    this.buildIndex([]);
    log.error('adapter-catalog.state_invalid', { kind, reason, state: this._state });
  }

  private async loadFromRegistry(): Promise<AdapterCatalogEntry[]> {
    const url = this.config.registryUrl;
    if (!url) throw new Error('invariant: registryUrl required for registry source');

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Registry returned ${response.status}`);
      }

      // Read the RAW bytes, not `response.text()` round-tripped through
      // UTF-8 string decoding. Text decoding can normalize BOMs, strip
      // invalid sequences, or rewrite line endings on some platforms,
      // which would diverge from whatever the registry actually signed.
      // The signature contract is byte-for-byte over the network-wire
      // bytes; any normalization invalidates it. `arrayBuffer()` gives
      // us the exact bytes the server sent.
      const bodyArrayBuffer = await response.arrayBuffer();
      const bodyBytes = Buffer.from(bodyArrayBuffer);

 // Pre-parse oversize check on the registry response too.
      // Same rationale as the bundle path — bound memory and parse cost
      // before JSON.parse touches the bytes.
      if (bodyBytes.length > MAX_CATALOG_BYTES) {
        throw new CatalogIntegrityError(
          `registry catalog response from ${url} is ${bodyBytes.length} bytes, ` +
            `exceeds MAX_CATALOG_BYTES=${MAX_CATALOG_BYTES} — refusing to parse`,
          { bytes: bodyBytes.length, limit: MAX_CATALOG_BYTES, url },
        );
      }

      // 1.3.0: verification is ON BY DEFAULT. Callers that need to
      // load from an unsigned registry endpoint must explicitly set
      // verifySignature: false in CatalogSourceConfig.
      if (this.verifyEnabled) {
        const signature = response.headers.get('catalog-signature');
        if (!signature) {
          throw new Error(
            `Registry at ${url} did not return a "catalog-signature" header. ` +
              'Chariot requires signed registry responses by default. ' +
              'Either configure your registry to sign responses and serve the ' +
              'base64 Ed25519 signature in the catalog-signature header, or ' +
              'explicitly set verifySignature: false in CatalogSourceConfig ' +
              'to opt out (not recommended).',
          );
        }
        const verifyResult = this.verifyAgainstAnyKey(bodyBytes, signature);
        if (!verifyResult.matched) {
          const acceptedIds = this.acceptedKeys.map((k) => k.id).join(', ');
          throw new Error(
            `Registry catalog signature verification failed for ${url}. ` +
              `Tried keys: ${acceptedIds}. ` +
              'The response bytes do not verify against the catalog-signature header.',
          );
        }
        log.info('adapter-catalog.signature_verified', {
          source: 'registry',
          url,
          keyId: verifyResult.keyId,
          bytes: bodyBytes.length,
        });
      }

      // Decode AFTER verification so verification always runs against
      // the raw bytes regardless of what JSON.parse would otherwise do.
      const entries = JSON.parse(bodyBytes.toString('utf-8')) as AdapterCatalogPayload;
 // / Envelope monotonicity, same semantics as
      // the bundle path. The persisted (epoch, catalogVersion) is
      // shared across both load paths so a registry-served replay of
      // a previously-bundled catalog is also rejected. Identity-bound
      // to the SHA-256 of the verified wire bytes (§5.6).
      await this.enforceMonotonicityAndPersist(
        entries,
        'registry',
        createHash('sha256').update(bodyBytes).digest('hex'),
      );
      // CHARIOT::§5.2::1/2/4 — same state recomputation as the bundle path.
      // A registry SIGNATURE failure above still throws (unlike the bundle
      // terminal path): §5.4 requires a registry failure to fall back to
      // bundle, and that fallback's own `loadFromBundle()` call sets the
      // FINAL state for this `load()`/refresh cycle — setting `invalid`
      // here first would just be overwritten a moment later. This call
      // only covers the SUCCESS case, where `loadFromBundle` is never
      // invoked and state would otherwise never leave its initial value.
      this.applyLoadedState(
        { signatureValid: true, materializedAtMs: extractMaterializedAt(entries) },
        { source: 'registry', url },
      );
      return unpackCatalogPayload(entries);
    } catch (err) {
      log.error('failed to load catalog from registry', { url, error: String(err) });
      throw err;
    }
  }

  /**
   * Verify a base64 Ed25519 signature against a byte buffer using the
   * `crypto.verify(null, ...)` direct form. This is the correct Node.js
   * idiom for raw Ed25519 — the older `createVerify('ed25519')` form
   * has produced interop bugs because `createVerify` is designed for
   * hash-based signature algorithms. The signer script
   * (`scripts/sign-catalog.mjs`) uses the matching `sign(null, ...)`
   * form, so signer and verifier stay bit-compatible.
   */
  private verifyEd25519Bytes(
    data: Buffer,
    signatureB64: string,
    publicKeyPem: string,
  ): boolean {
    try {
      const sig = Buffer.from(signatureB64, 'base64');
      return cryptoVerify(null, data, publicKeyPem, sig);
    } catch (err) {
      log.error('Ed25519 verification error', { error: String(err) });
      return false;
    }
  }

  /**
 * Multi-key Ed25519 verification. Tries each key in
   * `acceptedKeys` and returns the matching key id, or null if no key
   * accepts the signature. The matched key id is logged by the caller
   * so operators can see which key authenticated each catalog refresh
   * during a rotation overlap window.
   */
  private verifyAgainstAnyKey(
    data: Buffer,
    signatureB64: string,
  ): { matched: true; keyId: string } | { matched: false } {
    for (const key of this.acceptedKeys) {
      if (this.verifyEd25519Bytes(data, signatureB64, key.pem)) {
        return { matched: true, keyId: key.id };
      }
    }
    return { matched: false };
  }

  // ---------------------------------------------------------------------------
  // Indexing
  // ---------------------------------------------------------------------------

  /**
   * Replace the full catalog atomically. Rebuilds every index
   * (category, keyword, name, revocation) from the new entries list.
   * Public so consumers that build the catalog programmatically — or
   * refresh it from a signed source after construction — can reuse the
   * same indexing code path as `load()`. Tests also use this to avoid
   * coupling to the bundle-file resolution path.
   */
  setEntries(entries: AdapterCatalogEntry[]): void {
    this.buildIndex(entries);
  }

  private buildIndex(entries: AdapterCatalogEntry[]): void {
    // §5.5: build the new catalog entirely into FRESH local structures and
    // only reassign the instance references once, at the very end, on
    // success. Mutating the live this.categoryIndex/keywordIndex/nameIndex/
    // revocationSet in place (clear-then-refill) let a reader observe a
    // cleared-but-not-yet-repopulated index mid-build, and — worse — left
    // the live catalog PERMANENTLY corrupted if a CatalogIntegrityError
    // threw partway through the loop below (the clear had already run, the
    // throw aborted the refill). Building off to the side means a thrown
    // build leaves the previously-loaded catalog completely untouched, and
    // a successful build becomes a single atomic reference swap.
    const categoryIndex = new Map<AdapterCategory, AdapterCatalogEntry[]>();
    const keywordIndex = new Map<string, Set<string>>();
    const nameIndex = new Map<string, AdapterCatalogEntry>();
    const revocationSet = new Set<string>();

 // collision detection scratch — tracks every identifier we
    // have already inserted into nameIndex during this build pass.
    // Map.set silently shadows on collision; we explicitly fail-closed.
    const seenIds = new Set<string>();
    const sanitizedEntries: AdapterCatalogEntry[] = [];
    const nowMs = Date.now();

    for (const original of entries) {
 // Sanitize every free-text field that flows into the
      // LLM system context. Strip control chars, zero-width glyphs,
      // and HTML-tag-shaped substrings, then cap. We mutate a SHALLOW
      // CLONE so the input array (which callers may still hold) is not
      // tampered with.
      const sanitizedName = sanitizeFreeText(original.name);
      const sanitizedDisplayName = sanitizeFreeText(original.displayName);
      const sanitizedDescription = sanitizeFreeText(original.description);
      const sanitizedId = original.id ? sanitizeFreeText(original.id) : undefined;
 // (test-10 gap): keywords flow into LLM tool-description context
      // via QueryExpander + ToolPreFilter; sanitize each element with the same
      // pipeline as name/displayName/description, then drop empties.
      const sanitizedKeywords = Array.isArray(original.keywords)
        ? original.keywords
            .map((k) => sanitizeFreeText(k))
            .filter((k) => k.length > 0)
        : [];

 // Reject the entry (skip + log) if sanitization
      // emptied a structurally critical field. `name` is the primary
      // index key; if a hostile bundle uses a name that is entirely
      // control chars or HTML tags, we skip rather than load a
      // zero-keyed adapter.
      if (sanitizedName.length === 0) {
        log.warn('adapter-catalog.entry_rejected.sanitized_name_empty', {
          originalNameSample: typeof original.name === 'string' ? original.name.slice(0, 64) : null,
        });
        continue;
      }
      if (original.id !== undefined && sanitizedId !== undefined && sanitizedId.length === 0) {
        log.warn('adapter-catalog.entry_rejected.sanitized_id_empty', {
          name: sanitizedName,
          originalIdSample: typeof original.id === 'string' ? original.id.slice(0, 64) : null,
        });
        continue;
      }

 // publishedAt range validation. Hygiene check, NOT
      // security: skip + log; do not reject the whole bundle.
      if (!isPublishedAtAcceptable((original as { publishedAt?: unknown }).publishedAt, nowMs)) {
        log.warn('adapter-catalog.entry_rejected.published_at_out_of_range', {
          name: sanitizedName,
          publishedAt: (original as { publishedAt?: unknown }).publishedAt,
          minMs: PUBLISHED_AT_MIN_MS,
          maxMs: nowMs + PUBLISHED_AT_MAX_FUTURE_MS,
        });
        continue;
      }

      const entry: AdapterCatalogEntry = {
        ...original,
        name: sanitizedName,
        displayName: sanitizedDisplayName,
        description: sanitizedDescription,
        id: sanitizedId,
        keywords: sanitizedKeywords,
 // EFFICIENCY #2: pre-build the Set at catalog-load time so
        // handleCall.toolNamesSet.has(toolName) is O(1) instead of
        // Array.includes (O(n)).
        toolNamesSet: new Set<string>(original.toolNames ?? []),
      };

 // Adapter id collisions silently shadowed via Map.set.
      // Fail-closed: throw a CatalogIntegrityError naming both colliding
      // entries. The bundle is rejected as a whole. The collision check
      // covers BOTH the canonical `name` and the optional `id` slug
      // because nameIndex is keyed by both.
      if (seenIds.has(entry.name)) {
        throw new CatalogIntegrityError(
          `adapter id collision on "${entry.name}" — duplicate name in catalog bundle`,
          { collidingKey: entry.name, kind: 'name' },
        );
      }
      seenIds.add(entry.name);
      nameIndex.set(entry.name, entry);

      if (entry.id && entry.id !== entry.name) {
        if (seenIds.has(entry.id)) {
          throw new CatalogIntegrityError(
            `adapter id collision on "${entry.id}" — duplicate id slug in catalog bundle`,
            { collidingKey: entry.id, kind: 'id' },
          );
        }
        seenIds.add(entry.id);
        nameIndex.set(entry.id, entry);
      }

      // Category index
      if (!categoryIndex.has(entry.category)) {
        categoryIndex.set(entry.category, []);
      }
      const catList = categoryIndex.get(entry.category);
      if (!catList) throw new Error(`invariant: category ${entry.category} missing from index`);
      catList.push(entry);

      // Keyword index: token → set of adapter names
      for (const keyword of entry.keywords) {
        const lower = keyword.toLowerCase();
        if (!keywordIndex.has(lower)) {
          keywordIndex.set(lower, new Set());
        }
        const kwSet = keywordIndex.get(lower);
        if (!kwSet) throw new Error(`invariant: keyword ${lower} missing from index`);
        kwSet.add(entry.name);
      }

      // Tool name index: treat tool names as keywords too
      for (const toolName of entry.toolNames) {
        const lower = toolName.toLowerCase();
        if (!keywordIndex.has(lower)) {
          keywordIndex.set(lower, new Set());
        }
        const tnSet = keywordIndex.get(lower);
        if (!tnSet) throw new Error(`invariant: tool keyword ${lower} missing from index`);
        tnSet.add(entry.name);
      }

      // Revocation tracking — index BOTH the `name` (package) and the
      // `id` (slug) in the same set so `isRevoked()` matches regardless
      // of which identifier the caller has. Federation-layer callers
      // pass the slug (`entry.id` via ServerConnection.name); classifier
      // callers pass the package name. Both must resolve to the same
      // revocation state.
      if (entry.revoked) {
        revocationSet.add(entry.name);
        if (entry.id) {
          revocationSet.add(entry.id);
        }
      }

      sanitizedEntries.push(entry);
    }

    // §5.5 atomic swap: every field is reassigned here, in one synchronous
    // block, only after the build above has fully succeeded. A thrown
    // CatalogIntegrityError (or any other throw) above never reaches this
    // point, so the previously-loaded catalog is left completely intact.
    this.categoryIndex = categoryIndex;
    this.keywordIndex = keywordIndex;
    this.nameIndex = nameIndex;
    this.revocationSet = revocationSet;
    // Replace `entries_` with the sanitized + filtered list so
    // `entries()` and `size` reflect what was actually indexed, not
    // what was offered. Callers querying the catalog see ONLY clean,
    // schema-valid entries — never raw bundle data.
    this.entries_ = sanitizedEntries;

    // CHARIOT::§7.5::1 / §7.6::1 — notify subscribers AFTER the atomic
    // reference swap above, so a listener that reads `this.entries()` /
    // `this.revokedNames()` synchronously from inside the callback always
    // observes the just-rebuilt state, never the stale pre-swap one.
    for (const listener of this.changeListeners) {
      try {
        listener();
      } catch (err) {
        log.error('adapter-catalog.change_listener_failed', { error: String(err) });
      }
    }
  }

  /**
   * CHARIOT::§7.5::1 / §7.6::1 — subscribe to catalog rebuilds (initial
   * load and every successful refresh/refresh-fallback cycle). Listeners
   * are invoked synchronously, in registration order, after the new
   * entries/revocationSet are already live.
   */
  onChanged(listener: () => void): void {
    this.changeListeners.push(listener);
  }

  /**
   * CHARIOT::§7.6::1 — "The set is populated from ... the catalog's
   * per-entry `revoked: true` flag." Read-only view of the catalog's
   * own revocation index, keyed by both `name` and `id` for every
   * `revoked: true` entry (see `buildIndex`'s alias handling above) —
   * the same keys `isRevoked()` checks. FederationManager unions this
   * into its own revocation set rather than re-deriving it from
   * `entries()`, so the two never drift out of alias-handling sync.
   */
  revokedNames(): ReadonlySet<string> {
    return this.revocationSet;
  }

  // ---------------------------------------------------------------------------
  // Queries (O(1) lookups via indexes)
  // ---------------------------------------------------------------------------

  entries(): AdapterCatalogEntry[] {
    return this.entries_;
  }

  byCategory(category: AdapterCategory): AdapterCatalogEntry[] {
    return this.categoryIndex.get(category) ?? [];
  }

  byKeywords(tokens: string[]): AdapterCatalogEntry[] {
    const matchedNames = new Set<string>();
    for (const token of tokens) {
      const lower = token.toLowerCase();
      const names = this.keywordIndex.get(lower);
      if (names) {
        for (const name of names) {
          matchedNames.add(name);
        }
      }
    }

    const results: AdapterCatalogEntry[] = [];
    for (const name of matchedNames) {
      const entry = this.nameIndex.get(name);
      if (entry && !this.revocationSet.has(name)) {
        results.push(entry);
      }
    }
    return results;
  }

  byName(name: string): AdapterCatalogEntry | undefined {
    return this.nameIndex.get(name);
  }

  /**
   * Check whether a catalog entry is revoked. Accepts either the
   * kebab-case `id` slug (federation-layer identifier, matching
   * `ServerConnection.name`) or the `name` package identifier
   * (classifier-layer identifier, matching `byName` lookups).
   * `buildIndex` populates `revocationSet` with both keys for every
   * revoked entry, so either form resolves correctly.
   */
  isRevoked(nameOrId: string): boolean {
    return this.revocationSet.has(nameOrId);
  }

  /**
   * Return the full revocation detail for a catalog entry, or undefined
   * if the entry is not revoked. Accepts either the `id` slug
   * (federation-layer identifier) or the `name` package identifier
   * (classifier-layer identifier) because `buildIndex()` registers
   * both in `nameIndex` and `revocationSet`. The `reason` and
   * `revokedAt` fields come straight from the catalog entry's
   * `revokedReason` and `revokedAt` columns so consumers
   * (FederationManager, loggers, operator tooling) can surface a
   * specific rejection message.
   */
  getRevocationDetails(nameOrId: string): { revoked: true; revokedAt?: string; reason?: string } | undefined {
    if (!this.revocationSet.has(nameOrId)) return undefined;
    const entry = this.nameIndex.get(nameOrId);
    return {
      revoked: true,
      revokedAt: entry?.revokedAt,
      reason: entry?.revokedReason,
    };
  }

  get size(): number {
    return this.entries_.length;
  }

  // ---------------------------------------------------------------------------
  // Refresh (signed registry)
  // ---------------------------------------------------------------------------

  /**
   * Start the signed-catalog refresh loop.
   *
   * Requires `source: 'registry'` and a `registryUrl`. Polls on a
   * configurable interval (default 1 hour). Every refresh calls
   * `loadFromRegistry()` which in 1.3.0+ enforces the catalog-signature
   * header check against the bundled (or caller-supplied) public key.
   *
   * Semantics:
   *   - In-flight guard: if a refresh tick fires while the previous
   *     tick is still running (slow network, slow verify), the new
   *     tick is skipped rather than overlapping. This prevents two
   *     concurrent `setEntries()` rebuilds from racing.
   *   - Failure preserves state: when the fetch or signature check
   *     fails and the bundle fallback ALSO fails to even complete (I/O
   *     error, replay/downgrade rejection), the existing entries stay in
   *     place — a refresh failure never leaves the catalog partially
   *     populated. The one exception is CHARIOT::§5.2::3 (CH-02): if the
   *     bundle fallback itself COMPLETES but its signature is invalid,
   *     that is a confirmed integrity failure on the terminal load path,
   *     and CH-02 ("empty effective catalog, never a partial one") wins —
   *     the catalog goes empty (`state` becomes `invalid`) rather than
   *     continuing to serve a stale-but-formerly-good catalog past a
   *     confirmed signature break.
   *   - `unref()`'d: the refresh timer does not keep the Node event
   *     loop alive. Shutting down the agent without calling
   *     `stopRefresh()` is safe.
   *
   * No-op when source !== 'registry'. Idempotent — calling
   * `startRefresh()` twice in a row is the same as calling it once.
   */
  startRefresh(): void {
    if (this.config.source !== 'registry' || !this.config.registryUrl) return;
    if (this.refreshTimer) return; // idempotent

    const intervalMs = this.config.refreshIntervalMs ?? 3_600_000;
    this.refreshTimer = setInterval(() => {
      if (this.refreshInFlight) {
        log.warn('adapter-catalog.refresh.skipped_overlapping');
        return;
      }
      this.refreshInFlight = true;
      this.loadFromRegistry()
        .then((entries) => {
          this.buildIndex(entries);
          log.info('adapter-catalog.refresh.success', {
            entries: entries.length,
            keyId: this.verifyEnabled ? this.acceptedKeys[0]?.id ?? 'unknown' : 'disabled',
          });
        })
        .catch(async (err) => {
          log.error('adapter-catalog.refresh.failed', {
            error: String(err),
            note: 'falling back to bundle catalog',
          });
          // CHARIOT::§5.4::5 — "SHALL fall back to bundle when refresh
          // fails." Retaining the stale in-memory catalog (the prior
          // behavior here) is not a bundle fallback; read
          // chariot-adapter-bundle.json and rebuild the index from it. If
          // the bundle read throws (I/O error, replay/downgrade — NOT a
          // signature failure, which `loadFromBundle` now resolves rather
          // than throws), preserve the invariant above by retaining
          // current in-memory state. If the bundle fallback instead
          // COMPLETES with an invalid signature, `loadFromBundle` already
          // set `state` to `invalid` and returned `[]`; `buildIndex([])`
          // below then correctly empties the catalog per CH-02.
          try {
            const bundleEntries = await this.loadFromBundle();
            this.buildIndex(bundleEntries);
            log.info('adapter-catalog.refresh.bundle_fallback_success', {
              entries: bundleEntries.length,
            });
          } catch (bundleErr) {
            log.error('adapter-catalog.refresh.bundle_fallback_failed', {
              error: String(bundleErr),
              note: 'retaining current catalog — previous entries remain in effect',
            });
          }
        })
        .finally(() => {
          this.refreshInFlight = false;
        });
    }, intervalMs);

    if (this.refreshTimer && typeof this.refreshTimer === 'object' && 'unref' in this.refreshTimer) {
      this.refreshTimer.unref();
    }

    log.info('adapter-catalog.refresh.started', {
      intervalMs,
      url: this.config.registryUrl,
      verify: this.verifyEnabled,
    });
  }

  stopRefresh(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
      log.info('adapter-catalog.refresh.stopped');
    }
  }
}
