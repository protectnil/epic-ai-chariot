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
import { verify as cryptoVerify } from 'node:crypto';
import { createLogger } from '../logger.js';
import {
  CHARIOT_CATALOG_PUBLIC_KEYS,
  type ChariotCatalogPublicKey,
} from '../keys/chariot-catalog-public.js';
import { ARTIFACT_LIMITS } from '../keys/artifact-limits.js';
import { resolvePublishedArtifactDir } from './artifact-publication.js';
import { stripInvisibleChars } from '../persona/injection-defense.js';

const log = createLogger('federation.catalog');

// =============================================================================
// Types
// =============================================================================

export type AdapterCategory =
  | 'cybersecurity' | 'cloud' | 'devops' | 'data' | 'collaboration'
  | 'crm' | 'commerce' | 'observability' | 'communication' | 'ai-ml'
  | 'identity' | 'compliance' | 'finance' | 'social' | 'misc';

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
    const parsed = JSON.parse(raw) as { epoch?: unknown; catalogVersion?: unknown };
    if (!Number.isInteger(parsed.epoch) || !Number.isInteger(parsed.catalogVersion)) {
      log.warn('adapter-catalog.persisted_epoch_malformed', { epochPath, raw });
      return null;
    }
    return {
      epoch: parsed.epoch as number,
      catalogVersion: parsed.catalogVersion as number,
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
  const body = JSON.stringify({ epoch: state.epoch, catalogVersion: state.catalogVersion }) + '\n';
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
 * BEFORE JSON.parse runs. 64 MB is well above the largest known
 * production bundle (~5 MB at 4,000+ adapters) and bounds memory +
 * parse cost on a hostile input. Rejects oversized payloads at the
 * envelope before any structural recursion happens.
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
   * Ed25519 public keys accepted for catalog signature verification. A
   * caller-supplied `publicKeyPem` collapses this to one entry; the
   * default uses the bundled multi-key array so a rotation overlap
   * accepts both old and new signing keys.
   */
  private readonly acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey>;

  constructor(config: CatalogSourceConfig) {
    this.config = config;
    this.verifyEnabled = config.verifySignature !== false;
    this.acceptedKeys = config.publicKeyPem
      ? [{ id: 'caller-supplied', pem: config.publicKeyPem }]
      : CHARIOT_CATALOG_PUBLIC_KEYS;

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
      raw = await this.loadFromRegistry();
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
   * (epoch <= persisted), or downgrade (catalogVersion < persisted).
   * On accept, persists the new pair BEFORE returning so a subsequent
   * load in the same process sees the bumped baseline.
   */
  private async enforceMonotonicityAndPersist(parsed: unknown, source: 'bundle' | 'registry'): Promise<void> {
    const envelope = extractEnvelopeMonotonicity(parsed);
    const store = await this.resolveEpochStore();
    // EFFICIENCY #11 — in-process cache short-circuits a store read for
    // back-to-back loads in the same instance. The cache reflects the
    // last value THIS instance accepted; for cross-instance correctness
    // the store itself is consulted on first load and any path where the
    // cache was reset.
    const persisted = this._lastAcceptedEpoch ?? (await store.load());
    const epochPath = this.resolveEpochPath();

    if (persisted !== null) {
      if (envelope.epoch <= persisted.epoch) {
        throw new CatalogIntegrityError(
          `adapter-catalog bundle epoch ${envelope.epoch} is not strictly greater than ` +
            `persisted epoch ${persisted.epoch} — refusing replay/rollback`,
          {
            envelopeEpoch: envelope.epoch,
            persistedEpoch: persisted.epoch,
            source,
            epochStore: store.describe(),
          },
        );
      }
      if (envelope.catalogVersion < persisted.catalogVersion) {
        throw new CatalogIntegrityError(
          `adapter-catalog bundle catalogVersion ${envelope.catalogVersion} is less than ` +
            `persisted catalogVersion ${persisted.catalogVersion} — refusing downgrade`,
          {
            envelopeCatalogVersion: envelope.catalogVersion,
            persistedCatalogVersion: persisted.catalogVersion,
            source,
            epochStore: store.describe(),
          },
        );
      }
    }

    await store.persist(envelope);
    // EFFICIENCY #11: update the in-process cache so subsequent loads in
    // the same process lifetime skip the disk read.
    this._lastAcceptedEpoch = envelope;
    log.info('adapter-catalog.envelope_accepted', {
      source,
      epoch: envelope.epoch,
      catalogVersion: envelope.catalogVersion,
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
      if (this.verifyEnabled) {
        if (!existsSync(sigPath)) {
          throw new Error(
            'adapter-catalog.json.sig not found alongside adapter-catalog.json. ' +
              'Chariot requires a signed bundled catalog by default. ' +
              'Either reinstall @epicai/chariot (which ships a signed .sig), ' +
              're-sign your custom catalog with scripts/sign-catalog.mjs, ' +
              'or explicitly set verifySignature: false in CatalogSourceConfig ' +
              'to opt out (not recommended — see SECURITY.md).',
          );
        }
        const sigB64 = readFileSync(sigPath, 'utf-8').trim();
        const verifyResult = this.verifyAgainstAnyKey(catalogBytes, sigB64);
        if (!verifyResult.matched) {
          const acceptedIds = this.acceptedKeys.map((k) => k.id).join(', ');
          throw new Error(
            'adapter-catalog.json signature verification failed. ' +
              'The bundled catalog bytes do not match the detached signature ' +
              `against any accepted key. Tried: ${acceptedIds}. ` +
              'This indicates either catalog tampering or a key mismatch — ' +
              'do not proceed without investigating. See SECURITY.md.',
          );
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
      // never reaches the index. Persists on accept.
      await this.enforceMonotonicityAndPersist(parsed, 'bundle');
      return unpackCatalogPayload(parsed);
    } catch (err) {
      log.error('loadFromBundle failed', { error: String(err) });
      throw err;
    }
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
      // a previously-bundled catalog is also rejected.
      await this.enforceMonotonicityAndPersist(entries, 'registry');
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
    // Clear all indexes — atomic replace.
    this.categoryIndex.clear();
    this.keywordIndex.clear();
    this.nameIndex.clear();
    this.revocationSet.clear();

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
      this.nameIndex.set(entry.name, entry);

      if (entry.id && entry.id !== entry.name) {
        if (seenIds.has(entry.id)) {
          throw new CatalogIntegrityError(
            `adapter id collision on "${entry.id}" — duplicate id slug in catalog bundle`,
            { collidingKey: entry.id, kind: 'id' },
          );
        }
        seenIds.add(entry.id);
        this.nameIndex.set(entry.id, entry);
      }

      // Category index
      if (!this.categoryIndex.has(entry.category)) {
        this.categoryIndex.set(entry.category, []);
      }
      const catList = this.categoryIndex.get(entry.category);
      if (!catList) throw new Error(`invariant: category ${entry.category} missing from index`);
      catList.push(entry);

      // Keyword index: token → set of adapter names
      for (const keyword of entry.keywords) {
        const lower = keyword.toLowerCase();
        if (!this.keywordIndex.has(lower)) {
          this.keywordIndex.set(lower, new Set());
        }
        const kwSet = this.keywordIndex.get(lower);
        if (!kwSet) throw new Error(`invariant: keyword ${lower} missing from index`);
        kwSet.add(entry.name);
      }

      // Tool name index: treat tool names as keywords too
      for (const toolName of entry.toolNames) {
        const lower = toolName.toLowerCase();
        if (!this.keywordIndex.has(lower)) {
          this.keywordIndex.set(lower, new Set());
        }
        const tnSet = this.keywordIndex.get(lower);
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
        this.revocationSet.add(entry.name);
        if (entry.id) {
          this.revocationSet.add(entry.id);
        }
      }

      sanitizedEntries.push(entry);
    }

    // Replace `entries_` with the sanitized + filtered list so
    // `entries()` and `size` reflect what was actually indexed, not
    // what was offered. Callers querying the catalog see ONLY clean,
    // schema-valid entries — never raw bundle data.
    this.entries_ = sanitizedEntries;
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
   *     fails, the existing entries stay in place. A refresh failure
   *     NEVER leaves the catalog empty or partially populated.
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
        .catch((err) => {
          log.error('adapter-catalog.refresh.failed', {
            error: String(err),
            note: 'retaining current catalog — previous entries remain in effect',
          });
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
