/**
 * Enterprise Bootstrap — Single entry point for all enterprise startup validation.
 *
 *
 * Validates all required secrets, backing services, and native binary before
 * any enterprise routes are mounted. Fails fast with explicit error messages.
 *
 * Call `bootstrapEnterprise()` once at application startup. If it throws,
 * enterprise mode is not available and multi-user routes must not be mounted.
 */

import type { RedisClientType } from 'redis';
import { MongoClient, type Db } from 'mongodb';
import { loadNativeBinding } from '../license/binding.js';
import { validateLicense, isEnterpriseEnvEnabled, type LicenseInfo } from '../license/loader.js';
import { checkoutEntitlementAtBoot, checkInEntitlement } from '../license/license-manager.js';
import { ensureEnterpriseIndexes } from './indexes.js';
import { setMongoClient } from './db.js';
import { setRedisClient as setRedisGlobal } from './redis.js';
import { setRedisClient as setRedisSession, setSessionRedisDegraded, validateEnterpriseJwtSecret } from './services/session.js';
// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)
import { validateMasterKey } from './crypto.js';
import { createLogger } from '../engine/logger.js';
import { resolveEnterpriseRedisClient } from './resolveEnterpriseRedis.js';
// CHARIOT::§16.1 Operational (rulings item 91/105) — direct import,
// matching this repo's established pattern.
import { chariotEmitter } from '../observability/emitter.js';
import { redactConnectionString } from './redactConnectionString.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('iam.bootstrap');

// ── Types ─────────────────────────────────────────────────────────────────

export interface EnterpriseConfig {
  jwtSecret: string;
  masterKey: string;
  mongoUri: string;
  mongoDb: string;
  // CHARIOT::§18.2::2 — Redis is optional in enterprise mode ("optionally
  // uses Redis (in-process fallback if absent)"); `undefined` means the
  // in-process shim is active rather than a real REDIS_URL.
  redisUrl: string | undefined;
  redisMode: 'external' | 'in-process-shim';
  license: LicenseInfo;
  nativeBinaryAvailable: boolean;
}

export interface BootstrapResult {
  config: EnterpriseConfig;
  mongoClient: MongoClient;
  db: Db;
  redisClient: RedisClientType;
  /**
   * AWS License Manager consumption token (CH-24). Present only in License
   * Manager mode; `undefined` on the offline Ed25519 path. Returned so an
   * explicit caller can CheckIn at graceful shutdown; bootstrap also registers
   * a best-effort signal-handler check-in.
   */
  licenseConsumptionToken?: string;
}

// ── Validation ────────────────────────────────────────────────────────────

function requireEnv(name: string, description: string): string {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(
      `Enterprise startup failed: ${name} is not set. ${description}`
    );
  }
  if (isWeakSecret(value)) {
    throw new Error(
      `Enterprise startup failed: ${name} is set to an insecure default ("${value}"). ` +
      `Set a real value before starting enterprise mode.`
    );
  }
  if (value.length < 16) {
    throw new Error(
      `Enterprise startup failed: ${name} is too short (${value.length} chars). ` +
      `Require at least 16 characters of high-entropy random data.`
    );
  }
  return value;
}

/**
 * CHARIOT::§20::4 — "ENTERPRISE_JWT_SECRET values shorter than 32 characters
 * SHALL be rejected at startup." (CHARIOT-SPEC.md:1535: "values shorter than
 * 32 chars are rejected"; :988: "the session module ... additionally rejects
 * ... any value shorter than 32 characters.")
 *
 * requireEnv()'s generic floor above (16 chars) is shared with
 * ENTERPRISE_MASTER_KEY, MONGODB_URI, and REDIS_URL — none of which carry a
 * 32-char clause — so it cannot enforce the JWT-secret-specific floor on its
 * own; a 16-31 char secret would pass requireEnv() and reach the mounted
 * IAM routes. Delegates to session.ts's validateEnterpriseJwtSecret(),
 * already boundary-tested at 31/32 chars in
 * session.insecure-jwt-secret.test.ts, so bootstrap and the per-request
 * signing path (session.ts getJwtSecret(), called on every issueToken()/
 * verifyToken()) share one source of truth and can never diverge on the
 * floor value.
 *
 * Exported (rather than inlined at the call site) so this integration seam
 * is directly unit-testable: the rest of bootstrapEnterprise() additionally
 * requires a loadable native binary plus reachable MongoDB/Redis, none of
 * which this call depends on.
 */
export function enforceJwtSecretLengthFloor(): void {
  validateEnterpriseJwtSecret();
}

/**
 * CHARIOT::§18.3::1 — "IF the master key is missing in enterprise mode THEN
 * the system SHALL fail-fast at startup (CH-19)." (CHARIOT-SPEC.md:1472)
 *
 * Wraps crypto.ts's validateMasterKey() (the single source of truth for
 * "is ENTERPRISE_MASTER_KEY present/well-formed", already exercised by
 * every credential-vault call site) with the "Enterprise startup failed:
 * ..." message prefix requireEnv() uses above, so every enterprise-startup
 * fail-fast path (bootstrapEnterprise() below AND `chariot serve --http`'s
 * own enterprise bootstrap in engine/bin/setup.ts, which does not call
 * bootstrapEnterprise()) reports this failure class identically.
 *
 * Exported/extracted (mirroring enforceJwtSecretLengthFloor() above) so
 * this seam is directly unit-testable: it depends only on
 * process.env.ENTERPRISE_MASTER_KEY, not on a loadable native binary or
 * reachable MongoDB/Redis, none of which bootstrapEnterprise() as a whole
 * can exercise in this sandbox (see bootstrap.jwt-secret-floor.test.ts).
 */
export function requireMasterKeyForEnterpriseStartup(): void {
  try {
    validateMasterKey();
  } catch (err) {
    throw new Error(
      `Enterprise startup failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Recognize common insecure-default secrets that operators leave in
 * place after copy-paste setup. Compared case-insensitively. Extended
 * from the original 3-value list so a placeholder cannot
 * boot a production enterprise instance.
 */
function isWeakSecret(value: string): boolean {
  const v = value.trim().toLowerCase();
  return WEAK_SECRETS.has(v);
}

function buildBootstrapLicense(
  checkout: Awaited<ReturnType<typeof checkoutEntitlementAtBoot>>,
): LicenseInfo {
  if (checkout.provider === 'offline-ed25519') {
    return validateLicense();
  }

  const {
    provider: _provider,
    entitlementsAllowed: _entitlementsAllowed,
    consumptionToken: _consumptionToken,
    tier: _tier,
    ...license
  } = checkout;

  return license;
}

function registerLicenseCheckInShutdown(consumptionToken: string): void {
  const handleShutdown = (): void => {
    void (async () => {
      try {
        await checkInEntitlement(consumptionToken);
      } finally {
        process.exit(0);
      }
    })();
  };

  process.once('SIGTERM', handleShutdown);
  process.once('SIGINT', handleShutdown);
}

const WEAK_SECRETS: ReadonlySet<string> = new Set([
  // generic placeholders
  'change-me', 'changeme', 'changeit', 'change_me', 'change',
  'secret', 'mysecret', 'topsecret', 'supersecret',
  'password', 'passwd', 'pwd', 'p@ssword', 'p@ssw0rd',
  'admin', 'administrator', 'root', 'user', 'test', 'demo', 'example',
  'default', 'defaultpassword', 'defaultsecret',
  // doc-template patterns
  'your-secret-here', 'your_secret_here',
  'your-secret', 'your_secret',
  'your-jwt-secret', 'your_jwt_secret',
  'your-api-key', 'your_api_key',
  'replace-me', 'replace_me', 'replaceme',
  'todo', 'fixme', 'tbd',
  'placeholder', 'placeholder-secret',
  // common keyboard patterns
  '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
  'qwerty', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'abc123', 'password1', 'password123',
  // sample / dev tokens that ship in tutorials
  'sample', 'sample-secret', 'sample_secret',
  'dev', 'devsecret', 'dev-secret', 'dev_secret',
  'localhost', 'local',
]);

// ── Bootstrap ─────────────────────────────────────────────────────────────

/**
 * Validate all enterprise dependencies and return the verified configuration.
 *
 * Throws with an explicit message if any requirement is not met.
 * The caller should catch and either:
 * - abort (if enterprise mode was explicitly requested)
 * - fall back to single-user mode (if enterprise was optional)
 */
export async function bootstrapEnterprise(): Promise<BootstrapResult> {
  // ── 1. Native binary (items 10, 11, 12) ──────────────────────────────

  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Enterprise startup failed: native binary not available. ' +
      'Install the matching platform binary for @epicai/chariot to enable enterprise features. ' +
      'Enterprise mode requires the compiled Rust binary for license validation, ' +
      'RBAC, and credential vault operations.'
    );
  }

  // ── 2. Secrets (items 1, 8) ──────────────────────────────────────────

  const jwtSecret = requireEnv(
    'ENTERPRISE_JWT_SECRET',
    'Required for signing enterprise session tokens. ' +
    'Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'base64\'))"'
  );
  // CHARIOT::§20::4
  enforceJwtSecretLengthFloor();

  const masterKey = requireEnv(
    'ENTERPRISE_MASTER_KEY',
    'Required for AES-256-GCM credential vault encryption. ' +
    'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
  );
  // CHARIOT::§18.3::1 — "Master key missing in enterprise mode | Fail-fast
  // at startup (CH-19)." (CHARIOT-SPEC.md:1476) requireEnv() above already
  // fails fast on unset/insecure-default/too-short, but only validateMasterKey()
  // (crypto.ts) proves the value actually decodes to the required 32 AES-256
  // bytes. That deeper check previously ran at step 5, AFTER the MongoDB
  // dial below — a key that passed requireEnv()'s generic floor but failed
  // 32-byte decoding would only surface post-connect, contacting Mongo on a
  // doomed boot. Moved here, before any Mongo/Redis I/O, so "fail-fast at
  // startup" holds for this failure class too.
  validateMasterKey();

  // ── 3. MongoDB (item 9) ──────────────────────────────────────────────

  const mongoUri = requireEnv(
    'MONGODB_URI',
    'Required for enterprise IAM data storage. ' +
    'Example: mongodb://localhost:27017/'
  );

  const mongoDb = process.env.MONGODB_DB || 'chariot';

  let mongoClient!: MongoClient;
  let db!: Db;
  try {
    mongoClient = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });
    await mongoClient.connect();
    db = mongoClient.db(mongoDb);
    // Verify connection by running a ping
    await db.command({ ping: 1 });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    // CHARIOT::§16.1 Operational (CHARIOT-SPEC.md:1353, rulings item
    // 91/105) — unlike Redis (which degrades gracefully), Mongo
    // unreachable at boot is a hard fail-fast (no in-process fallback
    // exists for the IAM store) — emitted BEFORE the throw so the
    // customer-facing event still reaches any subscriber that was wired
    // up earlier in the boot sequence, even though the process aborts
    // enterprise startup immediately after.
    chariotEmitter.send('mongo.unreachable', {
      severity: 'urgent',
      alertWorthy: true,
      data: { mongoUri: redactConnectionString(mongoUri), reason, phase: 'boot' },
    });
    // rulings item 126 (W-IAM-REDACT) — the raw mongoUri (which may carry
    // embedded userinfo) MUST NOT be interpolated into this message: it
    // is a thrown Error, and an uncaught/logged Error.message is exactly
    // the kind of sink the 3.1.1 leak incident named. Redact before
    // interpolating, not after.
    throw new Error(
      `Enterprise startup failed: MongoDB unavailable at ${redactConnectionString(mongoUri)}. ` +
      `Error: ${reason}`
    );
  }

  // Create indexes. Backfill idJagSubIdAliasCanon FIRST so the unique-canon
  // index build validates corrected values (upgrade / format-change safety).
  try {
    const { backfillSubIdAliasCanon } = await import('./services/id-jag-issuer.js');
    await backfillSubIdAliasCanon(db);
    await ensureEnterpriseIndexes(db);
  } catch (err) {
    throw new Error(
      `Enterprise startup failed: could not create MongoDB indexes. ` +
      `Error: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // ── 4. Redis (items 7, 9) ────────────────────────────────────────────
  //
  // CHARIOT::§18.2::2 — "Enterprise mode ... optionally uses Redis
  // (in-process fallback if absent)." (CHARIOT-SPEC.md:1467-1469) REDIS_URL
  // is therefore read directly (never via requireEnv, which would fail-fast
  // on an unset value) — unset/empty means "absent", not misconfigured.
  //
  // CHARIOT::§18.3::4 — resolveEnterpriseRedisClient() also degrades (never
  // throws) when REDIS_URL is SET but unreachable at boot — see that
  // module for the full clause quote and rationale. Shared with
  // engine/bin/setup.ts's enterprise IAM bootstrap so the two
  // enterprise-startup paths cannot diverge on Redis-absent/unreachable
  // semantics, and so this decision is independently unit-testable without
  // the native binary bootstrapEnterprise() as a whole requires.
  const redisUrlRaw = process.env.REDIS_URL;
  const redisUrl = redisUrlRaw && redisUrlRaw.trim() !== '' ? redisUrlRaw : undefined;
  const { redisClient, redisMode, degraded: redisDegraded, reason: redisDegradedReason } = await resolveEnterpriseRedisClient(
    redisUrl,
    (message, data) => moduleLog.warn(`[iam/bootstrap] ${message}`, data),
  );

  // ── 5. (removed — master key now validated at step 2, before any I/O) ──

  // ── 6. Wire up injected clients ─────────────────────────────────────

  setMongoClient(mongoClient, mongoDb);
  setRedisGlobal(redisClient);
  setRedisSession(redisClient);
  // CHARIOT::§18.3 — thread the degrade state into session.ts so
  // verifyToken() knows whether a missing activity key is fail-closed
  // (normal) or ignorable (degraded — see setSessionRedisDegraded()'s doc).
  setSessionRedisDegraded(redisDegraded, redisDegradedReason);

  // ── 7. Entitlement gate (CH-24, items 14, 15) ───────────────────────
  //
  // Offline Ed25519 (default, §11) OR AWS License Manager CheckoutLicense
  // (opt-in via CHARIOT_LICENSE_PROVIDER=aws-license-manager / Marketplace).
  // In LM mode a denied/missing/unavailable entitlement THROWS here, so
  // enterprise boot fails closed exactly like the secret/service checks above.
  const checkout = await checkoutEntitlementAtBoot();
  const license = buildBootstrapLicense(checkout);
  const licenseConsumptionToken = checkout.consumptionToken;

  // CH-24: return the consumed entitlement to License Manager at graceful
  // shutdown (best-effort; provisional tokens expire on their own, and
  // checkInEntitlement is a no-op off the LM path). Wired here so every
  // enterprise boot path gets check-in without extra caller code; the token
  // is also returned for an explicit shutdown sequence.
  if (licenseConsumptionToken) {
    registerLicenseCheckInShutdown(licenseConsumptionToken);
  }

  // ── 8. Assemble config ──────────────────────────────────────────────

  const config: EnterpriseConfig = {
    jwtSecret,
    masterKey,
    mongoUri,
    mongoDb,
    redisUrl,
    redisMode,
    license,
    nativeBinaryAvailable: true,
  };

  return { config, mongoClient, db, redisClient, licenseConsumptionToken };
}

/**
 * CHARIOT::§18.2::1/2 — mode selection is CHARIOT_ENTERPRISE alone:
 * "Single-user mode: `npx @epicai/chariot` with no `CHARIOT_ENTERPRISE=1`."
 * / "Enterprise mode: `CHARIOT_ENTERPRISE=1 npx @epicai/chariot`."
 * (CHARIOT-SPEC.md:1465, 1467). Native-binary presence is NOT a mode
 * trigger under the clause — a host that happens to have the compiled
 * binary installed (e.g. `chariot health`, dev machines) must still boot
 * single-user with no IAM/Mongo/Redis requirement absent the flag. Prior
 * to this fix, `binding !== null` alone flipped this to `true`, which
 * would have caused a caller gating on this function to demand IAM/Mongo
 * on every host with the native binary present, contradicting §18.2::1's
 * "no CHARIOT_ENTERPRISE=1" single-user case. loadNativeBinding() import
 * kept only for isEnterpriseEnvEnabled's own binary-mismatch check
 * upstream in license/loader.ts; this function no longer consults it.
 */
export function isEnterpriseModeRequested(): boolean {
  return isEnterpriseEnvEnabled();
}
