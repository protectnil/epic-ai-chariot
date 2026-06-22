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

import { createClient, type RedisClientType } from 'redis';
import { MongoClient, type Db } from 'mongodb';
import { loadNativeBinding } from '../license/binding.js';
import { validateLicense, type LicenseInfo } from '../license/loader.js';
import { ensureEnterpriseIndexes } from './indexes.js';
import { setMongoClient } from './db.js';
import { setRedisClient as setRedisGlobal } from './redis.js';
import { setRedisClient as setRedisSession } from './services/session.js';
import { validateMasterKey } from './crypto.js';

// ── Types ─────────────────────────────────────────────────────────────────

export interface EnterpriseConfig {
  jwtSecret: string;
  masterKey: string;
  mongoUri: string;
  mongoDb: string;
  redisUrl: string;
  license: LicenseInfo;
  nativeBinaryAvailable: boolean;
}

export interface BootstrapResult {
  config: EnterpriseConfig;
  mongoClient: MongoClient;
  db: Db;
  redisClient: RedisClientType;
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
 * Recognize common insecure-default secrets that operators leave in
 * place after copy-paste setup. Compared case-insensitively. Extended
 * from the original 3-value list so a placeholder cannot
 * boot a production enterprise instance.
 */
function isWeakSecret(value: string): boolean {
  const v = value.trim().toLowerCase();
  return WEAK_SECRETS.has(v);
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

  const masterKey = requireEnv(
    'ENTERPRISE_MASTER_KEY',
    'Required for AES-256-GCM credential vault encryption. ' +
    'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
  );

  // ── 3. MongoDB (item 9) ──────────────────────────────────────────────

  const mongoUri = requireEnv(
    'MONGODB_URI',
    'Required for enterprise IAM data storage. ' +
    'Example: mongodb://localhost:27017/'
  );

  const mongoDb = process.env.MONGODB_DB || 'epicai';

  let mongoClient!: MongoClient;
  let db!: Db;
  try {
    mongoClient = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });
    await mongoClient.connect();
    db = mongoClient.db(mongoDb);
    // Verify connection by running a ping
    await db.command({ ping: 1 });
  } catch (err) {
    throw new Error(
      `Enterprise startup failed: MongoDB unavailable at ${mongoUri}. ` +
      `Error: ${err instanceof Error ? err.message : String(err)}`
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

  const redisUrl = requireEnv(
    'REDIS_URL',
    'Required for enterprise session management and revocation. ' +
    'Example: redis://localhost:6379'
  );

  let redisClient: RedisClientType;
  try {
    redisClient = createClient({ url: redisUrl }) as RedisClientType;
    // The 'error' event handler is required to prevent unhandled exceptions
    // from taking down the process. Startup connection failures still throw
    // from `connect()` below and are caught by the outer try/catch.
    //
    // Runtime errors AFTER successful connect (cluster failover, TLS hiccups,
    // auth expiry, network partitions) ARE surfaced here — they were
    // previously silently swallowed, which hid operational problems. The
    // handler logs with a stable prefix so operators can grep for it, and
    // does NOT re-throw: a runtime Redis error must not crash the enterprise
    // process, only make itself visible.
    redisClient.on('error', (err: unknown) => {
       
      console.error('[iam/bootstrap] redis runtime error', err);
    });
    await redisClient.connect();
    // Verify connection
    await redisClient.ping();
  } catch (err) {
    throw new Error(
      `Enterprise startup failed: Redis unavailable at ${redisUrl}. ` +
      `Error: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // ── 5. Validate master key eagerly (item 8) ──────────────────────────

  validateMasterKey();

  // ── 6. Wire up injected clients ─────────────────────────────────────

  setMongoClient(mongoClient, mongoDb);
  setRedisGlobal(redisClient);
  setRedisSession(redisClient);

  // ── 7. License check (items 14, 15) ─────────────────────────────────

  const license = validateLicense();

  // ── 8. Assemble config ──────────────────────────────────────────────

  const config: EnterpriseConfig = {
    jwtSecret,
    masterKey,
    mongoUri,
    mongoDb,
    redisUrl,
    license,
    nativeBinaryAvailable: true,
  };

  return { config, mongoClient, db, redisClient };
}

/**
 * Check if enterprise mode is explicitly requested.
 * Enterprise mode is active when:
 * - CHARIOT_ENTERPRISE=true is set, OR
 * - the native binary is present
 */
export function isEnterpriseModeRequested(): boolean {
  if (process.env.CHARIOT_ENTERPRISE === 'true') return true;
  const binding = loadNativeBinding();
  return binding !== null;
}
