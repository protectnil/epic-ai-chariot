/**
 * @epicai/chariot — AWS License Manager entitlement gate (CH-24)
 *
 * Boot-time entitlement check for the AWS Marketplace Container product
 * (CH-24 — CHARIOT::§23.2::21 Container product with Contract Pricing,
 * CHARIOT::§23.2::23 License Manager `CheckoutLicense` gates entitlement at
 * boot; listing economics in §23.1). When Chariot is deployed from the Marketplace
 * listing it calls AWS License Manager `CheckoutLicense` once at gateway
 * boot to prove the buyer holds a current entitlement, and maps the
 * granted entitlements onto the Basic / Intermediate / Premium tier +
 * seat model (§10 IAM seat reservation).
 *
 * Two invariants from §23:
 *   1. License Manager is opt-in. The offline Ed25519 license path
 *      (`./loader.ts`, §11) stays the DEFAULT for every non-Marketplace
 *      and air-gapped deployment. The LM path activates ONLY under the
 *      explicit `CHARIOT_LICENSE_PROVIDER=aws-license-manager` flag
 *      (CH-24: "offline Ed25519 stays default off-Marketplace").
 *   2. No baked AWS credentials (CH-25). This module never reads or
 *      forwards `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`; the SDK
 *      client resolves credentials from the ambient default provider
 *      chain, which on EKS is IRSA (web-identity token file) and on ECS
 *      is the task role. The container ships zero static keys.
 *
 * Fail-closed: in LM mode a missing/denied/unavailable entitlement (or a
 * missing SDK) ABORTS boot by throwing. Entitlement is a customer-facing
 * gate, so it follows the same fail-fast posture as
 * `src/iam/bootstrap.ts` rather than degrading silently.
 *
 * Writers: the consumption-token cache targets the mounted writable
 * volume via `EPIC_AI_DIR_OVERRIDE` (CH-30), mirroring `src/cli/paths.ts`.
 *
 * The actual `@aws-sdk/client-license-manager` dependency is added at the
 * 4.0.0 Marketplace cut (§23.5 "not yet in source"); it is loaded with a
 * dynamic, non-literal specifier so the offline build neither requires
 * nor bundles it. A `LicenseManagerClientLike` seam lets tests inject a
 * fake client with no AWS calls.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { validateLicense, type LicenseInfo, type LicenseMode } from './loader.js';
import { createLogger } from '../engine/logger.js';

// Production logging goes through the project logger (never console.*).
const moduleLog = createLogger('license.manager');

// ── Provider + tier model ──────────────────────────────────────────────────

/** Where entitlement comes from. Offline Ed25519 is the default (§11). */
export type LicenseProvider = 'offline-ed25519' | 'aws-license-manager';

/** Chariot entitlement tiers (§10 / §23.1). Ordered low → high. */
export type LicenseTier = 'basic' | 'intermediate' | 'premium';

const TIER_RANK: Record<LicenseTier, number> = { basic: 1, intermediate: 2, premium: 3 };

/**
 * Canonical entitlement names checked out from License Manager, one per
 * tier plus the seat-count dimension. The Marketplace listing defines
 * these as the product's entitlement/dimension keys; the operator can
 * override them per-listing via env without a code change.
 */
const DEFAULT_TIER_ENTITLEMENT_PREFIX = 'chariot:tier:';
const DEFAULT_SEATS_ENTITLEMENT = 'chariot:seats';

/**
 * AWS Marketplace's well-known license issuer fingerprint. Every
 * Marketplace-issued entitlement is signed by this issuer; the default
 * is the published constant and is overridable for non-Marketplace
 * License Manager grants.
 */
const AWS_MARKETPLACE_KEY_FINGERPRINT = 'aws:294406891311:AWS/Marketplace:issuer-fingerprint';

// ── Result shape ────────────────────────────────────────────────────────────

/**
 * Outcome of the boot entitlement check. A superset of `LicenseInfo`
 * (so existing callers keep working) plus the LM-specific fields. In LM
 * mode a non-valid result is never returned — failure throws (fail
 * closed) — so `valid` is always `true` on the LM return path.
 */
export interface EntitlementCheckout {
  valid: boolean;
  provider: LicenseProvider;
  mode: LicenseMode;
  tier?: LicenseTier;
  totalSeats?: number;
  entitlementsAllowed?: string[];
  consumptionToken?: string;
  expiresAt?: string;
  reason?: string;
}

// ── License Manager client seam ─────────────────────────────────────────────
//
// Minimal structural typing of just the `CheckoutLicense` / `CheckInLicense`
// surface we use. Declaring it here (rather than importing AWS SDK types)
// keeps the offline build free of the SDK and lets tests inject a fake.

export interface CheckoutEntitlementData {
  Name: string;
  Unit: string;
  Value?: string;
}

export interface CheckoutLicenseInput {
  CheckoutType: 'PROVISIONAL' | 'PERPETUAL';
  ClientToken: string;
  Entitlements: CheckoutEntitlementData[];
  KeyFingerprint: string;
  ProductSKU: string;
  Beneficiary?: string;
  NodeId?: string;
}

export interface CheckoutLicenseOutput {
  CheckoutType?: string;
  EntitlementsAllowed?: CheckoutEntitlementData[];
  Expiration?: string;
  LicenseConsumptionToken?: string;
  SignedToken?: string;
  NodeId?: string;
  IssuedAt?: string;
}

export interface LicenseManagerClientLike {
  checkoutLicense(input: CheckoutLicenseInput): Promise<CheckoutLicenseOutput>;
  checkInLicense(consumptionToken: string): Promise<void>;
}

// ── Config resolution (fail-closed on missing required) ─────────────────────

export interface LicenseManagerConfig {
  productSKU: string;
  keyFingerprint: string;
  region: string;
  tier: LicenseTier;
  seats?: number;
  checkoutType: 'PROVISIONAL' | 'PERPETUAL';
  beneficiary?: string;
  nodeId?: string;
  tierEntitlementName: string;
  seatsEntitlementName: string;
}

type Env = NodeJS.ProcessEnv;

function requireLmEnv(env: Env, name: string, description: string): string {
  const value = env[name];
  if (!value || value.trim() === '') {
    throw new Error(
      `License Manager entitlement check failed: ${name} is not set. ${description}`,
    );
  }
  return value.trim();
}

function parseTier(raw: string): LicenseTier {
  const v = raw.trim().toLowerCase();
  if (v === 'basic' || v === 'intermediate' || v === 'premium') return v;
  throw new Error(
    `License Manager entitlement check failed: CHARIOT_LM_TIER="${raw}" is not a valid tier. ` +
      `Expected one of: basic, intermediate, premium.`,
  );
}

/**
 * Select the active license provider. Default is offline Ed25519; the
 * AWS License Manager path is opt-in only (CH-24). Accepts the explicit
 * `CHARIOT_LICENSE_PROVIDER` value or the `CHARIOT_AWS_LICENSE_MANAGER`
 * boolean convenience flag.
 */
export function selectedLicenseProvider(env: Env = process.env): LicenseProvider {
  const explicit = (env.CHARIOT_LICENSE_PROVIDER ?? '').trim().toLowerCase();
  if (explicit === 'aws-license-manager') return 'aws-license-manager';
  if (explicit === 'offline-ed25519' || explicit === 'offline') return 'offline-ed25519';
  const bool = (env.CHARIOT_AWS_LICENSE_MANAGER ?? '').trim().toLowerCase();
  if (bool === 'true' || bool === '1') return 'aws-license-manager';
  return 'offline-ed25519';
}

/** Convenience predicate for the LM path being active. */
export function isLicenseManagerMode(env: Env = process.env): boolean {
  return selectedLicenseProvider(env) === 'aws-license-manager';
}

/**
 * Read + validate the LM configuration from the environment. Throws
 * (fail closed) when a required value is missing or malformed. Only
 * called on the LM path, so offline deployments never need these vars.
 */
export function resolveLicenseManagerConfig(env: Env = process.env): LicenseManagerConfig {
  const productSKU = requireLmEnv(
    env,
    'CHARIOT_LM_PRODUCT_SKU',
    'Required: the AWS Marketplace product SKU / License Manager license ARN for the Chariot listing.',
  );
  const region = (env.AWS_REGION ?? env.AWS_DEFAULT_REGION ?? '').trim();
  if (!region) {
    throw new Error(
      'License Manager entitlement check failed: AWS_REGION (or AWS_DEFAULT_REGION) is not set. ' +
        'The License Manager client requires a region; on EKS/ECS this is injected by the platform.',
    );
  }
  const tier = parseTier(
    requireLmEnv(
      env,
      'CHARIOT_LM_TIER',
      'Required: the purchased entitlement tier (basic | intermediate | premium).',
    ),
  );

  let seats: number | undefined;
  const seatsRaw = (env.CHARIOT_LM_SEATS ?? '').trim();
  if (seatsRaw) {
    const n = Number.parseInt(seatsRaw, 10);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(
        `License Manager entitlement check failed: CHARIOT_LM_SEATS="${seatsRaw}" must be a positive integer.`,
      );
    }
    seats = n;
  }

  const checkoutRaw = (env.CHARIOT_LM_CHECKOUT_TYPE ?? 'PROVISIONAL').trim().toUpperCase();
  if (checkoutRaw !== 'PROVISIONAL' && checkoutRaw !== 'PERPETUAL') {
    throw new Error(
      `License Manager entitlement check failed: CHARIOT_LM_CHECKOUT_TYPE="${checkoutRaw}" must be PROVISIONAL or PERPETUAL.`,
    );
  }

  return {
    productSKU,
    keyFingerprint: (env.CHARIOT_LM_KEY_FINGERPRINT ?? AWS_MARKETPLACE_KEY_FINGERPRINT).trim(),
    region,
    tier,
    seats,
    checkoutType: checkoutRaw,
    beneficiary: (env.CHARIOT_LM_BENEFICIARY ?? '').trim() || undefined,
    nodeId: (env.CHARIOT_LM_NODE_ID ?? '').trim() || undefined,
    tierEntitlementName:
      (env.CHARIOT_LM_TIER_ENTITLEMENT ?? '').trim() ||
      `${DEFAULT_TIER_ENTITLEMENT_PREFIX}${tier}`,
    seatsEntitlementName: (env.CHARIOT_LM_SEATS_ENTITLEMENT ?? '').trim() || DEFAULT_SEATS_ENTITLEMENT,
  };
}

// ── SDK loader (dynamic, optional dependency) ───────────────────────────────
//
// `@aws-sdk/client-license-manager` is a 4.0.0 Marketplace-cut dependency
// (§23.5). The specifier is typed `string` so the TypeScript compiler does
// not statically resolve it — the offline build neither requires nor emits
// a static import of the SDK. If the LM path is requested but the SDK is
// absent, loading fails closed.

interface AwsLicenseManagerSdk {
  LicenseManagerClient: new (cfg: { region: string }) => {
    send(command: unknown): Promise<unknown>;
  };
  CheckoutLicenseCommand: new (input: CheckoutLicenseInput) => unknown;
  CheckInLicenseCommand: new (input: { LicenseConsumptionToken: string }) => unknown;
}

const SDK_MODULE_ID: string = '@aws-sdk/client-license-manager';

async function loadLicenseManagerSdkClient(region: string): Promise<LicenseManagerClientLike> {
  let sdk: AwsLicenseManagerSdk;
  try {
    sdk = (await import(SDK_MODULE_ID)) as unknown as AwsLicenseManagerSdk;
  } catch (err) {
    throw new Error(
      'License Manager entitlement check failed: the AWS License Manager SDK ' +
        '(@aws-sdk/client-license-manager) is not installed. It is required when ' +
        'CHARIOT_LICENSE_PROVIDER=aws-license-manager. ' +
        `Underlying error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  // No credentials are passed: the SDK resolves them from the ambient
  // default provider chain (IRSA on EKS, task role on ECS) per CH-25.
  const client = new sdk.LicenseManagerClient({ region });
  return {
    checkoutLicense: async (input) =>
      (await client.send(new sdk.CheckoutLicenseCommand(input))) as CheckoutLicenseOutput,
    checkInLicense: async (consumptionToken) => {
      await client.send(new sdk.CheckInLicenseCommand({ LicenseConsumptionToken: consumptionToken }));
    },
  };
}

// ── Retry classification ────────────────────────────────────────────────────
//
// CheckoutLicense throttling / transient service errors are retried with
// bounded exponential backoff before failing closed, so a momentary
// control-plane blip does not abort an otherwise-entitled boot.

const RETRYABLE_ERROR_NAMES: ReadonlySet<string> = new Set([
  'RateLimitExceededException',
  'ThrottlingException',
  'ServerInternalException',
  'ServiceUnavailableException',
  'TimeoutError',
  'RequestTimeout',
  'RequestTimeoutException',
]);

function isRetryable(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { name?: string; $retryable?: { throttling?: boolean } };
  if (e.name && RETRYABLE_ERROR_NAMES.has(e.name)) return true;
  return Boolean(e.$retryable);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Writable-volume consumption-token cache (CH-30) ─────────────────────────

/** Chariot home, honoring EPIC_AI_DIR_OVERRIDE (mirrors src/cli/paths.ts). */
function chariotDataDir(env: Env): string {
  return env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai');
}

/**
 * Cache the consumption token + granted entitlements to the mounted
 * writable volume. Best-effort: a write failure is logged but does not
 * fail the (already valid) checkout — the entitlement came from the live
 * CheckoutLicense response, not from this file.
 */
function persistConsumptionToken(checkout: EntitlementCheckout, env: Env): void {
  try {
    const dir = join(chariotDataDir(env), 'state');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const path = join(dir, 'lm-consumption.json');
    const tmp = `${path}.tmp`;
    const body = JSON.stringify(
      {
        provider: checkout.provider,
        tier: checkout.tier,
        totalSeats: checkout.totalSeats,
        entitlementsAllowed: checkout.entitlementsAllowed,
        consumptionToken: checkout.consumptionToken,
        expiresAt: checkout.expiresAt,
        cachedAt: new Date().toISOString(),
      },
      null,
      2,
    );
    writeFileSync(tmp, body, { encoding: 'utf-8', mode: 0o600 });
    renameSync(tmp, path);
  } catch (err) {
    moduleLog.warn(
      `[license/license-manager] could not cache consumption token to writable volume: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// ── Entitlement → tier mapping ──────────────────────────────────────────────

/**
 * Resolve the highest tier present in the granted entitlement set. The
 * configured `tierEntitlementName` is matched first; we also recognize
 * the canonical `chariot:tier:<tier>` form so a listing that grants a
 * higher tier than requested is honored at the higher level.
 */
function grantedTier(allowed: string[], cfg: LicenseManagerConfig): LicenseTier | undefined {
  let best: LicenseTier | undefined;
  for (const name of allowed) {
    let tier: LicenseTier | undefined;
    if (name === cfg.tierEntitlementName) {
      tier = cfg.tier;
    } else if (name.startsWith(DEFAULT_TIER_ENTITLEMENT_PREFIX)) {
      const suffix = name.slice(DEFAULT_TIER_ENTITLEMENT_PREFIX.length).toLowerCase();
      if (suffix === 'basic' || suffix === 'intermediate' || suffix === 'premium') tier = suffix;
    }
    if (tier && (!best || TIER_RANK[tier] > TIER_RANK[best])) best = tier;
  }
  return best;
}

/** Read the granted seat count from the seats entitlement, if present. */
function grantedSeats(
  allowed: CheckoutEntitlementData[],
  cfg: LicenseManagerConfig,
): number | undefined {
  const seat = allowed.find((e) => e.Name === cfg.seatsEntitlementName);
  if (!seat || seat.Value === undefined) return undefined;
  const n = Number.parseInt(seat.Value, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

// ── Boot gate ───────────────────────────────────────────────────────────────

export interface CheckoutOptions {
  env?: Env;
  /** Inject a client (tests / alt transports). Real SDK loaded when omitted. */
  client?: LicenseManagerClientLike;
  /** Max CheckoutLicense attempts on retryable errors. Default 3. */
  maxAttempts?: number;
  /** Base backoff in ms between retries. Default 250. */
  baseBackoffMs?: number;
}

/**
 * The §23.1/CH-24 boot entitlement gate.
 *
 * - Offline (default): delegates to `validateLicense()` and returns its
 *   state wrapped as an `EntitlementCheckout`. Does not throw; the
 *   offline modes (`unlicensed` / `grace` / `degraded`) carry validity
 *   exactly as today.
 * - AWS License Manager (opt-in): calls `CheckoutLicense`, verifies the
 *   requested tier is granted, maps entitlements to tier + seats, caches
 *   the consumption token to the writable volume, and returns a valid
 *   `licensed` result. Any misconfiguration, denial, missing SDK, or
 *   exhausted retry THROWS — boot must fail closed.
 */
export async function checkoutEntitlementAtBoot(
  opts: CheckoutOptions = {},
): Promise<EntitlementCheckout> {
  const env = opts.env ?? process.env;
  const provider = selectedLicenseProvider(env);

  if (provider === 'offline-ed25519') {
    const info: LicenseInfo = validateLicense();
    return {
      valid: info.valid,
      provider,
      mode: info.mode,
      totalSeats: info.totalSeats,
      reason: info.reason,
    };
  }

  // ── AWS License Manager path ──────────────────────────────────────────
  const cfg = resolveLicenseManagerConfig(env);
  const client = opts.client ?? (await loadLicenseManagerSdkClient(cfg.region));

  const entitlements: CheckoutEntitlementData[] = [{ Name: cfg.tierEntitlementName, Unit: 'None' }];
  if (cfg.seats !== undefined) {
    entitlements.push({ Name: cfg.seatsEntitlementName, Unit: 'Count', Value: String(cfg.seats) });
  }

  const input: CheckoutLicenseInput = {
    CheckoutType: cfg.checkoutType,
    ClientToken: randomUUID(),
    Entitlements: entitlements,
    KeyFingerprint: cfg.keyFingerprint,
    ProductSKU: cfg.productSKU,
    ...(cfg.beneficiary ? { Beneficiary: cfg.beneficiary } : {}),
    ...(cfg.nodeId ? { NodeId: cfg.nodeId } : {}),
  };

  const maxAttempts = Math.max(1, opts.maxAttempts ?? 3);
  const baseBackoffMs = Math.max(0, opts.baseBackoffMs ?? 250);

  let out: CheckoutLicenseOutput | undefined;
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      out = await client.checkoutLicense(input);
      break;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts && isRetryable(err)) {
        await sleep(baseBackoffMs * 2 ** (attempt - 1));
        continue;
      }
      throw new Error(
        `License Manager entitlement check failed: CheckoutLicense did not succeed after ` +
          `${attempt} attempt(s). Boot is failing closed. ` +
          `Underlying error: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`,
      );
    }
  }

  if (!out || !out.LicenseConsumptionToken) {
    throw new Error(
      'License Manager entitlement check failed: CheckoutLicense returned no consumption token. ' +
        'Boot is failing closed.',
    );
  }

  const allowed = out.EntitlementsAllowed ?? [];
  const allowedNames = allowed.map((e) => e.Name);
  const tier = grantedTier(allowedNames, cfg);
  if (!tier || TIER_RANK[tier] < TIER_RANK[cfg.tier]) {
    throw new Error(
      `License Manager entitlement check failed: requested tier "${cfg.tier}" ` +
        `(entitlement "${cfg.tierEntitlementName}") was not granted. ` +
        `Granted entitlements: [${allowedNames.join(', ') || 'none'}]. Boot is failing closed.`,
    );
  }

  const checkout: EntitlementCheckout = {
    valid: true,
    provider,
    mode: 'licensed',
    tier,
    totalSeats: grantedSeats(allowed, cfg) ?? cfg.seats,
    entitlementsAllowed: allowedNames,
    consumptionToken: out.LicenseConsumptionToken,
    expiresAt: out.Expiration,
    reason: `AWS License Manager entitlement granted (tier=${tier}).`,
  };

  persistConsumptionToken(checkout, env);
  return checkout;
}

/**
 * Return a consumed entitlement to License Manager at graceful shutdown
 * (CheckIn). Best-effort: a failed check-in is logged, not thrown — the
 * provisional token expires on its own. No-op outside LM mode or when no
 * token was obtained.
 */
export async function checkInEntitlement(
  consumptionToken: string | undefined,
  opts: { env?: Env; client?: LicenseManagerClientLike } = {},
): Promise<void> {
  const env = opts.env ?? process.env;
  if (!consumptionToken || selectedLicenseProvider(env) !== 'aws-license-manager') return;
  try {
    const cfg = resolveLicenseManagerConfig(env);
    const client = opts.client ?? (await loadLicenseManagerSdkClient(cfg.region));
    await client.checkInLicense(consumptionToken);
  } catch (err) {
    moduleLog.warn(
      `[license/license-manager] CheckInLicense failed (token will expire on its own): ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
