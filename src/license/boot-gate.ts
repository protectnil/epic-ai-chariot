/**
 * @epicai/chariot — Gateway boot entitlement gate (§23.1 / CH-24)
 *
 * CHARIOT-SPEC §23.1: "Contract Pricing integrates with AWS License Manager
 * (`CheckoutLicense` at gateway boot) ... The offline Ed25519 license path
 * (§11) remains the default for every non-Marketplace deployment; License
 * Manager is selected only under an explicit env flag."
 *
 * `checkoutEntitlementAtBoot()` (license-manager.ts) implements the checkout
 * but was reachable only through `bootstrapEnterprise()`, which the container
 * ENTRYPOINT (`node dist/bin/gateway.js`) never calls. This module is the one
 * call site on the real gateway boot path (src/bin/gateway.ts):
 *
 * - Outside License Manager mode it is a pure no-op: no SDK load, no AWS
 *   call, no license-file read — the offline Ed25519 path (§11) is untouched.
 * - In License Manager mode it runs CheckoutLicense and THROWS on any
 *   misconfiguration, denial, exhausted seats, missing SDK or SDK error, so
 *   the caller can refuse to serve (fail closed).
 * - It is idempotent per process: a second call returns the first result
 *   without a second CheckoutLicense, so a double boot never consumes two
 *   seats.
 * - `releaseBootEntitlement()` returns the consumed entitlement (CheckIn) at
 *   graceful shutdown; best-effort, idempotent, never throws.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  checkInEntitlement,
  checkoutEntitlementAtBoot,
  isLicenseManagerMode,
  type EntitlementCheckout,
  type LicenseManagerClientLike,
} from './license-manager.js';

type Env = NodeJS.ProcessEnv;

export interface BootEntitlementOptions {
  env?: Env;
  /** Inject a License Manager client (tests / alt transports). */
  client?: LicenseManagerClientLike;
}

export interface BootEntitlementResult {
  /** True only when a License Manager CheckoutLicense was performed. */
  enforced: boolean;
  /** The checkout, present only when `enforced`. */
  checkout?: EntitlementCheckout;
}

let inFlight: Promise<BootEntitlementResult> | undefined;
let heldToken: string | undefined;
let heldEnv: Env | undefined;
let heldClient: LicenseManagerClientLike | undefined;

/**
 * Run the boot entitlement gate. Resolves with `{ enforced: false }` outside
 * License Manager mode; in License Manager mode resolves only after a granted
 * CheckoutLicense and otherwise rejects (the caller must not serve).
 */
export function enforceBootEntitlement(
  opts: BootEntitlementOptions = {},
): Promise<BootEntitlementResult> {
  const env = opts.env ?? process.env;
  if (!isLicenseManagerMode(env)) {
    return Promise.resolve({ enforced: false });
  }
  if (inFlight) return inFlight;

  const run = (async (): Promise<BootEntitlementResult> => {
    const checkout = await checkoutEntitlementAtBoot({ env, client: opts.client });
    heldToken = checkout.consumptionToken;
    heldEnv = env;
    heldClient = opts.client;
    return { enforced: true, checkout };
  })();
  inFlight = run;
  // A failed gate must not be cached as a pass or wedge a retry.
  run.catch(() => {
    if (inFlight === run) inFlight = undefined;
  });
  return run;
}

/**
 * Return the consumed entitlement to License Manager (CheckIn). Idempotent;
 * no-op when nothing is held. Never throws (checkInEntitlement swallows and
 * logs a failed CheckIn; the provisional token expires on its own).
 */
export async function releaseBootEntitlement(): Promise<void> {
  const token = heldToken;
  const env = heldEnv;
  const client = heldClient;
  heldToken = undefined;
  heldEnv = undefined;
  heldClient = undefined;
  inFlight = undefined;
  if (!token) return;
  await checkInEntitlement(token, { env, client });
}
