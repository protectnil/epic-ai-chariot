/**
 * CHARIOT-SPEC §23.1 / CH-24 — gateway boot entitlement gate.
 *
 * Clause (CHARIOT-SPEC §23): "Contract Pricing
 * integrates with AWS License Manager (`CheckoutLicense` at gateway boot) ...
 * The offline Ed25519 license path (§11) remains the default for every
 * non-Marketplace deployment; License Manager is selected only under an
 * explicit env flag." CH-24 (:2146): "License Manager `CheckoutLicense` gates
 * entitlement at boot; offline Ed25519 stays default off-Marketplace."
 *
 * Failure classes (derived from the clause, not from the implementation):
 *   F1 LM env absent            -> no SDK/AWS call, boot proceeds (offline default)
 *   F2 LM env present + granted -> exactly one CheckoutLicense, boot proceeds
 *   F3 checkout denied          -> gate rejects (fail closed)
 *   F4 SDK/transport throws     -> gate rejects (fail closed)
 *   F5 seats exhausted          -> gate rejects (fail closed), not retried
 *   F6 shutdown                 -> CheckInLicense with the consumed token, once
 *   F7 double boot              -> one CheckoutLicense, not two (no double seat)
 *   F8 LM selected, config bad  -> rejects before any client call
 *   F9 failed gate is not cached as a pass; a retry re-checks
 *
 * Run after `tsc`: node --test dist/license/boot-gate.test.js
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { enforceBootEntitlement, releaseBootEntitlement } from './boot-gate.js';
import type {
  CheckoutLicenseInput,
  CheckoutLicenseOutput,
  LicenseManagerClientLike,
} from './license-manager.js';

function lmEnv(dir: string, over: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    CHARIOT_LICENSE_PROVIDER: 'aws-license-manager',
    CHARIOT_LM_PRODUCT_SKU: 'prod-abc123',
    AWS_REGION: 'us-east-1',
    CHARIOT_LM_TIER: 'basic',
    EPIC_AI_DIR_OVERRIDE: dir,
    ...over,
  };
}

interface Fake {
  client: LicenseManagerClientLike;
  checkouts: CheckoutLicenseInput[];
  checkins: string[];
}

function fake(
  checkout: (input: CheckoutLicenseInput) => Promise<CheckoutLicenseOutput>,
): Fake {
  const f: Fake = {
    checkouts: [],
    checkins: [],
    client: {
      checkoutLicense: async (input) => {
        f.checkouts.push(input);
        return checkout(input);
      },
      checkInLicense: async (token) => {
        f.checkins.push(token);
      },
    },
  };
  return f;
}

const granted = async (): Promise<CheckoutLicenseOutput> => ({
  LicenseConsumptionToken: 'tok-1',
  EntitlementsAllowed: [{ Name: 'chariot:tier:basic', Unit: 'None' }],
});

let dir: string;
beforeEach(async () => {
  await releaseBootEntitlement();
  dir = mkdtempSync(join(tmpdir(), 'boot-gate-'));
});

test('F1 LM env absent: no-op, no client use, offline default untouched', async () => {
  const f = fake(granted);
  const r = await enforceBootEntitlement({ env: {}, client: f.client });
  assert.equal(r.enforced, false);
  assert.equal(f.checkouts.length, 0);
  // explicit offline selection is also a no-op
  const r2 = await enforceBootEntitlement({
    env: { CHARIOT_LICENSE_PROVIDER: 'offline-ed25519' },
    client: f.client,
  });
  assert.equal(r2.enforced, false);
  assert.equal(f.checkouts.length, 0);
});

test('F1b LM vars present but provider not selected: no checkout', async () => {
  const f = fake(granted);
  const env = lmEnv(dir);
  delete env.CHARIOT_LICENSE_PROVIDER;
  const r = await enforceBootEntitlement({ env, client: f.client });
  assert.equal(r.enforced, false);
  assert.equal(f.checkouts.length, 0);
  rmSync(dir, { recursive: true, force: true });
});

test('F2 LM env + granted: exactly one CheckoutLicense, enforced', async () => {
  const f = fake(granted);
  const r = await enforceBootEntitlement({ env: lmEnv(dir), client: f.client });
  assert.equal(r.enforced, true);
  assert.equal(r.checkout?.valid, true);
  assert.equal(r.checkout?.consumptionToken, 'tok-1');
  assert.equal(f.checkouts.length, 1);
  assert.equal(f.checkouts[0].ProductSKU, 'prod-abc123');
  rmSync(dir, { recursive: true, force: true });
});

test('F3 checkout denied (tier not granted): rejects', async () => {
  const f = fake(async () => ({
    LicenseConsumptionToken: 'tok-x',
    EntitlementsAllowed: [],
  }));
  await assert.rejects(
    enforceBootEntitlement({ env: lmEnv(dir), client: f.client }),
    /was not granted|failing closed/,
  );
  rmSync(dir, { recursive: true, force: true });
});

test('F3b checkout returns no consumption token: rejects', async () => {
  const f = fake(async () => ({
    EntitlementsAllowed: [{ Name: 'chariot:tier:basic', Unit: 'None' }],
  }));
  await assert.rejects(
    enforceBootEntitlement({ env: lmEnv(dir), client: f.client }),
    /no consumption token/,
  );
  rmSync(dir, { recursive: true, force: true });
});

test('F4 SDK/transport throws: rejects', async () => {
  const f = fake(async () => {
    throw new Error('connect ECONNREFUSED');
  });
  await assert.rejects(
    enforceBootEntitlement({ env: lmEnv(dir), client: f.client }),
    /failing closed/,
  );
  rmSync(dir, { recursive: true, force: true });
});

test('F5 seats exhausted: rejects without retry', async () => {
  const f = fake(async () => {
    const e = new Error('no entitlements allowed');
    e.name = 'NoEntitlementsAllowedException';
    throw e;
  });
  await assert.rejects(
    enforceBootEntitlement({ env: lmEnv(dir, { CHARIOT_LM_SEATS: '5' }), client: f.client }),
    /failing closed/,
  );
  assert.equal(f.checkouts.length, 1, 'a denial must not be retried');
  rmSync(dir, { recursive: true, force: true });
});

test('F6 shutdown: CheckInLicense with the consumed token, once', async () => {
  const f = fake(granted);
  await enforceBootEntitlement({ env: lmEnv(dir), client: f.client });
  await releaseBootEntitlement();
  await releaseBootEntitlement(); // idempotent
  assert.deepEqual(f.checkins, ['tok-1']);
  rmSync(dir, { recursive: true, force: true });
});

test('F6b shutdown after offline boot: no check-in, no throw', async () => {
  await enforceBootEntitlement({ env: {} });
  await releaseBootEntitlement();
});

test('F7 double boot: one CheckoutLicense (concurrent and sequential)', async () => {
  const f = fake(granted);
  const env = lmEnv(dir);
  const [a, b] = await Promise.all([
    enforceBootEntitlement({ env, client: f.client }),
    enforceBootEntitlement({ env, client: f.client }),
  ]);
  const c = await enforceBootEntitlement({ env, client: f.client });
  assert.equal(f.checkouts.length, 1);
  assert.equal(a.checkout?.consumptionToken, b.checkout?.consumptionToken);
  assert.equal(c.checkout?.consumptionToken, 'tok-1');
  rmSync(dir, { recursive: true, force: true });
});

test('F8 LM selected but config missing: rejects before any client call', async () => {
  const f = fake(granted);
  const env = lmEnv(dir);
  delete env.CHARIOT_LM_PRODUCT_SKU;
  await assert.rejects(
    enforceBootEntitlement({ env, client: f.client }),
    /CHARIOT_LM_PRODUCT_SKU/,
  );
  assert.equal(f.checkouts.length, 0);
  rmSync(dir, { recursive: true, force: true });
});

test('F9 a failed gate is not cached as a pass; retry re-checks', async () => {
  let n = 0;
  const f = fake(async (input) => {
    n++;
    if (n === 1) throw new Error('boom');
    return granted();
  });
  const env = lmEnv(dir);
  await assert.rejects(enforceBootEntitlement({ env, client: f.client }));
  const r = await enforceBootEntitlement({ env, client: f.client });
  assert.equal(r.enforced, true);
  assert.equal(f.checkouts.length, 2);
  rmSync(dir, { recursive: true, force: true });
});
