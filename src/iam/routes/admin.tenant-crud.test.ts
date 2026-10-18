/**
 * Prove-on-revert for CHARIOT §10.8::1/::2/::3 — tenant management SHALL provide
 * full CRUD (incl. delete), settings updates for the six named fields, and
 * suspension/resumption.
 *
 * Defect this catches: tenant.ts had no delete (CRUD incomplete, §10.8::1); the
 * admin settings schema exposed only session-TTL/max-concurrent/admin-group,
 * missing idle-timeout, JIT-toggle, and log-retention (§10.8::2); and
 * suspend/activate existed but were wired to no route (§10.8::3). Behavioral
 * route coverage (auth+Mongo) lives in the infra-gated harness; this asserts the
 * service surface + route wiring + schema fields via source.
 *
 * Run (after tsc): node --test dist/iam/routes/admin.tenant-crud.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import * as tenantService from '../services/tenant.js';

const adminSrc = readFileSync(fileURLToPath(new URL('./admin.js', import.meta.url)), 'utf8');

test('§10.8::1: tenant CRUD includes create/read/update AND delete', () => {
  assert.equal(typeof tenantService.create, 'function');
  assert.equal(typeof tenantService.getByTenantId, 'function');
  assert.equal(typeof tenantService.updateSettings, 'function');
  assert.equal(typeof tenantService.deleteTenant, 'function');
});

test('§10.8::2: settings schema exposes idle-timeout, JIT toggle, and log-retention', () => {
  for (const field of ['idleTimeoutMinutes', 'jitProvisioningEnabled', 'logRetentionDays']) {
    assert.ok(adminSrc.includes(field), `tenant settings must be updatable via ${field}`);
  }
});

test('§10.8::3: suspend and activate are wired to admin routes', () => {
  assert.equal(typeof tenantService.suspend, 'function');
  assert.equal(typeof tenantService.activate, 'function');
  assert.ok(/tenant\/suspend/.test(adminSrc), 'a /tenant/suspend route must be wired');
  assert.ok(/tenant\/activate/.test(adminSrc), 'a /tenant/activate route must be wired');
});
