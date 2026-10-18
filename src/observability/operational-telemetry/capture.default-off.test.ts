/**
 * C4AMD::§8::2 (traceability.spec_nodes): "Operational telemetry SHALL be
 * off by default." C4AMD::§8::4: "Customer authorization to use an
 * adapter SHALL NOT imply telemetry permission."
 *
 * Real execution against the repo's existing fake-Mongo fixture
 * (src/iam/testFakes/fakeMongoCollection.ts — same fixture
 * credential-loader/oidc/id-jag-client's concurrency tests use), not
 * source inspection: a tenant with NO consent history (the
 * `iam_audit_events` collection seeded empty) must produce zero captured
 * events, and the write path (`operational_telemetry_events`) must never
 * be touched.
 *
 * Run (after tsc): node --test dist/observability/operational-telemetry/capture.default-off.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { captureEvent } = await import('./capture.js');
const { setMongoClient } = await import('../../iam/db.js');
const { makeFakeCollection, makeFakeMongoClient } = await import('../../iam/testFakes/fakeMongoCollection.js');

test('§8::2: captureEvent is a no-op for a tenant with no consent history (default off)', async () => {
  const events = makeFakeCollection([]);
  const telemetry = makeFakeCollection([]);
  setMongoClient(
    makeFakeMongoClient({ iam_audit_events: events, operational_telemetry_events: telemetry }),
    'chariot',
  );

  const result = await captureEvent({
    tenantId: 'never-consented-tenant',
    canonicalToolId: 'stripe.charge_create',
    outcome: 'success',
    latencyMs: 42,
    failureStage: null,
    occurredAt: new Date(),
  });

  assert.strictEqual(result, null, 'captureEvent must return null when telemetry has never been enabled');
  assert.strictEqual(telemetry.docs.length, 0, 'no event may be written when consent is absent (off by default)');
});

test('§8::4: an adapter-authorization signal alone (no telemetry consent event) still leaves telemetry off', async () => {
  // Simulate "the customer has authorized an adapter" by seeding an
  // UNRELATED collection some other IAM write path would touch — the
  // point is that nothing in this module's own read path (iam_audit_events
  // filtered to eventType: 'telemetry_consent_changed') is affected by any
  // adapter-authorization state, because it never queries adapter/tenant
  // authorization data at all.
  const events = makeFakeCollection([]);
  const telemetry = makeFakeCollection([]);
  const tenants = makeFakeCollection([
    { _id: 'authorized-tenant', tenantId: 'authorized-tenant', settings: { allowedAdapterIds: ['stripe'] } } as never,
  ]);
  setMongoClient(
    makeFakeMongoClient({ iam_audit_events: events, operational_telemetry_events: telemetry, iam_tenants: tenants }),
    'chariot',
  );

  const result = await captureEvent({
    tenantId: 'authorized-tenant',
    canonicalToolId: 'stripe.charge_create',
    outcome: 'success',
    latencyMs: 10,
    failureStage: null,
    occurredAt: new Date(),
  });

  assert.strictEqual(result, null, 'adapter authorization (iam_tenants row) must not imply telemetry permission');
  assert.strictEqual(telemetry.docs.length, 0);
});
