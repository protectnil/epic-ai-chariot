/**
 * @epicai/chariot — CHARIOT-SPEC §8.6a: TenantOverlayToolRegistry tests.
 *
 * Failure classes (team-lead review 2026-09-05, "the customer-verified
 * tools must be DISPATCHABLE and QUERYABLE for that tenant after the
 * embed"):
 *   1. a tool absent before recordTools() is refused by hasTool/getTool.
 *   2. after recordTools(), the SAME tool is accepted.
 *   3. tenant B never sees tenant A's recorded tools (hasTool/getTools
 *      AND resolveForTenant's cross-tenant refusal).
 *   4. a fresh registry instance over the SAME directory (simulating a
 *      process restart) still accepts what a prior instance recorded.
 *   5. a malformed on-disk file fails CLOSED with
 *      TenantOverlayRegistryCorruptError — never a silently empty
 *      registry.
 *   6. two concurrent recordTools() calls for the SAME tenant, different
 *      adapters, both persist (no read-modify-write clobber).
 *   7. resolveForTenant correctly parses overlayToolId()'s exact format
 *      and refuses a malformed/non-overlay id.
 *
 * Run (after tsc): node --test dist/engine/federation/TenantOverlayToolRegistry.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  TenantOverlayToolRegistry,
  TenantOverlayRegistryCorruptError,
} from './TenantOverlayToolRegistry.js';
import { overlayToolId, InvalidTenantIdError } from '../retrieval/overlay/OverlayEmbedder.js';
import type { CustomerVerifiedTool } from '../retrieval/overlay/OverlayEmbedder.js';

function freshRootDir(): string {
  return mkdtempSync(join(tmpdir(), 'overlay-registry-test-'));
}

const tool1: CustomerVerifiedTool = { name: 'send_invoice', description: 'Send an invoice', inputSchema: { type: 'object' } };
const tool2: CustomerVerifiedTool = { name: 'get_balance', description: 'Get account balance', inputSchema: { type: 'object' } };

test('a tool absent before recordTools() is refused', () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.equal(reg.hasTool('tenant-a', 'paypal', 'send_invoice'), false);
    assert.equal(reg.getTool('tenant-a', 'paypal', 'send_invoice'), undefined);
    assert.deepEqual(reg.getTools('tenant-a', 'paypal'), []);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('after recordTools(), the same tool is accepted', async () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await reg.recordTools('tenant-a', 'paypal', [tool1]);
    assert.equal(reg.hasTool('tenant-a', 'paypal', 'send_invoice'), true);
    assert.deepEqual(reg.getTool('tenant-a', 'paypal', 'send_invoice'), tool1);
    assert.deepEqual(reg.getTools('tenant-a', 'paypal'), [tool1]);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('tenant B never sees tenant A\'s recorded tools', async () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await reg.recordTools('tenant-a', 'paypal', [tool1]);
    assert.equal(reg.hasTool('tenant-b', 'paypal', 'send_invoice'), false);
    assert.deepEqual(reg.getTools('tenant-b', 'paypal'), []);

    const toolId = overlayToolId('tenant-a', 'paypal', 'send_invoice');
    // The requesting tenant is B; even holding tenant A's exact toolId
    // string, B must be refused.
    assert.equal(reg.resolveForTenant(toolId, 'tenant-b'), undefined);
    // The genuine requester (A) resolves it.
    assert.deepEqual(reg.resolveForTenant(toolId, 'tenant-a'), tool1);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('a fresh registry instance over the SAME directory (simulated restart) still accepts', async () => {
  const rootDir = freshRootDir();
  try {
    const reg1 = new TenantOverlayToolRegistry({ rootDir });
    await reg1.recordTools('tenant-a', 'paypal', [tool1]);

    // A brand-new instance — no shared in-memory state with reg1 — reading
    // the SAME on-disk directory must reconstruct identical state.
    const reg2 = new TenantOverlayToolRegistry({ rootDir });
    assert.equal(reg2.hasTool('tenant-a', 'paypal', 'send_invoice'), true);
    assert.deepEqual(reg2.getTool('tenant-a', 'paypal', 'send_invoice'), tool1);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('a malformed on-disk file fails CLOSED with TenantOverlayRegistryCorruptError, never an empty registry', () => {
  const rootDir = freshRootDir();
  try {
    const tenantDir = join(rootDir, 'tenant-a');
    mkdirSync(tenantDir, { recursive: true });
    writeFileSync(join(tenantDir, 'tool-registry.json'), '{ not valid json');
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.throws(() => reg.getTools('tenant-a', 'paypal'), TenantOverlayRegistryCorruptError);
    assert.throws(() => reg.hasTool('tenant-a', 'paypal', 'send_invoice'), TenantOverlayRegistryCorruptError);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('a well-formed-JSON-but-wrong-shape file also fails CLOSED (schema violation, not just parse failure)', () => {
  const rootDir = freshRootDir();
  try {
    const tenantDir = join(rootDir, 'tenant-a');
    mkdirSync(tenantDir, { recursive: true });
    writeFileSync(join(tenantDir, 'tool-registry.json'), JSON.stringify({ version: 1, tenantId: 'tenant-a', adapters: { paypal: { tools: 'not-an-array', updatedAt: 'x' } } }));
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.throws(() => reg.getTools('tenant-a', 'paypal'), TenantOverlayRegistryCorruptError);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('a file whose stamped tenantId does not match its directory fails CLOSED', () => {
  const rootDir = freshRootDir();
  try {
    const tenantDir = join(rootDir, 'tenant-a');
    mkdirSync(tenantDir, { recursive: true });
    writeFileSync(join(tenantDir, 'tool-registry.json'), JSON.stringify({ version: 1, tenantId: 'tenant-WRONG', adapters: {} }));
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.throws(() => reg.getTools('tenant-a', 'paypal'), TenantOverlayRegistryCorruptError);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('an unsupported version number fails CLOSED', () => {
  const rootDir = freshRootDir();
  try {
    const tenantDir = join(rootDir, 'tenant-a');
    mkdirSync(tenantDir, { recursive: true });
    writeFileSync(join(tenantDir, 'tool-registry.json'), JSON.stringify({ version: 99, tenantId: 'tenant-a', adapters: {} }));
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.throws(() => reg.getTools('tenant-a', 'paypal'), TenantOverlayRegistryCorruptError);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('two concurrent recordTools() calls for the SAME tenant, different adapters, both persist', async () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await Promise.all([
      reg.recordTools('tenant-a', 'paypal', [tool1]),
      reg.recordTools('tenant-a', 'grafana', [tool2]),
    ]);
    assert.deepEqual(reg.getTools('tenant-a', 'paypal'), [tool1]);
    assert.deepEqual(reg.getTools('tenant-a', 'grafana'), [tool2]);

    // Restart-simulation: a fresh instance reading the same directory must
    // see BOTH writes — proves the read-modify-write serialization did not
    // drop either concurrent write.
    const reg2 = new TenantOverlayToolRegistry({ rootDir });
    assert.deepEqual(reg2.getTools('tenant-a', 'paypal'), [tool1]);
    assert.deepEqual(reg2.getTools('tenant-a', 'grafana'), [tool2]);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('recordTools() with an empty tool array is a valid write, not a corruption or a no-op skip', async () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await reg.recordTools('tenant-a', 'paypal', [tool1]);
    assert.equal(reg.hasTool('tenant-a', 'paypal', 'send_invoice'), true);
    await reg.recordTools('tenant-a', 'paypal', []);
    assert.equal(reg.hasTool('tenant-a', 'paypal', 'send_invoice'), false);
    assert.deepEqual(reg.getTools('tenant-a', 'paypal'), []);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('resolveForTenant refuses a malformed/non-overlay toolId', () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    assert.equal(reg.resolveForTenant('paypal:send_invoice', 'tenant-a'), undefined, 'a sealed-catalog server:name id is not an overlay id');
    assert.equal(reg.resolveForTenant('overlay:tenant-a', 'tenant-a'), undefined, 'too few segments');
    assert.equal(reg.resolveForTenant('overlay:tenant-a:paypal:', 'tenant-a'), undefined, 'empty tool name segment');
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('resolveForTenant handles a tool name containing a colon (rejoined, not truncated)', async () => {
  const rootDir = freshRootDir();
  try {
    const weirdTool: CustomerVerifiedTool = { name: 'namespace:action', description: '', inputSchema: {} };
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await reg.recordTools('tenant-a', 'paypal', [weirdTool]);
    const toolId = overlayToolId('tenant-a', 'paypal', 'namespace:action');
    assert.deepEqual(reg.resolveForTenant(toolId, 'tenant-a'), weirdTool);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

// ─── R4 (team-lead review 2026-09-05): tenantId path confinement ───────────
//
// `tenantId` becomes `join(overlayRootDir, tenantId)` — an unconfined value
// is a path traversal out of the overlay root. Mirrors
// `NativeOverlayEmbedder`'s own `assertValidTenantId`/`TENANT_ID_PATTERN`
// (OverlayEmbedder.ts:180-201) byte-for-byte (that function is not
// exported; `InvalidTenantIdError`, which IS exported, is reused directly
// so both modules throw the identical error type).

const MALFORMED_TENANT_IDS = ['../../etc', '..', '.', 'a/b', '', 'x'.repeat(129)] as const;

for (const bad of MALFORMED_TENANT_IDS) {
  test(`a malformed tenantId ${JSON.stringify(bad)} throws InvalidTenantIdError on the READ path (getTools/hasTool)`, () => {
    const rootDir = freshRootDir();
    try {
      const reg = new TenantOverlayToolRegistry({ rootDir });
      assert.throws(() => reg.getTools(bad, 'paypal'), InvalidTenantIdError);
      assert.throws(() => reg.hasTool(bad, 'paypal', 'send_invoice'), InvalidTenantIdError);
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  });

  test(`a malformed tenantId ${JSON.stringify(bad)} throws InvalidTenantIdError on the WRITE path (recordTools) and never touches disk`, async () => {
    const rootDir = freshRootDir();
    try {
      const reg = new TenantOverlayToolRegistry({ rootDir });
      await assert.rejects(() => reg.recordTools(bad, 'paypal', [tool1]), InvalidTenantIdError);
      // No new directory must have been created for the rejected tenantId —
      // the assertion must fire BEFORE mkdirSync/writeFileSync, not after.
      assert.deepEqual(readdirSyncSafe(rootDir), [], 'a rejected recordTools() must not create any tenant directory');
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  });
}

test('a VALID tenantId still round-trips normally (the confinement rejects only malformed ids)', async () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    await reg.recordTools('tenant-valid-123.a_b-c', 'paypal', [tool1]);
    assert.equal(reg.hasTool('tenant-valid-123.a_b-c', 'paypal', 'send_invoice'), true);
    assert.deepEqual(reg.getTools('tenant-valid-123.a_b-c', 'paypal'), [tool1]);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('resolveForTenant also fails closed on a malformed requesting tenantId once it reaches the confined lookup', () => {
  const rootDir = freshRootDir();
  try {
    const reg = new TenantOverlayToolRegistry({ rootDir });
    // requestingTenantId 'tenant-a' is well-formed but the toolId's OWN
    // embedded tenantId segment is malformed — parseOverlayToolId does not
    // itself validate shape, so this proves the confinement still catches
    // it downstream at getTool()->load()->tenantDir(), not just at the
    // public getTools/hasTool/recordTools entry points.
    assert.throws(() => reg.resolveForTenant('overlay:../../etc:paypal:send_invoice', '../../etc'), InvalidTenantIdError);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

function readdirSyncSafe(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}
