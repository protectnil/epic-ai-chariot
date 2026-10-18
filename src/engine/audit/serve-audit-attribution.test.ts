/**
 * @epicai/chariot — serve-path audit attribution eval (feed #15)
 *
 * Proves that recordDispatch() (the actual serve-path audit sink called from
 * handleCallImpl for every REST/HTTP/stdio tool dispatch) now persists the
 * authenticated principal (userId) and client IP (sourceIp) onto the
 * ActionRecord when the caller (toolHandlers.ts, fed from CallContext) supplies
 * them — closing the gap where commit 5026479 added ActionRecord.userId/
 * sourceIp but no caller on the serve path ever populated them.
 *
 * Also proves the negative case: when the dispatch context genuinely has no
 * userId/sourceIp (e.g. stdio / shared-bearer loopback), the fields are
 * omitted rather than fabricated.
 *
 * Run after `tsc`: node --test dist/engine/audit/serve-audit-attribution.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  configureServeAudit,
  recordDispatch,
  getServeAuditTrail,
  __resetServeAudit,
} from './serveAuditSink.js';

test('recordDispatch persists userId and sourceIp when the caller supplies them', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-audit-attribution-'));
  __resetServeAudit();
  try {
    const chainPath = join(dir, 'chain.jsonl');
    const trail = await configureServeAudit({ chainPath });
    assert.ok(trail, 'expected serve audit trail to be configured');

    await recordDispatch({
      adapterId: 'test-adapter',
      toolName: 'test_tool',
      args: { q: 'hello' },
      tenantId: 'tenant-001',
      status: 'completed',
      durationMs: 12,
      userId: 'user-42',
      sourceIp: '203.0.113.7',
    });

    const records = await getServeAuditTrail()!.query({});
    assert.equal(records.length, 1);
    const [record] = records;
    assert.equal(record.userId, 'user-42', 'ActionRecord must carry the authenticated userId');
    assert.equal(record.sourceIp, '203.0.113.7', 'ActionRecord must carry the client sourceIp');
  } finally {
    __resetServeAudit();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('recordDispatch omits userId/sourceIp (never fabricates) when the caller has neither', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-audit-attribution-'));
  __resetServeAudit();
  try {
    const chainPath = join(dir, 'chain.jsonl');
    await configureServeAudit({ chainPath });

    await recordDispatch({
      adapterId: 'test-adapter',
      toolName: 'test_tool',
      args: {},
      tenantId: 'local',
      status: 'completed',
      durationMs: 5,
      // no userId / sourceIp — mirrors stdio / shared-bearer loopback dispatch
    });

    const records = await getServeAuditTrail()!.query({});
    assert.equal(records.length, 1);
    const [record] = records;
    assert.equal(record.userId, undefined);
    assert.equal(record.sourceIp, undefined);
  } finally {
    __resetServeAudit();
    rmSync(dir, { recursive: true, force: true });
  }
});
