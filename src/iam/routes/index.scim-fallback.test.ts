/**
 * Prove-on-revert for CHARIOT §10.4::2 — "The SCIM router SHALL accept both
 * /scim/v2/-prefixed and root-level (prefix-stripped) shapes for
 * path-stripping IdPs." (CHARIOT-SPEC.md:1049, "Chariot's router accepts
 * both shapes.")
 *
 * Defect this catches: `createEnterpriseRoutes()` mounted `scimRouter` at
 * exactly one path, `/:tenantId/scim/v2`. A path-stripping IdP POSTing
 * directly to `/enterprise/{tenantId}/Users` (no /scim/v2 segment) 404'd.
 *
 * Ruling item 88(5): "root-level" means root-level RELATIVE TO THE TENANT
 * PREFIX (CH-17/§10.8 forbids a route that omits the tenant segment
 * entirely) — /enterprise/{tenantId}/Users, never a bare app-root /Users.
 *
 * This repo has no supertest/mongodb-memory-server dependency for
 * colocated unit tests (see admin.tenant-crud.test.ts for the established
 * source-inspection convention this file follows); it asserts the route
 * wiring and mount ORDER via source inspection, without Mongo/Express.
 *
 * Run (after tsc): node --test dist/iam/routes/index.scim-fallback.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const routesIndexSrc = readFileSync(fileURLToPath(new URL('./index.js', import.meta.url)), 'utf8');

function mountLine(src: string, mountPath: string): string {
  const re = new RegExp(`router\\.use\\(\\s*'${mountPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'[^;]*;`);
  const m = src.match(re);
  assert.ok(m, `expected a router.use('${mountPath}', ...) mount`);
  return m![0];
}

test('§10.4::2: a bare /:tenantId root-level SCIM mount exists, using the same scimRouter', () => {
  const line = mountLine(routesIndexSrc, '/:tenantId');
  assert.match(line, /scimRouter/, 'the root-level fallback must reuse the identical scimRouter instance as the /scim/v2 mount, not a second copy');
});

test('§10.4::2: the root-level fallback mount uses the SAME gate chain as the /scim/v2 mount (tenant isolation + multi-user license gate)', () => {
  const rootLine = mountLine(routesIndexSrc, '/:tenantId');
  const scimV2Line = mountLine(routesIndexSrc, '/:tenantId/scim/v2');
  for (const guard of ['requireUrlTenantIsolation', 'multiUserGate']) {
    assert.ok(rootLine.includes(guard), `root-level fallback must apply ${guard}`);
    assert.ok(scimV2Line.includes(guard), `/scim/v2 mount must apply ${guard} (baseline check)`);
  }
});

test('§10.4::2: the fallback is NOT a true app-root mount — it still carries the :tenantId URL segment (CH-17/§10.8)', () => {
  const line = mountLine(routesIndexSrc, '/:tenantId');
  assert.match(line, /^router\.use\(\s*'\/:tenantId'/, 'mount path must be exactly "/:tenantId" — a tenant-scoped path, never a bare "/" app-root mount');
});

test('§10.4::2: the root-level fallback is registered AFTER every other tenant sub-route mount, so it cannot shadow them', () => {
  // Express tries router.use() mounts in registration order and only falls
  // through to the next one when the current mount has no matching route
  // for the remaining path. A bare '/:tenantId' mount registered BEFORE a
  // more specific one (e.g. '/:tenantId/admin') would still fall through
  // correctly in practice (scimRouter has no /admin route), but registering
  // it LAST is the fail-safe order: it can only ever claim paths nothing
  // more specific already claimed, with no dependency on scimRouter's own
  // route table staying disjoint from every other router's forever.
  const paths = ['/:tenantId/auth', '/:tenantId/oauth', '/:tenantId/scim/v2', '/:tenantId/admin/trust', '/:tenantId/admin', '/:tenantId/adapters', '/:tenantId'];
  const positions = paths.map((p) => {
    const idx = routesIndexSrc.search(new RegExp(`router\\.use\\(\\s*'${p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
    assert.ok(idx >= 0, `expected to find a router.use('${p}', ...) mount`);
    return idx;
  });
  const bareTenantIdIdx = positions[positions.length - 1];
  for (let i = 0; i < positions.length - 1; i++) {
    assert.ok(bareTenantIdIdx > positions[i], `bare '/:tenantId' mount must be registered after '${paths[i]}'`);
  }
});
