/**
 * CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)) —
 * "Surfaced via `GET /enterprise/{tenantId}/admin/metrics` (JSON) ...".
 *
 * No supertest/mongodb-memory-server in this repo (see
 * admin.audit-logs-export.test.ts's own header comment) — this file
 * follows the same established source-inspection convention for proving
 * the route's RBAC gating and shape without standing up a live Mongo +
 * Express server.
 *
 * Run (after tsc): node --test dist/iam/routes/admin.metrics-route.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const adminSrc = readFileSync(fileURLToPath(new URL('./admin.js', import.meta.url)), 'utf8');

function routeBody(src: string, routeDecl: string): string {
  const start = src.indexOf(routeDecl);
  assert.ok(start >= 0, `${routeDecl} route must exist`);
  const rest = src.slice(start + 1);
  const nextRouteRel = rest.search(/\nrouter\.(get|post|put|delete|patch)\(/);
  return nextRouteRel === -1 ? rest : rest.slice(0, nextRouteRel);
}

test('§16.3::1: GET /metrics exists and is mounted after the router-level auth+admin-guard middleware', () => {
  const guardIdx = adminSrc.indexOf('router.use(enterpriseAdminGuard())');
  const routeIdx = adminSrc.indexOf("router.get('/metrics'");
  assert.ok(guardIdx >= 0, 'enterpriseAdminGuard() must be applied at router level');
  assert.ok(routeIdx > guardIdx, 'GET /metrics must be declared after the router-level admin guard, so it inherits the same RBAC gate as every other route in this file (exactly like /audit-logs)');
});

test('§16.3::1: GET /metrics calls requireEnterpriseAuth() exactly like the /audit-logs route does', () => {
  const metricsBody = routeBody(adminSrc, "router.get('/metrics'");
  const auditBody = routeBody(adminSrc, "router.get('/audit-logs'");
  assert.match(metricsBody, /requireEnterpriseAuth\(req,\s*res\)/, 'the metrics route must call requireEnterpriseAuth exactly like every other route in this file');
  assert.match(auditBody, /requireEnterpriseAuth\(req,\s*res\)/, 'sanity: the audit-logs route this route is modeled on must itself call requireEnterpriseAuth');
});

test('§16.3::1: GET /metrics returns a 503 (not a crash) when no ChariotMetrics instance has been injected', () => {
  const body = routeBody(adminSrc, "router.get('/metrics'");
  assert.match(body, /if \(!chariotMetricsSource\)/, 'must guard the uninjected case');
  assert.match(body, /res\.status\(503\)/, 'the uninjected case must respond 503, not throw');
});

test('§16.3::1: GET /metrics responds with chariotMetricsSource.getSummary() as the JSON body', () => {
  const body = routeBody(adminSrc, "router.get('/metrics'");
  assert.match(body, /res\.json\(chariotMetricsSource\.getSummary\(\)\)/);
});

test('§16.3::1: setChariotMetricsSource is exported for the boot-time injector', () => {
  assert.match(adminSrc, /export function setChariotMetricsSource\(/);
});
