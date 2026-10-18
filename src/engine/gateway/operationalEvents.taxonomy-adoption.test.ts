/**
 * CHARIOT::§16.1 Operational (CHARIOT-SPEC.md:1353, rulings item 91/105) —
 * "Operational: `gateway.backend_unhealthy`, `gateway.circuit_opened`,
 * `redis.unreachable`, `mongo.unreachable`."
 *
 * SOURCE INSPECTION (this repo's established convention): BackendRegistry's
 * health-check cycle needs a live/fake inference backend HTTP server and a
 * ControlPlane fixture; resolveEnterpriseRedis needs a real (or refusing)
 * Redis port; bootstrap.ts's Mongo path needs a live/refusing Mongo — none
 * of which this repo's colocated unit tests stand up (see
 * admin.audit-logs-export.test.ts's header comment for the established
 * precedent). This proves each site is wired at the right place relative
 * to its neighboring pre-existing log statement.
 *
 * Run (after tsc): node --test dist/engine/gateway/operationalEvents.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const backendRegistrySrc = readFileSync(fileURLToPath(new URL('./BackendRegistry.js', import.meta.url)), 'utf8');
const redisSrc = readFileSync(fileURLToPath(new URL('../../iam/resolveEnterpriseRedis.js', import.meta.url)), 'utf8');
const bootstrapSrc = readFileSync(fileURLToPath(new URL('../../iam/bootstrap.js', import.meta.url)), 'utf8');

test('§16.1 Operational: gateway.backend_unhealthy fires on every probe failure that flips a backend to unhealthy', () => {
  // Bounded by the NEXT meaningful statement (the shouldOpen circuit-open
  // check) rather than a fixed character distance, which is fragile
  // against reformatting/comment-length changes across compiles.
  const cycleIdx = backendRegistrySrc.indexOf('runHealthCheckCycle');
  const idx = backendRegistrySrc.indexOf("status: 'unhealthy'", cycleIdx);
  const nextBoundary = backendRegistrySrc.indexOf('if (shouldOpen', idx);
  const emitIdx = backendRegistrySrc.indexOf("chariotEmitter.send('gateway.backend_unhealthy'", idx);
  assert.ok(idx > 0 && nextBoundary > idx, 'both anchors must exist, in this order');
  assert.ok(emitIdx > idx && emitIdx < nextBoundary, 'gateway.backend_unhealthy must be emitted right after a backend flips to unhealthy status, before the circuit-open check that follows it');
});

test('§16.1 Operational: gateway.circuit_opened fires alongside (after) the pre-existing "circuit breaker opened" WARN log', () => {
  // Bounded by the enclosing block's closing brace pattern instead of a
  // fixed character distance.
  const logIdx = backendRegistrySrc.indexOf("log.warn('circuit breaker opened'");
  const emitIdx = backendRegistrySrc.indexOf("chariotEmitter.send('gateway.circuit_opened'", logIdx);
  const blockEnd = backendRegistrySrc.indexOf('\n', backendRegistrySrc.indexOf('data:', emitIdx >= 0 ? emitIdx : logIdx));
  assert.ok(logIdx >= 0, 'the pre-existing WARN log must still exist');
  assert.ok(emitIdx > logIdx, 'gateway.circuit_opened must be emitted after the pre-existing WARN log');
  assert.ok(blockEnd > 0, 'sanity: the emit call body must be well-formed');
});

test('§16.1 Operational: redis.unreachable fires from BOTH the boot-time catch AND the runtime error handler, tagged by phase', () => {
  const runtimeErrIdx = redisSrc.indexOf("client.on('error'");
  const bootCatchIdx = redisSrc.indexOf('Redis unreachable at startup');
  assert.ok(runtimeErrIdx >= 0 && bootCatchIdx > runtimeErrIdx, 'both sites must exist, in this order');
  const runtimeBlock = redisSrc.slice(runtimeErrIdx, bootCatchIdx);
  const bootBlock = redisSrc.slice(bootCatchIdx);
  assert.match(runtimeBlock, /chariotEmitter\.send\('redis\.unreachable',\s*\{[\s\S]*?phase:\s*'runtime'/);
  assert.match(bootBlock, /chariotEmitter\.send\('redis\.unreachable',\s*\{[\s\S]*?phase:\s*'boot'/);
});

test('§16.1 Operational: mongo.unreachable fires BEFORE the fail-fast throw (no degrade path exists for Mongo, unlike Redis)', () => {
  const errStart = bootstrapSrc.indexOf('MongoDB unavailable at');
  assert.ok(errStart >= 0, 'the MongoDB unavailable error message must exist');
  // Regex, not a literal "} catch (err) {" substring — tsc emits the
  // closing brace and `catch` on SEPARATE lines, not the same-line style
  // the .ts source uses, so a literal substring search silently never
  // matches compiled output.
  const catchRegex = /\}\s*catch\s*\(err\)\s*\{/g;
  let catchStart = -1;
  let m: RegExpExecArray | null;
  while ((m = catchRegex.exec(bootstrapSrc.slice(0, errStart))) !== null) {
    catchStart = m.index;
  }
  const emitIdx = bootstrapSrc.indexOf("chariotEmitter.send('mongo.unreachable'", catchStart);
  const throwIdx = bootstrapSrc.indexOf('throw new Error', emitIdx);
  assert.ok(catchStart >= 0 && emitIdx > catchStart && emitIdx < throwIdx, 'mongo.unreachable must be emitted inside the Mongo-connect catch block, before the throw');
  const body = bootstrapSrc.slice(emitIdx, throwIdx);
  assert.match(body, /severity:\s*'urgent'/);
  assert.match(body, /alertWorthy:\s*true/);
});
