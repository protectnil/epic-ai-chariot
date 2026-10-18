/**
 * CH-54 adversarial eval — Attack 4
 *
 * ECS task-definition structural assertions added in 5ddcb7f:
 *
 *  - readonlyRootFilesystem: true (hardened container FS)
 *  - linuxParameters.tmpfs includes /tmp with size 64 MiB so Node temp writes
 *    do not hit EROFS under readonlyRootFilesystem (the CH-54 fix)
 *  - volumes has a chariot-data entry backed by efsVolumeConfiguration so
 *    license tokens / EdgeShard survive task restarts
 *  - healthCheck command contains both timeout:4000 and .on('timeout',…destroy)
 *    so the 4 s HTTP deadline triggers a clean socket destroy+exit(1) instead
 *    of a 5 s wall-clock hang — aligning the probe with the Dockerfile HEALTHCHECK
 *
 * Parses the REAL JSON file and asserts structure — no mocks, no hardcoded copies.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TASKDEF_PATH = join(__dirname, '..', '..', 'helm', 'chariot', 'ecs', 'chariot-gateway-taskdef.json');

const taskdef = JSON.parse(readFileSync(TASKDEF_PATH, 'utf-8'));
const [container] = taskdef.containerDefinitions;

// ── readonlyRootFilesystem ────────────────────────────────────────────────────

test('ECS taskdef — readonlyRootFilesystem is true', () => {
  assert.strictEqual(container.readonlyRootFilesystem, true,
    'readonlyRootFilesystem must be true (hardened container FS)');
});

// ── tmpfs writable /tmp (CH-54 fix) ──────────────────────────────────────────

test('ECS taskdef — linuxParameters.tmpfs provides writable /tmp (CH-54 fix)', () => {
  const lp = container.linuxParameters;
  assert.ok(lp, 'linuxParameters must be present');
  assert.ok(Array.isArray(lp.tmpfs) && lp.tmpfs.length > 0,
    'linuxParameters.tmpfs must be a non-empty array');

  const tmpMount = lp.tmpfs.find((e) => e.containerPath === '/tmp');
  assert.ok(tmpMount,
    `no tmpfs entry for /tmp; found: ${JSON.stringify(lp.tmpfs)}`);
  assert.ok(typeof tmpMount.size === 'number' && tmpMount.size > 0,
    `tmpfs /tmp size must be a positive number (MiB); got ${tmpMount.size}`);
  assert.ok(tmpMount.size >= 64,
    `tmpfs /tmp must be at least 64 MiB (CH-54 specifies 64); got ${tmpMount.size} MiB`);
});

// ── EFS-backed chariot-data volume (durable across restarts) ─────────────────

test('ECS taskdef — chariot-data volume uses efsVolumeConfiguration (durable)', () => {
  assert.ok(Array.isArray(taskdef.volumes), 'volumes must be an array');

  const chariotData = taskdef.volumes.find((v) => v.name === 'chariot-data');
  assert.ok(chariotData,
    `no volume named "chariot-data"; found: ${taskdef.volumes.map((v) => v.name).join(', ')}`);

  const efs = chariotData.efsVolumeConfiguration;
  assert.ok(efs, 'chariot-data volume must have efsVolumeConfiguration (not a plain tmpfs / host mount)');
  assert.ok(typeof efs.fileSystemId === 'string' && efs.fileSystemId.length > 0,
    'efsVolumeConfiguration.fileSystemId must be a non-empty string');
  assert.equal(efs.transitEncryption, 'ENABLED',
    'efsVolumeConfiguration.transitEncryption must be ENABLED');
});

// ── Healthcheck timeout alignment (CH-54 fix) ─────────────────────────────────
//
// Dockerfile HEALTHCHECK uses a 4 s HTTP timeout so the health probe exits
// before the task-definition healthCheck.timeout of 5 s fires. The CH-54 fix
// also adds .on('timeout', destroy) to ensure the socket is actually torn down
// and the Node process exits(1) cleanly instead of hanging to the 5 s wall
// deadline.

test('ECS taskdef — healthCheck command contains timeout:4000 (aligns with Dockerfile)', () => {
  const hc = container.healthCheck;
  assert.ok(hc, 'healthCheck must be defined');
  assert.ok(Array.isArray(hc.command), 'healthCheck.command must be an array');

  const cmdStr = hc.command.join(' ');
  assert.match(cmdStr, /timeout:4000/,
    `healthCheck command must contain "timeout:4000"; got: ${cmdStr}`);
});

test('ECS taskdef — healthCheck command contains .on(timeout,…destroy) (clean exit, CH-54)', () => {
  const cmdStr = container.healthCheck.command.join(' ');
  // The fix adds .on('timeout',function(){this.destroy();process.exit(1)}) so
  // a timed-out socket is destroyed before the 5 s task-level timeout fires.
  assert.match(cmdStr, /on.*timeout.*destroy/i,
    `healthCheck command must contain on('timeout'…destroy); got: ${cmdStr}`);
});

test('ECS taskdef — healthCheck outer timeout exceeds inner HTTP timeout', () => {
  const hc = container.healthCheck;
  // timeout field is in seconds; inner HTTP timeout is 4000 ms = 4 s.
  assert.ok(typeof hc.timeout === 'number',
    `healthCheck.timeout must be a number (seconds); got ${JSON.stringify(hc.timeout)}`);
  assert.ok(hc.timeout > 4,
    `healthCheck.timeout (${hc.timeout}s) must exceed the 4 s HTTP inner timeout`);
});
