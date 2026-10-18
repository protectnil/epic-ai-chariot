/**
 * CHARIOT::§3.1::8 — "The system SHALL write wizard and health-check logs
 * to ~/.epic-ai/logs/ (Chariot-process-owned), with Loki-style emission
 * also available." (CHARIOT-SPEC.md:191).
 *
 * Failure classes enumerated from the clause and closed here:
 *   - opt-in: a logger created WITHOUT { logFile: true } must never write a
 *     file (the high-frequency dispatch-path loggers must not gain a
 *     per-call disk write merely by importing this module)
 *   - opt-in enabled: a logger created WITH { logFile: true } appends a
 *     line under LOGS_DIR, honoring EPIC_AI_DIR_OVERRIDE like every other
 *     ~/.epic-ai path
 *   - level gating: a level below the configured minimum still does not
 *     write to the file (mirrors the existing stderr/Loki gating)
 *   - first-run: LOGS_DIR does not exist yet — must be created on demand,
 *     never throw
 *   - multiple components get separate files, never cross-contaminating
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// createLogger's file sink resolves LOGS_DIR from EPIC_AI_DIR_OVERRIDE at
// import time (via cli/paths.ts), so the override must be set before the
// first import of logger.ts in this process.
const sandbox = mkdtempSync(join(tmpdir(), 'chariot-logger-filesink-test-'));
process.env.EPIC_AI_DIR_OVERRIDE = sandbox;

const { createLogger } = await import('./logger.js');
const { LOGS_DIR } = await import('../cli/paths.js');

function logFileFor(component: string): string {
  return join(LOGS_DIR, `${component}.log`);
}

test('createLogger without { logFile: true } never writes a log file', () => {
  const log = createLogger('test.no-file-sink', 'debug');
  log.warn('should not hit disk', { x: 1 });
  assert.equal(existsSync(logFileFor('test.no-file-sink')), false);
});

test('createLogger with { logFile: true } appends a line under LOGS_DIR', () => {
  const log = createLogger('test.wizard-like', 'info', { logFile: true });
  log.info('wizard.started', { foo: 'bar' });
  const file = logFileFor('test.wizard-like');
  assert.ok(existsSync(file), `expected ${file} to exist`);
  const contents = readFileSync(file, 'utf-8');
  assert.ok(contents.includes('wizard.started'));
  assert.ok(contents.includes('"foo":"bar"'));
});

test('file sink respects the configured log level (below-threshold messages are not written)', () => {
  const log = createLogger('test.level-gated', 'warn', { logFile: true });
  log.debug('should be suppressed', {});
  log.info('should also be suppressed', {});
  const file = logFileFor('test.level-gated');
  if (existsSync(file)) {
    const contents = readFileSync(file, 'utf-8');
    assert.ok(!contents.includes('should be suppressed'));
    assert.ok(!contents.includes('should also be suppressed'));
  }
  // Absence of the file entirely is also a valid pass — nothing at/above
  // 'warn' was logged yet.
  log.warn('this one should land', {});
  assert.ok(existsSync(file));
  const contents = readFileSync(file, 'utf-8');
  assert.ok(contents.includes('this one should land'));
  assert.ok(!contents.includes('should be suppressed'));
});

test('LOGS_DIR is created on demand when it does not exist yet', () => {
  rmSync(LOGS_DIR, { recursive: true, force: true });
  assert.equal(existsSync(LOGS_DIR), false, 'precondition: LOGS_DIR must be absent');
  const log = createLogger('test.first-run', 'info', { logFile: true });
  assert.doesNotThrow(() => log.info('created on demand', {}));
  assert.ok(existsSync(LOGS_DIR));
  assert.ok(existsSync(logFileFor('test.first-run')));
});

test('two components get separate log files', () => {
  const a = createLogger('test.component-a', 'info', { logFile: true });
  const b = createLogger('test.component-b', 'info', { logFile: true });
  a.info('from a', {});
  b.info('from b', {});
  const aContents = readFileSync(logFileFor('test.component-a'), 'utf-8');
  const bContents = readFileSync(logFileFor('test.component-b'), 'utf-8');
  assert.ok(aContents.includes('from a'));
  assert.ok(!aContents.includes('from b'));
  assert.ok(bContents.includes('from b'));
  assert.ok(!bContents.includes('from a'));
});
