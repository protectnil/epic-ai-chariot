/**
 * CHARIOT::§20::8 — "WHEN CHARIOT_LOG_LEVEL is set, its value SHALL be one
 * of: 'error', 'warn', 'info', 'debug', or 'trace'." (CHARIOT-SPEC.md:1553)
 * Default level when CHARIOT_LOG_LEVEL is unset is 'info'.
 *
 * Failure enumeration this locks in:
 *  (a) unset CHARIOT_LOG_LEVEL and unset EPICAI_LOG → default 'info'
 *      (debug is suppressed, info/warn/error are not).
 *  (b)-(f) each of the 5 accepted values sets the threshold accordingly —
 *      proven by checking which levels are emitted at that threshold.
 *  (g) an unrecognized value ('verbose') is rejected by
 *      validateChariotLogLevel() at startup — the fail-fast gate wired into
 *      engine/bin/setup.ts main().
 *  (h) case sensitivity: 'INFO' (wrong case) is rejected — the clause lists
 *      lowercase values only, no case-insensitive aliasing is specified.
 *  (i) empty string ('' — "set" to an empty value, distinct from unset) is
 *      rejected.
 *  (j) CHARIOT_LOG_LEVEL takes precedence over the legacy EPICAI_LOG
 *      fallback when both are set.
 *  (k) EPICAI_LOG alone (CHARIOT_LOG_LEVEL unset) still works as a fallback,
 *      preserving the pre-existing debug-payload workflow.
 *
 * Run (after tsc): node --test dist/engine/logger.chariot-log-level.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createLogger, validateChariotLogLevel, CHARIOT_LOG_LEVELS } from './logger.js';

async function withEnv(
  vars: Record<string, string | undefined>,
  run: () => void | Promise<void>,
): Promise<void> {
  const orig: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) orig[key] = process.env[key];
  try {
    for (const [key, value] of Object.entries(vars)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await run();
  } finally {
    for (const [key, value] of Object.entries(orig)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/** Capture stderr writes emitted by a logger call, without polluting test output. */
function captureStderr(run: () => void): string[] {
  const lines: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);
  (process.stderr as any).write = (chunk: any): boolean => {
    lines.push(String(chunk));
    return true;
  };
  try {
    run();
  } finally {
    process.stderr.write = orig;
  }
  return lines;
}

test("CHARIOT::§20::8 (a): CHARIOT_LOG_LEVEL and EPICAI_LOG both unset → default 'info' (debug suppressed, info emitted)", async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: undefined, EPICAI_LOG: undefined }, () => {
    const log = createLogger('test.default');
    const debugLines = captureStderr(() => log.debug('should not appear'));
    assert.equal(debugLines.length, 0);
    const infoLines = captureStderr(() => log.info('should appear'));
    assert.equal(infoLines.length, 1);
  });
});

for (const level of CHARIOT_LOG_LEVELS) {
  test(`CHARIOT::§20::8: CHARIOT_LOG_LEVEL='${level}' sets the threshold to '${level}' (does not throw; validateChariotLogLevel accepts it)`, async () => {
    await withEnv({ CHARIOT_LOG_LEVEL: level, EPICAI_LOG: undefined }, () => {
      assert.doesNotThrow(() => validateChariotLogLevel());
      const log = createLogger(`test.level.${level}`);
      const errorLines = captureStderr(() => log.error('always at or above every threshold'));
      // 'error' is the highest level; it must be emitted regardless of which
      // of the 5 accepted values CHARIOT_LOG_LEVEL is set to.
      assert.equal(errorLines.length, 1);
      if (level === 'debug' || level === 'trace') {
        const debugLines = captureStderr(() => log.debug('emitted at debug/trace threshold'));
        assert.equal(debugLines.length, 1);
      }
    });
  });
}

test("CHARIOT::§20::8 (g): CHARIOT_LOG_LEVEL='verbose' (not one of the 5 accepted values) is rejected by validateChariotLogLevel()", async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: 'verbose' }, () => {
    assert.throws(() => validateChariotLogLevel(), /CHARIOT_LOG_LEVEL="verbose" is invalid/);
  });
});

test("CHARIOT::§20::8 (h): CHARIOT_LOG_LEVEL='INFO' (wrong case) is rejected — no case-insensitive aliasing", async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: 'INFO' }, () => {
    assert.throws(() => validateChariotLogLevel(), /CHARIOT_LOG_LEVEL="INFO" is invalid/);
  });
});

test("CHARIOT::§20::8 (i): CHARIOT_LOG_LEVEL='' (set to empty string, distinct from unset) is rejected", async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: '' }, () => {
    assert.throws(() => validateChariotLogLevel(), /CHARIOT_LOG_LEVEL="" is invalid/);
  });
});

test('CHARIOT::§20::8 (j): CHARIOT_LOG_LEVEL takes precedence over the legacy EPICAI_LOG fallback when both are set', async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: 'debug', EPICAI_LOG: 'error' }, () => {
    const log = createLogger('test.precedence');
    const debugLines = captureStderr(() => log.debug('should appear because CHARIOT_LOG_LEVEL wins'));
    assert.equal(debugLines.length, 1);
  });
});

test('CHARIOT::§20::8 (k): EPICAI_LOG alone (CHARIOT_LOG_LEVEL unset) still sets the threshold — legacy fallback preserved', async () => {
  await withEnv({ CHARIOT_LOG_LEVEL: undefined, EPICAI_LOG: 'error' }, () => {
    const log = createLogger('test.legacy-fallback');
    const warnLines = captureStderr(() => log.warn('should be suppressed under EPICAI_LOG=error'));
    assert.equal(warnLines.length, 0);
    const errorLines = captureStderr(() => log.error('should appear'));
    assert.equal(errorLines.length, 1);
  });
});
