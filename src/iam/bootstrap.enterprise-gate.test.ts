/**
 * CHARIOT::§18.2::1/2 — "Single-user mode: `npx @epicai/chariot` with no
 * `CHARIOT_ENTERPRISE=1`. Loads only the engine (no IAM, no MongoDB
 * requirement, no Redis requirement)." / "Enterprise mode:
 * `CHARIOT_ENTERPRISE=1 npx @epicai/chariot`. Loads the IAM service,
 * requires `ENTERPRISE_MASTER_KEY`, requires MongoDB, optionally uses Redis
 * (in-process fallback if absent)." (CHARIOT-SPEC.md:1463-1469)
 *
 * CHARIOT::§18.3::1 — "IF the master key is missing in enterprise mode THEN
 * the system SHALL fail-fast at startup (CH-19)." (CHARIOT-SPEC.md:1472)
 *
 * Mode selection (isEnterpriseModeRequested) and the master-key fail-fast
 * seam (requireMasterKeyForEnterpriseStartup) are the two integration seams
 * this unit changed that are exercisable without a native binary, MongoDB,
 * or Redis — the rest of bootstrapEnterprise() cannot run end-to-end in
 * this sandbox (see bootstrap.jwt-secret-floor.test.ts). The `serve --http`
 * CHARIOT_ENTERPRISE gate itself (engine/bin/setup.ts) delegates to
 * isEnterpriseEnvEnabled(), the exact function under test here, so proving
 * its failure-class enumeration proves the gate's behavior by construction.
 *
 * Failure enumeration for isEnterpriseModeRequested (value/alias):
 * (a) unset -> false (single-user); (b) '1' -> true; (c) 'true' -> true;
 * (d) 'TRUE' (case-insensitive) -> true; (e) ' 1 ' (whitespace-tolerant)
 * -> true; (f) '0' -> false; (g) 'yes' (look-alike truthy, must NOT
 * silently enable) -> false; (h) '2' -> false.
 *
 * Failure enumeration for requireMasterKeyForEnterpriseStartup:
 * (a) unset -> throws, prefixed "Enterprise startup failed: ";
 * (b) insecure default ('change-me') -> throws, same prefix;
 * (c) wrong decoded length -> throws, same prefix;
 * (d) a real 32-byte base64 key -> does not throw.
 *
 * Run (after tsc): node --test dist/iam/bootstrap.enterprise-gate.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { isEnterpriseModeRequested, requireMasterKeyForEnterpriseStartup } from './bootstrap.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

async function withEnv(name: string, value: string | undefined, run: () => void | Promise<void>): Promise<void> {
  const orig = process.env[name];
  try {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
    await run();
  } finally {
    if (orig !== undefined) process.env[name] = orig;
    else delete process.env[name];
  }
}

// ── isEnterpriseModeRequested — §18.2::1/2 mode selection ──────────────────

test('CHARIOT::§18.2::1 (a): CHARIOT_ENTERPRISE unset -> single-user (isEnterpriseModeRequested false)', async () => {
  await withEnv('CHARIOT_ENTERPRISE', undefined, () => {
    assert.equal(isEnterpriseModeRequested(), false);
  });
});

test('CHARIOT::§18.2::2 (b): CHARIOT_ENTERPRISE=1 -> enterprise requested (true)', async () => {
  await withEnv('CHARIOT_ENTERPRISE', '1', () => {
    assert.equal(isEnterpriseModeRequested(), true);
  });
});

test('CHARIOT::§18.2::2 (c): CHARIOT_ENTERPRISE=true -> enterprise requested (true)', async () => {
  await withEnv('CHARIOT_ENTERPRISE', 'true', () => {
    assert.equal(isEnterpriseModeRequested(), true);
  });
});

test('CHARIOT::§18.2::2 (d): CHARIOT_ENTERPRISE=TRUE (case-insensitive) -> true', async () => {
  await withEnv('CHARIOT_ENTERPRISE', 'TRUE', () => {
    assert.equal(isEnterpriseModeRequested(), true);
  });
});

test('CHARIOT::§18.2::2 (e): CHARIOT_ENTERPRISE=" 1 " (surrounding whitespace) -> true', async () => {
  await withEnv('CHARIOT_ENTERPRISE', ' 1 ', () => {
    assert.equal(isEnterpriseModeRequested(), true);
  });
});

test('CHARIOT::§18.2::1 (f): CHARIOT_ENTERPRISE=0 -> single-user (false)', async () => {
  await withEnv('CHARIOT_ENTERPRISE', '0', () => {
    assert.equal(isEnterpriseModeRequested(), false);
  });
});

test('CHARIOT::§18.2::1 (g): CHARIOT_ENTERPRISE=yes (look-alike truthy) must NOT silently enable -> false', async () => {
  await withEnv('CHARIOT_ENTERPRISE', 'yes', () => {
    assert.equal(isEnterpriseModeRequested(), false);
  });
});

test('CHARIOT::§18.2::1 (h): CHARIOT_ENTERPRISE=2 -> false', async () => {
  await withEnv('CHARIOT_ENTERPRISE', '2', () => {
    assert.equal(isEnterpriseModeRequested(), false);
  });
});

// ── requireMasterKeyForEnterpriseStartup — §18.3::1 fail-fast ─────────────

test('CHARIOT::§18.3::1 (a): unset ENTERPRISE_MASTER_KEY -> throws "Enterprise startup failed: ..."', async () => {
  await withEnv('ENTERPRISE_MASTER_KEY', undefined, () => {
    assert.throws(
      () => requireMasterKeyForEnterpriseStartup(),
      /Enterprise startup failed: ENTERPRISE_MASTER_KEY is not set/,
    );
  });
});

test('CHARIOT::§18.3::1 (b): insecure-default ENTERPRISE_MASTER_KEY -> throws "Enterprise startup failed: ..."', async () => {
  await withEnv('ENTERPRISE_MASTER_KEY', 'change-me', () => {
    assert.throws(
      () => requireMasterKeyForEnterpriseStartup(),
      /Enterprise startup failed: ENTERPRISE_MASTER_KEY is not set or is an insecure default/,
    );
  });
});

test('CHARIOT::§18.3::1 (c): ENTERPRISE_MASTER_KEY decoding to the wrong byte length -> throws "Enterprise startup failed: ..."', async () => {
  const wrongLength = randomBytes(16).toString('base64'); // 16 bytes, not 32
  await withEnv('ENTERPRISE_MASTER_KEY', wrongLength, () => {
    assert.throws(
      () => requireMasterKeyForEnterpriseStartup(),
      /Enterprise startup failed: ENTERPRISE_MASTER_KEY must decode to exactly 32 bytes/,
    );
  });
});

test('CHARIOT::§18.3::1 (d): a real 32-byte base64 ENTERPRISE_MASTER_KEY does not throw', async () => {
  const real = randomBytes(32).toString('base64');
  await withEnv('ENTERPRISE_MASTER_KEY', real, () => {
    assert.doesNotThrow(() => requireMasterKeyForEnterpriseStartup());
  });
});
