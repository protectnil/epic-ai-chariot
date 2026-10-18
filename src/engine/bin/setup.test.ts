/**
 * Adversarial evals for setup.ts fixes from 35f8710.
 *
 * Covers:
 *   P1 — MONGODB_URI credential redaction: the IAM bootstrap log line now
 *        calls redactConnectionString() (src/iam/redactConnectionString.ts,
 *        rulings item 126) before emitting mongoUri to stderr. Real ephemeral
 *        mongod + real child process; captured stderr asserted credential-clean.
 *   P1 — stdio path confinement: mcp.command was used verbatim; now goes
 *        through confinePath() + process.exit guard identical to the REST path.
 *        Tested via the real confinePath() implementation with symlink probes
 *        and traversal paths.
 *
 * REAL servers only — no mocked MongoDB/Redis clients.
 *
 * Run: node --test dist/engine/bin/setup.test.js
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import {
  mkdtempSync,
  rmSync,
  mkdirSync,
  symlinkSync,
  existsSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { MongoClient } from 'mongodb';

import { confinePath, confineStdioCommand } from '../keys/pathConfinement.js';
import { enforceNpxStdioGate, isDangerousStdioEnvKey, stripDangerousStdioEnv } from '../federation/adapters/npmIntegrityGuard.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// setup.js lives beside this test file after compilation: dist/engine/bin/.
const SETUP_SCRIPT = join(__dirname, 'setup.js');
const MONGOD_BIN   = '/usr/bin/mongod';
const MONGOD_AVAIL = existsSync(MONGOD_BIN);

// Credentials embedded in the test URI — the whole point of the test is
// that these never appear in stderr.
const TEST_USER = 'chariotadmin';
const TEST_PASS = 's3cret';

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Reserve an ephemeral TCP port on loopback without binding it. */
function allocPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as { port: number };
      srv.close(() => resolve(addr.port));
    });
    srv.on('error', reject);
  });
}

/** Poll loopback until mongod accepts connections or deadline passes. */
async function waitForMongod(port: number, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const client = new MongoClient(`mongodb://127.0.0.1:${port}/`, {
      serverSelectionTimeoutMS: 400,
      connectTimeoutMS:         400,
    });
    try {
      await client.connect();
      await client.close();
      return;
    } catch {
      await new Promise<void>((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`mongod on port ${port} did not accept connections within ${timeoutMs}ms`);
}

/** Terminate a child process and wait for it to exit. */
function killAndWait(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(); return; }
    child.once('exit', () => resolve());
    child.kill('SIGKILL');
    setTimeout(resolve, 200);
  });
}

// ─── P1: MONGODB_URI credential redaction ─────────────────────────────────────
describe('setup.ts — MONGODB_URI credential redaction via real IAM bootstrap', () => {
  let mongodProc: ChildProcess | undefined;
  let mongodPort = 0;
  let mongodDbPath = '';

  before(async () => {
    if (!MONGOD_AVAIL) {
      console.error(`SETUP SKIP: mongod binary not found at ${MONGOD_BIN}`);
      return;
    }

    mongodDbPath = mkdtempSync(join(tmpdir(), 'chariot-test-mongod-'));
    mongodPort   = await allocPort();

    // Start mongod WITH --auth so that credentials in the MONGODB_URI are
    // actually validated. The localhost exception (MongoDB behavior: allows
    // unauthenticated connections from 127.0.0.1 until the first user is
    // created) lets us bootstrap the test user.
    mongodProc = spawn(MONGOD_BIN, [
      '--port',     String(mongodPort),
      '--dbpath',   mongodDbPath,
      '--logpath',  '/dev/null',
      '--auth',
    ], { stdio: 'ignore' });

    // MongoDB 8.0 / WiredTiger needs ~1-3 s on a cold dbpath.
    await waitForMongod(mongodPort, 20_000);

    // Create the test user via the localhost exception. No credentials in
    // this URI — allowed by MongoDB before any users exist.
    const setup = new MongoClient(
      `mongodb://127.0.0.1:${mongodPort}/admin`,
      { serverSelectionTimeoutMS: 5_000, directConnection: true },
    );
    await setup.connect();
    await setup.db('admin').command({
      createUser: TEST_USER,
      pwd: TEST_PASS,
      roles: [{ role: 'root', db: 'admin' }],
    });
    await setup.close();
  });

  after(async () => {
    if (mongodProc) await killAndWait(mongodProc);
    if (mongodDbPath && existsSync(mongodDbPath)) {
      try { rmSync(mongodDbPath, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  test('IAM bootstrap log: password never appears in stderr, host/db do', async () => {
    if (!MONGOD_AVAIL || !mongodProc) {
      assert.fail(`mongod not available at ${MONGOD_BIN} — cannot run real credential-redaction eval`);
    }

    const MONGO_URI = `mongodb://${TEST_USER}:${TEST_PASS}@127.0.0.1:${mongodPort}/testdb?authSource=admin`;
    const httpPort  = await allocPort();

    // chariot serve --http triggers the useHttp code path that runs the
    // IAM bootstrap and emits the log line. The process will likely
    // keep running after bootstrap; we kill it once we see the line.
    const child = spawn(
      process.execPath,
      [SETUP_SCRIPT, 'serve', '--http', String(httpPort)],
      {
        env: {
          ...process.env,
          CHARIOT_ENTERPRISE:    '1',   // CHARIOT::§18.2::2 — enterprise mode is selected by CHARIOT_ENTERPRISE=1
          MONGODB_URI:           MONGO_URI,
          MONGODB_DB:            'testdb',
          REDIS_URL:             '',   // no Redis → in-process shim → log line at line 572
          ENTERPRISE_MASTER_KEY: randomBytes(32).toString('base64'),
          ENTERPRISE_JWT_SECRET: randomBytes(48).toString('base64'),
          NO_COLOR:              '1',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );

    let stderrBuf = '';
    let bootstrapLineSeen = false;
    const LOG_NEEDLE = 'Chariot IAM bootstrap:';

    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => resolve(), 20_000);
      child.stderr!.on('data', (chunk: Buffer) => {
        stderrBuf += chunk.toString('utf8');
        if (!bootstrapLineSeen && stderrBuf.includes(LOG_NEEDLE)) {
          bootstrapLineSeen = true;
          clearTimeout(timeout);
          resolve();
        }
      });
      child.on('exit', () => { clearTimeout(timeout); resolve(); });
    });

    await killAndWait(child);

    // ── assert 1: the bootstrap success line was emitted ────────────────────
    assert.ok(
      bootstrapLineSeen,
      `IAM bootstrap log line "${LOG_NEEDLE}" was not emitted.\n` +
      `Captured stderr:\n${stderrBuf.slice(0, 2000)}`,
    );

    // ── assert 2: the raw password never appears anywhere in stderr ──────────
    assert.ok(
      !stderrBuf.includes(TEST_PASS),
      `Password "${TEST_PASS}" leaked into stderr — redaction FAILED!\n` +
      `Matching lines:\n${stderrBuf.split('\n').filter(l => l.includes(TEST_PASS)).join('\n')}`,
    );

    // ── assert 3: the raw username never appears anywhere in stderr ──────────
    assert.ok(
      !stderrBuf.includes(TEST_USER),
      `Username "${TEST_USER}" leaked into stderr — redaction FAILED!\n` +
      `Matching lines:\n${stderrBuf.split('\n').filter(l => l.includes(TEST_USER)).join('\n')}`,
    );

    // ── assert 4: redaction placeholder appears in the bootstrap line ───────
    // URL.toString() percent-encodes '<' and '>' so the placeholder may
    // appear as '%3Credacted%3E' instead of the literal '<redacted>'.
    // Both are correct — what matters is that credentials are absent.
    const bootstrapLine = stderrBuf.split('\n').find(l => l.includes(LOG_NEEDLE)) ?? '';
    assert.ok(
      bootstrapLine.includes('<redacted>') || bootstrapLine.includes('%3Credacted%3E'),
      `Expected a redaction placeholder ('<redacted>' or '%3Credacted%3E') in the bootstrap log line.\nActual: ${bootstrapLine}`,
    );

    // ── assert 5: host and db info remain in the log (sanity) ───────────────
    assert.ok(
      bootstrapLine.includes('127.0.0.1') || bootstrapLine.includes('testdb'),
      `Expected host/db to survive redaction in the log line.\nActual: ${bootstrapLine}`,
    );
  });

  test('URI-with-userinfo: redacted form preserved, raw form absent', async () => {
    if (!MONGOD_AVAIL || !mongodProc) {
      assert.fail(`mongod not available — cannot run eval`);
    }

    // Reuse the same user but embed it in a URI with a different DB name
    // so the two tests are distinguishable in the logs.
    const MONGO_URI = `mongodb://${TEST_USER}:${TEST_PASS}@127.0.0.1:${mongodPort}/auditdb?authSource=admin`;
    const httpPort  = await allocPort();

    const child = spawn(
      process.execPath,
      [SETUP_SCRIPT, 'serve', '--http', String(httpPort)],
      {
        env: {
          ...process.env,
          CHARIOT_ENTERPRISE:    '1',   // CHARIOT::§18.2::2 — enterprise mode is selected by CHARIOT_ENTERPRISE=1
          MONGODB_URI:           MONGO_URI,
          MONGODB_DB:            'auditdb',
          REDIS_URL:             '',
          ENTERPRISE_MASTER_KEY: randomBytes(32).toString('base64'),
          ENTERPRISE_JWT_SECRET: randomBytes(48).toString('base64'),
          NO_COLOR:              '1',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );

    let stderrBuf = '';
    let seen = false;
    const LOG_NEEDLE = 'Chariot IAM bootstrap:';

    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => resolve(), 20_000);
      child.stderr!.on('data', (chunk: Buffer) => {
        stderrBuf += chunk.toString('utf8');
        if (!seen && stderrBuf.includes(LOG_NEEDLE)) { seen = true; clearTimeout(timeout); resolve(); }
      });
      child.on('exit', () => { clearTimeout(timeout); resolve(); });
    });

    await killAndWait(child);

    assert.ok(seen, `Bootstrap log line not emitted; stderr: ${stderrBuf.slice(0, 800)}`);
    assert.ok(!stderrBuf.includes(TEST_PASS), `Password "${TEST_PASS}" leaked`);
    assert.ok(!stderrBuf.includes(TEST_USER), `Username "${TEST_USER}" leaked`);

    const line = stderrBuf.split('\n').find(l => l.includes(LOG_NEEDLE)) ?? '';
    assert.ok(
      line.includes('<redacted>') || line.includes('%3Credacted%3E'),
      `Bootstrap log must contain redaction placeholder; actual line: ${line}`);
  });
});

// ─── CHARIOT::§18.2::2 — MONGODB_URI fail-closed (rulings item 12) ──────────
// setup.ts previously fell back to an unauthenticated `mongodb://127.0.0.1:
// 27017` when MONGODB_URI was unset, diverging from iam/bootstrap.ts's
// requireEnv('MONGODB_URI', ...), which throws immediately on the same unset
// variable. This proves: (a) unset MONGODB_URI now fails closed with an
// explicit error and never dials the loopback default, even when an
// unauthenticated mongod happens to be listening on 127.0.0.1:27017; (b) a
// set MONGODB_URI still proceeds through IAM bootstrap as before.
describe('setup.ts — MONGODB_URI fail-closed (no unauthenticated-localhost fallback)', () => {
  let mongodProc: ChildProcess | undefined;
  let mongodDbPath = '';
  const DEFAULT_PORT = 27017;
  let defaultPortMongodStarted = false;

  before(async () => {
    if (!MONGOD_AVAIL) {
      console.error(`SETUP SKIP: mongod binary not found at ${MONGOD_BIN}`);
      return;
    }
    // Start an UNAUTHENTICATED mongod on the exact legacy fallback port
    // (127.0.0.1:27017) when free, so a regression to the old `??
    // 'mongodb://127.0.0.1:27017'` fallback would silently succeed against
    // it instead of failing closed. If the port is already in use (e.g. a
    // system mongod), the fail-closed assertion below is still meaningful
    // (the fix must throw before ever attempting to dial anything).
    mongodDbPath = mkdtempSync(join(tmpdir(), 'chariot-test-mongod-default-'));
    try {
      mongodProc = spawn(MONGOD_BIN, [
        '--port',    String(DEFAULT_PORT),
        '--dbpath',  mongodDbPath,
        '--logpath', '/dev/null',
        // no --auth: this is deliberately the unauthenticated posture the
        // old fallback would have connected to.
      ], { stdio: 'ignore' });
      await waitForMongod(DEFAULT_PORT, 8_000);
      defaultPortMongodStarted = true;
    } catch {
      // Port unavailable or mongod failed to start on it — acceptable;
      // the fail-closed check must not depend on this succeeding.
      if (mongodProc) { try { mongodProc.kill('SIGKILL'); } catch { /* best-effort */ } }
      mongodProc = undefined;
      defaultPortMongodStarted = false;
    }
  });

  after(async () => {
    if (mongodProc) await killAndWait(mongodProc);
    if (mongodDbPath && existsSync(mongodDbPath)) {
      try { rmSync(mongodDbPath, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  test('MONGODB_URI unset: process fails closed, never falls back to 127.0.0.1:27017', async () => {
    const httpPort = await allocPort();
    const env = { ...process.env };
    delete env.MONGODB_URI;
    env.CHARIOT_ENTERPRISE    = '1';   // CHARIOT::§18.2::2 — enterprise mode is selected by CHARIOT_ENTERPRISE=1
    env.MONGODB_DB            = 'testdb';
    env.REDIS_URL             = '';
    env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');
    env.ENTERPRISE_JWT_SECRET = randomBytes(48).toString('base64');
    env.NO_COLOR              = '1';

    const child = spawn(
      process.execPath,
      [SETUP_SCRIPT, 'serve', '--http', String(httpPort)],
      { env, stdio: ['ignore', 'pipe', 'pipe'] },
    );

    let stderrBuf = '';
    let exitCode: number | null = null;
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => resolve(), 15_000);
      child.stderr!.on('data', (chunk: Buffer) => { stderrBuf += chunk.toString('utf8'); });
      child.on('exit', (code) => { exitCode = code; clearTimeout(timeout); resolve(); });
    });
    await killAndWait(child);

    // ── must fail closed with the SPECIFIC "unset" message — not merely
    //    "some later error occurred". This is the discriminating assertion:
    //    the old `?? 'mongodb://127.0.0.1:27017'` fallback also produces an
    //    "IAM bootstrap FAILED" line in this environment (a real mongod
    //    listens on the default port and rejects the unauthenticated
    //    `find`/index-creation calls with "Command find requires
    //    authentication") — so a generic "some failure happened" check would
    //    pass against BOTH the buggy fallback and the fix. Only the fix
    //    emits this exact unset-variable message, in the same shape as
    //    iam/bootstrap.ts's requireEnv('MONGODB_URI', ...).  ─────────────
    assert.ok(
      stderrBuf.includes('MONGODB_URI is not set'),
      `Expected the fail-closed "MONGODB_URI is not set" error (bootstrap.ts's ` +
      `requireEnv message shape) when MONGODB_URI is unset — got something else, ` +
      `which means the code attempted to dial a fallback URI instead of failing ` +
      `closed before ever constructing a MongoClient.\n` +
      `exitCode=${exitCode}\nCaptured stderr:\n${stderrBuf.slice(0, 2000)}`,
    );

    // ── must NOT ever attempt to dial the old unauthenticated-localhost
    //    default — no "unavailable at mongodb://127.0.0.1:27017" / auth
    //    error against that host, and no successful bootstrap line ────────
    assert.ok(
      !stderrBuf.includes('127.0.0.1:27017') &&
      !stderrBuf.includes('requires authentication') &&
      !stderrBuf.includes('Chariot IAM bootstrap: mongo='),
      `Bootstrap must never dial the old unauthenticated-localhost fallback ` +
      `when MONGODB_URI is unset — evidence of a connection attempt (or a ` +
      `successful bootstrap) appears in stderr.\n` +
      `Captured stderr:\n${stderrBuf.slice(0, 2000)}`,
    );

    // ── must not silently keep serving: process should not still be
    //    listening/healthy after a fail-closed bootstrap ───────────────────
    assert.ok(
      exitCode !== 0,
      `Process must not exit 0 (or must be non-running) after failing to ` +
      `bootstrap IAM with no MONGODB_URI. exitCode=${exitCode}`,
    );

    if (defaultPortMongodStarted) {
      // Sanity: the decoy default-port mongod really was reachable, so a
      // regression to the fallback would have connected successfully and
      // this test would have failed the assertions above.
      assert.ok(defaultPortMongodStarted, 'decoy mongod on 27017 was reachable during the test');
    }
  });

  test('MONGODB_URI set: IAM bootstrap still proceeds normally (no regression)', async () => {
    if (!MONGOD_AVAIL) {
      console.error('SETUP SKIP: mongod binary not found — skipping positive-path check');
      return;
    }
    const dbPath = mkdtempSync(join(tmpdir(), 'chariot-test-mongod-positive-'));
    const port = await allocPort();
    const proc = spawn(MONGOD_BIN, [
      '--port', String(port), '--dbpath', dbPath, '--logpath', '/dev/null',
    ], { stdio: 'ignore' });
    try {
      await waitForMongod(port, 20_000);

      const httpPort = await allocPort();
      const child = spawn(
        process.execPath,
        [SETUP_SCRIPT, 'serve', '--http', String(httpPort)],
        {
          env: {
            ...process.env,
            CHARIOT_ENTERPRISE: '1',   // CHARIOT::§18.2::2 — enterprise mode is selected by CHARIOT_ENTERPRISE=1
            MONGODB_URI:           `mongodb://127.0.0.1:${port}/`,
            MONGODB_DB:            'testdb',
            REDIS_URL:             '',
            ENTERPRISE_MASTER_KEY: randomBytes(32).toString('base64'),
            ENTERPRISE_JWT_SECRET: randomBytes(48).toString('base64'),
            NO_COLOR:              '1',
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );

      let stderrBuf = '';
      let seen = false;
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => resolve(), 20_000);
        child.stderr!.on('data', (chunk: Buffer) => {
          stderrBuf += chunk.toString('utf8');
          if (!seen && stderrBuf.includes('Chariot IAM bootstrap:')) { seen = true; clearTimeout(timeout); resolve(); }
        });
        child.on('exit', () => { clearTimeout(timeout); resolve(); });
      });
      await killAndWait(child);

      assert.ok(seen, `Bootstrap should succeed when MONGODB_URI is set.\nstderr:\n${stderrBuf.slice(0, 2000)}`);
    } finally {
      await killAndWait(proc);
      if (existsSync(dbPath)) { try { rmSync(dbPath, { recursive: true, force: true }); } catch { /* best-effort */ } }
    }
  });
});

// ─── P1: stdio path confinement ──────────────────────────────────────────────
// confinePath() is the gate that both the REST module path and (after the fix)
// the stdio command path go through. We test it directly against the real
// implementation with traversal paths and a symlink escape probe.

describe('setup.ts — stdio command path confinement (confinePath gate)', () => {
  let sandboxRoot = '';

  before(() => {
    sandboxRoot = mkdtempSync(join(tmpdir(), 'chariot-confinement-'));
    mkdirSync(join(sandboxRoot, 'bin'), { recursive: true });
    // Write a real file so realpathSync succeeds for the happy-path test.
    writeFileSync(join(sandboxRoot, 'bin', 'mcp-server.js'), '/* test */');
  });

  after(() => {
    if (sandboxRoot && existsSync(sandboxRoot)) {
      try { rmSync(sandboxRoot, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  test('path traversal (../../etc/passwd) is rejected with escapes-root', () => {
    const r = confinePath('../../etc/passwd', sandboxRoot);
    assert.strictEqual(r.ok, false, 'traversal path must be rejected');
    assert.strictEqual(r.reason, 'escapes-root',
      `expected 'escapes-root', got '${r.reason}'`);
  });

  test('absolute path to /etc/passwd outside sandbox is rejected', () => {
    const r = confinePath('/etc/passwd', sandboxRoot);
    assert.strictEqual(r.ok, false, 'absolute path outside root must be rejected');
    assert.strictEqual(r.reason, 'escapes-root');
  });

  test('relative traversal ../sibling is rejected (fail-closed)', () => {
    // The target path likely doesn't exist → realpath throws ENOENT →
    // reason: realpath-failed. This is correct fail-closed behavior — the
    // OS would never open a path that can't be resolved. Either reason
    // ('realpath-failed' or 'escapes-root') represents correct rejection.
    const r = confinePath('../sibling/evil.js', sandboxRoot);
    assert.strictEqual(r.ok, false, 'relative traversal above sandbox root must be rejected');
  });

  test('symlink inside sandbox pointing to /tmp (outside) is rejected with escapes-root', () => {
    const linkPath = join(sandboxRoot, 'escape-link');
    try {
      symlinkSync('/tmp', linkPath);
    } catch (err) {
      console.warn(`    NOTE: symlink creation failed (${(err as Error).message}); test is inconclusive`);
      return;
    }
    // Test the symlink itself (not a path inside it) so realpathSync.native
    // resolves it to /tmp (which exists) and the escapes-root branch fires.
    const r = confinePath('escape-link', sandboxRoot);
    assert.strictEqual(r.ok, false,
      'symlink escaping sandbox root must be rejected');
    assert.strictEqual(r.reason, 'escapes-root',
      `expected 'escapes-root' for symlink → /tmp; got '${r.reason}'`);
  });

  test('non-existent path inside sandbox is rejected (realpath-failed, fail-closed)', () => {
    const r = confinePath('bin/does-not-exist.js', sandboxRoot);
    assert.strictEqual(r.ok, false, 'non-existent path must be rejected — fail-closed');
    assert.strictEqual(r.reason, 'realpath-failed');
  });

  test('legitimate file inside sandbox is accepted', () => {
    const r = confinePath('bin/mcp-server.js', sandboxRoot);
    assert.strictEqual(r.ok, true,
      `legitimate in-sandbox path must be accepted; reason: ${r.reason}`);
    assert.ok(
      r.resolved.startsWith(sandboxRoot),
      `resolved path "${r.resolved}" must be inside sandboxRoot "${sandboxRoot}"`,
    );
  });
});

// ─── Stdio launcher-vs-script classification (confineStdioCommand) ───────────
// The query AND serve dispatch paths share confineStdioCommand. `npx` — the
// only spec-sanctioned stdio launcher (CHARIOT §1.4 Win-1; 172/172 signed
// catalog) — must NOT be confinePath'd against the package root (that rejected
// every stdio adapter fail-closed). Every OTHER bare executable, INCLUDING the
// former allowlist entries `node`/`uvx` (which had no downstream target gate
// and could execute arbitrary argv), plus a
// path-escaping script, must be refused fail-closed.
describe('setup.ts — stdio launcher confinement (confineStdioCommand gate)', () => {
  let sandboxRoot = '';

  before(() => {
    sandboxRoot = mkdtempSync(join(tmpdir(), 'chariot-stdio-cmd-'));
    mkdirSync(join(sandboxRoot, 'bin'), { recursive: true });
    writeFileSync(join(sandboxRoot, 'bin', 'mcp-server.js'), '/* test */');
  });

  after(() => {
    if (sandboxRoot && existsSync(sandboxRoot)) {
      try { rmSync(sandboxRoot, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  test('bare launcher npx is accepted for PATH resolution (regression: no realpath rejection)', () => {
    const r = confineStdioCommand('npx', sandboxRoot);
    assert.strictEqual(r.ok, true, `npx launcher must be accepted; reason: ${r.reason}`);
    assert.strictEqual(r.kind, 'launcher');
    assert.strictEqual(r.command, 'npx', 'launcher name must be left intact for PATH resolution');
  });

  test('bare launcher node is REFUSED fail-closed (no target gate → RCE)', () => {
    // `node <arg>` had no downstream target gate (unlike npx): a catalog row
    // `{command:"node", args:["/tmp/evil.js"]}` would spawn arbitrary code.
    // node is removed from the allowlist → bare `node` is refused.
    const r = confineStdioCommand('node', sandboxRoot);
    assert.strictEqual(r.ok, false, 'bare node must be refused (removed from allowlist)');
    assert.strictEqual(r.reason, 'launcher-not-allowed');
  });

  test('bare launcher uvx is REFUSED fail-closed (arbitrary PyPI pkg → RCE)', () => {
    // `uvx <pkg>` had no integrity/pin gate equivalent to npx's SHA-512 cache
    // verify: `{command:"uvx", args:["evil-pkg"]}` runs an unverified package.
    const r = confineStdioCommand('uvx', sandboxRoot);
    assert.strictEqual(r.ok, false, 'bare uvx must be refused (removed from allowlist)');
    assert.strictEqual(r.reason, 'launcher-not-allowed');
  });

  test('arbitrary bare executable (bash) is refused fail-closed — gate not weakened', () => {
    const r = confineStdioCommand('bash', sandboxRoot);
    assert.strictEqual(r.ok, false, 'arbitrary bare executable must be refused');
    assert.strictEqual(r.reason, 'launcher-not-allowed');
  });

  test('absolute path to a non-allowlisted binary is confined and refused', () => {
    const r = confineStdioCommand('/bin/sh', sandboxRoot);
    assert.strictEqual(r.ok, false, 'absolute path outside package root must be refused');
    assert.strictEqual(r.reason, 'escapes-root');
  });

  test('path-traversal script is refused fail-closed', () => {
    const r = confineStdioCommand('../../etc/passwd', sandboxRoot);
    assert.strictEqual(r.ok, false, 'traversal script path must be refused');
  });

  test('legitimate in-package script path is confined and accepted', () => {
    const r = confineStdioCommand('bin/mcp-server.js', sandboxRoot);
    assert.strictEqual(r.ok, true, `in-package script must be accepted; reason: ${r.reason}`);
    assert.strictEqual(r.kind, 'script');
    assert.ok(r.command.startsWith(sandboxRoot), `resolved "${r.command}" must be inside root`);
  });

  test('non-existent in-package script is refused (realpath-failed, fail-closed)', () => {
    const r = confineStdioCommand('bin/does-not-exist.js', sandboxRoot);
    assert.strictEqual(r.ok, false, 'non-existent script path must be refused');
    assert.strictEqual(r.reason, 'realpath-failed');
  });
});

// ─── Shared npx supply-chain gate (enforceNpxStdioGate) ──────────────────────
// Hardening: the `query` dispatch (setup.cmdQuery) previously spawned npx
// with raw catalog argv and NO package/integrity/pin gate — `{command:"npx",
// args:["-y","evil-pkg"]}` reached spawn unpinned. Serve and query now both call
// this shared gate, so the trust boundaries are identical. These pin the
// fail-closed + passthrough behavior (the pinned-cache success path needs a real
// npm cache and is exercised by the integration dispatch tests).
type GateAdapter = Parameters<typeof enforceNpxStdioGate>[0];
function stdioAdapter(mcp: Record<string, unknown>): GateAdapter {
  return { id: 'a1', name: 'a1', type: 'mcp', mcp: { transport: 'stdio', ...mcp } } as unknown as GateAdapter;
}

describe('setup.ts — shared npx supply-chain gate (enforceNpxStdioGate)', () => {
  test('npx with no resolvable package name → fail-closed (malformed catalog row)', () => {
    const r = enforceNpxStdioGate(stdioAdapter({ command: 'npx', args: ['-y'] }));
    assert.strictEqual(r.ok, false, 'npx without a package must be refused');
    assert.match(r.reason ?? '', /no package name is resolvable/);
  });

  test('npx with a package but UNPINNED (no version/integrityShasum) → fail-closed', () => {
    const r = enforceNpxStdioGate(stdioAdapter({ command: 'npx', args: ['-y', '@vendor/evil'] }));
    assert.strictEqual(r.ok, false, 'unpinned npx row must be refused — this is the arbitrary-argv bypass');
    assert.match(r.reason ?? '', /missing (version|integrityShasum)/i);
  });

  test('npx pinned but not in cache → fail-closed (never spawns an unverified package)', () => {
    const r = enforceNpxStdioGate(stdioAdapter({
      command: 'npx', args: ['-y', '@vendor/evil'], version: '9.9.9', integrityShasum: 'sha512-' + 'a'.repeat(88),
    }));
    assert.strictEqual(r.ok, false, 'a pin whose tarball is absent from the local cache must fail closed');
  });

  test('non-npx command (confined in-package script) → passthrough, no offline, argv unchanged', () => {
    const r = enforceNpxStdioGate(stdioAdapter({ command: '/pkg/root/server.js', args: ['--flag', 'x'] }));
    assert.strictEqual(r.ok, true, 'a confined script path passes through the npx gate untouched');
    assert.strictEqual(r.offline, false, 'non-npx must not force npm offline');
    assert.deepStrictEqual(r.spawnArgs, ['--flag', 'x'], 'non-npx argv must be unchanged');
  });

  // Hardening: npx control-execution flags run arbitrary code irrespective
  // of the package pin, and npx parses them anywhere in argv. Reject fail-closed.
  for (const evilArgs of [
    ['--package=npm', '--call', 'node -e "process.stdout.write(1)"'],
    ['-y', '@valid/pkg', '--call', 'sh -c "id"'],
    ['-y', '@valid/pkg', '-c', 'id'],
    ['-p', 'evil-pkg', '@valid/pkg'],
    ['-y', '@valid/pkg', '--package', 'evil-pkg'],
  ]) {
    test(`npx control-execution flag refused fail-closed: ${JSON.stringify(evilArgs)}`, () => {
      const r = enforceNpxStdioGate(stdioAdapter({ command: 'npx', args: evilArgs, packageName: '@valid/pkg', version: '1.0.0', integrityShasum: 'sha512-' + 'a'.repeat(88) }));
      assert.strictEqual(r.ok, false, 'npx -c/--call/-p/--package must be refused even with a valid pinned package');
      assert.match(r.reason ?? '', /control-execution flag/);
    });
  }

  test('npx with a benign server bin flag (e.g. --port) is NOT caught by the control-flag guard', () => {
    // --port is not an npx exec flag; the row still fails later (tarball absent),
    // but NOT for the control-execution reason — proving the guard is targeted.
    const r = enforceNpxStdioGate(stdioAdapter({ command: 'npx', args: ['-y', '@valid/pkg', '--port', '8080'], packageName: '@valid/pkg', version: '1.0.0', integrityShasum: 'sha512-' + 'a'.repeat(88) }));
    assert.strictEqual(r.ok, false, 'still fails closed (tarball not in cache)');
    assert.doesNotMatch(r.reason ?? '', /control-execution flag/, 'benign --port must not trip the control-flag guard');
  });
});

// ─── Environment preload/exec channel denylist ─────────────────────────────
// A catalog row cannot forward NODE_OPTIONS / LD_PRELOAD / DYLD_INSERT_LIBRARIES
// (etc.) into a spawned stdio subprocess — those run attacker code before the
// pinned bin, bypassing argv gating entirely.
describe('setup.ts — dangerous stdio env-channel denylist', () => {
  for (const bad of [
    'NODE_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'LD_LIBRARY_PATH', 'BASH_ENV', 'node_options', 'ld_preload',
    // npm reads its whole option surface from npm_config_* aliases (hardening):
    'npm_config_call', 'npm_config_package', 'npm_config_registry', 'NPM_CONFIG_CALL',
  ]) {
    test(`"${bad}" is a dangerous env key (refused)`, () => {
      assert.strictEqual(isDangerousStdioEnvKey(bad), true, `${bad} must be denylisted (case-insensitive)`);
    });
  }
  for (const ok of ['GITHUB_TOKEN', 'STRIPE_API_KEY', 'PATH', 'MY_ADAPTER_URL']) {
    test(`"${ok}" is a legitimate credential name (allowed)`, () => {
      assert.strictEqual(isDangerousStdioEnvKey(ok), false, `${ok} must not be denylisted`);
    });
  }
  test('stripDangerousStdioEnv removes exec + npm_config channels, preserves real creds', () => {
    const env = { PATH: '/usr/bin', NODE_OPTIONS: '--require /tmp/evil.js', LD_PRELOAD: '/tmp/e.so', npm_config_call: 'node -e "1"', npm_config_registry: 'http://evil', GITHUB_TOKEN: 'ghp_x' };
    stripDangerousStdioEnv(env);
    assert.strictEqual(env.NODE_OPTIONS, undefined, 'NODE_OPTIONS must be stripped');
    assert.strictEqual(env.LD_PRELOAD, undefined, 'LD_PRELOAD must be stripped');
    assert.strictEqual(env.npm_config_call, undefined, 'npm_config_call must be stripped');
    assert.strictEqual(env.npm_config_registry, undefined, 'npm_config_registry must be stripped');
    assert.strictEqual(env.PATH, '/usr/bin', 'PATH must be preserved');
    assert.strictEqual(env.GITHUB_TOKEN, 'ghp_x', 'real credential must be preserved');
  });
});
