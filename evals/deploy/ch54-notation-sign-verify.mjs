/**
 * CH-54 adversarial eval — Attack 1 + Attack 2
 *
 * Attack 1 (sign→verify→tamper): generate a real RSA key and self-signed cert,
 * push a real OCI artifact to a local zot registry, sign it with the real
 * `notation` CLI, verify via verifyImageSeal() (NO mocked execFile), confirm
 * SUCCEEDED; then push a tampered artifact under the same tag and confirm
 * verifyImageSeal() returns FAILED with the notation-issued reason string.
 *
 * Attack 2 (trust-store discovery): prove that `notation verify` with
 * NOTATION_CONFIG pointing to a flat truststore/certs.pem does NOT succeed
 * (notation reads only the named x509/<type>/<name>/ layout), while the
 * correct named layout does succeed.
 *
 * Root cause of CH-54: without NOTATION_CONFIG set, notation falls back to its
 * default config location and cannot find the shipped trust material.
 *
 * Infrastructure required: $CHARIOT_NOTATION_BIN (default /tmp/notation),
 * $CHARIOT_ORAS_BIN (default /tmp/oras), $CHARIOT_ZOT_BIN (default /tmp/zot).
 * All three are real binaries — notation/oras/zot, NOT mocks. If any is absent
 * the suite exits 0 with a SKIP notice; it never passes vacuously.
 *
 * Tests run INSIDE a describe() block so they execute SEQUENTIALLY. Top-level
 * test() calls in node:test v26 run concurrently; mixing sync spawnSync tests
 * with async verifyImageSeal tests in the same concurrent group causes the
 * spawnSync calls to block the event loop while verifyImageSeal's execFile is
 * dispatching, which races against after() cleanup of the registry data dir.
 */

import { strict as assert } from 'node:assert';
import { describe, before, after, test } from 'node:test';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, spawn, execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(execFileCb);

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');

const NOTATION_BIN  = process.env.CHARIOT_NOTATION_BIN  || '/tmp/notation';
const ORAS_BIN      = process.env.CHARIOT_ORAS_BIN      || '/tmp/oras';
const ZOT_BIN       = process.env.CHARIOT_ZOT_BIN       || '/tmp/zot';
const REGISTRY_PORT = process.env.CHARIOT_ZOT_PORT      || '15055';
const REGISTRY_HOST = `127.0.0.1:${REGISTRY_PORT}`;

// ── Prerequisite check — exit 0 with notice rather than silently pass ────────

for (const [label, bin] of [['notation', NOTATION_BIN], ['oras', ORAS_BIN], ['zot', ZOT_BIN]]) {
  if (!existsSync(bin)) {
    console.log(`SKIP ch54-notation-sign-verify: ${label} binary not found at ${bin}`);
    process.exit(0);
  }
}

// Import verifyImageSeal (the function under test) at module level.
// This import runs once before any test infrastructure starts, so the
// module's side-effects (requiring @aws-sdk packages) happen before the
// zot process is spawned — no interference from module loading.
const { verifyImageSeal } = await import(
  join(ROOT, 'helm', 'chariot', 'ecs', 'lifecycle-hook', 'verify-image.mjs'),
);

/**
 * Real execFile adapter for local testing.
 *
 * This is NOT a mock. It calls the real notation binary via child_process
 * execFile with one extra flag: --insecure-registry. That flag is required
 * only because the test-only local zot registry serves plain HTTP; production
 * always targets TLS registries and never needs it.
 */
async function realExecFileInsecure(bin, args, opts) {
  return execFile(bin, [...args, '--insecure-registry'], opts);
}

/**
 * Fake ECS client for DescribeServiceRevisions. verifyImageSeal now binds
 * verification to the image ECS is ACTUALLY deploying (the service revision),
 * not the static hookDetails.imageReference. This stub returns the deploying
 * revision's container image so the verify target is the real signed artifact
 * in the local zot registry.
 */
function fakeEcsClient(imageDigest, image = `${REGISTRY_HOST}/chariot-test/img`) {
  return {
    send: async () => ({
      serviceRevisions: [
        { containerImages: [{ containerName: 'gateway', image, imageDigest }] },
      ],
    }),
  };
}

async function waitForRegistry(url, maxMs = 10000) {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.status === 200 || r.status === 401) return;
    } catch { /* not ready yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`registry not ready at ${url} after ${maxMs}ms`);
}

// ── Tests wrapped in describe() — tests run SEQUENTIALLY inside describe() ───
//
// Top-level test() calls in node:test v26 run concurrently. Using describe()
// with concurrency:false (the default) ensures sequential execution so that:
//   a) before() always completes and populates shared state before any test sees it
//   b) the sync spawnSync tests (2a, 2b) cannot block the event loop during
//      setup or during async tests (1a, 1b)
//   c) after() fires only when ALL sibling tests have completed

describe('CH-54 notation sign/verify/tamper + trust-store discovery', { concurrency: false }, () => {
  let zotProc   = null;
  let notationDir;
  let generatedCert;
  let digest1;
  let digest2;
  const tmpRoots = [];

  function makeTmpDir() {
    const d = mkdtempSync(join(tmpdir(), 'ch54-'));
    tmpRoots.push(d);
    return d;
  }

  before(async () => {
    // ── 1. Start a local zot OCI registry ────────────────────────────────────
    const zotRoot = makeTmpDir();
    const zotData = join(zotRoot, 'data');
    mkdirSync(zotData, { recursive: true });
    const zotCfg = join(zotRoot, 'zot.json');
    writeFileSync(zotCfg, JSON.stringify({
      distSpecVersion: '1.1.0',
      storage: { rootDirectory: zotData },
      http: { address: '127.0.0.1', port: REGISTRY_PORT },
      log: { level: 'warn' },
    }));
    zotProc = spawn(ZOT_BIN, ['serve', zotCfg], {
      stdio: 'pipe',
      detached: false,
    });
    // Drain stdout/stderr so zot doesn't hang on a full pipe buffer.
    zotProc.stdout.resume();
    zotProc.stderr.resume();

    await waitForRegistry(`http://${REGISTRY_HOST}/v2/`);

    // ── 2. Generate a real RSA key + self-signed cert with notation ───────────
    notationDir = makeTmpDir();
    const genResult = spawnSync(
      NOTATION_BIN,
      ['cert', 'generate-test', '--default', 'chariot-test'],
      { encoding: 'utf-8', env: { ...process.env, NOTATION_CONFIG: notationDir } },
    );
    assert.equal(genResult.status, 0,
      `notation cert generate-test failed: ${genResult.stderr}`);

    // The generated cert lives at localkeys/chariot-test.crt (CA type, named
    // store at truststore/x509/ca/chariot-test/).
    generatedCert = readFileSync(
      join(notationDir, 'localkeys', 'chariot-test.crt'), 'utf-8',
    );

    // Copy the cert to the signingAuthority layout that verify-image.mjs's
    // existsSync guard requires (notationTrustStorePaths defaults to
    // signingAuthority type with aws-signer-ts / aws-us-gov-signer-ts names).
    for (const name of ['aws-signer-ts', 'aws-us-gov-signer-ts']) {
      const dir = join(notationDir, 'truststore', 'x509', 'signingAuthority', name);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'certs.pem'), generatedCert);
    }

    // Write the trust policy referencing the CA store created by generate-test.
    // We use '*' trusted identity because the self-signed DN lacks the mandatory
    // C/ST/O attributes that a strict x509.subject filter requires.
    writeFileSync(join(notationDir, 'trustpolicy.json'), JSON.stringify({
      version: '1.0',
      trustPolicies: [{
        name: 'chariot-local-tp',
        registryScopes: ['*'],
        signatureVerification: { level: 'permissive' },
        trustStores: ['ca:chariot-test'],
        trustedIdentities: ['*'],
      }],
    }, null, 2));

    // ── 3. Push the original artifact via oras ────────────────────────────────
    const artifactDir = makeTmpDir();
    writeFileSync(join(artifactDir, 'artifact.txt'), 'chariot-gateway-seal-test-v1\n');

    const push1 = spawnSync(
      ORAS_BIN,
      ['push', `${REGISTRY_HOST}/chariot-test/img:v1`, 'artifact.txt', '--plain-http', '--no-tty'],
      { encoding: 'utf-8', cwd: artifactDir },
    );
    assert.equal(push1.status, 0, `oras push (original) failed: ${push1.stderr}`);

    const resolve1 = spawnSync(
      ORAS_BIN,
      ['resolve', `${REGISTRY_HOST}/chariot-test/img:v1`, '--plain-http'],
      { encoding: 'utf-8' },
    );
    assert.equal(resolve1.status, 0, `oras resolve (original) failed: ${resolve1.stderr}`);
    digest1 = resolve1.stdout.trim();
    assert.match(digest1, /^sha256:[a-f0-9]{64}$/, `malformed digest: ${digest1}`);

    // ── 4. Sign the original artifact with the real notation CLI ──────────────
    const signResult = spawnSync(
      NOTATION_BIN,
      ['sign', '--key', 'chariot-test',
        `${REGISTRY_HOST}/chariot-test/img@${digest1}`, '--insecure-registry'],
      { encoding: 'utf-8', env: { ...process.env, NOTATION_CONFIG: notationDir } },
    );
    assert.equal(signResult.status, 0,
      `notation sign failed: ${signResult.stderr}\n${signResult.stdout}`);

    // ── 5. Push a tampered artifact (different content → new digest) ──────────
    // IMPORTANT: use a DIFFERENT tag (:tampered, not :v1). Zot performs
    // immediate tag-based GC when a new manifest overwrites the same tag —
    // the old manifest becomes unreachable by digest (HTTP 404) even though
    // its content hash is still valid. Using a separate tag keeps digest1
    // accessible so tests 1a and 2b can still verify the signed artifact.
    writeFileSync(join(artifactDir, 'artifact.txt'), 'TAMPERED-supply-chain-payload-9x7k\n');
    const push2 = spawnSync(
      ORAS_BIN,
      ['push', `${REGISTRY_HOST}/chariot-test/img:tampered`, 'artifact.txt', '--plain-http', '--no-tty'],
      { encoding: 'utf-8', cwd: artifactDir },
    );
    assert.equal(push2.status, 0, `oras push (tampered) failed: ${push2.stderr}`);

    const resolve2 = spawnSync(
      ORAS_BIN,
      ['resolve', `${REGISTRY_HOST}/chariot-test/img:tampered`, '--plain-http'],
      { encoding: 'utf-8' },
    );
    assert.equal(resolve2.status, 0, `oras resolve (tampered) failed: ${resolve2.stderr}`);
    digest2 = resolve2.stdout.trim();
    assert.notEqual(digest1, digest2,
      `tampered artifact digest must differ from original; both are ${digest1}`);
  });

  after(() => {
    if (zotProc && !zotProc.killed) zotProc.kill('SIGTERM');
    for (const d of tmpRoots) {
      try { rmSync(d, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  // ── Attack 1a — sign→verify: verifyImageSeal SUCCEEDED (real notation) ──────

  test('Attack 1a — verifyImageSeal SUCCEEDED on signed artifact (real notation, no mock execFile)', async () => {
    // Strip ambient AWS_REGION so notationVerifyCommand emits no --plugin-config.
    // Without an AWS Signer plugin installed, adding --plugin-config to the
    // verify args would cause notation to error on an unrecognised plugin option.
    const savedRegion        = process.env.AWS_REGION;
    const savedDefaultRegion = process.env.AWS_DEFAULT_REGION;
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;

    try {
      const result = await verifyImageSeal(
        {
          hookDetails: {
            imageReference:  `${REGISTRY_HOST}/chariot-test/img@${digest1}`,
            notationBaseDir: notationDir,
            notationBinary:  NOTATION_BIN,
            stopTask:        false,
          },
          executionDetails: {
            serviceArn:               'arn:aws:ecs:us-east-1:000000000000:service/chariot/chariot-gateway',
            targetServiceRevisionArn: 'arn:aws:ecs:us-east-1:000000000000:service-revision/chariot/chariot-gateway/1',
          },
        },
        { execFile: realExecFileInsecure, ecsClient: fakeEcsClient(digest1) },
      );

      assert.equal(result.hookStatus, 'SUCCEEDED',
        `expected SUCCEEDED, got ${result.hookStatus}: ${JSON.stringify(result.hookDetails)}`);
      assert.match(result.hookDetails.verifiedImage, /sha256:/,
        'SUCCEEDED result must carry verifiedImage with digest');
    } finally {
      if (savedRegion        !== undefined) process.env.AWS_REGION         = savedRegion;
      if (savedDefaultRegion !== undefined) process.env.AWS_DEFAULT_REGION = savedDefaultRegion;
    }
  });

  // ── Attack 1b — tamper: verifyImageSeal FAILED (no sig for tampered digest) ─

  test('Attack 1b — verifyImageSeal FAILED on tampered artifact (real notation rejects unsigned digest)', async () => {
    const savedRegion        = process.env.AWS_REGION;
    const savedDefaultRegion = process.env.AWS_DEFAULT_REGION;
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;

    try {
      const result = await verifyImageSeal(
        {
          hookDetails: {
            imageReference:  `${REGISTRY_HOST}/chariot-test/img@${digest2}`,
            notationBaseDir: notationDir,
            notationBinary:  NOTATION_BIN,
            stopTask:        false,
          },
          executionDetails: {
            serviceArn:               'arn:aws:ecs:us-east-1:000000000000:service/chariot/chariot-gateway',
            targetServiceRevisionArn: 'arn:aws:ecs:us-east-1:000000000000:service-revision/chariot/chariot-gateway/1',
          },
        },
        { execFile: realExecFileInsecure, ecsClient: fakeEcsClient(digest2) },
      );

      assert.equal(result.hookStatus, 'FAILED',
        `expected FAILED on tampered digest, got ${result.hookStatus}`);
      assert.match(
        result.hookDetails.reason,
        /no signature is associated|verification failed|not found/i,
        `unexpected failure reason: ${result.hookDetails.reason}`,
      );
    } finally {
      if (savedRegion        !== undefined) process.env.AWS_REGION         = savedRegion;
      if (savedDefaultRegion !== undefined) process.env.AWS_DEFAULT_REGION = savedDefaultRegion;
    }
  });

  // ── Attack 1c — deploying-image binding: signed imageReference (digest1) but
  // the service revision ECS is actually deploying carries UNSIGNED digest2.
  // verifyImageSeal must verify the DEPLOYING artifact, not the config string,
  // and FAIL on the drift — this is the core CH-54 fix (guard the guarded
  // object, not a proxy).
  test('Attack 1c — imageReference (signed) that mismatches the deploying revision FAILS', async () => {
    const savedRegion        = process.env.AWS_REGION;
    const savedDefaultRegion = process.env.AWS_DEFAULT_REGION;
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;

    try {
      const result = await verifyImageSeal(
        {
          hookDetails: {
            // Config still pins the SIGNED digest1 …
            imageReference:  `${REGISTRY_HOST}/chariot-test/img@${digest1}`,
            notationBaseDir: notationDir,
            notationBinary:  NOTATION_BIN,
            stopTask:        false,
          },
          executionDetails: {
            serviceArn:               'arn:aws:ecs:us-east-1:000000000000:service/chariot/chariot-gateway',
            targetServiceRevisionArn: 'arn:aws:ecs:us-east-1:000000000000:service-revision/chariot/chariot-gateway/1',
          },
        },
        // … but ECS is deploying the UNSIGNED digest2.
        { execFile: realExecFileInsecure, ecsClient: fakeEcsClient(digest2) },
      );

      assert.equal(result.hookStatus, 'FAILED',
        `expected FAILED on imageReference/deploying-image drift, got ${result.hookStatus}`);
      assert.match(
        result.hookDetails.reason,
        /does not match any image in the deploying revision/i,
        `unexpected failure reason: ${result.hookDetails.reason}`,
      );
    } finally {
      if (savedRegion        !== undefined) process.env.AWS_REGION         = savedRegion;
      if (savedDefaultRegion !== undefined) process.env.AWS_DEFAULT_REGION = savedDefaultRegion;
    }
  });

  // ── Attack 2a — flat truststore must NOT satisfy notation ───────────────────

  test('Attack 2a — flat truststore/certs.pem NOT read by notation (named layout required)', () => {
    const flatDir = mkdtempSync(join(tmpdir(), 'ch54-flat-'));

    try {
      // Trust policy that references the named store — but the cert is at the WRONG path.
      writeFileSync(join(flatDir, 'trustpolicy.json'), JSON.stringify({
        version: '1.0',
        trustPolicies: [{
          name: 'flat-test-tp',
          registryScopes: ['*'],
          signatureVerification: { level: 'permissive' },
          trustStores: ['ca:chariot-test'],
          trustedIdentities: ['*'],
        }],
      }, null, 2));

      // Place the cert at the FLAT path — not the named x509/ca/<name>/ layout.
      mkdirSync(join(flatDir, 'truststore'), { recursive: true });
      writeFileSync(join(flatDir, 'truststore', 'certs.pem'), generatedCert);

      const result = spawnSync(
        NOTATION_BIN,
        ['verify', `${REGISTRY_HOST}/chariot-test/img@${digest1}`, '--insecure-registry'],
        { encoding: 'utf-8', env: { ...process.env, NOTATION_CONFIG: flatDir } },
      );
      assert.notEqual(result.status, 0,
        'notation verify must FAIL when cert is at flat truststore/certs.pem (not named layout)');
      const combined = result.stderr + result.stdout;
      // Notation must reject with a trust-material or trust-store related error,
      // not a network error (which would be a false pass).
      assert.match(combined, /trust|cert|store|policy|no signature|signature verification failed/i,
        `expected a trust-material error; got: ${combined}`);
    } finally {
      try { rmSync(flatDir, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  });

  // ── Attack 2b — named truststore MUST verify ─────────────────────────────────

  test('Attack 2b — named truststore/x509/ca/<name>/ layout is read by notation (verify PASSES)', () => {
    // notationDir already has cert at truststore/x509/ca/chariot-test/chariot-test.crt
    // from `notation cert generate-test` in before().
    const result = spawnSync(
      NOTATION_BIN,
      ['verify', `${REGISTRY_HOST}/chariot-test/img@${digest1}`, '--insecure-registry'],
      { encoding: 'utf-8', env: { ...process.env, NOTATION_CONFIG: notationDir } },
    );
    assert.equal(result.status, 0,
      `notation verify failed with named layout: ${result.stderr}\n${result.stdout}`);
    assert.match(result.stdout + result.stderr, /Successfully verified/,
      'expected "Successfully verified" in notation output');
  });
});
