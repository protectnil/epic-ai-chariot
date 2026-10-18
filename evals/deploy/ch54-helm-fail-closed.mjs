/**
 * CH-54 adversarial eval — Attack 3
 *
 * Helm chart fail-closed gate: exercises the chariot.assertImageVerifyFailClosed
 * helper added in 5ddcb7f. Rules under test:
 *
 *   - Enforce + Fail (secure defaults) → `helm template` renders successfully.
 *   - Audit (weakened validationFailureAction) → ABORTS with CH-54 message.
 *   - Ignore (weakened failurePolicy) → ABORTS with CH-54 message.
 *   - break-glass (allowInsecureAdmissionMode=true) → renders despite Audit/Ignore.
 *
 * Uses the real helm binary at $CHARIOT_HELM_BIN or /tmp/helmbin/linux-amd64/helm.
 * If helm is not found the suite exits 0 with a SKIP notice — never vacuously passes.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { existsSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT  = join(__dirname, '..', '..');
const CHART = join(ROOT, 'helm', 'chariot');

const HELM = (() => {
  for (const bin of [
    process.env.CHARIOT_HELM_BIN,
    '/tmp/helmbin/linux-amd64/helm',
    'helm',
  ].filter(Boolean)) {
    const r = spawnSync(bin, ['version', '--short'], { encoding: 'utf-8' });
    if (r.status === 0) return bin;
  }
  return null;
})();

if (!HELM) {
  console.log('SKIP ch54-helm-fail-closed: helm binary not found');
  process.exit(0);
}

// Strong credentials that satisfy CH-28 gates so renders reach the CH-54 gate.
const STRONG = 'Str0ng-Eval-Pass-9f3a2b71!';

const BASE_VALID = [
  // CH-29: the chart aborts when no image registry resolves (never Docker Hub).
  '--set', 'global.imageRegistry=000000000000.dkr.ecr.us-east-1.amazonaws.com',
  '--set', 'gateway.existingSecret=chariot-gateway-secret',
  '--set', `mongodb.auth.rootPassword=${STRONG}`,
  '--set', `redis.auth.password=${STRONG}`,
];

function render(extraArgs) {
  return spawnSync(
    HELM,
    ['template', 'chariot', CHART, ...BASE_VALID, ...extraArgs],
    { encoding: 'utf-8' },
  );
}

function assertRenderOk(extraArgs, description) {
  const r = render(extraArgs);
  assert.equal(r.status, 0,
    `${description}: expected successful render, got status ${r.status}\nstderr: ${r.stderr}`);
  return r;
}

function assertAbortCH54(extraArgs, weakenedField, description) {
  const r = render(extraArgs);
  assert.notEqual(r.status, 0,
    `${description}: expected ABORT (non-zero exit), got status 0`);
  assert.match(r.stderr, /CH-54/,
    `${description}: stderr must contain "CH-54" fail-closed message\nstderr: ${r.stderr}`);
  assert.match(r.stderr, new RegExp(weakenedField, 'i'),
    `${description}: stderr must mention the weakened field "${weakenedField}"\nstderr: ${r.stderr}`);
}

// ── Test: Enforce + Fail renders (secure default) ────────────────────────────

test('CH-54 helm — Enforce+Fail renders (secure defaults)', () => {
  const r = assertRenderOk(
    [
      '--set', 'imageVerification.kyverno.validationFailureAction=Enforce',
      '--set', 'imageVerification.kyverno.failurePolicy=Fail',
    ],
    'Enforce+Fail',
  );
  // Confirm the ClusterPolicy is in the rendered output.
  assert.match(r.stdout, /kind: ClusterPolicy/, 'rendered output must include ClusterPolicy');
});

// ── Test: Audit aborts with CH-54 message ────────────────────────────────────

test('CH-54 helm — Audit aborts with CH-54 fail-closed message', () => {
  assertAbortCH54(
    ['--set', 'imageVerification.kyverno.validationFailureAction=Audit'],
    'Audit',
    'validationFailureAction=Audit',
  );
});

// ── Test: Ignore aborts with CH-54 message ───────────────────────────────────

test('CH-54 helm — Ignore (failurePolicy) aborts with CH-54 fail-closed message', () => {
  assertAbortCH54(
    ['--set', 'imageVerification.kyverno.failurePolicy=Ignore'],
    'Ignore',
    'failurePolicy=Ignore',
  );
});

// ── Test: break-glass overrides and renders with Audit ───────────────────────

test('CH-54 helm — break-glass (allowInsecureAdmissionMode=true) renders with Audit', () => {
  const r = assertRenderOk(
    [
      '--set', 'imageVerification.kyverno.validationFailureAction=Audit',
      '--set', 'imageVerification.allowInsecureAdmissionMode=true',
    ],
    'break-glass with Audit',
  );
  // ClusterPolicy is still rendered but with Audit action.
  assert.match(r.stdout, /kind: ClusterPolicy/,
    'break-glass render must include ClusterPolicy');
  assert.match(r.stdout, /validationFailureAction: Audit/,
    'break-glass render must carry Audit in the policy spec');
});

// ── Test: break-glass overrides and renders with Ignore ──────────────────────

test('CH-54 helm — break-glass (allowInsecureAdmissionMode=true) renders with Ignore', () => {
  const r = assertRenderOk(
    [
      '--set', 'imageVerification.kyverno.failurePolicy=Ignore',
      '--set', 'imageVerification.allowInsecureAdmissionMode=true',
    ],
    'break-glass with Ignore',
  );
  assert.match(r.stdout, /kind: ClusterPolicy/,
    'break-glass render must include ClusterPolicy');
  assert.match(r.stdout, /failurePolicy: Ignore/,
    'break-glass render must carry Ignore in the policy spec');
});

// ── helm lint as a sanity gate ────────────────────────────────────────────────

test('CH-54 helm — helm lint passes on chart', () => {
  const r = spawnSync(HELM, ['lint', CHART], { encoding: 'utf-8' });
  assert.equal(r.status, 0,
    `helm lint failed (status ${r.status})\n${r.stdout}\n${r.stderr}`);
});
