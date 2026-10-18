/**
 * CHARIOT-SPEC §23.2 / CH-29 — image reference consistency + no silent Docker Hub.
 *
 * Clauses (CHARIOT-SPEC §23):
 *   :2124 "The chart ships three images to the AWS-managed Marketplace ECR ...
 *          (no Docker Hub / Quay / ECR Public)"
 *   :2126 "1. `chariot-gateway`"
 *   :2140 "The `chariot-gateway` image is signed at push to Amazon ECR ..."
 *   :2151 CH-29 "... all images ship inside Marketplace ECR with zero external
 *          egress at install or runtime. Image refs live only in `values.yaml`."
 *
 * Failure classes:
 *   R1 chart repository name != the repository CI pushes
 *   R2 an ECS JSON (taskdef / lifecycle hook) names a different repository
 *   R3 CI chart-staging does not pin the repository it pushed (drift)
 *   R4 registry empty (per-image and global) renders instead of aborting
 *      -> image pulls from Docker Hub
 *   R5 per-image registry or global registry alone must still render (air-gap
 *      overlay and Marketplace regionalization both keep working)
 *
 * R1-R3 and the helper guard are static (always run). R4/R5 render with helm
 * when a helm binary exists, else they are skipped WITH A REASON.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const CHART = join(ROOT, 'helm', 'chariot');
const read = (p) => readFileSync(join(ROOT, p), 'utf-8');

const workflow = read('.github/workflows/marketplace-ecr.yml');
const pushedRepo = /GATEWAY_IMAGE_REPOSITORY_NAME:\s*'([^']+)'/.exec(workflow)?.[1];

test('R0 the pushed gateway repository is the spec name `chariot-gateway`', () => {
  assert.equal(pushedRepo, 'chariot-gateway');
});

test('R1 chart gateway.image.repository equals the pushed repository', () => {
  const values = read('helm/chariot/values.yaml');
  const m = /^gateway:[\s\S]*?^  image:[\s\S]*?^    repository:\s*(\S+)/m.exec(values);
  assert.ok(m, 'could not locate gateway.image.repository in values.yaml');
  assert.equal(m[1], pushedRepo);
});

test('R2 ECS taskdef and lifecycle hook reference the pushed repository', () => {
  const task = JSON.parse(read('helm/chariot/ecs/chariot-gateway-taskdef.json'));
  const hook = JSON.parse(read('helm/chariot/ecs/chariot-gateway-service-lifecycle-hook.json'));
  const image = task.containerDefinitions.find((c) => c.name === 'chariot-gateway' || c.image)?.image;
  assert.ok(image, 'taskdef has no container image');
  const repoOf = (ref) => ref.replace(/@sha256:.*$/, '').split('/').slice(1).join('/');
  assert.equal(repoOf(image), pushedRepo);
  assert.equal(repoOf(hook.hookDetails.imageReference), pushedRepo);
});

test('R3 CI chart staging pins gateway.image.repository to what it pushed', () => {
  assert.match(
    workflow,
    /doc\.gateway\.image\.repository\s*=\s*process\.env\.GATEWAY_IMAGE_REPOSITORY_NAME/,
  );
});

test('R4s the registry resolver aborts when nothing resolves (static)', () => {
  const helpers = read('helm/chariot/templates/_helpers.tpl');
  const body = /define "chariot\.resolveRegistry" -}}([\s\S]*?)\{\{- end -\}\}\s*\n\s*\{\{\/\*/.exec(helpers)?.[1]
    ?? helpers.slice(helpers.indexOf('define "chariot.resolveRegistry"'));
  assert.match(body, /fail "CH-29 fail-closed/);
});

// ── helm-level (skipped with a reason when helm is absent) ───────────────────

const HELM = (() => {
  for (const bin of [process.env.CHARIOT_HELM_BIN, '/tmp/helmbin/linux-amd64/helm', 'helm'].filter(Boolean)) {
    if (spawnSync(bin, ['version', '--short'], { encoding: 'utf-8' }).status === 0) return bin;
  }
  return null;
})();
const skip = HELM ? false : 'SKIP: helm binary not found (set CHARIOT_HELM_BIN)';
const STRONG = 'Str0ng-Eval-Pass-9f3a2b71!';
const CREDS = [
  '--set', 'gateway.existingSecret=chariot-gateway-secret',
  '--set', `mongodb.auth.rootPassword=${STRONG}`,
  '--set', `redis.auth.password=${STRONG}`,
];
const render = (...extra) =>
  spawnSync(HELM, ['template', 'chariot', CHART, ...CREDS, ...extra], { encoding: 'utf-8' });

test('R4 helm: no registry anywhere aborts and names CH-29', { skip }, () => {
  const r = render();
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /CH-29 fail-closed/);
});

test('R5a helm: global.imageRegistry alone renders all three images from it', { skip }, () => {
  const reg = '000000000000.dkr.ecr.us-east-1.amazonaws.com';
  const r = render('--set', `global.imageRegistry=${reg}`);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`image: ${reg}/chariot-gateway:chariot-v`));
  assert.match(r.stdout, new RegExp(`image: ${reg}/mongo:`));
  assert.match(r.stdout, new RegExp(`image: ${reg}/redis:`));
  assert.doesNotMatch(r.stdout, /image: (docker\.io\/)?(protectnil\/|mongo:|redis:)/);
});

test('R5b helm: per-image registries alone render', { skip }, () => {
  const reg = '000000000000.dkr.ecr.us-east-1.amazonaws.com';
  const r = render(
    '--set', `gateway.image.registry=${reg}`,
    '--set', `mongodb.image.registry=${reg}`,
    '--set', `redis.image.registry=${reg}`,
  );
  assert.equal(r.status, 0, r.stderr);
});

test('R4b helm: one image left without a registry still aborts', { skip }, () => {
  const reg = '000000000000.dkr.ecr.us-east-1.amazonaws.com';
  const r = render(
    '--set', `gateway.image.registry=${reg}`,
    '--set', `mongodb.image.registry=${reg}`,
  );
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /CH-29 fail-closed/);
});

test('R5c helm: values-airgap overlay renders', { skip }, () => {
  const r = spawnSync(
    HELM,
    ['template', 'chariot', CHART, '-f', join(CHART, 'values-airgap.yaml'), ...CREDS],
    { encoding: 'utf-8' },
  );
  assert.equal(r.status, 0, r.stderr);
});
