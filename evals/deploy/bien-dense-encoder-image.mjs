/**
 * BIEN::§9::10 / BIEN::§9::11 / BIEN::§9::12 — Chariot runtime image
 * document-side encoder shipment.
 *
 * BIEN SPEC §9 (Progressive-auth overlay, 2026-07-08; quoted verbatim):
 *   "The Chariot runtime image MUST ship the document-side encoder path —
 *   the BIEN dense encoder + the hashed `serialize_tool` serializer,
 *   alongside the SPLADE document encoder (CHARIOT §1970) — so the runtime
 *   can embed newly `customer-verified` tools ON-DEVICE into the per-tenant
 *   overlay `EdgeShard`."
 *
 * Prior to this eval, the Dockerfile COPYed EDGESHARD_SNAPSHOT, SPLADE_DIR
 * and ONNXRUNTIME_DIR into the build-context allow-list but carried no
 * BIEN_DIR — the dense encoder was reachable only via an operator-supplied
 * CHARIOT_DENSE_MODEL_DIR pointing outside the image, so a stock image never
 * shipped it. This eval fails on that prior state and passes once the
 * Dockerfile (ARG BIEN_DIR + COPY + ENV CHARIOT_DENSE_MODEL_DIR default) and
 * the marketplace-ecr.yml CI guard both wire the artifact in, mirroring the
 * existing SPLADE_DIR wiring exactly.
 *
 * Reads the REAL files and asserts textual / structural properties — no
 * mocks, no hardcoded copies (same discipline as the other CH-54 evals in
 * this directory).
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCKERFILE_PATH = join(__dirname, '..', '..', 'Dockerfile');
const WORKFLOW_PATH = join(__dirname, '..', '..', '.github', 'workflows', 'marketplace-ecr.yml');

const dockerfile = readFileSync(DOCKERFILE_PATH, 'utf-8');
const workflow = readFileSync(WORKFLOW_PATH, 'utf-8');

// ── BIEN::§9::10 — the Dockerfile ships the BIEN dense encoder ──────────────

test('Dockerfile — BIEN_DIR ARG is declared with a default, mirroring SPLADE_DIR', () => {
  assert.match(
    dockerfile,
    /^ARG BIEN_DIR=artifacts\/models\/bien\s*$/m,
    'Dockerfile must declare "ARG BIEN_DIR=artifacts/models/bien" (BIEN::§9::10), ' +
      'the same shape as the existing "ARG SPLADE_DIR=artifacts/models/splade"',
  );
});

test('Dockerfile — BIEN_DIR is COPYed into the image at artifacts/models/bien/', () => {
  assert.match(
    dockerfile,
    /^COPY \$\{BIEN_DIR\}\/ \.\/artifacts\/models\/bien\/\s*$/m,
    'Dockerfile must COPY ${BIEN_DIR}/ into ./artifacts/models/bien/ (BIEN::§9::10), ' +
      'the same shape as the existing "COPY ${SPLADE_DIR}/ ./artifacts/models/splade/"',
  );
});

test('Dockerfile — the BIEN_DIR COPY destination matches the CHARIOT_DENSE_MODEL_DIR default', () => {
  const copyMatch = dockerfile.match(/^COPY \$\{BIEN_DIR\}\/ (\.\/[^\s]+)\/\s*$/m);
  const envMatch = dockerfile.match(/^\s*CHARIOT_DENSE_MODEL_DIR=(\/[^\s\\]+)\s*\\?\s*$/m);
  assert.ok(copyMatch, 'BIEN_DIR COPY destination not found');
  assert.ok(
    envMatch,
    'Dockerfile must default CHARIOT_DENSE_MODEL_DIR so ChariotState.loadDenseEncoder() ' +
      'resolves the shipped artifact without operator config (same defect class the ' +
      'CHARIOT_SPLADE_MODEL_DIR default closes for the SPLADE leg)',
  );
  // COPY destination is relative to WORKDIR /app; the ENV value is absolute
  // under /app — normalize both to compare the same path.
  const copyDestAbs = '/app/' + copyMatch[1].replace(/^\.\//, '');
  assert.equal(
    envMatch[1],
    copyDestAbs,
    `CHARIOT_DENSE_MODEL_DIR (${envMatch[1]}) must point at the BIEN_DIR COPY destination (${copyDestAbs})`,
  );
});

// ── BIEN::§9::11 — the Dockerfile ships the document-side serialize_tool ────

test('Dockerfile — native addon COPY carries the BIEN::§9::11 citation for serialize_tool', () => {
  // serialize_tool is compiled into chariot-native.node (native/src/bien_serializer.rs,
  // mod bien_serializer in native/src/lib.rs) — no separate on-disk artifact ships it,
  // so the existing native addon COPY is the implementing line for this node.
  assert.match(
    dockerfile,
    /BIEN::§9::11[\s\S]{0,400}COPY \$\{NATIVE_DIR\}\/chariot-native\.node/,
    'the native addon COPY must carry a BIEN::§9::11 citation explaining that ' +
      'serialize_tool ships as part of chariot-native.node, not a separate artifact',
  );
});

// ── BIEN::§9::12 — SPLADE document encoder still ships alongside BIEN dense ─

test('Dockerfile — SPLADE_DIR is still COPYed alongside the new BIEN_DIR (BIEN::§9::12)', () => {
  assert.match(
    dockerfile,
    /^ARG SPLADE_DIR=artifacts\/models\/splade\s*$/m,
    'SPLADE_DIR must remain declared — BIEN::§9::12 requires the SPLADE document ' +
      'encoder to ship ALONGSIDE the BIEN dense encoder, not in place of it',
  );
  assert.match(
    dockerfile,
    /^COPY \$\{SPLADE_DIR\}\/ \.\/artifacts\/models\/splade\/\s*$/m,
    'SPLADE_DIR COPY must remain present alongside the new BIEN_DIR COPY',
  );
});

// ── CI guard — build-context availability check covers BIEN_DIR too ────────

test('marketplace-ecr.yml — guard job checks artifacts/models/bien, mirroring artifacts/models/splade', () => {
  // Find the "Verify Dockerfile build-context artifacts are available" step
  // and check its path list, the same way the Dockerfile's own ARG defaults
  // are mirrored there today for EDGESHARD_SNAPSHOT/SPLADE_DIR/ONNXRUNTIME_DIR.
  const stepMatch = workflow.match(
    /Verify Dockerfile build-context artifacts are available[\s\S]*?for p in([\s\S]*?)done/,
  );
  assert.ok(stepMatch, 'guard step "Verify Dockerfile build-context artifacts are available" not found');
  const pathList = stepMatch[1];
  assert.match(
    pathList,
    /artifacts\/models\/bien/,
    'the guard step\'s path list must include artifacts/models/bien (mirrors artifacts/models/splade), ' +
      'so a build with a missing BIEN encoder fails closed with a clear error instead of ' +
      'letting `docker build` fail opaquely on a missing COPY source downstream',
  );
  assert.match(
    pathList,
    /artifacts\/models\/splade/,
    'artifacts/models/splade must remain checked alongside the new artifacts/models/bien entry',
  );
});
