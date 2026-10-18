/**
 * Adversarial eval: §5.6 epoch-replay WARN log shape (CHARIOT::§5.6::17)
 *
 * §5.6 (CHARIOT-SPEC.md:456): "reject the bundle, log
 * `WARN catalog.epoch_replay_rejected {bundleEpoch, persistedEpoch, reason}`
 * naming the failing condition" for every replay/downgrade-without-identity
 * rejection (`bundle.epoch < persisted_epoch` and `bundle.epoch ==
 * persisted_epoch` without proven identity).
 *
 * Pre-fix, `wireHybridRetrieval` only emitted `retrieval.bundle_rejected
 * {code, reason}` on admission failure — the spec-named event
 * `catalog.epoch_replay_rejected` with `{bundleEpoch, persistedEpoch}` was
 * never logged, so this eval FAILS against the pre-fix code (no call to
 * `logger.warn` has event name `catalog.epoch_replay_rejected`).
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/loadRetrieval.epoch-replay-log.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { wireHybridRetrieval } from './loadRetrieval.js';
import {
  DEFAULT_RETRIEVAL_CONTRACT,
  COMPILED_SERIALIZER_HASH,
} from './VectorIndexVerifier.js';
import type { CatalogEpochState } from '../federation/AdapterCatalog.js';

function validManifest() {
  const c = DEFAULT_RETRIEVAL_CONTRACT;
  return {
    version: c.version,
    encoder: {
      denseModelId: c.denseModelId,
      denseModelVersion: c.denseModelVersion,
      denseDims: c.denseDims,
      sparseModelId: c.sparseModelId,
      bm25Method: c.bm25Method,
      idfPolicy: c.idfPolicy,
    },
    recordCount: 1,
    tool_record_count: 1,
    capability_record_count: 0,
    recordCountPreOverlay: 1,
    serializer_hash: COMPILED_SERIALIZER_HASH,
  };
}

function validCatalog() {
  return [
    {
      id: 'pagerduty',
      descriptionForRetrieval: 'incident management and on-call alerting',
      searchQueries: ['page on-call', 'create incident'],
      industries: ['software'],
      departments: ['sre'],
      tools: [{ name: 'create_incident', description: 'Create a new incident', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] }],
    },
  ];
}

function envelope(epoch: number, catalogVersion: number = 2) {
  return {
    catalog: validCatalog(),
    registry: [],
    manifest: validManifest(),
    epoch,
    catalogVersion,
  };
}

test('§5.6: epoch <= persisted_epoch (replay) logs WARN catalog.epoch_replay_rejected {bundleEpoch, persistedEpoch, reason}', () => {
  const persisted: CatalogEpochState = { epoch: 10, catalogVersion: 2 };
  const warns: Array<{ event: string; fields: unknown }> = [];
  const logger = {
    warn: (event: string, fields: unknown) => { warns.push({ event, fields }); },
    debug: () => {},
    error: () => {},
  };

  const result = wireHybridRetrieval({
    envelope: envelope(5), // 5 < persisted 10 → replay rejected
    signatureVerified: true,
    persisted,
    persist: () => { throw new Error('persist MUST NOT be called on a rejected bundle'); },
    native: null,
    artifacts: null,
    logger,
  });

  assert.equal(result.mode, 'fail-closed', 'a replayed epoch must fail closed');

  const replayWarn = warns.find((w) => w.event === 'catalog.epoch_replay_rejected');
  assert.ok(
    replayWarn,
    'must log the spec-named event `catalog.epoch_replay_rejected` (§5.6) — ' +
      `got only: ${warns.map((w) => w.event).join(', ')}`,
  );
  assert.deepEqual(
    replayWarn!.fields,
    { bundleEpoch: 5, persistedEpoch: 10, reason: (result as { reason: string }).reason },
    '§5.6 requires the exact fields {bundleEpoch, persistedEpoch, reason}',
  );
});
