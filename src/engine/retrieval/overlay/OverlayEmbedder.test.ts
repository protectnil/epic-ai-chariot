/**
 * Adversarial eval: NativeOverlayEmbedder (BIEN::§9::10/13/14, CHARIOT-SPEC.md:767)
 *
 * Failure classes enumerated from the clause bytes (see OverlayEmbedder.ts
 * header for the full quotes) and each proven closed here:
 *  1. Encoder identity mismatch (dims, serializer hash, absent manifest
 *     block) is refused at construction — fail-closed, typed error, never
 *     silent.
 *  2. Empty tool list is a no-op with a stable hash — no shard directory is
 *     even created.
 *  3. The same tools embedded twice (idempotent customer re-verify) produce
 *     the identical `overlayStateHash`.
 *  4. Different tenants are isolated — embedding for one tenant never
 *     changes another tenant's hash or touches its directory.
 *  5. Every upserted point's payload carries the reserved
 *     `overlay:<tenant>:<adapter>:<tool>` toolId (the collision-safety
 *     property `CompositeEdgeShard` depends on).
 *  6. The overlay shard directory is scoped exactly to
 *     `<overlayRootDir>/<tenantId>` — nothing is written outside that
 *     tenant's own subtree.
 *  7. Gate finding D1 — `tenantId` is confined: path traversal / invalid
 *     characters are rejected fail-closed on EVERY method that takes one.
 *  8. Gate finding D1 — `getOverlayShard` never CREATES a shard on a query;
 *     it returns `null` for a tenant with no prior embed, and the same
 *     shard instance for one that has.
 *  9. Gate finding D3 — `overlayStateHash` is a function of the ON-DISK
 *     manifest, not this-process-lifetime memory: a brand-new embedder
 *     instance constructed over the SAME directory (simulating a restart)
 *     reproduces the identical hash, and `listTools` reflects the
 *     persisted manifest too.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/overlay/OverlayEmbedder.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  InvalidTenantIdError,
  NativeOverlayEmbedder,
  OverlayEncoderIdentityMismatchError,
  OverlayManifestCorruptError,
  overlayToolId,
  type OverlayEncoderIdentity,
  type NativeOverlayEmbedderOptions,
} from './OverlayEmbedder.js';
import { COMPILED_SERIALIZER_HASH } from '../VectorIndexVerifier.js';
import type { NativeEdgeBinding, NativeEdgeShard, NativeDenseEncoder, NativeSpladeEncoder } from '../nativeEdge.js';

const VALID_IDENTITY: OverlayEncoderIdentity = {
  denseModelId: 'bien-nomic-v1',
  denseModelVersion: '2026-07-29',
  denseDims: 768,
  sparseModelId: 'prithivida/Splade_PP_en_v1',
  serializerHash: COMPILED_SERIALIZER_HASH,
};

function fakeDenseEncoder(): NativeDenseEncoder {
  return { embed: (texts: string[]) => texts.map(() => new Array(768).fill(0.01)) };
}

function fakeSparseEncoder(): NativeSpladeEncoder {
  return { embed: (texts: string[]) => texts.map(() => ({ indices: [1, 2, 3], values: [0.5, 0.3, 0.1] })) };
}

/** In-memory fake shard: `query()` returns exactly what was `upsert()`-ed,
 * so tests can assert on payload shape without a real native build. */
function fakeInMemoryShard(): NativeEdgeShard & { upsertedPoints: unknown[] } {
  const points: unknown[] = [];
  return {
    upsertedPoints: points,
    upsert(pointsJson: string) { points.push(...(JSON.parse(pointsJson) as unknown[])); },
    flush() {},
    pointsCount() { return points.length; },
    snapshotManifestJson() { return '{}'; },
    query() { return []; },
  };
}

/**
 * A fresh fake native binding — NO in-memory state is shared across two
 * calls to this function, deliberately: a "restart" test constructs a
 * second `NativeOverlayEmbedder` against a SECOND `fakeNativeBinding()`
 * result, so the only thing that can make the two agree is what actually
 * persists to real disk (the manifest JSON) — never a shared JS closure.
 */
function fakeNativeBinding(overrides: Partial<NativeEdgeBinding> = {}): { native: NativeEdgeBinding; created: string[]; loaded: string[] } {
  const created: string[] = [];
  const loaded: string[] = [];
  const shardsByDir = new Map<string, ReturnType<typeof fakeInMemoryShard>>();
  const native: NativeEdgeBinding = {
    EdgeShardHandle: {
      create(path: string) {
        created.push(path);
        const shard = fakeInMemoryShard();
        shardsByDir.set(path, shard);
        return shard;
      },
      load(path: string) {
        loaded.push(path);
        const existing = shardsByDir.get(path);
        if (existing) return existing;
        const shard = fakeInMemoryShard();
        shardsByDir.set(path, shard);
        return shard;
      },
    },
    DenseEncoder: { load: () => { throw new Error('not used — denseEncoder is injected directly'); } },
    unsealAndVerifySnapshot: () => { throw new Error('not used in this fixture'); },
    edgeUnpackSnapshot: () => { throw new Error('not used in this fixture'); },
    verifySnapshotSignature: () => { throw new Error('not used in this fixture'); },
    serializeQuery: () => { throw new Error('not used in this fixture'); },
    serializeTool: (_base: string, recJson: string) => {
      // Minimal stand-in for the real bien_serializer: deterministic text
      // derived from the record, sufficient for hash/idempotency assertions
      // (the REAL byte-identical serializer is native, compiled, and
      // already proven by the serializer conformance corpus gate —
      // re-testing its byte contract here would duplicate that gate).
      const rec = JSON.parse(recJson) as { name?: string; description?: string };
      return `search_document: «NAME»${rec.name}\n«DESC»${rec.description ?? ''}`;
    },
    frozenSerializerHash: () => COMPILED_SERIALIZER_HASH,
    ...overrides,
  };
  return { native, created, loaded };
}

function makeEmbedder(overlayRootDir: string, opts: Partial<NativeOverlayEmbedderOptions> = {}) {
  const { native } = fakeNativeBinding();
  return new NativeOverlayEmbedder({
    native,
    denseEncoder: fakeDenseEncoder(),
    sparseEncoder: fakeSparseEncoder(),
    manifestEncoder: VALID_IDENTITY,
    overlayRootDir,
    ...opts,
  });
}

/**
 * Run `fn` against a fresh temp directory, then remove it. `fn` may be sync
 * OR async — a naive `try { return fn(dir) } finally { rmSync(dir) }` is
 * WRONG for an async `fn`: `fn(dir)` returns a pending `Promise`
 * *synchronously*, so a bare `finally` runs (and deletes the directory)
 * immediately, before any of `fn`'s `await`s have resolved, racing the
 * directory out from under the callback mid-flight. Caught by this file's
 * own suite (two tests failed with exactly that race — ENOENT on the temp
 * dir, and a "first tenant's subdirectory vanished" assertion — before this
 * fix): both are test-harness bugs, not `OverlayEmbedder` bugs.
 */
function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'overlay-embedder-test-'));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  let result: T;
  try {
    result = fn(dir);
  } catch (err) {
    cleanup();
    throw err;
  }
  if (result instanceof Promise) {
    return result.then(
      (value) => { cleanup(); return value; },
      (err) => { cleanup(); throw err; },
    ) as unknown as T;
  }
  cleanup();
  return result;
}

// ── 1. encoder identity mismatch — construction-time fail-closed ───────────

test('constructor: refuses a manifest encoder with the wrong dense width', () => {
  withTempDir((dir) => {
    assert.throws(
      () => makeEmbedder(dir, { manifestEncoder: { ...VALID_IDENTITY, denseDims: 384 } }),
      OverlayEncoderIdentityMismatchError,
    );
  });
});

test('constructor: refuses a manifest encoder with a mismatched serializer hash', () => {
  withTempDir((dir) => {
    assert.throws(
      () => makeEmbedder(dir, { manifestEncoder: { ...VALID_IDENTITY, serializerHash: 'deadbeef' } }),
      OverlayEncoderIdentityMismatchError,
    );
  });
});

test('constructor: refuses when the manifest encoder block is entirely absent (explicit failure, never silent)', () => {
  withTempDir((dir) => {
    // Deliberately violating the type (via `as unknown as ...`) to prove the
    // RUNTIME guard, not just the compiler, catches an absent manifest block
    // — a caller could still construct this via untyped JS or a JSON-sourced
    // options object.
    assert.throws(
      () => makeEmbedder(dir, { manifestEncoder: undefined as unknown as OverlayEncoderIdentity }),
      OverlayEncoderIdentityMismatchError,
    );
  });
});

test('constructor: refuses when the native frozenSerializerHash disagrees with the compiled-in hash', () => {
  withTempDir((dir) => {
    const { native } = fakeNativeBinding({ frozenSerializerHash: () => 'stale-hash' });
    assert.throws(
      () => new NativeOverlayEmbedder({
        native,
        denseEncoder: fakeDenseEncoder(),
        manifestEncoder: VALID_IDENTITY,
        overlayRootDir: dir,
      }),
      OverlayEncoderIdentityMismatchError,
    );
  });
});

test('constructor: accepts a fully matching identity without throwing', () => {
  withTempDir((dir) => {
    assert.doesNotThrow(() => makeEmbedder(dir));
  });
});

// ── 2. empty tool list — no-op, stable hash, no shard created ──────────────

test('embed: an empty tool list is a no-op and never creates a shard directory', async () => {
  await withTempDir(async (dir) => {
    const { native, created } = fakeNativeBinding();
    const embedder = new NativeOverlayEmbedder({
      native, denseEncoder: fakeDenseEncoder(), sparseEncoder: fakeSparseEncoder(),
      manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    const result = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', []);
    assert.equal(result.embedded, 0);
    assert.equal(created.length, 0, 'no shard directory should be created for zero tools');
    assert.equal(readdirSync(dir).length, 0, 'overlay root must stay empty');
  });
});

test('overlayStateHash: a tenant that was never embedded for returns the same stable constant as an explicit empty embed', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const neverSeen = embedder.overlayStateHash('ghost-tenant');
    const explicitEmpty = await embedder.embedCustomerVerifiedTools('another-tenant', 'acme', []);
    assert.equal(neverSeen, explicitEmpty.overlayStateHash);
  });
});

// ── 3. idempotent re-embed — identical content, identical hash ─────────────

test('embed: embedding the identical tools twice (idempotent customer re-verify) yields the identical overlayStateHash', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const tools = [{ name: 'widget_lookup', description: 'Look up a widget', inputSchema: { required: ['id'], properties: { id: {} } } }];
    const first = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', tools);
    const second = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', tools);
    assert.equal(first.overlayStateHash, second.overlayStateHash);
  });
});

test('embed: a different tool set produces a different overlayStateHash', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const first = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
    ]);
    const second = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'b', description: 'B', inputSchema: null },
    ]);
    assert.notEqual(first.overlayStateHash, second.overlayStateHash);
  });
});

// ── 4. tenant isolation ─────────────────────────────────────────────────────

test('embed: different tenants are isolated — embedding for tenant B never changes tenant A\'s hash', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const toolsA = [{ name: 'a-tool', description: 'A', inputSchema: null }];
    const before = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', toolsA);
    await embedder.embedCustomerVerifiedTools('tenant-b', 'other-adapter', [
      { name: 'b-tool', description: 'B', inputSchema: null },
    ]);
    const hashAAfterB = embedder.overlayStateHash('tenant-a');
    assert.equal(before.overlayStateHash, hashAAfterB, 'tenant A\'s hash must be unaffected by tenant B\'s embed');
  });
});

test('embed: each tenant gets its own shard subdirectory, nothing written outside its own scope', async () => {
  await withTempDir(async (dir) => {
    const { native, created } = fakeNativeBinding();
    const embedder = new NativeOverlayEmbedder({
      native, denseEncoder: fakeDenseEncoder(), sparseEncoder: fakeSparseEncoder(),
      manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [{ name: 'x', description: 'X', inputSchema: null }]);
    await embedder.embedCustomerVerifiedTools('tenant-b', 'acme', [{ name: 'y', description: 'Y', inputSchema: null }]);
    assert.deepEqual(created.sort(), [join(dir, 'tenant-a'), join(dir, 'tenant-b')].sort());
    assert.deepEqual(readdirSync(dir).sort(), ['tenant-a', 'tenant-b']);
  });
});

// ── 5. reserved toolId namespace on every upserted point ────────────────────

test('embed: every upserted point payload carries the reserved overlay: toolId namespace', async () => {
  await withTempDir(async (dir) => {
    const { native } = fakeNativeBinding();
    const embedder = new NativeOverlayEmbedder({
      native, denseEncoder: fakeDenseEncoder(), sparseEncoder: fakeSparseEncoder(),
      manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    const shardHandle = native.EdgeShardHandle;
    let capturedPoints: any[] = [];
    const originalCreate = shardHandle.create.bind(shardHandle);
    shardHandle.create = (path: string, cfg: string) => {
      const shard = originalCreate(path, cfg) as any;
      const originalUpsert = shard.upsert.bind(shard);
      shard.upsert = (json: string) => { capturedPoints = JSON.parse(json); return originalUpsert(json); };
      return shard;
    };
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'Look up a widget', inputSchema: null },
    ]);
    assert.equal(capturedPoints.length, 1);
    assert.equal(capturedPoints[0].payload.toolId, overlayToolId('tenant-a', 'acme', 'widget_lookup'));
    assert.equal(capturedPoints[0].payload.toolId, 'overlay:tenant-a:acme:widget_lookup');
    assert.equal(capturedPoints[0].vector.dense.length, 768);
    assert.deepEqual(capturedPoints[0].vector.splade, { indices: [1, 2, 3], values: [0.5, 0.3, 0.1] });
  });
});

// ── 6. sparse leg is optional (mirrors loadSparseEncoder's own contract) ───

test('embed: works with no SPLADE encoder wired — dense-only overlay point, never throws', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir, { sparseEncoder: null });
    const result = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'x', description: 'X', inputSchema: null },
    ]);
    assert.equal(result.embedded, 1);
  });
});

// ── 7. tenantId confinement (gate finding D1) ───────────────────────────────

test('tenantId confinement: path traversal and disallowed characters are rejected on every tenant-taking method', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const bad = ['../../etc/passwd', '..', '.', 'a/b', 'a\\b', '', 'a b', 'tenant;rm -rf', 'x'.repeat(129), 'a..b'];
    for (const tenantId of bad) {
      assert.throws(() => embedder.overlayStateHash(tenantId), InvalidTenantIdError, `overlayStateHash must reject ${JSON.stringify(tenantId)}`);
      assert.throws(() => embedder.getOverlayShard(tenantId), InvalidTenantIdError, `getOverlayShard must reject ${JSON.stringify(tenantId)}`);
      assert.throws(() => embedder.listTools(tenantId), InvalidTenantIdError, `listTools must reject ${JSON.stringify(tenantId)}`);
      await assert.rejects(
        embedder.embedCustomerVerifiedTools(tenantId, 'acme', [{ name: 'x', description: 'X', inputSchema: null }]),
        InvalidTenantIdError,
        `embedCustomerVerifiedTools must reject ${JSON.stringify(tenantId)}`,
      );
    }
  });
});

test('tenantId confinement: valid characters (letters, digits, dot, underscore, hyphen) are accepted', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    const result = await embedder.embedCustomerVerifiedTools('tenant.A-1_2', 'acme', [
      { name: 'x', description: 'X', inputSchema: null },
    ]);
    assert.equal(result.embedded, 1);
  });
});

// ── 8. getOverlayShard never creates on a query ─────────────────────────────

test('getOverlayShard: returns null for a tenant that has never embedded anything (never creates a shard)', async () => {
  await withTempDir(async (dir) => {
    const { native, created } = fakeNativeBinding();
    const embedder = new NativeOverlayEmbedder({
      native, denseEncoder: fakeDenseEncoder(), manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    const shard = embedder.getOverlayShard('never-embedded-tenant');
    assert.equal(shard, null);
    assert.equal(created.length, 0, 'a query must never create a shard directory');
    assert.equal(readdirSync(dir).length, 0);
  });
});

test('getOverlayShard: returns the tenant\'s shard after an embed, and the SAME instance on repeat calls', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [{ name: 'x', description: 'X', inputSchema: null }]);
    const shard1 = embedder.getOverlayShard('tenant-a');
    const shard2 = embedder.getOverlayShard('tenant-a');
    assert.notEqual(shard1, null);
    assert.equal(shard1, shard2, 'the same in-process shard handle must be reused, not reopened per call');
  });
});

test('getOverlayShard: after a simulated restart (fresh embedder instance), the PERSISTED shard is loaded lazily from disk', async () => {
  await withTempDir(async (dir) => {
    const embedder1 = makeEmbedder(dir);
    await embedder1.embedCustomerVerifiedTools('tenant-a', 'acme', [{ name: 'x', description: 'X', inputSchema: null }]);

    // Simulated restart: an entirely fresh embedder + fresh native mock —
    // no in-memory state is shared with embedder1.
    const { native: native2, loaded } = fakeNativeBinding();
    const embedder2 = new NativeOverlayEmbedder({
      native: native2, denseEncoder: fakeDenseEncoder(), manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    const shard = embedder2.getOverlayShard('tenant-a');
    assert.notEqual(shard, null, 'the tenant\'s overlay directory exists on disk (from embedder1) and must be loadable by a fresh instance');
    assert.deepEqual(loaded, [join(dir, 'tenant-a')]);
  });
});

// ── 9. D3 — persistence of overlayStateHash and listTools across restart ──

test('D3: overlayStateHash survives a brand-new embedder instance over the same directory (simulated restart)', async () => {
  await withTempDir(async (dir) => {
    const embedder1 = makeEmbedder(dir);
    const { overlayStateHash: hash1 } = await embedder1.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'x', description: 'X', inputSchema: null },
    ]);

    // Simulated restart: fresh embedder AND fresh native mock — the only
    // thing that can make hash2 equal hash1 is the on-disk manifest file.
    const embedder2 = makeEmbedder(dir);
    const hash2 = embedder2.overlayStateHash('tenant-a');
    assert.equal(hash1, hash2, 'overlayStateHash must be computed from the persisted manifest, not this-process memory');

    // Embedding one more tool through the "restarted" instance changes it.
    await embedder2.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'y', description: 'Y', inputSchema: null },
    ]);
    assert.notEqual(embedder2.overlayStateHash('tenant-a'), hash1);
  });
});

test('D3: listTools reflects the persisted manifest across a simulated restart', async () => {
  await withTempDir(async (dir) => {
    const embedder1 = makeEmbedder(dir);
    await embedder1.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'widget_lookup', description: 'W', inputSchema: null },
      { name: 'gadget_lookup', description: 'G', inputSchema: null },
    ]);

    const embedder2 = makeEmbedder(dir);
    const tools = embedder2.listTools('tenant-a');
    assert.equal(tools.length, 2);
    const names = tools.map((t) => t.toolName).sort();
    assert.deepEqual(names, ['gadget_lookup', 'widget_lookup']);
    for (const t of tools) {
      assert.equal(t.adapterId, 'acme');
      assert.equal(t.toolId, overlayToolId('tenant-a', 'acme', t.toolName));
    }
  });
});

test('D3: listTools returns empty for a tenant that has never embedded anything', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    assert.deepEqual(embedder.listTools('ghost-tenant'), []);
  });
});

// ── E1(a): re-embed CORRECTS the manifest, not just grows it ───────────────

test('E1(a): re-embedding a SMALLER set for the same adapter removes the dropped tool from listTools/overlayStateHash/manifest', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
      { name: 'b', description: 'B', inputSchema: null },
    ]);
    const second = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
    ]);

    // listTools reflects only the live set.
    const tools = embedder.listTools('tenant-a');
    assert.equal(tools.length, 1);
    assert.equal(tools[0].toolName, 'a');

    // overlayStateHash equals a FRESH embed of {a} alone, in a separate
    // tenant directory — proves the correction isn't just "close enough",
    // it is byte-identical to never having embedded 'b' at all.
    const freshDir = mkdtempSync(join(tmpdir(), 'e1a-fresh-'));
    try {
      const freshEmbedder = makeEmbedder(freshDir);
      const freshResult = await freshEmbedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
        { name: 'a', description: 'A', inputSchema: null },
      ]);
      assert.equal(second.overlayStateHash, freshResult.overlayStateHash);
      assert.equal(embedder.overlayStateHash('tenant-a'), freshResult.overlayStateHash);
    } finally {
      rmSync(freshDir, { recursive: true, force: true });
    }

    // The on-disk manifest itself has exactly one entry.
    const manifestPath = join(dir, 'tenant-a', 'overlay-manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Record<string, unknown>;
    assert.equal(Object.keys(manifest).length, 1);

    // liveOverlayToolIds (the set CompositeEdgeShard filters against)
    // agrees exactly.
    const live = embedder.liveOverlayToolIds('tenant-a');
    assert.notEqual(live, null);
    assert.deepEqual([...live!], [overlayToolId('tenant-a', 'acme', 'a')]);
  });
});

test('E1(a): a re-embed for adapter X never touches adapter Y\'s entries for the same tenant', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'x', description: 'X', inputSchema: null },
    ]);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'other-adapter', [
      { name: 'y', description: 'Y', inputSchema: null },
    ]);
    // Re-embed acme with a DIFFERENT tool — 'x' should be dropped, but
    // other-adapter's 'y' must survive untouched.
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'z', description: 'Z', inputSchema: null },
    ]);

    const tools = embedder.listTools('tenant-a').map((t) => `${t.adapterId}:${t.toolName}`).sort();
    assert.deepEqual(tools, ['acme:z', 'other-adapter:y']);
  });
});

test('E1(a): a full revoke (re-embed with an empty tool list) purges the adapter\'s manifest entries without creating a shard', async () => {
  await withTempDir(async (dir) => {
    const { native, created } = fakeNativeBinding();
    const embedder = new NativeOverlayEmbedder({
      native, denseEncoder: fakeDenseEncoder(), sparseEncoder: fakeSparseEncoder(),
      manifestEncoder: VALID_IDENTITY, overlayRootDir: dir,
    });
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
    ]);
    assert.equal(created.length, 1, 'sanity: the first embed did create a shard');

    const result = await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', []);
    assert.equal(result.embedded, 0);
    assert.equal(created.length, 1, 'the empty re-embed must not create a SECOND shard');
    assert.deepEqual(embedder.listTools('tenant-a'), [], 'the revoked adapter\'s entry must be gone');
    assert.equal(result.overlayStateHash, createHashOfEmpty());
  });
});

// ── E2: a corrupt (but present) manifest throws a typed error, never silently empties ──

test('E2: a truncated/corrupt manifest file throws OverlayManifestCorruptError from every accessor', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
    ]);
    const manifestPath = join(dir, 'tenant-a', 'overlay-manifest.json');
    writeFileSync(manifestPath, '{not valid json', 'utf-8');

    // A FRESH embedder instance (nothing cached in memory) so every
    // accessor is forced to actually re-read the damaged file.
    const fresh = makeEmbedder(dir);
    assert.throws(() => fresh.overlayStateHash('tenant-a'), OverlayManifestCorruptError);
    assert.throws(() => fresh.listTools('tenant-a'), OverlayManifestCorruptError);
    assert.throws(() => fresh.getOverlayShard('tenant-a'), OverlayManifestCorruptError);
    assert.throws(() => fresh.liveOverlayToolIds('tenant-a'), OverlayManifestCorruptError);
    await assert.rejects(
      fresh.embedCustomerVerifiedTools('tenant-a', 'acme', [{ name: 'b', description: 'B', inputSchema: null }]),
      OverlayManifestCorruptError,
    );
  });
});

test('E2: a manifest entry with the wrong shape (fails validation, not just JSON parse) also throws', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    await embedder.embedCustomerVerifiedTools('tenant-a', 'acme', [
      { name: 'a', description: 'A', inputSchema: null },
    ]);
    const manifestPath = join(dir, 'tenant-a', 'overlay-manifest.json');
    // Valid JSON, but an entry missing the required fields.
    writeFileSync(manifestPath, JSON.stringify({ 'overlay:tenant-a:acme:a': { adapterId: 'acme' } }), 'utf-8');

    const fresh = makeEmbedder(dir);
    assert.throws(() => fresh.overlayStateHash('tenant-a'), OverlayManifestCorruptError);
  });
});

test('E2: a MISSING manifest file remains legitimate empty state — no error', async () => {
  await withTempDir(async (dir) => {
    const embedder = makeEmbedder(dir);
    // Never embedded anything for this tenant — no manifest file exists at all.
    assert.doesNotThrow(() => embedder.overlayStateHash('unseen-tenant'));
    assert.doesNotThrow(() => embedder.listTools('unseen-tenant'));
    assert.equal(embedder.liveOverlayToolIds('unseen-tenant'), null);
  });
});

function createHashOfEmpty(): string {
  return createHash('sha256').update('').digest('hex');
}
