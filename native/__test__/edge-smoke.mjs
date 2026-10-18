// Phase 3.5 — smoke-load a tiny dev EdgeShard end-to-end through the NAPI binding.
//
// Usage: node native/__test__/edge-smoke.mjs <path-to-chariot-native.node>
//
// Loads the native module, creates a 4-d dense EdgeShard, upserts 3 points,
// runs a single-leg EXACT nearest query (deterministic path), asserts the
// nearest neighbor + run-to-run order determinism, runs a 2-leg RRF hybrid
// fusion, reads the snapshot manifest, and checks the BIEN serializer +
// snapshot-crypto exports are wired. Prints "SMOKE OK" and exits 0 on success.
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const nativePath = process.argv[2];
if (!nativePath || !existsSync(nativePath)) {
  console.error("usage: node edge-smoke.mjs <chariot-native.node>");
  process.exit(1);
}
const native = require(nativePath);

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERT FAIL:", msg);
    process.exit(1);
  }
  console.log("ok -", msg);
}

// Exports present.
assert(typeof native.EdgeShardHandle === "function", "EdgeShardHandle exported");
assert(typeof native.serializeTool === "function", "serializeTool exported");
assert(typeof native.unsealAndVerifySnapshot === "function", "unsealAndVerifySnapshot exported");
assert(typeof native.frozenSerializerHash === "function", "frozenSerializerHash exported");
// Dense encoder (P3.2) wired into the binding. A real end-to-end embed needs the
// BIEN 768-d ONNX (Track A / BIEN M8), so smoke only asserts the export + the
// `load` factory are present here; numeric parity is gated in BIEN M8 / P4.
assert(typeof native.DenseEncoder === "function", "DenseEncoder exported");
assert(typeof native.DenseEncoder.load === "function", "DenseEncoder.load factory exported");
// SPLADE encoder (P3.2, option b). The real Splade_PP_en_v1 ONNX is loaded from
// the signed bundle at runtime, so smoke asserts the export + factory here; the
// post-process + serialization contract is exercised model-free below.
assert(typeof native.SpladeEncoder === "function", "SpladeEncoder exported");
assert(typeof native.SpladeEncoder.load === "function", "SpladeEncoder.load factory exported");
assert(typeof native.spladePostProcess === "function", "spladePostProcess exported");

// SPLADE PARITY GATE (model-free): feed the committed golden synthetic logits
// through the native post-process and assert indices + canonical + sha256 match.
// This locks the lockstep contract (ReLU+log1p, masked max-pool, >0 suppression,
// asc-id 4-dp canonical). End-to-end real-model parity vs the P5.2 publisher is
// the separate release gate.
{
  const here = dirname(fileURLToPath(import.meta.url));
  const golden = JSON.parse(readFileSync(join(here, "splade-parity-golden.json"), "utf8"));
  const [, seq, vocab] = golden.dims;
  const res = native.spladePostProcess(golden.logits, seq, vocab, golden.attention_mask);
  assert(
    JSON.stringify(res.indices) === JSON.stringify(golden.expected_indices),
    `SPLADE parity indices match golden (got ${JSON.stringify(res.indices)})`,
  );
  assert(
    res.canonical === golden.expected_canonical,
    `SPLADE parity canonical matches golden (got "${res.canonical}")`,
  );
  assert(
    res.sha256 === golden.expected_sha256,
    `SPLADE parity sha256 matches golden (got ${res.sha256})`,
  );
}
assert(
  native.frozenSerializerHash() ===
    "8bed00ff2afed5367ac607b388be2f2c76d797108dbde9d08e31d74e109de43f",
  "frozenSerializerHash matches the BIEN frozen hash",
);

// Serializer (CH-23): the cli-bridge fixture must byte-match BIEN's corpus.
const got = native.serializeTool(
  "nomic",
  JSON.stringify({
    name: "git",
    category: "devops",
    description: "Distributed version control inspection.",
    keywords: ["git", "vcs", "history"],
  }),
);
const expected =
  "search_document: «NAME»git\n«CATEGORY»devops\n«DESC»Distributed version control inspection.\n«KW»git, history, vcs";
assert(got === expected, "serializeTool byte-matches the BIEN cli-bridge fixture");

// EdgeShard: create a 4-d dense ("dense", cosine) shard in a temp dir.
const dir = mkdtempSync(join(tmpdir(), "edge-smoke-"));
const shardPath = join(dir, "shard");
mkdirSync(shardPath, { recursive: true }); // create() requires the shard dir to exist
const config = { vectors: { dense: { size: 4, distance: "Cosine" } }, on_disk_payload: false };
const shard = native.EdgeShardHandle.create(shardPath, JSON.stringify(config));
assert(shard != null, "EdgeShard created");

// Upsert 3 points (named vector "dense") with payload.
const points = [
  { id: 1, vector: { dense: [1.0, 0.0, 0.0, 0.0] }, payload: { tool: "alpha" } },
  { id: 2, vector: { dense: [0.0, 1.0, 0.0, 0.0] }, payload: { tool: "beta" } },
  { id: 3, vector: { dense: [0.9, 0.1, 0.0, 0.0] }, payload: { tool: "gamma" } },
];
shard.upsert(JSON.stringify(points));
assert(shard.pointsCount() === 3, "3 points upserted (pointsCount == 3)");

// Single-leg EXACT nearest query → point 1 for [1,0,0,0].
const res1 = shard.query({
  prefetches: [],
  query: { using: "dense", dense: [1.0, 0.0, 0.0, 0.0] },
  limit: 3,
  exact: true,
  withPayload: true,
});
assert(res1.length === 3, "single-leg exact query returned 3 results");
assert(res1[0].id === "1", `nearest to [1,0,0,0] is point 1 (got ${res1[0].id})`);
assert(
  res1[0].payloadJson && JSON.parse(res1[0].payloadJson).tool === "alpha",
  "payload returned for the top hit",
);

// Determinism: identical exact query twice → identical id ordering.
const res1b = shard.query({
  prefetches: [],
  query: { using: "dense", dense: [1.0, 0.0, 0.0, 0.0] },
  limit: 3,
  exact: true,
  withPayload: false,
});
assert(
  JSON.stringify(res1.map((r) => r.id)) === JSON.stringify(res1b.map((r) => r.id)),
  "exact query is order-deterministic across runs",
);

// 2-leg RRF hybrid (two dense legs fused) → a fused ranking.
const res2 = shard.query({
  prefetches: [
    { query: { using: "dense", dense: [1.0, 0.0, 0.0, 0.0] }, limit: 3 },
    { query: { using: "dense", dense: [0.9, 0.1, 0.0, 0.0] }, limit: 3 },
  ],
  limit: 3,
  rrfK: 60,
  exact: true,
  withPayload: false,
});
assert(res2.length >= 1, `RRF hybrid returned ${res2.length} fused results`);

// Snapshot manifest is a JSON string.
const manifest = shard.snapshotManifestJson();
assert(typeof manifest === "string" && manifest.length > 0, "snapshot manifest is a JSON string");

shard.flush();
console.log("\nSMOKE OK — EdgeShard create/upsert/query(single+RRF, exact)/manifest + serializer all pass");
// Exit before the native EdgeShard's Drop (which flushes to disk) runs; deleting
// the temp dir from JS first would race that Drop. The OS tmp reaper handles it.
process.exit(0);
