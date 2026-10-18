#!/usr/bin/env node
/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: runner (§6 of the 4.0.0 plan)
 *
 * The North-Star "provable" artifact. Measures the retriever-under-test (today
 * the shipped BM25 ToolPreFilter baseline) on the curated gold set and emits a
 * committed, re-runnable JSON + markdown artifact covering:
 *   6.2  recall@8 + precision over the gold set (§4.5 floor recall@8 ≥ 0.95)
 *   6.3  determinism: each query run N times → assert sha-equal candidate set
 *   6.4  latency p50/p99 of Tier-1 selection under load
 *   6.5  named-competitor scaffold (pending stubs; never fabricated)
 *   6.6  biomedical-misroute-repro biomedical query carried in the gold set (pendingP4 paraphrase)
 *
 * ALL numbers are measured live against the signed production catalog. Nothing
 * is hard-coded. recall@8 / determinism reproduce exactly on re-run; latency is
 * machine/run-dependent and reported as measured.
 *
 *   node dist/engine/eval/proof/run-proof.js
 *
 * Env overrides:
 *   CHARIOT_PROOF_DETERMINISM_RUNS  (default 5)   runs per query for §6.3
 *   CHARIOT_PROOF_LATENCY_ITERS     (default 20)  passes over the gold set for §6.4
 *   CHARIOT_PROOF_OUT_DIR           (default src/engine/eval/proof/artifacts;
 *                                    private evaluation output)
 *   CHARIOT_GOLD_SET_PATH           (override the gold set location)
 *   CHARIOT_ADAPTER_CATALOG_PATH    (override the catalog bundle, e.g. air-gap)
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DEFAULT_MAX_TOOLS } from '../../federation/ToolPreFilter.js';
import { loadProductionCatalog } from './catalog.js';
import { loadGoldSet, validateLabelsAgainstCatalog, PKG_ROOT } from './gold.js';
import { BM25ToolPreFilterRetriever } from './retriever.js';
import { evaluateQuery, aggregate } from './scoring.js';
import { summarizeLatencies, round } from './metrics.js';
import { measureDeterminism } from './determinism.js';
import { listCompetitors } from './competitors.js';
import { summarizeFirstCall } from './firstcall.js';
import type { SchemaResolver, ToolSchemaInfo } from './firstcall.js';
import { reliabilityBins, expectedCalibrationError } from './calibration.js';
import type { CalibrationSample } from './calibration.js';
import { buildRequiresCustomerAuthSegment } from './auth-segment.js';
import type { ProductionCatalog } from './catalog.js';
import type {
  Retriever,
  PerQueryResult,
  AggregateMetrics,
  LatencyReport,
  CompetitorEntryReport,
  FirstCallSuccessReport,
  CalibrationReport,
  RequiresCustomerAuthSegmentReport,
  ProofArtifact,
  GoldSet,
} from './types.js';

const CALIBRATION_BIN_COUNT = 10;

/** §4.5 recall floor; §1.4 North Star. */
const RECALL_FLOOR = 0.95;
const NORTH_STAR =
  'For any request, return the most accurate, fastest, 100%-repeatable candidate set the LLM picks from, provable against named competitors.';
const SCHEMA_VERSION = '1.0.0';

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** §6.2 — score every gold query against a retriever at k. */
async function scoreGoldSet(
  retriever: Retriever,
  goldSet: GoldSet,
  k: number,
): Promise<{ perQuery: PerQueryResult[]; metrics: AggregateMetrics }> {
  const perQuery: PerQueryResult[] = [];
  for (const q of goldSet.queries) {
    const returned = await retriever.retrieve(q.query, k);
    const r = evaluateQuery(q, returned.map((t) => t.id), k);
    // Capture the top candidate's score as the query's retrieval confidence,
    // when the retriever exposes one (feeds the calibration report). Never
    // fabricated: undefined for score-less retrievers (e.g. BM25 baseline).
    const top = returned[0];
    if (top && typeof top.score === 'number') r.confidence = top.score;
    perQuery.push(r);
  }
  return { perQuery, metrics: aggregate(perQuery, k, RECALL_FLOOR) };
}

/**
 * Resolve a tool id to its input-schema availability for the first-call argsValid
 * check. buildToolsForRouting emits `parameters = { type:'object', properties:{} }`
 * — i.e. NO per-tool input schema — so this honestly returns hasInputSchema:false
 * for the current catalog, with a typed reason (never a fabricated pass).
 */
function makeSchemaResolver(catalog: ProductionCatalog): SchemaResolver {
  return (toolId: string): ToolSchemaInfo => {
    const tool = catalog.toolById.get(toolId);
    if (!tool) return { hasInputSchema: false, reason: 'tool-not-in-catalog' };
    const params = tool.parameters as { properties?: Record<string, unknown> } | undefined;
    const props = params?.properties;
    const has = !!props && typeof props === 'object' && Object.keys(props).length > 0;
    return has
      ? { hasInputSchema: true }
      : { hasInputSchema: false, reason: 'catalog-tool-has-no-input-schema' };
  };
}

/**
 * Build the calibration report. When the retriever exposes confidence, bin
 * confidence vs route-correctness into a reliability curve + ECE; otherwise
 * record `unavailable` with a typed reason (the binning machinery is unit-tested
 * and populates for a scoring retriever in Phase 4).
 */
function buildCalibration(
  retrieverInfoId: string,
  providesConfidence: boolean,
  perQuery: readonly PerQueryResult[],
): CalibrationReport {
  if (!providesConfidence) {
    return {
      retrieverId: retrieverInfoId,
      providesConfidence: false,
      status: 'unavailable',
      reason:
        'baseline BM25 ToolPreFilter exposes no per-candidate score (read-only; not modified). Calibration populates when a scoring retriever (Phase 4 hybrid) is measured.',
    };
  }
  const samples: CalibrationSample[] = perQuery
    .filter((r) => typeof r.confidence === 'number')
    .map((r) => ({ confidence: r.confidence as number, routeCorrect: r.recallAtK >= 1 }));
  // FAIL CLOSED on unnormalized scores. reliabilityBins expects confidence in
  // [0,1] (calibration.ts contract); a raw BM25/RRF-scale score (>1) would
  // land in NO bin, every bin would count 0, and ECE would come back 0 —
  // reporting an unmeasured retriever as 'measured' perfectly calibrated
  // (the exact 3.1.2 over-confidence blind spot this report exists to catch).
  const outOfRange = samples.filter(
    (s) => !Number.isFinite(s.confidence) || s.confidence < 0 || s.confidence > 1,
  );
  if (outOfRange.length > 0) {
    return {
      retrieverId: retrieverInfoId,
      providesConfidence: true,
      status: 'unavailable',
      reason:
        `retriever emitted ${outOfRange.length}/${samples.length} confidence values outside [0,1]; ` +
        'scores must be normalized before calibration (see calibration.ts contract). ' +
        'Refusing to report a measured ECE over unnormalized scores.',
    };
  }
  const bins = reliabilityBins(samples, CALIBRATION_BIN_COUNT);
  return {
    retrieverId: retrieverInfoId,
    providesConfidence: true,
    status: 'measured',
    binCount: CALIBRATION_BIN_COUNT,
    sampleCount: samples.length,
    expectedCalibrationError: round(expectedCalibrationError(bins)),
    bins,
  };
}


/** §6.4 — latency p50/p99 of Tier-1 selection under load. */
async function measureLatency(
  retriever: Retriever,
  goldSet: GoldSet,
  k: number,
  iterations: number,
): Promise<LatencyReport> {
  const queries = goldSet.queries.map((q) => q.query);
  // Warmup: one full pass (JIT, caches) — excluded from the sample.
  for (const query of queries) await retriever.retrieve(query, k);

  const samplesMs: number[] = [];
  for (let i = 0; i < iterations; i += 1) {
    for (const query of queries) {
      const start = process.hrtime.bigint();
      await retriever.retrieve(query, k);
      const end = process.hrtime.bigint();
      samplesMs.push(Number(end - start) / 1e6);
    }
  }
  return {
    retrieverId: retriever.info.id,
    k,
    measuredSelections: samplesMs.length,
    warmupSelections: queries.length,
    summaryMs: summarizeLatencies(samplesMs),
  };
}

/** §6.5 — measure runnable competitors; record non-runnable ones as pending. */
async function runCompetitors(
  tools: Parameters<Retriever['index']>[0],
  goldSet: GoldSet,
  k: number,
): Promise<CompetitorEntryReport[]> {
  const out: CompetitorEntryReport[] = [];
  for (const reg of listCompetitors()) {
    const { retriever, pendingReason } = reg;
    if (!retriever.info.runnable) {
      out.push({
        info: retriever.info,
        status: 'pending',
        pendingReason: pendingReason ?? 'non-runnable stub',
      });
      continue;
    }
    // Runnable competitor: measure on the SAME gold set, REAL numbers only.
    await retriever.index(tools);
    const { metrics } = await scoreGoldSet(retriever, goldSet, k);
    out.push({ info: retriever.info, status: 'measured', metrics });
  }
  return out;
}

// ─── artifact serialization (round metrics for a stable, readable JSON) ──────

function roundMetrics(m: AggregateMetrics): AggregateMetrics {
  const r: AggregateMetrics = {
    ...m,
    macroRecallAtK: round(m.macroRecallAtK),
    microRecallAtK: round(m.microRecallAtK),
    macroPrecisionAtK: round(m.macroPrecisionAtK),
    meanNdcgAtK: round(m.meanNdcgAtK),
    meanReciprocalRank: round(m.meanReciprocalRank),
    hitAt1: round(m.hitAt1),
    anyHitAtK: round(m.anyHitAtK),
    hitRateWilsonLcb95: round(m.hitRateWilsonLcb95),
  };
  if (m.excludingPendingP4) r.excludingPendingP4 = roundMetrics(m.excludingPendingP4 as AggregateMetrics);
  return r;
}

function roundRequiresCustomerAuthSegment(
  s: RequiresCustomerAuthSegmentReport,
): RequiresCustomerAuthSegmentReport {
  return s.metrics ? { ...s, metrics: roundMetrics(s.metrics) } : s;
}

/** Exported for unit testing (run-proof.round.test.ts) — not otherwise imported elsewhere. */
export function roundPerQuery(r: PerQueryResult): PerQueryResult {
  return {
    ...r,
    recallAtK: round(r.recallAtK),
    precisionAtK: round(r.precisionAtK),
    ndcgAtK: round(r.ndcgAtK),
    reciprocalRank: round(r.reciprocalRank),
  };
}

function renderMarkdown(a: ProofArtifact): string {
  const m = a.baseline.metrics;
  const lat = a.latency.summaryMs;
  const pct = (x: number): string => `${(x * 100).toFixed(2)}%`;
  const lines: string[] = [];
  lines.push('# Chariot Routing Proof Artifact');
  lines.push('');
  lines.push(`Generated: ${a.generatedUtc} · schema ${a.schemaVersion}`);
  lines.push('');
  lines.push('> North Star (§1.4): ' + a.spec.northStar);
  lines.push('');
  lines.push('## Catalog under test');
  lines.push('');
  lines.push(`- epoch: \`${a.catalog.epoch}\` · catalogVersion (catalog revision, CH-22): \`${a.catalog.catalogVersion}\` · recordCount (CH-22 frozen tool-granular count): \`${a.catalog.recordCount}\``);
  lines.push(`- adapters: ${a.catalog.adapterCount} · servers: ${a.catalog.serverCount} · tools: ${a.catalog.toolCount}`);
  lines.push(`- gold set: \`${a.catalog.goldSetPath}\``);
  lines.push('');
  lines.push('## Gold set');
  lines.push('');
  lines.push(`- version ${a.goldSet.version} · ${a.goldSet.queryCount} queries (target ${a.goldSet.targetSize})`);
  lines.push(`- styles: ${Object.entries(a.goldSet.styleBreakdown).map(([s, n]) => `${s}=${n}`).join(', ')}`);
  lines.push(`- pending-P4 queries: ${a.goldSet.pendingP4Count} · bug refs: ${a.goldSet.bugRefs.join(', ') || 'none'}`);
  lines.push(`- label validation: ${a.goldSet.labelValidation.ok ? 'OK' : 'FAILED'} (${a.goldSet.labelValidation.totalLabels} labels, ${a.goldSet.labelValidation.unknownLabels} unknown)`);
  lines.push('');
  lines.push(`## 6.2 Recall@${m.k} + precision — baseline: ${a.baseline.info.label}`);
  lines.push('');
  lines.push('| metric | value |');
  lines.push('| --- | --- |');
  lines.push(`| macro recall@${m.k} (headline) | **${pct(m.macroRecallAtK)}** |`);
  lines.push(`| §4.5 floor | ${pct(m.recallFloor)} |`);
  lines.push(`| meets floor | ${m.meetsFloor ? 'YES' : 'NO'} |`);
  lines.push(`| micro recall@${m.k} | ${pct(m.microRecallAtK)} |`);
  lines.push(`| macro precision@${m.k} | ${pct(m.macroPrecisionAtK)} |`);
  lines.push(`| NDCG@${m.k} (mean) | ${m.meanNdcgAtK.toFixed(4)} |`);
  lines.push(`| MRR@${m.k} | ${m.meanReciprocalRank.toFixed(4)} |`);
  lines.push(`| Hit@1 (diagnostic, NOT a claim) | ${pct(m.hitAt1)} |`);
  lines.push(`| hit-rate@${m.k} (any-hit) | ${pct(m.anyHitAtK)} |`);
  lines.push(`| hit-rate@${m.k} one-sided 95% Wilson LCB | ${pct(m.hitRateWilsonLcb95)} |`);
  if (m.excludingPendingP4) {
    lines.push(`| macro recall@${m.k} excl. pending-P4 | ${pct(m.excludingPendingP4.macroRecallAtK)} |`);
  }
  lines.push('');
  if (!m.meetsFloor) {
    const gap = m.recallFloor - m.macroRecallAtK;
    lines.push(`> HONEST GAP: BM25 baseline is ${pct(gap)} below the ${pct(m.recallFloor)} floor. Closing it is the job of the Phase 4 hybrid (dense+SPLADE+BM25 → RRF → rerank) retriever, which drops into the same Retriever interface.`);
    lines.push('');
  }
  const fc = a.firstCallSuccess;
  lines.push('## CH-37 First-call success — THE release gate');
  lines.push('');
  lines.push('| axis | value |');
  lines.push('| --- | --- |');
  lines.push(`| routeCorrect (full labeled set in top-${fc.k}) | **${pct(fc.routeCorrectRate)}** (${fc.routeCorrectCount}/${fc.queryCount}) |`);
  lines.push(`| argsValid | valid ${fc.argsValidBreakdown.valid} / invalid ${fc.argsValidBreakdown.invalid} / unknown ${fc.argsValidBreakdown.unknown} |`);
  lines.push(`| dispatchSucceeded | success ${fc.dispatchBreakdown.success} / failure ${fc.dispatchBreakdown.failure} / pending ${fc.dispatchBreakdown.pending} |`);
  lines.push(`| end-to-end first-call-success | ${fc.firstCallSuccessDeterminable ? pct(fc.firstCallSuccessRate ?? 0) : 'NOT YET DETERMINABLE'} |`);
  lines.push('');
  lines.push(`> routeCorrect is measured now. argsValid is unknown (the routing catalog carries no per-tool input schema) and dispatchSucceeded is pending the Phase 4 hybrid retriever + safe dispatcher fixture — so the end-to-end gate is wired but not yet determinable. NO number is fabricated. Pending reasons: ${fc.pendingReasons.join('; ')}.`);
  lines.push('');
  const auth = a.requiresCustomerAuthSegment;
  lines.push('## §4.5 / AS §1.2a — requiresCustomerAuth segment (reported separately)');
  lines.push('');
  if (auth.status === 'no-adapters-present') {
    lines.push(`- status: **NO ADAPTERS PRESENT** (adapters: ${auth.adapterCount}, in-class queries: ${auth.queryCount})`);
    lines.push(`- ⚠️ ${auth.reason}`);
  } else {
    const am = auth.metrics as AggregateMetrics;
    lines.push(`- status: **measured** · requiresCustomerAuth adapters: ${auth.adapterCount} · in-class queries: ${auth.queryCount}`);
    lines.push(`- macro recall@${am.k} for this class: **${pct(am.macroRecallAtK)}** (pooled headline above is NOT restricted to this class)`);
  }
  lines.push('');
  const cal = a.calibration;
  lines.push('## Retrieval-confidence calibration (3.1.2 over-confidence finding)');
  lines.push('');
  if (cal.status === 'unavailable') {
    lines.push(`- status: **unavailable** — ${cal.reason}`);
    lines.push('- The reliability-bin + ECE machinery is built and unit-tested; it renders the curve when a scoring retriever (Phase 4) is measured.');
  } else {
    lines.push(`- status: **measured** · samples ${cal.sampleCount} · bins ${cal.binCount} · ECE **${(cal.expectedCalibrationError ?? 0).toFixed(4)}**`);
    lines.push('');
    lines.push('| confidence bin | n | mean conf | routeCorrect | gap |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const b of cal.bins ?? []) {
      if (b.count === 0) continue;
      lines.push(`| [${b.lower.toFixed(1)},${b.upper.toFixed(1)}] | ${b.count} | ${b.meanConfidence.toFixed(3)} | ${pct(b.routeCorrectRate)} | ${b.gap.toFixed(3)} |`);
    }
  }
  lines.push('');
  lines.push('## 6.3 Determinism (100%-repeatability invariant)');
  lines.push('');
  lines.push(`- runs per query: ${a.determinism.runsPerQuery} · queries: ${a.determinism.queryCount}`);
  lines.push(`- scope: intra-query run-to-run stability (cross-query distinctness is not verified here)`);
  lines.push(`- deterministic: **${a.determinism.deterministic ? 'YES — every candidate set sha-stable across runs of the same query' : 'NO'}**`);
  if (!a.determinism.deterministic) {
    lines.push(`- nondeterministic query ids: ${a.determinism.nondeterministicQueryIds.join(', ')}`);
  }
  lines.push('');
  lines.push('## 6.4 Latency — Tier-1 selection under load (ms)');
  lines.push('');
  lines.push(`- measured selections: ${a.latency.measuredSelections} (after ${a.latency.warmupSelections} warmup)`);
  lines.push('');
  lines.push('| stat | ms |');
  lines.push('| --- | --- |');
  lines.push(`| p50 | ${lat.p50.toFixed(3)} |`);
  lines.push(`| p95 | ${lat.p95.toFixed(3)} |`);
  lines.push(`| p99 | ${lat.p99.toFixed(3)} |`);
  lines.push(`| min / max | ${lat.min.toFixed(3)} / ${lat.max.toFixed(3)} |`);
  lines.push(`| mean | ${lat.mean.toFixed(3)} |`);
  lines.push('');
  lines.push('> Latency is machine/run-dependent and reported as measured; recall@k and intra-query determinism reproduce exactly on re-run.');
  lines.push('');
  lines.push('## 6.5 Named competitors');
  lines.push('');
  lines.push('| competitor | status | recall@k | precision@k | hit-rate LCB95 | note |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const c of a.competitors) {
    if (c.status === 'measured' && c.metrics) {
      lines.push(
        `| ${c.info.label} | measured | ${pct(c.metrics.macroRecallAtK)} | ${pct(c.metrics.macroPrecisionAtK)} | ${pct(c.metrics.hitRateWilsonLcb95)} | k=${c.metrics.k} |`,
      );
    } else {
      lines.push(`| ${c.info.label} | pending | — | — | — | ${c.pendingReason ?? ''} |`);
    }
  }
  lines.push('');
  lines.push('> No competitor number is fabricated: a "best in class" claim is made only on a reproduced result (§1.4). Pending entries await a vendored, offline-runnable adapter implementing the Retriever interface.');
  lines.push('');
  lines.push('## 6.6 biomedical-misroute-repro (biomedical mis-route)');
  lines.push('');
  for (const r of a.baseline.perQuery.filter((q) => q.bugRef === 'biomedical-misroute-repro')) {
    const pass = r.firstRelevantRank !== null;
    const flag = r.pendingP4 ? ' [pending-P4]' : '';
    lines.push(`- \`${r.id}\`${flag} "${r.query}" → ${pass ? `HIT (rank ${r.firstRelevantRank})` : 'MISS'} (recall@${m.k}=${r.recallAtK})`);
  }
  lines.push('');
  for (const n of a.notes) lines.push(`> ${n}`);
  lines.push('');
  return lines.join('\n');
}

async function main(): Promise<void> {
  const k = DEFAULT_MAX_TOOLS;
  const determinismRuns = intEnv('CHARIOT_PROOF_DETERMINISM_RUNS', 5);
  const latencyIters = intEnv('CHARIOT_PROOF_LATENCY_ITERS', 20);
  const outDir = process.env.CHARIOT_PROOF_OUT_DIR
    ?? join(PKG_ROOT, 'src', 'engine', 'eval', 'proof', 'artifacts');

  // ── catalog + gold set (fail closed on label drift) ──
  const catalog = await loadProductionCatalog();
  const { goldSet, path: goldSetPath } = loadGoldSet();
  const labelValidation = validateLabelsAgainstCatalog(goldSet, catalog.toolIds);
  if (!labelValidation.ok) {
    console.error('FAIL-CLOSED: gold set references tool ids absent from the catalog:');
    for (const u of labelValidation.unknownLabels) console.error(`  ${u.queryId}: ${u.toolId}`);
    process.exit(1);
  }

  console.log(`catalog: ${catalog.adapterCount} adapters / ${catalog.serverCount} servers / ${catalog.toolIds.size} tools`);
  console.log(`gold set: ${goldSet.queries.length} queries (v${goldSet.meta.version}); labels OK (${labelValidation.totalLabels})`);

  // ── baseline retriever ──
  const baseline = new BM25ToolPreFilterRetriever();
  baseline.index(catalog.tools);

  // 6.2 / 6.3 / 6.4 / 6.5
  const { perQuery, metrics } = await scoreGoldSet(baseline, goldSet, k);
  console.log(`6.2 macro recall@${k} = ${(metrics.macroRecallAtK * 100).toFixed(2)}% (floor ${(RECALL_FLOOR * 100).toFixed(0)}%, meets=${metrics.meetsFloor})`);

  const determinism = await measureDeterminism(baseline, goldSet, k, determinismRuns);
  console.log(`6.3 deterministic = ${determinism.deterministic} (${determinismRuns} runs/query)`);

  const latency = await measureLatency(baseline, goldSet, k, latencyIters);
  console.log(`6.4 latency p50/p99 = ${latency.summaryMs.p50.toFixed(3)}/${latency.summaryMs.p99.toFixed(3)} ms (n=${latency.measuredSelections})`);

  const competitors = await runCompetitors(catalog.tools, goldSet, k);
  console.log(`6.5 competitors: ${competitors.filter((c) => c.status === 'measured').length} measured, ${competitors.filter((c) => c.status === 'pending').length} pending`);

  // CH-37 first-call success + confidence calibration
  const firstCallSuccess: FirstCallSuccessReport = summarizeFirstCall(perQuery, k, makeSchemaResolver(catalog));
  console.log(`CH-37 routeCorrect = ${(firstCallSuccess.routeCorrectRate * 100).toFixed(2)}% (${firstCallSuccess.routeCorrectCount}/${firstCallSuccess.queryCount}); firstCallSuccess determinable=${firstCallSuccess.firstCallSuccessDeterminable}`);
  const calibration: CalibrationReport = buildCalibration(baseline.info.id, baseline.info.providesConfidence, perQuery);
  console.log(`calibration: ${calibration.status}${calibration.status === 'measured' ? ` (ECE ${calibration.expectedCalibrationError})` : ''}`);

  // §4.5 / AS §1.2a — requiresCustomerAuth Recall@8, reported SEPARATELY from
  // the pooled headline. Fails LOUD (never silently omitted / never a
  // fabricated 0/0 "measured") when the catalog or gold set has no coverage.
  const requiresCustomerAuthSegment = buildRequiresCustomerAuthSegment(
    perQuery,
    catalog.requiresCustomerAuthToolIds,
    catalog.requiresCustomerAuthAdapterCount,
    k,
    RECALL_FLOOR,
  );
  if (requiresCustomerAuthSegment.status === 'no-adapters-present') {
    console.warn(`§4.5 requiresCustomerAuth segment: NO ADAPTERS PRESENT — ${requiresCustomerAuthSegment.reason}`);
  } else {
    console.log(
      `§4.5 requiresCustomerAuth segment: macro recall@${k} = ${((requiresCustomerAuthSegment.metrics?.macroRecallAtK ?? 0) * 100).toFixed(2)}% ` +
        `(${requiresCustomerAuthSegment.queryCount} in-class queries, ${requiresCustomerAuthSegment.adapterCount} adapters)`,
    );
  }

  // ── style breakdown + bug refs for the artifact header ──
  const styleBreakdown: Record<string, number> = {};
  const bugRefs = new Set<string>();
  let pendingP4Count = 0;
  for (const q of goldSet.queries) {
    styleBreakdown[q.style] = (styleBreakdown[q.style] ?? 0) + 1;
    if (q.bugRef) bugRefs.add(q.bugRef);
    if (q.pendingP4) pendingP4Count += 1;
  }

  const artifact: ProofArtifact = {
    schemaVersion: SCHEMA_VERSION,
    generatedUtc: new Date().toISOString(),
    spec: { recallFloor: RECALL_FLOOR, k, northStar: NORTH_STAR },
    catalog: {
      epoch: goldSet.meta.catalogEpoch,
      catalogVersion: goldSet.meta.catalogVersion,
      // CHARIOT::§3.5::33 (CH-22) — frozen recordCount stamped alongside the
      // catalogVersion "catalog revision" identifier above, both captured at
      // the same catalog freeze the gold-set labels were derived against.
      recordCount: catalog.toolIds.size,
      adapterCount: catalog.adapterCount,
      serverCount: catalog.serverCount,
      toolCount: catalog.toolIds.size,
      // Repo-relative so the committed artifact is portable/reproducible across hosts.
      goldSetPath: relative(PKG_ROOT, goldSetPath) || goldSetPath,
    },
    goldSet: {
      version: goldSet.meta.version,
      queryCount: goldSet.queries.length,
      targetSize: goldSet.meta.targetSize,
      styleBreakdown,
      pendingP4Count,
      bugRefs: [...bugRefs].sort(),
      labelValidation: {
        ok: labelValidation.ok,
        totalLabels: labelValidation.totalLabels,
        unknownLabels: labelValidation.unknownLabels.length,
      },
    },
    baseline: {
      info: baseline.info,
      metrics: roundMetrics(metrics),
      perQuery: perQuery.map(roundPerQuery),
    },
    firstCallSuccess,
    requiresCustomerAuthSegment: roundRequiresCustomerAuthSegment(requiresCustomerAuthSegment),
    calibration,
    determinism,
    latency: {
      ...latency,
      summaryMs: {
        ...latency.summaryMs,
        min: round(latency.summaryMs.min, 3),
        p50: round(latency.summaryMs.p50, 3),
        p95: round(latency.summaryMs.p95, 3),
        p99: round(latency.summaryMs.p99, 3),
        max: round(latency.summaryMs.max, 3),
        mean: round(latency.summaryMs.mean, 3),
      },
    },
    competitors: competitors.map((c) =>
      c.metrics ? { ...c, metrics: roundMetrics(c.metrics) } : c,
    ),
    notes: [
      'recall@k and intra-query determinism (each query sha-stable across N runs) reproduce exactly on re-run against the same catalog epoch; latency is machine/run-dependent. Cross-query distinctness is not verified by the determinism check.',
      'The BM25 ToolPreFilter is the 4.0.0 baseline retriever-under-test; the Phase 4 hybrid retriever (dense+SPLADE+BM25 → RRF → cross-encoder rerank) implements the same Retriever interface and drops in with no harness change.',
      'No competitor numbers are fabricated; pending competitors await a vendored offline adapter (§1.4).',
      'CH-37 first-call-success is the release gate: routeCorrect is measured now; argsValid is unknown (catalog has no per-tool input schema) and dispatchSucceeded is pending the Phase 4 hybrid retriever + safe dispatcher fixture — wired, never assumed.',
      'Confidence calibration is unavailable for the BM25 baseline (it exposes no per-candidate score and is read-only); the binning + ECE machinery is unit-tested and populates for a scoring retriever.',
      requiresCustomerAuthSegment.status === 'no-adapters-present'
        ? `§4.5 requiresCustomerAuth segment is UNMEASURED: ${requiresCustomerAuthSegment.reason}`
        : `§4.5 requiresCustomerAuth segment is measured over ${requiresCustomerAuthSegment.queryCount} in-class queries against ${requiresCustomerAuthSegment.adapterCount} adapters, separately from the pooled headline recall.`,
    ],
  };

  mkdirSync(outDir, { recursive: true });
  const jsonPath = join(outDir, 'routing-proof.v1.json');
  const mdPath = join(outDir, 'routing-proof.v1.md');
  writeFileSync(jsonPath, JSON.stringify(artifact, null, 2) + '\n', 'utf-8');
  writeFileSync(mdPath, renderMarkdown(artifact), 'utf-8');
  console.log(`artifact written:\n  ${jsonPath}\n  ${mdPath}`);
}

// Guard so `roundPerQuery` (and other pure exports) can be imported by
// run-proof.round.test.ts without triggering the full production-catalog +
// gold-set pipeline as a side effect of the import. Runtime behavior when
// invoked directly (`node dist/engine/eval/proof/run-proof.js`) is unchanged:
// argv[1] is resolved through the filesystem (relative paths and symlinks
// both collapse to the module's real path, which is what `import.meta.url`
// carries) before comparison.
function isMainModule(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  let resolved: string;
  try {
    resolved = realpathSync(entry);
  } catch {
    return false;
  }
  return import.meta.url === pathToFileURL(resolved).href;
}
if (isMainModule()) {
  main().catch((err) => {
    console.error('run-proof failed:', err);
    process.exit(1);
  });
}
