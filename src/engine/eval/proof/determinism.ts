/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: determinism measurement
 *
 * §6.3 — run each query N times and assert the candidate-set hash is identical
 * across all runs (intra-query run-to-run stability). Extracted from run-proof.ts
 * so the proof harness and the adversarial test suite can call the same
 * implementation — no re-implementation, no stub.
 *
 * What this checks: each query is run N times and the candidate-set hash must
 * be identical across all N runs. Cross-query distinctness — whether different
 * queries return distinct candidate sets — is a separate concern and is NOT
 * verified here; see DeterminismReport.scope for the explicit statement.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { hashCandidateSet } from './metrics.js';
import type { Retriever, GoldSet, DeterminismReport, DeterminismPerQuery } from './types.js';

/**
 * Run each query in `goldSet` exactly `runsPerQuery` times through `retriever`,
 * hash the ordered candidate-id list after each run, and report whether the hash
 * is identical across all runs for every query. A single distinct hash per query
 * means the retriever is deterministic (intra-query stable). Two or more distinct
 * hashes for any query means the retriever is nondeterministic.
 *
 * Cross-query distinctness (whether two different queries happen to return the same
 * candidate set) is explicitly OUT OF SCOPE — the report.scope field says so.
 */
export async function measureDeterminism(
  retriever: Retriever,
  goldSet: GoldSet,
  k: number,
  runsPerQuery: number,
): Promise<DeterminismReport> {
  const perQuery: DeterminismPerQuery[] = [];
  const nondeterministicQueryIds: string[] = [];
  for (const q of goldSet.queries) {
    const hashes = new Set<string>();
    let firstSha = '';
    for (let run = 0; run < runsPerQuery; run += 1) {
      const returned = await retriever.retrieve(q.query, k);
      const sha = hashCandidateSet(returned.map((t) => t.id));
      if (run === 0) firstSha = sha;
      hashes.add(sha);
    }
    perQuery.push({ id: q.id, distinctHashes: hashes.size, sha256: firstSha });
    if (hashes.size !== 1) nondeterministicQueryIds.push(q.id);
  }
  return {
    runsPerQuery,
    queryCount: goldSet.queries.length,
    scope: 'intra-query run-to-run stability',
    deterministic: nondeterministicQueryIds.length === 0,
    nondeterministicQueryIds,
    perQuery,
  };
}
