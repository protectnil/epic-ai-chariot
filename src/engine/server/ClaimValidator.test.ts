/**
 * Adversarial evals for ClaimValidator fixes from 35f8710.
 *
 * Covers:
 *   P1 — disjoint-vocabulary contradiction (fix: scan full evidence, abstain
 *        rather than falsely 'supported' when a contradiction exists outside
 *        claim-relevant spans).
 *
 * No mocked dependencies. All inputs drive the real heuristic engine
 * imported from the compiled dist.
 *
 * Run: node --test dist/engine/server/ClaimValidator.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  groundClaimHeuristic,
  contradictionStrength,
} from './ClaimValidator.js';

// ─── disjoint-vocabulary fix ──────────────────────────────────────────────────
// Pre-fix: overlapRatio >= 0.5 with a contradiction that lives in a DIFFERENT
// sentence than the claim tokens returned 'supported'.
// Post-fix: contradictionStrength is also applied to the full evidence text;
// a disjoint signal forces verdict to 'insufficient' (abstain).
//
// KEY DESIGN CONSTRAINT: claim tokens must not share any word (even "the",
// "our") with the disjoint-contradiction sentence, otherwise extractRelevantSpans
// pulls that sentence into the relevant spans and the span-scoped check fires
// instead of the fix. All examples below avoid such bridging.

describe('ClaimValidator — disjoint-vocabulary contradiction (P1 fix)', () => {

  // Primary attack: claim with 100% token overlap in sentence 1; contradiction
  // ("errors") lives only in sentence 2 which shares zero claim tokens.
  test('disjoint contradiction → insufficient, NOT supported', () => {
    // Claim tokens: authentication, subsystem, operations, complete, successfully
    // Evidence sentence 1 shares all five → overlapRatio = 1.0.
    // Evidence sentence 2 has "errors" (SIGNAL match) but shares ZERO claim tokens
    // → not included in relevantSpans by extractRelevantSpans → span check returns 0.
    // fullContradiction picks it up → fix abstains.
    const claim    = 'Authentication subsystem operations complete successfully';
    const evidence =
      'Authentication subsystem operations complete successfully within timeout bounds. ' +
      'Distributed cache connection encountered errors during startup.';

    const r = groundClaimHeuristic(claim, evidence);

    assert.notStrictEqual(
      r.verdict, 'supported',
      `disjoint contradiction must not yield 'supported'; got '${r.verdict}'`,
    );
    assert.strictEqual(
      r.verdict, 'insufficient',
      `expected 'insufficient' (abstain via fullContradiction), got '${r.verdict}'. rationale: ${r.rationale}`,
    );
  });

  // Second attack: high overlap (not 100%) plus disjoint contradiction.
  test('disjoint contradiction with partial overlap → still insufficient, not supported', () => {
    // Claim tokens: payment, gateway, uptime, exceeds, percent (5 tokens; "99.9" → "99" 2-chars dropped)
    // Sentence 1 shares 5/5 → overlapRatio 1.0.
    // Sentence 2 has "failed" (SIGNAL) but shares zero claim tokens → disjoint.
    const claim    = 'Payment gateway uptime exceeds 99.9 percent';
    const evidence =
      'Payment gateway uptime exceeds 99.9 percent across all regions. ' +
      'Billing pipeline failed yesterday.';

    const r = groundClaimHeuristic(claim, evidence);

    assert.notStrictEqual(
      r.verdict, 'supported',
      `got '${r.verdict}'; must not be supported when disjoint "failed" exists`,
    );
    assert.strictEqual(r.verdict, 'insufficient',
      `expected 'insufficient', got '${r.verdict}'. rationale: ${r.rationale}`);
  });

  // Task's verbatim adversarial pair — no shared tokens at all.
  test("task example: 'system is highly available' vs '3-hour outage yesterday' → NOT supported", () => {
    const r = groundClaimHeuristic(
      'system is highly available',
      '3-hour outage yesterday',
    );
    assert.notStrictEqual(
      r.verdict, 'supported',
      `'3-hour outage' evidence must never yield supported; got '${r.verdict}'`,
    );
  });

  // ── no false-negatives: clean evidence remains 'supported' ───────────────
  test('true-supported case: clean evidence → supported (no false negatives)', () => {
    // Same claim structure as attack 1, but evidence sentence 2 has NO
    // contradiction words — fullContradiction = 0 → 'supported' is correct.
    const claim    = 'Authentication subsystem operations complete successfully';
    const evidence =
      'Authentication subsystem operations complete successfully within timeout bounds. ' +
      'All health probes returned positive status during validation.';

    const r = groundClaimHeuristic(claim, evidence);
    assert.strictEqual(
      r.verdict, 'supported',
      `expected 'supported' for clean evidence; got '${r.verdict}'. rationale: ${r.rationale}`,
    );
  });

  test('negated contradiction "zero errors" is neutralised — should not be contradicted', () => {
    // "zero errors" matches the NEG_OF_NEGATIVE pattern and is stripped
    // before the SIGNAL scan. "no failed health checks" is also neutralised.
    const claim    = 'API deployment succeeded without issues';
    const evidence =
      'API deployment succeeded without issues: zero errors logged and no failed health checks.';

    const r = groundClaimHeuristic(claim, evidence);
    assert.notStrictEqual(
      r.verdict, 'contradicted',
      `negated negatives must not produce 'contradicted'; got '${r.verdict}'`,
    );
  });

  // ── contradictionStrength unit checks ────────────────────────────────────
  test('contradictionStrength detects "errors" in isolation', () => {
    const s = contradictionStrength('connection encountered errors during startup');
    assert.ok(s > 0, `expected > 0 contradiction strength, got ${s}`);
  });

  test('contradictionStrength detects "failed" in isolation', () => {
    const s = contradictionStrength('billing pipeline failed yesterday');
    assert.ok(s > 0, `expected > 0, got ${s}`);
  });

  test('contradictionStrength: "zero errors" neutralised to 0', () => {
    const s = contradictionStrength('zero errors logged in production');
    assert.strictEqual(s, 0, `NEG_OF_NEGATIVE must neutralise 'zero errors'`);
  });
});
