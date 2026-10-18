/**
 * @epicai/chariot — Engine-Level Claim Validation / Grounding
 *
 * Provides chariot_validate_claim: a general-purpose grounding layer that
 * evaluates whether caller-supplied evidence text supports, contradicts, or
 * is insufficient to assess a stated claim. A native engine grounding layer.
 *
 * Design:
 *   - Pure text/heuristic grounding when no LLM is wired (default OSS path).
 *     Lexical overlap + negation detection produce a conservative verdict that
 *     is always deterministic and never requires an outbound API call.
 *   - Optional LLM-grounding path: when `claimValidatorLlm` is supplied on
 *     ChariotState, the evidence+claim are sent to the LLM for a structured
 *     verdict.  The LLM path is additive — the heuristic result is always
 *     computed first and returned if the LLM call fails, so the fallback is
 *     transparent to callers.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createLogger } from '../logger.js';

const _log = createLogger('engine.claimValidator');

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Grounding verdict returned by validateClaim().
 *
 *   'supported'    — evidence text contains concrete, non-negated signals that
 *                    substantiate the claim.
 *   'contradicted' — evidence contains explicit negation or a direct counter-
 *                    assertion relative to the claim.
 *   'insufficient' — evidence is present but does not contain enough relevant
 *                    signal to confirm or contradict the claim.
 *   'needs_review' — CH-44: the claim and evidence carry comparable structured
 *                    values (numbers, percentages, currency, versions, dates,
 *                    IDs) that DISAGREE (e.g. claim "7.5%" vs evidence "2.9%").
 *                    A disagreement is neither support nor a clean prose
 *                    contradiction — it is flagged for review so the layer
 *                    never returns a false 'supported'.
 *   'no_evidence'  — evidence is empty or too short to evaluate.
 */
export type ClaimVerdict = 'supported' | 'contradicted' | 'insufficient' | 'needs_review' | 'no_evidence';

export interface ClaimValidationResult {
  /** The original claim text (unchanged). */
  claim: string;
  /** Grounding verdict. */
  verdict: ClaimVerdict;
  /**
   * Confidence in the verdict [0, 1].  Heuristic path uses a simple scoring
   * model; LLM path delegates confidence to the model.
   */
  confidence: number;
  /**
   * Human-readable rationale.  Always present so operators and calling agents
   * can log or display the reasoning without re-running the check.
   */
  rationale: string;
  /**
   * Span(s) from the evidence that most strongly influenced the verdict.
   * Empty when evidence is absent or the path produced no signal.
   */
  evidenceSpans: string[];
  /** Which grounding path produced this result. */
  groundingPath: 'heuristic' | 'llm';
}

// ---------------------------------------------------------------------------
// Optional LLM interface (same shape as engine LLMFunction for compatibility)
// ---------------------------------------------------------------------------

export interface ClaimValidatorLlm {
  (params: {
    messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
  }): Promise<{ content: string | null }>;
}

// ---------------------------------------------------------------------------
// Heuristic grounding
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CH-44 — structured-value (numeric / version / date / id) extraction & match
// ---------------------------------------------------------------------------

/** Normalize a numeric string so "7.50" and "7.5" compare equal. */
function normNum(s: string): string {
  const n = Number(s);
  return Number.isFinite(n) ? String(n) : s.toLowerCase();
}

/**
 * Extract structured quantities from `text`, keyed by KIND. Spans are consumed
 * in priority order (most specific first) so "7.5%" is recorded as a percent,
 * not also as a bare number. Versions require a leading `v` or three
 * components so a decimal like 7.5 is not misread as a version.
 */
export function extractQuantities(text: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (kind: string, value: string): void => {
    let set = out.get(kind);
    if (!set) { set = new Set(); out.set(kind, set); }
    set.add(value);
  };
  let work = ` ${text} `;
  const consume = (re: RegExp, kind: string, norm: (m: RegExpExecArray) => string): void => {
    work = work.replace(re, (...args) => {
      // args: match, ...groups, offset, string  → reconstruct an exec-like array
      const groups = args.slice(0, -2) as string[];
      add(kind, norm(groups as unknown as RegExpExecArray));
      return ' '.repeat(args[0].length);
    });
  };
  // 1. dates — ISO and common slash/dotted forms
  consume(/\b(\d{4})-(\d{2})-(\d{2})\b/g, 'date', (m) => `${m[1]}-${m[2]}-${m[3]}`);
  consume(/\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/g, 'date', (m) => `${m[1]}/${m[2]}/${m[3]}`);
  // 2. percent
  consume(/(\d+(?:\.\d+)?)\s*(?:%|percent\b|pct\b)/gi, 'percent', (m) => normNum(m[1]));
  // 3. currency — cents then dollars
  consume(/(\d+(?:\.\d+)?)\s*(?:¢|cents?\b)/gi, 'cents', (m) => normNum(m[1]));
  consume(/[$£€]\s?(\d+(?:\.\d+)?)/g, 'currency', (m) => normNum(m[1]));
  consume(/(\d+(?:\.\d+)?)\s*(?:dollars?\b|usd\b|eur\b)/gi, 'currency', (m) => normNum(m[1]));
  // 4. versions (v-prefixed, or 3+ components) — kept before plain numbers
  consume(/\bv(\d+(?:\.\d+)+)\b/gi, 'version', (m) => m[1].toLowerCase());
  consume(/\b(\d+\.\d+\.\d+(?:\.\d+)*)\b/g, 'version', (m) => m[1]);
  // 5. structured ids — TICKET-123, CVE-2021-44228, #4321
  consume(/\b([A-Za-z]{2,}-\d+(?:-\d+)*)\b/g, 'id', (m) => m[1].toUpperCase());
  consume(/#(\d{2,})\b/g, 'id', (m) => `#${m[1]}`);
  // 6. plain numbers (whatever decimals/integers remain)
  consume(/\b(\d+(?:\.\d+)?)\b/g, 'number', (m) => normNum(m[1]));
  return out;
}

export interface QuantityComparison {
  /** A kind present in BOTH with NO shared value → the claim asserts a value the evidence disagrees with. */
  mismatch: boolean;
  /** At least one kind present in both shared a value. */
  matched: boolean;
  /** Kinds comparable across claim+evidence. */
  comparableKinds: string[];
}

/**
 * Compare the structured quantities of a claim against the evidence. A
 * `mismatch` is the CH-44 trigger: the claim states a value (percent, number,
 * version, …) and the evidence carries a value of the SAME KIND but never the
 * claimed one (7.5% vs 2.9%). Kinds the evidence does not mention at all are
 * not comparable and never produce a mismatch.
 */
export function compareQuantities(claim: string, evidence: string): QuantityComparison {
  const c = extractQuantities(claim);
  const e = extractQuantities(evidence);
  let mismatch = false;
  let matched = false;
  const comparableKinds: string[] = [];
  for (const [kind, cVals] of c) {
    const eVals = e.get(kind);
    if (!eVals || eVals.size === 0) continue; // evidence is silent on this kind
    comparableKinds.push(kind);
    const shared = [...cVals].some((v) => eVals.has(v));
    if (shared) matched = true;
    else mismatch = true;
  }
  return { mismatch, matched, comparableKinds };
}

/**
 * CH-44 — contradiction-signal strength that does NOT trip on affirmative text
 * containing a negated negative ("zero error logs", "no failed health
 * checks"). A grammatical negation immediately preceding a negative-sentiment
 * word flips it to positive, so those spans are neutralized before counting.
 * Bare "no" is intentionally NOT a standalone contradiction signal (the 3.1.2
 * false-contradicted case); "not"/"never" and un-negated negative-sentiment
 * words (an un-negated "failed") still count.
 */
export function contradictionStrength(text: string): number {
  const lower = ` ${text.toLowerCase()} `;
  // Neutralize negated-negatives: (no|zero|without|free of|none of|not) <neg word>
  const NEG_OF_NEGATIVE =
    /\b(?:no|zero|without|free\s+of|none\s+of|not|never|nil)\s+(?:\w+\s+){0,2}?(?:fail\w*|error\w*|issue\w*|problem\w*|bug\w*|downtime|outage\w*|defect\w*|incident\w*|fault\w*|vulnerab\w*|crash\w*|warning\w*|deni\w*|reject\w*|miss\w*|absent|unavailab\w*|unable|broken|invalid|incorrect|wrong)\b/g;
  const neutralized = lower.replace(NEG_OF_NEGATIVE, ' ');
  // Remaining contradiction signals: grammatical negations (excluding bare
  // "no") + un-negated negative-sentiment words.
  const SIGNAL =
    /\b(?:not|never|none|neither|cannot|can't|won't|isn't|aren't|doesn't|don't|didn't|wasn't|weren't|hasn't|haven't|hadn't|couldn't|wouldn't|shouldn't|mustn't|fail\w*|error\w*|incorrect|wrong|invalid|denied|rejected|unable|unavailable|missing|absent|broken|false)\b/g;
  const matches = neutralized.match(SIGNAL);
  return matches ? matches.length : 0;
}

/**
 * Tokenize text into lowercase words (strips punctuation so "world." matches
 * "world" in the claim without needing exact-string tricks).
 */
function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2);
}

/**
 * Extract up to `maxSpans` evidence sentences that contain at least one claim
 * keyword.  Sentence splitting on '.', '!', '?' handles plain prose and JSON
 * values embedded in stringified payloads alike.
 */
function extractRelevantSpans(evidence: string, claimTokens: Set<string>, maxSpans = 3): string[] {
  // Split on sentence boundaries; keep each fragment trimmed.
  const sentences = evidence
    .split(/(?<=[.!?])\s+|[\n\r]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const spans: string[] = [];
  for (const sentence of sentences) {
    if (spans.length >= maxSpans) break;
    const sentTokens = new Set(tokenize(sentence));
    // Require at least one overlap with the claim's meaningful tokens.
    const overlap = [...claimTokens].some((t) => sentTokens.has(t));
    if (overlap) spans.push(sentence.slice(0, 200));
  }
  return spans;
}

/**
 * Heuristic grounding engine.  Never throws — returns 'no_evidence' on any
 * internal failure so callers always get a valid ClaimValidationResult.
 */
export function groundClaimHeuristic(claim: string, evidence: string): ClaimValidationResult {
  const trimmedClaim = claim.trim();
  const trimmedEvidence = evidence.trim();

  if (trimmedEvidence.length < 10) {
    return {
      claim: trimmedClaim,
      verdict: 'no_evidence',
      confidence: 0.9,
      rationale: 'Evidence is empty or too short to evaluate the claim.',
      evidenceSpans: [],
      groundingPath: 'heuristic',
    };
  }

  const claimTokens = new Set(tokenize(trimmedClaim));
  // Set for O(1) membership — overlap is O(claim) not O(claim × evidence).
  const evidenceTokens = new Set(tokenize(trimmedEvidence));

  // Lexical overlap: fraction of claim tokens present in evidence.
  const overlapCount = [...claimTokens].filter((t) => evidenceTokens.has(t)).length;
  const overlapRatio = claimTokens.size > 0 ? overlapCount / claimTokens.size : 0;

  const relevantSpans = extractRelevantSpans(trimmedEvidence, claimTokens);
  const relevantText = relevantSpans.join(' ').toLowerCase();

  // CH-44 — structured-value agreement. Compare numbers/percent/currency/
  // version/date/id between claim and evidence. A same-kind disagreement (the
  // 7.5%-vs-2.9% case) can NEVER read as 'supported': it is flagged
  // needs_review. Comparison runs over the full claim+evidence, not just the
  // overlap window, so a quantity in either is not missed by span splitting.
  const quant = compareQuantities(trimmedClaim, trimmedEvidence);

  // CH-44 — contradiction strength that ignores negated-negatives so affirmative
  // text ("zero error logs, no failed health checks") is NOT a false
  // 'contradicted'.
  const contradiction = contradictionStrength(relevantText);
  // Also scan the full evidence for contradiction signals that are
  // disjoint from claim tokens (e.g. "3-hour outage" vs a claim of
  // "highly available"). span-scoped scoring above misses these because
  // extractRelevantSpans only returns sentences that share a claim token.
  // When a disjoint contradiction exists we cannot assert 'supported' —
  // the safe verdict is 'insufficient' (abstain).
  const fullContradiction = contradictionStrength(trimmedEvidence.toLowerCase());
  const hasRelevantOverlap = overlapRatio >= 0.25;

  let verdict: ClaimVerdict;
  let confidence: number;
  let rationale: string;

  if (quant.mismatch) {
    // Structured values disagree → never 'supported'; flag for review.
    verdict = 'needs_review';
    confidence = 0.8;
    rationale =
      `Claim and evidence carry comparable ${quant.comparableKinds.join('/')} values that disagree ` +
      `— the claimed value does not appear in the evidence. Flagged for review rather than treated as supported.`;
  } else if (overlapRatio < 0.15) {
    // Too little evidence relevance to decide either way.
    verdict = 'insufficient';
    confidence = Math.max(0.5, 0.85 - overlapRatio);
    rationale =
      `Evidence has low lexical overlap with the claim (overlap ratio ${overlapRatio.toFixed(2)}). ` +
      'Cannot confirm or contradict without more relevant evidence.';
  } else if (contradiction > 0 && hasRelevantOverlap) {
    verdict = 'contradicted';
    confidence = Math.min(0.95, 0.6 + overlapRatio * 0.5);
    rationale =
      `Evidence contains un-negated contradiction signals adjacent to claim-relevant content ` +
      `(overlap ratio ${overlapRatio.toFixed(2)}). The evidence appears to refute the claim.`;
  } else if (overlapRatio >= 0.5) {
    if (fullContradiction > 0) {
      // A contradiction signal exists somewhere in the evidence that did not
      // land in the claim-token spans (disjoint vocabulary). We cannot confirm
      // support when a disjoint contradiction may refute it — abstain.
      verdict = 'insufficient';
      confidence = 0.6;
      rationale =
        `Evidence has substantial lexical overlap with the claim ` +
        `(overlap ratio ${overlapRatio.toFixed(2)}) but contains contradiction ` +
        `signals outside the claim-relevant spans (disjoint vocabulary). ` +
        `Cannot confirm support without full-coverage contradiction analysis.`;
    } else {
      verdict = 'supported';
      // Confirmed structured values raise confidence; their absence does not lower it.
      confidence = Math.min(0.95, 0.65 + overlapRatio * 0.3 + (quant.matched ? 0.05 : 0));
      rationale =
        `Evidence has substantial lexical overlap with the claim ` +
        `(overlap ratio ${overlapRatio.toFixed(2)})` +
        `${quant.matched ? ' with agreeing structured values' : ''} and no contradicting signal was detected.`;
    }
  } else {
    verdict = 'insufficient';
    confidence = 0.6;
    rationale =
      `Evidence partially overlaps with the claim (overlap ratio ${overlapRatio.toFixed(2)}) ` +
      'but does not contain enough unambiguous signal to confirm it.';
  }

  return {
    claim: trimmedClaim,
    verdict,
    confidence: Number(confidence.toFixed(3)),
    rationale,
    evidenceSpans: relevantSpans,
    groundingPath: 'heuristic',
  };
}

// ---------------------------------------------------------------------------
// LLM grounding (optional overlay)
// ---------------------------------------------------------------------------

const LLM_SYSTEM_PROMPT =
  'You are a grounding verifier.  Given a CLAIM and EVIDENCE, determine whether ' +
  'the evidence supports, contradicts, or is insufficient to assess the claim.  ' +
  'If the claim and evidence carry comparable numbers, percentages, currency, ' +
  'versions, dates, or IDs that DISAGREE, answer "needs_review" — never ' +
  '"supported".  ' +
  'Reply with ONLY valid JSON matching this schema exactly:\n' +
  '{"verdict":"supported"|"contradicted"|"insufficient"|"needs_review"|"no_evidence",' +
  '"confidence":0.0-1.0,' +
  '"rationale":"<one sentence>",' +
  '"evidenceSpans":["<up to 3 short quotes from the evidence>"]}';

/**
 * Extract the first COMPLETE top-level JSON object from `text` via a
 * brace-balanced scan that respects string literals and escapes. Returns null
 * when no balanced object is present. Used instead of a greedy regex so a
 * braced preamble before the verdict object does not corrupt the parse.
 */
function extractFirstJsonObject(text: string): string | null {
  const start = text.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') {
      inStr = true;
    } else if (ch === '{') {
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * LLM-grounding overlay.  Returns null on any failure so the caller falls
 * back to the heuristic result transparently.
 *
 * EGRESS / DLP: `evidence` (caller-supplied, up to 4096 chars) is
 * sent VERBATIM to `llm`. This path is only reached when an embedder wires
 * `state.claimValidatorLlm`; the OSS default leaves it undefined and makes no
 * outbound call. The embedder owns egress controls and MUST wrap `llm` with
 * any required DLP/redaction before forwarding evidence off-process.
 */
async function groundClaimWithLlm(
  claim: string,
  evidence: string,
  llm: ClaimValidatorLlm,
): Promise<ClaimValidationResult | null> {
  const userContent =
    `CLAIM: ${claim.slice(0, 512)}\n\nEVIDENCE:\n${evidence.slice(0, 4096)}`;
  try {
    const response = await llm({
      messages: [
        { role: 'system', content: LLM_SYSTEM_PROMPT },
        { role: 'user', content: userContent },
      ],
    });
    const raw = response.content;
    if (!raw) return null;
    // Extract the FIRST COMPLETE JSON object via balanced-brace scan:
    // a greedy /\{[\s\S]*\}/ would span a braced preamble + the verdict object
    // and fail to parse, silently falling through to the heuristic.
    const jsonText = extractFirstJsonObject(raw);
    if (!jsonText) return null;
    const parsed = JSON.parse(jsonText) as {
      verdict?: unknown;
      confidence?: unknown;
      rationale?: unknown;
      evidenceSpans?: unknown;
    };
    const VALID_VERDICTS: ClaimVerdict[] = ['supported', 'contradicted', 'insufficient', 'needs_review', 'no_evidence'];
    if (!VALID_VERDICTS.includes(parsed.verdict as ClaimVerdict)) return null;
    return {
      claim,
      verdict: parsed.verdict as ClaimVerdict,
      confidence: typeof parsed.confidence === 'number'
        ? Math.max(0, Math.min(1, parsed.confidence))
        : 0.7,
      rationale: typeof parsed.rationale === 'string' ? parsed.rationale : '',
      evidenceSpans: Array.isArray(parsed.evidenceSpans)
        ? (parsed.evidenceSpans as unknown[])
            .filter((s): s is string => typeof s === 'string')
            .slice(0, 3)
        : [],
      groundingPath: 'llm',
    };
  } catch (err) {
    _log.warn('claim_validator_llm_failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Validate `claim` against `evidence`.  Uses the LLM path when `llm` is
 * supplied and the call succeeds; otherwise falls back to the heuristic path.
 *
 * Never throws — all errors produce a valid result with `verdict:'no_evidence'`
 * and an explanatory rationale.
 */
export async function validateClaim(
  claim: string,
  evidence: string,
  llm?: ClaimValidatorLlm,
): Promise<ClaimValidationResult> {
  // Always compute the heuristic result — it is the fallback and is cheap.
  const heuristic = groundClaimHeuristic(claim, evidence);

  if (!llm) return heuristic;

  const llmResult = await groundClaimWithLlm(claim, evidence, llm);
  // Return LLM result when valid; fall through to heuristic on any failure.
  return llmResult ?? heuristic;
}
