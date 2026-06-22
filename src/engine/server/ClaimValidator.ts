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
 *   'no_evidence'  — evidence is empty or too short to evaluate.
 */
export type ClaimVerdict = 'supported' | 'contradicted' | 'insufficient' | 'no_evidence';

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

/**
 * English negation markers, matched at WORD BOUNDARIES (not substrings) so a
 * claim/evidence word like "north", "notable", or "errors" cannot spuriously
 * trip negation, and contractions ("can't"/"won't") stay intact. (the
 * prior substring `.includes('no ')` flipped verdicts on "north", "no critical
 * alerts", a JSON key "error", etc.)
 */
const NEGATION_RE =
  /\b(?:not|never|no|none|neither|false|incorrect|wrong|invalid|denied|rejected|failed|error|unable|unavailable|missing|absent|cannot|can't|won't|isn't|aren't|doesn't|don't|didn't|wasn't|weren't|hasn't|haven't|hadn't|couldn't|wouldn't|shouldn't|mustn't)\b/;

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

  // Negation detection: scan the relevant window for negation terms adjacent
  // to claim keywords.  A true contradiction requires BOTH negation AND
  // relevant overlap — a generic "error" in unrelated evidence should not
  // flip a verdict to 'contradicted'.
  const hasNegation = NEGATION_RE.test(relevantText);
  const hasRelevantOverlap = overlapRatio >= 0.25;

  let verdict: ClaimVerdict;
  let confidence: number;
  let rationale: string;

  if (overlapRatio < 0.15) {
    // Too little evidence relevance to decide either way.
    verdict = 'insufficient';
    confidence = Math.max(0.5, 0.85 - overlapRatio);
    rationale =
      `Evidence has low lexical overlap with the claim (overlap ratio ${overlapRatio.toFixed(2)}). ` +
      'Cannot confirm or contradict without more relevant evidence.';
  } else if (hasNegation && hasRelevantOverlap) {
    verdict = 'contradicted';
    confidence = Math.min(0.95, 0.6 + overlapRatio * 0.5);
    rationale =
      `Evidence contains negation signals adjacent to claim-relevant content ` +
      `(overlap ratio ${overlapRatio.toFixed(2)}). The evidence appears to refute the claim.`;
  } else if (overlapRatio >= 0.5) {
    verdict = 'supported';
    confidence = Math.min(0.95, 0.65 + overlapRatio * 0.3);
    rationale =
      `Evidence has substantial lexical overlap with the claim ` +
      `(overlap ratio ${overlapRatio.toFixed(2)}) and no contradicting negation was detected.`;
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
  'Reply with ONLY valid JSON matching this schema exactly:\n' +
  '{"verdict":"supported"|"contradicted"|"insufficient"|"no_evidence",' +
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
    const VALID_VERDICTS: ClaimVerdict[] = ['supported', 'contradicted', 'insufficient', 'no_evidence'];
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
