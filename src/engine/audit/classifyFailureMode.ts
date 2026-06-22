/**
 * @epicai/chariot — MAST Failure Mode Classifier
 *
 * Heuristic classifier mapping Chariot's structured error codes and free-text
 * error messages to the MAST taxonomy (Cemri et al., arXiv:2503.13657).
 *
 * Classification strategy:
 *   1. Heuristic rules keyed on ChariotErrorCode — deterministic, zero cost.
 *   2. Regex rules on error message text — deterministic, zero cost.
 *   3. Returns null if no rule matches; caller may invoke LLM fallback.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { FailureMode } from '../types/index.js';

/**
 * Apply deterministic heuristic rules to produce a FailureMode classification.
 *
 * @param errorCode - The ChariotErrorCode string from the structured error
 *   payload, if present. May be undefined for transport-layer errors.
 * @param errorMessage - The human-readable error message from the failure.
 * @returns The classified FailureMode, or null if no heuristic rule matched.
 *   Callers should treat null as a signal to invoke the Haiku LLM classifier
 *   defined in spec §4B, and fall back to 'UNKNOWN' if that also fails.
 */
export function classifyFailureModeHeuristic(
  errorCode: string | undefined,
  errorMessage: string,
): FailureMode | null {
  // ── FC1 — System Design Issues ─────────────────────────────────────────────

  // FM-1.3: agent repeated actions — depth/fanout exceeded means looping
  if (errorCode === 'TOOL_DEPTH_EXCEEDED' || errorCode === 'TOOL_FANOUT_EXCEEDED') {
    return 'FM-1.3_STEP_REPETITION';
  }

  // FM-1.2: RBAC denied — agent attempted to act outside its role
  if (errorCode === 'RBAC_OPERATION_DENIED') {
    return 'FM-1.2_DISOBEY_ROLE_SPEC';
  }

  // FM-1.1: explicit task spec violations (response size, arg depth/payload)
  if (
    errorCode === 'RESPONSE_TOO_LARGE' ||
    errorCode === 'ARG_DEPTH_EXCEEDED' ||
    errorCode === 'ARG_PAYLOAD_TOO_LARGE'
  ) {
    return 'FM-1.1_DISOBEY_TASK_SPEC';
  }

  // ── FC2 — Inter-Agent Misalignment ─────────────────────────────────────────

  // FM-2.6: rate limit — agent over-called; reasoning did not anticipate limits
  if (errorCode === 'RATE_LIMIT_EXCEEDED') {
    return 'FM-2.6_REASONING_ACTION_MISMATCH';
  }

  // FM-2.3: agent tried a tool outside its task scope (unregistered tool)
  if (errorCode === 'TOOL_NOT_REGISTERED') {
    return 'FM-2.3_TASK_DERAILMENT';
  }

  // FM-2.2: License/auth errors — agent proceeded without clarifying credential state
  if (
    errorCode === 'LICENSE_REVOKED' ||
    errorCode === 'LICENSE_EXPIRED' ||
    errorCode === 'LICENSE_NOT_YET_VALID' ||
    errorCode === 'LICENSE_TENANT_MISMATCH'
  ) {
    return 'FM-2.2_FAIL_TO_CLARIFY';
  }

  // FM-2.6: audit/chain integrity violations — agent action contradicted the record
  if (
    errorCode === 'ANCHOR_VERIFY_FAILED' ||
    errorCode === 'LENGTH_ATTESTATION_FAILED' ||
    errorCode === 'CHAIN_TRUNCATION_DETECTED'
  ) {
    return 'FM-2.6_REASONING_ACTION_MISMATCH';
  }

  // CATALOG_INTEGRITY_ERROR: catalog-layer structural fault, not a runtime
  // agent behavior failure. Does not map cleanly to any MAST mode; classify
  // as UNKNOWN and let the LLM classifier or operator review assign it.
  if (errorCode === 'CATALOG_INTEGRITY_ERROR') {
    return 'UNKNOWN';
  }

  // ── Message-text rules: only applied when errorCode gave no match ──────────
  // Note: Rules are ordered from most-specific to least-specific to prevent
  // ambiguous cases from being caught by an overly broad pattern.

  // FM-1.5: agent ran to max iterations without recognising completion
  // Match: "max iterations hit", "max iter limit", "loop limit", "never terminated",
  //        "did not self-terminate", "loop limit exceeded"
  if (
    /max.{0,20}iter/i.test(errorMessage) ||
    /iteration.{0,10}limit/i.test(errorMessage) ||
    /loop.{0,10}limit/i.test(errorMessage) ||
    /never.{0,10}terminat/i.test(errorMessage) ||
    /did\s+not\s+self[- ]terminat/i.test(errorMessage)
  ) {
    return 'FM-1.5_UNAWARE_TERMINATION_CONDITIONS';
  }

  // FM-1.4: context/history loss signals
  if (
    /context.{0,15}truncat/i.test(errorMessage) ||
    /history.{0,10}lost/i.test(errorMessage) ||
    /context.{0,10}window/i.test(errorMessage)
  ) {
    return 'FM-1.4_LOSS_OF_CONV_HISTORY';
  }

  // FM-3.2: verification step was absent or incomplete
  // Match: "no verification", "verification skipped", "skipped verification",
  //        "missing check", "incomplete verification", "unverified"
  if (
    /no.{0,5}verif/i.test(errorMessage) ||
    /verif.{0,15}skip/i.test(errorMessage) ||
    /skip.{0,15}verif/i.test(errorMessage) ||
    /missing.{0,10}check/i.test(errorMessage) ||
    /incomplete.{0,5}verif/i.test(errorMessage) ||
    /unverified/i.test(errorMessage)
  ) {
    return 'FM-3.2_INCOMPLETE_VERIFICATION';
  }

  // FM-3.3: verification ran but produced the wrong result
  // Requires BOTH a verification signal AND a failure/mismatch signal.
  // Note: only free-text messages reach here; errorCode-classified errors
  // (e.g. CATALOG_INTEGRITY_ERROR) are handled above and do not fall through.
  // Use /\bfail/ (no trailing \b) so "failed" matches alongside "fail".
  if (
    /\b(verif|validat|assert|confirm|check)\w*/i.test(errorMessage) &&
    /\bfail|\b(wrong|incorrect|mismatch)\b/i.test(errorMessage)
  ) {
    return 'FM-3.3_INCORRECT_VERIFICATION';
  }

  // FM-3.1: agent terminated before completing the task
  // Match: "terminated", "premature", "early stop", "abandoned", "gave up",
  //        "early exit", "incomplete execution"
  if (
    /terminat/i.test(errorMessage) ||
    /premature/i.test(errorMessage) ||
    /early.{0,5}stop/i.test(errorMessage) ||
    /abandon/i.test(errorMessage) ||
    /gave.{0,5}up/i.test(errorMessage)
  ) {
    return 'FM-3.1_PREMATURE_TERMINATION';
  }

  // No heuristic matched — caller should invoke LLM classifier or use UNKNOWN
  return null;
}

/**
 * Convenience wrapper that returns 'UNKNOWN' instead of null when no heuristic
 * matches and no LLM fallback is wired. Use this in synchronous call sites
 * where an async LLM call is not feasible.
 */
export function classifyFailureModeSafe(
  errorCode: string | undefined,
  errorMessage: string,
): FailureMode {
  return classifyFailureModeHeuristic(errorCode, errorMessage) ?? 'UNKNOWN';
}
