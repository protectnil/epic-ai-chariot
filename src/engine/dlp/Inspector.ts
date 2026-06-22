/**
 * Gateway DLP — Inspector
 *
 * Inspects a stringified response body for secrets/PII. Returns a
 * decision (block / redact / allow) and the set of findings. Per-tenant
 * config selects which decision is applied per rule; default applies
 * when no per-tenant override exists.
 *
 * Wiring: call `inspect(content, tenantId, source)` from the federation
 * layer immediately after `adapter.callTool(...)` returns, before the
 * result reaches the orchestrator. Block → return synthetic error.
 * Redact → replace ToolResult.content with sanitizedContent. Allow →
 * pass through.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  DlpRule,
  DlpFinding,
  DlpDecision,
  DlpInspectionResult,
  DlpConfig,
  DlpTenantConfig,
} from './types.js';
import { BUILTIN_RULES } from './patterns.js';

/**
 * Decision precedence: block > redact > allow. If any matching rule
 * resolves to `block`, the inspector returns `block`. Otherwise if any
 * matching rule resolves to `redact`, the inspector returns `redact`.
 * Otherwise `allow`.
 */
function combineDecisions(decisions: DlpDecision[]): DlpDecision {
  if (decisions.includes('block')) return 'block';
  if (decisions.includes('redact')) return 'redact';
  return 'allow';
}

export class DlpInspector {
  private readonly rules: DlpRule[];
  private readonly defaultConfig: DlpTenantConfig;
  private readonly perTenant: Map<string, DlpTenantConfig>;

  constructor(config: DlpConfig) {
    // Merge: built-ins, then custom rules override by id.
    const byId = new Map<string, DlpRule>();
    for (const r of BUILTIN_RULES) byId.set(r.id, r);
    for (const r of config.customRules ?? []) byId.set(r.id, r);
    this.rules = [...byId.values()];

    this.defaultConfig = config.defaultConfig;
    this.perTenant = config.perTenant ?? new Map();
  }

  /**
   * Inspect a single tool-call response. `tenantId` selects the config;
   * unknown tenants fall through to the default config. The inspector
   * does not throw — pattern errors are caught per-rule so a single
   * faulty custom rule cannot disable inspection of the rest.
   */
  inspect(content: unknown, tenantId?: string): DlpInspectionResult {
    const tenantConfig =
      (tenantId !== undefined ? this.perTenant.get(tenantId) : undefined) ??
      this.defaultConfig;

    // Stringify for pattern application. Use the canonical form for
    // determinism across writes (matches whatever audit hashes will see).
    const text = typeof content === 'string' ? content : safeStringify(content);

 // Perturbation-robust matching: an attacker can split a known
    // secret across whitespace, line-wraps, or bidi-control chars to slip
    // past a regex that was authored against the canonical secret form.
    // Build a normalized view that strips these perturbations and run each
    // rule's pattern against BOTH the original text and the normalized text.
    // Offsets / sanitizedContent are taken from the ORIGINAL text whenever a
    // match occurs there; normalized-only matches contribute a finding with
    // start=0/end=text.length so callers see the detection signal even when
    // exact char offsets do not exist in the original surface.
    const normalizedText = normalizeForPerturbationDetection(text);

    const findings: DlpFinding[] = [];
    const matchedDecisions: DlpDecision[] = [];

    for (const rule of this.rules) {
      let m: RegExpExecArray | null;
      try {
        // Fresh regex per inspection so lastIndex is not shared across calls.
        // Constructed inside try so a faulty custom rule (bad source / bad
        // flags) is caught instead of throwing out of the inspector.
        const re = new RegExp(rule.pattern.source, rule.pattern.flags);
        while ((m = re.exec(text)) !== null) {
          const matched = m[0];
          if (rule.validate && !rule.validate(matched)) {
            // Validation rejected (e.g., Luhn check failed) — not a finding.
            continue;
          }
          findings.push({
            ruleId: rule.id,
            label: rule.label,
            start: m.index,
            end: m.index + matched.length,
          });
          // Guard against zero-width matches that would loop forever.
          if (m.index === re.lastIndex) re.lastIndex++;
        }

        // Second pass: run the rule against the normalized (perturbation-
        // stripped) text. Only record additional findings if the rule did
        // not already fire on the original text — avoids duplicate offsets.
        if (normalizedText !== text && !findings.some(f => f.ruleId === rule.id)) {
          const reN = new RegExp(rule.pattern.source, rule.pattern.flags);
          while ((m = reN.exec(normalizedText)) !== null) {
            const matched = m[0];
            if (rule.validate && !rule.validate(matched)) continue;
            // Offsets do not map cleanly back to the original text; report
            // the full span so callers see a detection. Redaction over the
            // whole text is the safe default when perturbation has obscured
            // exact bounds.
            findings.push({
              ruleId: rule.id,
              label: rule.label,
              start: 0,
              end: text.length,
            });
            if (m.index === reN.lastIndex) reN.lastIndex++;
            break; // one perturbation-finding per rule is enough
          }
        }
      } catch {
        // Faulty rule (custom regex with bad flags / catastrophic backtrack
        // surfaced as an exception here). Skip and continue — never let one
        // rule disable inspection of the rest.
        continue;
      }

      if (findings.some((f) => f.ruleId === rule.id)) {
        const ruleDecision =
          tenantConfig.rules.get(rule.id) ?? tenantConfig.defaultDecision;
        matchedDecisions.push(ruleDecision);
      }
    }

    const decision = combineDecisions(matchedDecisions);

    if (decision === 'allow') {
      return { decision, findings, sanitizedContent: content };
    }

    if (decision === 'block') {
      return {
        decision,
        findings,
        blockReason:
          `Response blocked by gateway DLP — ${findings.length} sensitive value(s) detected ` +
          `(${[...new Set(findings.map((f) => f.label))].join(', ')}). ` +
          'The originating MCP tool response contained data that the configured DLP policy ' +
          'forbids returning to the agent. Review the audit row for finding details.',
      };
    }

    // decision === 'redact' — apply replacements right-to-left so earlier
    // offsets stay valid as we rewrite text.
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    let working = text;
    for (const f of sorted) {
      const ruleDecision =
        tenantConfig.rules.get(f.ruleId) ?? tenantConfig.defaultDecision;
      if (ruleDecision !== 'redact') continue;
      const replacement = `[REDACTED-${f.ruleId}]`;
      f.replacement = replacement;
      working = working.slice(0, f.start) + replacement + working.slice(f.end);
    }

    return {
      decision,
      findings,
      sanitizedContent: working,
    };
  }

  /** Number of active rules (built-ins minus overridden + customs). */
  get ruleCount(): number {
    return this.rules.length;
  }
}

/**
 * Bidi-control characters: U+200E, U+200F, U+202A–U+202E, U+2066–U+2069.
 * An attacker can insert these between digits of a secret to obscure the
 * pattern from a naive regex. Strip them before the secondary match pass.
 */
const DLP_BIDI_CONTROLS_RE = new RegExp('[‎‏‪-‮⁦-⁩]', 'gu');

/**
 * Zero-width chars also used as perturbation cover.
 */
const DLP_ZERO_WIDTH_RE = new RegExp('[​-‍⁠﻿]', 'gu');

/**
 * Perturbation normalization for the secondary DLP match pass.
 *
 * Strips: whitespace (all categories), CR/LF, bidi-control chars, zero-
 * width chars. The intent is to collapse a perturbed secret back to its
 * canonical contiguous form so a regex authored against the canonical
 * form will match. Returns the original string when no perturbation
 * characters are present so callers can cheaply skip the second pass.
 */
function normalizeForPerturbationDetection(input: string): string {
  return input
    .replace(DLP_BIDI_CONTROLS_RE, '')
    .replace(DLP_ZERO_WIDTH_RE, '')
    .replace(/\s+/g, '');
}

/**
 * Stringify with a sane fallback for non-stringifiable values. We do
 * NOT use canonical-json here because preserving the operator's
 * intended output shape matters more than determinism — DLP runs
 * on a per-call basis, not in a hash chain.
 */
function safeStringify(value: unknown): string {
  if (value === null || value === undefined) return '';
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
