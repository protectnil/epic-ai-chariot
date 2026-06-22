/**
 * Gateway DLP — types
 *
 * Inspects MCP tool response bodies before they return to the calling
 * agent. Defense against an MCP server (legitimately or via compromise)
 * exfiltrating sensitive data through the response channel — credit
 * cards, SSNs, AWS access keys, private key material, JWTs, GitHub
 * PATs, generic API keys.
 *
 * Three decisions per match:
 *   - block:   replace the response with a sanitized error, do not
 *              return any payload to the agent
 *   - redact:  replace matched text with `[REDACTED-{type}]`, return
 *              the modified response
 *   - allow:   audit the finding, return the response unchanged
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Stable identifier for a DLP rule (used in config + audit). */
export type DlpPatternId =
  | 'credit-card'
  | 'ssn-us'
  | 'aws-access-key-id'
  | 'aws-secret-access-key'
  | 'private-key-pem'
  | 'jwt'
  | 'github-pat'
  | 'generic-api-key';

export type DlpDecision = 'block' | 'redact' | 'allow';

export interface DlpRule {
  /** Stable identifier. */
  id: DlpPatternId | string;
  /** Human-readable label, surfaced in audit + redaction marker. */
  label: string;
  /** Regex applied per-line to the stringified response content. */
  pattern: RegExp;
  /**
   * Optional secondary validation (e.g., Luhn check for credit cards).
   * Returns true to keep the match, false to discard it (false-positive).
   */
  validate?: (matchedText: string) => boolean;
}

export interface DlpFinding {
  ruleId: string;
  label: string;
  /** Position within the stringified response content. */
  start: number;
  end: number;
  /** The redaction marker that replaced this match (only set if decision was 'redact'). */
  replacement?: string;
}

export interface DlpInspectionResult {
  decision: DlpDecision;
  /** All matches found, regardless of the chosen decision. */
  findings: DlpFinding[];
  /**
   * The (possibly modified) response content. Identical to input when
   * decision is `'allow'`; redacted when `'redact'`; unset when `'block'`.
   */
  sanitizedContent?: unknown;
  /**
   * When decision is `'block'`, the message to surface to the agent in
   * place of the actual response. Set by the inspector; safe to log.
   */
  blockReason?: string;
}

export interface DlpTenantConfig {
  /** Per-rule decision override; rules absent from this map use `defaultDecision`. */
  rules: Map<string, DlpDecision>;
  /** Decision applied to any rule not present in `rules`. */
  defaultDecision: DlpDecision;
  /** When true, audit findings even for rules whose decision is 'allow'. */
  alwaysAudit: boolean;
}

export interface DlpConfig {
  /** Default config applied when no per-tenant override exists. */
  defaultConfig: DlpTenantConfig;
  /** Per-tenant overrides keyed by tenant id. */
  perTenant?: Map<string, DlpTenantConfig>;
  /**
   * Custom rules to merge with the built-in pattern set. Rules with the
   * same id as a built-in override the built-in (lets operators tighten
   * a regex without forking the package).
   */
  customRules?: DlpRule[];
}
