/**
 * @epicai/chariot — Access Policy Engine
 * RBAC/ABAC evaluation. Default-deny. Called before every tool dispatch.
 * Named AccessPolicyEngine to avoid collision with src/autonomy/PolicyEngine.ts.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createLogger } from '../logger.js';
import type {
  TenantContext,
  PolicyRule,
  PolicyDecision,
  PolicyEffect,
  PolicyCondition,
  EgressRule,
  EgressContext,
  EgressDecision,
} from './types.js';

const log = createLogger('trust.access-policy');

export class AccessPolicyEngine {
  private rules: PolicyRule[];
  private egressRules: EgressRule[];
  private readonly defaultEffect: PolicyEffect;
  private readonly egressDefaultEffect: PolicyEffect;

  constructor(
    rules: PolicyRule[],
    defaultEffect: PolicyEffect = 'deny',
    egressRules: EgressRule[] = [],
    egressDefaultEffect: PolicyEffect = 'deny',
  ) {
    this.rules = this.sortByPriority(rules);
    this.egressRules = this.sortEgressByPriority(egressRules);
    this.defaultEffect = defaultEffect;
    this.egressDefaultEffect = egressDefaultEffect;
  }

  /**
   * Evaluate whether a principal may invoke a tool with given args.
   * Returns PolicyDecision with allow/deny and reason.
   */
  evaluate(
    ctx: TenantContext,
    toolName: string,
    args: Record<string, unknown>,
    toolCategory?: string,
    adapterName?: string,
  ): PolicyDecision {
    // Find all matching rules
    const matching = this.rules.filter(rule => this.ruleMatches(rule, ctx, toolName, toolCategory, adapterName));

    if (matching.length === 0) {
      log.debug('no matching rules — applying default', { defaultEffect: this.defaultEffect, toolName, principal: ctx.principalId });
      return {
        allow: this.defaultEffect === 'allow',
        reason: `Default policy: ${this.defaultEffect}`,
      };
    }

    // Rules are pre-sorted by priority (highest first).
    // Among rules at the same priority, deny takes precedence over allow.
    const topPriority = matching[0].priority;
    const topRules = matching.filter(r => r.priority === topPriority);

    // If any deny rule exists at top priority, deny wins
    const denyRule = topRules.find(r => r.effect === 'deny');
    if (denyRule) {
      log.debug('deny rule matched', { ruleId: denyRule.id, toolName, principal: ctx.principalId });
      return {
        allow: false,
        reason: `Denied by rule: ${denyRule.id}`,
        ruleId: denyRule.id,
        redactedArgs: this.redactArgs(args),
      };
    }

    // Otherwise, allow wins at top priority
    const allowRule = topRules.find(r => r.effect === 'allow');
    if (allowRule) {
      log.debug('allow rule matched', { ruleId: allowRule.id, toolName, principal: ctx.principalId });
      return {
        allow: true,
        reason: `Allowed by rule: ${allowRule.id}`,
        ruleId: allowRule.id,
      };
    }

    // Should not reach here, but default-deny as safety
    return {
      allow: this.defaultEffect === 'allow',
      reason: `Default policy: ${this.defaultEffect}`,
    };
  }

  /**
   * Hot-swap rules without restart. Atomic replacement.
   */
  reload(rules: PolicyRule[]): void {
    const sorted = this.sortByPriority(rules);
    this.rules = sorted; // Single assignment — atomic in JS event loop
    log.info('policy rules reloaded', { count: sorted.length });
  }

  /**
   * Hot-swap egress rules without restart. Atomic replacement.
   */
  reloadEgress(rules: EgressRule[]): void {
    this.egressRules = this.sortEgressByPriority(rules);
    log.info('egress policy rules reloaded', { count: this.egressRules.length });
  }

  get ruleCount(): number {
    return this.rules.length;
  }

  get egressRuleCount(): number {
    return this.egressRules.length;
  }

  // ---------------------------------------------------------------------------
 // Egress Policy
  // ---------------------------------------------------------------------------

  /**
   * Evaluate whether a federated adapter may emit an outbound request to
   * the destination described by `ctx`. Default-deny when no rule matches.
   * The federation layer (ConnectionPool / FederationManager) calls this
   * before every adapter.callTool that crosses the network boundary.
   *
   * Stdio MCP adapters and in-process REST adapters that do not emit
   * outbound network calls SHOULD NOT be gated by this method — the
   * caller is responsible for skipping the check when no host is known.
   */
  evaluateEgress(ctx: EgressContext): EgressDecision {
    const matching = this.egressRules.filter(rule => this.egressRuleMatches(rule, ctx));

    if (matching.length === 0) {
      const allow = this.egressDefaultEffect === 'allow';
      log[allow ? 'debug' : 'info']('egress.default_decision', {
        defaultEffect: this.egressDefaultEffect,
        tenantId: ctx.tenantId,
        adapter: ctx.adapterName,
        host: ctx.host,
      });
      return {
        allow,
        reason: `Default egress policy: ${this.egressDefaultEffect}`,
        host: ctx.host,
        port: ctx.port,
        protocol: ctx.protocol,
      };
    }

    const topPriority = matching[0].priority;
    const topRules = matching.filter(r => r.priority === topPriority);

    const denyRule = topRules.find(r => r.effect === 'deny');
    if (denyRule) {
      log.info('egress.denied', {
        ruleId: denyRule.id,
        tenantId: ctx.tenantId,
        adapter: ctx.adapterName,
        host: ctx.host,
      });
      return {
        allow: false,
        reason: `Egress denied by rule: ${denyRule.id}`,
        ruleId: denyRule.id,
        host: ctx.host,
        port: ctx.port,
        protocol: ctx.protocol,
      };
    }

    const allowRule = topRules.find(r => r.effect === 'allow');
    if (allowRule) {
      log.debug('egress.allowed', {
        ruleId: allowRule.id,
        tenantId: ctx.tenantId,
        adapter: ctx.adapterName,
        host: ctx.host,
      });
      return {
        allow: true,
        reason: `Egress allowed by rule: ${allowRule.id}`,
        ruleId: allowRule.id,
        host: ctx.host,
        port: ctx.port,
        protocol: ctx.protocol,
      };
    }

    // Unreachable; safety default-deny.
    return {
      allow: this.egressDefaultEffect === 'allow',
      reason: `Default egress policy: ${this.egressDefaultEffect}`,
      host: ctx.host,
      port: ctx.port,
      protocol: ctx.protocol,
    };
  }

  private egressRuleMatches(rule: EgressRule, ctx: EgressContext): boolean {
    if (rule.tenantIds?.length && !rule.tenantIds.includes(ctx.tenantId)) return false;
    if (rule.adapters?.length && !rule.adapters.includes(ctx.adapterName)) return false;
    if (rule.tools?.length) {
      if (!ctx.toolName || !rule.tools.includes(ctx.toolName)) return false;
    }
    if (rule.hostPatterns?.length) {
      const matched = rule.hostPatterns.some(p => matchHostPattern(p, ctx.host));
      if (!matched) return false;
    }
    if (rule.portRange) {
      if (ctx.port === undefined) return false;
      const [lo, hi] = rule.portRange;
      if (ctx.port < lo || ctx.port > hi) return false;
    }
    if (rule.protocols?.length) {
      if (!ctx.protocol || !rule.protocols.includes(ctx.protocol)) return false;
    }
    return true;
  }

  private sortEgressByPriority(rules: EgressRule[]): EgressRule[] {
    return [...rules].sort((a, b) => b.priority - a.priority);
  }

  // ---------------------------------------------------------------------------
  // Rule Matching
  // ---------------------------------------------------------------------------

  private ruleMatches(
    rule: PolicyRule,
    ctx: TenantContext,
    toolName: string,
    toolCategory?: string,
    adapterName?: string,
  ): boolean {
    // Principal match: roles OR attributes
    const principalMatch = this.principalMatches(rule, ctx);
    if (!principalMatch) return false;

    // Resource match: tool categories, tool names, or adapters
    const resourceMatch = this.resourceMatches(rule, toolName, toolCategory, adapterName);
    if (!resourceMatch) return false;

    // Condition match (ABAC)
    if (rule.conditions && rule.conditions.length > 0) {
      return rule.conditions.every(c => this.conditionMatches(c, ctx));
    }

    return true;
  }

  private principalMatches(rule: PolicyRule, ctx: TenantContext): boolean {
    const { roles, attributes } = rule.principal;

    // If neither specified, matches all principals
    if (!roles?.length && (!attributes || Object.keys(attributes).length === 0)) {
      return true;
    }

    // Role match: any role in ctx.roles matches any role in rule.principal.roles
    if (roles?.length) {
      const hasRole = roles.some(r => ctx.roles.includes(r));
      if (hasRole) return true;
    }

    // Attribute match: all specified attributes must match
    if (attributes && Object.keys(attributes).length > 0) {
      const allMatch = Object.entries(attributes).every(
        ([key, value]) => ctx.attributes[key] === value,
      );
      if (allMatch) return true;
    }

    return false;
  }

  private resourceMatches(
    rule: PolicyRule,
    toolName: string,
    toolCategory?: string,
    adapterName?: string,
  ): boolean {
    const { toolCategories, toolNames, adapters } = rule.resource;

    // If nothing specified, matches all resources
    if (!toolCategories?.length && !toolNames?.length && !adapters?.length) {
      return true;
    }

    if (toolCategories?.length && toolCategory) {
      if (toolCategories.includes(toolCategory as never)) return true;
    }

    if (toolNames?.length) {
      if (toolNames.includes(toolName)) return true;
    }

    if (adapters?.length && adapterName) {
      if (adapters.includes(adapterName)) return true;
    }

    return false;
  }

  private conditionMatches(condition: PolicyCondition, ctx: TenantContext): boolean {
    const actual = ctx.attributes[condition.field];

    switch (condition.operator) {
      case 'eq':
        return actual === condition.value;
      case 'neq':
        return actual !== condition.value;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(actual);
      case 'not-in':
        return Array.isArray(condition.value) && !condition.value.includes(actual);
      case 'exists':
        return actual !== undefined;
      default:
        return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private sortByPriority(rules: PolicyRule[]): PolicyRule[] {
    return [...rules].sort((a, b) => b.priority - a.priority);
  }

  private redactArgs(args: Record<string, unknown>): Record<string, unknown> {
    const redacted: Record<string, unknown> = {};
    const sensitiveKeys = new Set(['password', 'token', 'secret', 'key', 'credential', 'api_key', 'apiKey']);

    for (const [key, value] of Object.entries(args)) {
      if (sensitiveKeys.has(key.toLowerCase())) {
        redacted[key] = '[REDACTED]';
      } else {
        redacted[key] = value;
      }
    }

    return redacted;
  }
}

/**
 * Glob-style match for egress host patterns. Each pattern matches the
 * FULL hostname (no path / no scheme). Supported wildcards:
 *   - `*`  matches any character sequence WITHIN A SINGLE LABEL.
 *          `*.openai.com` matches `api.openai.com` but NOT
 *          `a.b.openai.com` — the dot separators are literal.
 *   - `**` matches any character sequence INCLUDING DOTS (multi-label).
 *          Use sparingly. Anchored at both ends.
 *   - `?`  matches a single non-dot character.
 *
 * Both pattern and host are converted to ASCII via WHATWG URL/IDN
 * (`URL` constructor with `https://`) before comparison, so IDN /
 * Unicode patterns and homoglyph hostnames are normalized to their
 * punycode form. The match is case-insensitive per RFC 1035 §2.3.3
 * and anchored at both ends so `api.openai.com` does NOT match
 * `evil-api.openai.com.attacker.example`.
 *
 * Returns false on inputs that fail IDN normalization — the policy
 * engine's default-deny then catches the unparseable destination.
 *
 * Simplify findings closed by this implementation:
 * /P1 (IDN bypass): both sides normalized via URL.hostname
 * /P1 (glob crosses labels): `*` is now [^.]* not .*
 */
export function matchHostPattern(pattern: string, host: string): boolean {
  const normPattern = normalizeHostForMatch(pattern);
  const normHost = normalizeHostForMatch(host);
  if (normPattern === null || normHost === null) return false;
  if (normPattern === normHost) return true;
  if (!normPattern.includes('*') && !normPattern.includes('?')) return false;

  // Tokenize so `**` is parsed before `*` (greedy two-char first).
  let escaped = '';
  for (let i = 0; i < normPattern.length; i++) {
    const c = normPattern[i];
    if (c === '*' && normPattern[i + 1] === '*') {
      escaped += '.*';
      i++;
    } else if (c === '*') {
      escaped += '[^.]*';
    } else if (c === '?') {
      escaped += '[^.]';
    } else if (/[.+^${}()|[\]\\]/.test(c)) {
      escaped += '\\' + c;
    } else {
      escaped += c;
    }
  }
  return new RegExp(`^${escaped}$`).test(normHost);
}

/**
 * Convert a host or pattern to its lower-case IDN/punycode form. Uses
 * the WHATWG URL parser by wrapping the input in a synthetic
 * `https://<input>` URL — that path inherits the Node ICU normalization
 * and rejects malformed inputs by throwing. Wildcard characters survive
 * the round-trip because they are valid hostname syntax.
 *
 * Returns null when the host cannot be parsed at all (caller treats
 * this as no-match, which falls into default-deny for policy use).
 */
function normalizeHostForMatch(input: string): string | null {
  if (typeof input !== 'string' || input.length === 0) return null;
  if (input.trim().length === 0) return null;
  // URL parser does not preserve glob characters; substitute them with
  // lowercase markers that survive the parser's case normalization.
  const placeholderStar = 'starxxx000xxxplaceholder';
  const placeholderDoubleStar = 'doublestarxxx000xxxplaceholder';
  const placeholderQuestion = 'questionxxx000xxxplaceholder';
  const masked = input
    .replace(/\*\*/g, placeholderDoubleStar)
    .replace(/\*/g, placeholderStar)
    .replace(/\?/g, placeholderQuestion);
  let normalized: string;
  try {
    normalized = new URL(`https://${masked}`).hostname;
  } catch {
    return null;
  }
  return normalized
    .toLowerCase()
    .replace(new RegExp(placeholderDoubleStar, 'g'), '**')
    .replace(new RegExp(placeholderStar, 'g'), '*')
    .replace(new RegExp(placeholderQuestion, 'g'), '?');
}
