/**
 * IAM — URL validation helpers.
 *
 * Shared between idp-trust-registry and oauth-client-registry. The
 * https-only constraint is a hard rule for every external URL the ID-JAG
 * surface dereferences (JWKS endpoints, client JWKS URIs, redirect URIs);
 * enforced at registration time so the validator hot path never needs to
 * re-check.
 */

import type { Request } from 'express';

import { normaliseHtu } from '../services/dpop.js';

/**
 * Extract the originating client IP from an Express request.
 *
 * `X-Forwarded-For` is honoured ONLY when the immediate hop
 * (`req.socket.remoteAddress`) appears in the operator-configured
 * trusted-proxy allowlist (env `CHARIOT_TRUSTED_PROXIES`). The allowlist
 * is a comma-separated list of EXACT IPv4 / IPv6 address strings —
 * CIDR ranges are NOT supported in this implementation; the matcher
 * performs string equality only. The IPv4-mapped IPv6 form
 * `::ffff:<v4>` is normalised to its `<v4>` form so operators can list
 * plain v4 addresses without dual-stack boilerplate. Operators who
 * need broader ranges must enumerate the proxy IPs explicitly.
 *
 * Without an allowlist (env unset/empty, or immediate hop not in it),
 * XFF is attacker-controlled — any HTTP client can send
 * `X-Forwarded-For: 1.2.3.4` and bypass rate-limit buckets or poison
 * audit logs. Express does NOT auto-honour XFF unless
 * `app.set('trust proxy', ...)` is configured; grep on src/ shows no
 * such configuration today, so the safe default is to ignore XFF and
 * use `req.ip`.
 *
 * When the immediate hop IS in the allowlist, the FIRST value of XFF
 * is returned (the originating client per RFC 7239 §5.2 leftmost-
 * untrusted convention).
 *
 * When XFF is absent or the immediate hop is not trusted, return
 * `req.ip`, falling back to `req.socket.remoteAddress`, falling back to
 * 'unknown' (the last for environments without a real socket).
 *
 * Used by every IAM surface that records IP-keyed audit or rate-limit
 * state.
 */
function isTrustedProxy(immediateHop: string | undefined): boolean {
  if (!immediateHop) return false;
  const list = process.env.CHARIOT_TRUSTED_PROXIES;
  if (!list) return false;
  const trusted = list.split(',').map((s) => s.trim()).filter(Boolean);
  if (trusted.length === 0) return false;
  // Exact-string match only — see the helper's JSDoc for the rationale
  // (no CIDR arithmetic). The IPv4-mapped IPv6 form `::ffff:<v4>` is
  // normalised to its `<v4>` form so operator config can list plain
  // v4 addresses without dual-stack boilerplate.
  const normalised = immediateHop.startsWith('::ffff:') ? immediateHop.slice('::ffff:'.length) : immediateHop;
  return trusted.includes(immediateHop) || trusted.includes(normalised);
}

export function clientIp(req: Request): string {
  const immediateHop = req.socket?.remoteAddress;
  const fwd = req.headers['x-forwarded-for'];
  if (isTrustedProxy(immediateHop)) {
    // RFC 7239 §7.1: with a trusted immediate hop, derive the client by
    // walking X-Forwarded-For RIGHT→LEFT and returning the first hop that is
    // NOT itself a trusted proxy. The LEFTMOST value is client-CLAIMED and
    // spoofable — any HTTP client can prepend `X-Forwarded-For: 1.2.3.4`;
    // only the rightmost entries, appended by our own trusted proxies, are
    // trustworthy. The previous leftmost selection let an attacker forge the
    // recorded IP and poison rate-limit / audit state from behind a proxy.
    const chain = (Array.isArray(fwd) ? fwd.join(',') : (typeof fwd === 'string' ? fwd : ''))
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (let i = chain.length - 1; i >= 0; i--) {
      if (!isTrustedProxy(chain[i])) return chain[i];
    }
    // Every XFF entry is itself a trusted proxy (or XFF is empty) — fall
    // through to the (trusted) immediate hop.
  }
  return req.ip ?? immediateHop ?? 'unknown';
}

/**
 * Extract the User-Agent header as a string. Absent / array-valued
 * headers coerce to 'unknown' for parity with the audit-log convention
 * used by every other IAM route (oidc.ts, saml.ts, scim.ts,
 * session.ts, adapters.ts, admin-trust.ts, middleware.ts, and the
 * legacy inline `req.headers['user-agent'] ?? 'unknown'` pattern that
 * predates this helper). Returning 'unknown' here keeps the
 * iam_audit_events collection's `userAgent` field uniform across the
 * surface so operator SIEM/audit queries that group by literal value
 * see consistent results regardless of which route emitted the row.
 */
export function userAgent(req: Request): string {
  return typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'unknown';
}

/**
 * Build the RFC 9449 §4.3 normalised `htu` (HTTP target URI) for the
 * incoming request, honouring `x-forwarded-proto` when present. Shared
 * between the OAuth token endpoint (DPoP-bound issuance) and the
 * enterprise auth middleware (DPoP-bound resource access) so the
 * issuance side and the enforcement side cannot drift on URL
 * normalization rules.
 */
export function requestHtu(req: Request): string {
  const proto = (req.headers['x-forwarded-proto'] as string) ?? req.protocol;
  const host = req.headers.host ?? '';
  return normaliseHtu(`${proto}://${host}${req.originalUrl.split('?')[0]}`);
}

/**
 * Sanitise a value before embedding it in a `WWW-Authenticate` header
 * (RFC 9449 §7.1) OR a JSON `error_description` field. The same regex is
 * shared between every DPoP-failure path so the two surfaces cannot drift
 * (Phase 0.1 R4: oauth.ts /token + oauth.ts /revoke + middleware.ts
 * resource-DPoP all share this). Replaces CR/LF/backslash/double-quote
 * with a single space; preserves length-class but kills the four
 * characters that can break header framing or JSON quoting.
 */
export function escapeDpopHeaderValue(value: string): string {
  return value.replace(/[\r\n\\"]/g, ' ');
}

/**
 * Throw if `url` is not a parseable URL or does not use the https scheme.
 * `fieldName` is included in the thrown message so the registry surface
 * returns operator-actionable errors.
 */
export function ensureHttps(url: string, fieldName: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${fieldName} is not a valid URL`);
  }
  if (parsed.protocol === 'https:') return;
  // Narrow test-only bypass for hermetic evals (Step 6 — id-jag-flow-eval-
  // may-2026 + iam-id-jag tests). The mock IdP server runs on HTTP
  // loopback so JWKS fetch does not require a self-signed cert in CI.
  // The bypass is limited to 127.0.0.1 / [::1] / localhost so even if
  // the env var leaks it cannot be misused against an external host.
  // Production deployments never set CHARIOT_TEST_ALLOW_HTTP_LOOPBACK.
  if (
    process.env.CHARIOT_TEST_ALLOW_HTTP_LOOPBACK === '1'
    && parsed.protocol === 'http:'
    && (
      parsed.hostname === '127.0.0.1'
      || parsed.hostname === 'localhost'
      || parsed.hostname === '[::1]'
      || parsed.hostname === '::1'
    )
  ) {
    return;
  }
  throw new Error(`${fieldName} must be https:// (got ${parsed.protocol}//...)`);
}
