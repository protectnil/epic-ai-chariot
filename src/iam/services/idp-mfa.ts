/**
 * IAM - IdP MFA Detection
 *
 * Implements the `Delegate to the IdP` design principle for the multi-factor
 * case. When a tenant has `mfaRequired: true` and the upstream IdP already
 * performed MFA on its side, we MUST NOT force the user through a second
 * Chariot-side TOTP enrollment.
 *
 * Two signals tell us the IdP performed MFA:
 *
 *   - SAML 2.0: `<saml:AuthnContextClassRef>` URIs that explicitly denote
 *               multi-factor authentication.
 *
 *   - OIDC: The `amr` claim (RFC 8176). Either an explicit `"mfa"` value,
 *           OR two or more distinct factor categories from the explicit
 *           knowledge / possession / biometric sets below.
 *
 * If neither signal is present we fall through to Chariot-side TOTP, which
 * remains the safety net for IdPs that do not surface MFA assertions.
 *
 * @module iam/services/idp-mfa
 */

/**
 * SAML AuthnContextClassRef URIs that explicitly indicate MFA was performed
 * at the IdP.
 *
 * NOTE: Do not include single-factor context classes here. Smartcard,
 * SmartcardPKI, and TimeSyncToken are intentionally excluded because they
 * may be emitted on single-factor flows by some IdPs.
 */
const SAML_MFA_AUTHN_CONTEXTS: ReadonlySet<string> = new Set([
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorPhysical',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorUnregistered',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered',
  // Microsoft Entra / AD FS: emitted when MFA was satisfied at the IdP.
  'http://schemas.microsoft.com/claims/multipleauthn',
]);

/**
 * Extract every AuthnContextClassRef value from a node-saml `getAssertion()`
 * result. The xml2js shape is typically:
 *
 *   assertion.AuthnStatement[].AuthnContext[].AuthnContextClassRef[]._
 *
 * Each level may be missing or repeated. We walk defensively and yield every
 * string we find. Unknown / malformed shapes return [].
 */
function extractAuthnContextClassRefs(parsedAssertion: unknown): string[] {
  if (!parsedAssertion || typeof parsedAssertion !== 'object') return [];
  const refs: string[] = [];

  const visit = (node: unknown): void => {
    if (!node) return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;

    const stmts = obj.AuthnStatement;
    if (Array.isArray(stmts)) {
      for (const stmt of stmts) {
        if (!stmt || typeof stmt !== 'object') continue;
        const ctxs = (stmt as Record<string, unknown>).AuthnContext;
        if (!Array.isArray(ctxs)) continue;
        for (const ctx of ctxs) {
          if (!ctx || typeof ctx !== 'object') continue;
          const classRefs = (ctx as Record<string, unknown>).AuthnContextClassRef;
          if (!Array.isArray(classRefs)) continue;
          for (const cr of classRefs) {
            if (typeof cr === 'string') {
              refs.push(cr);
            } else if (cr && typeof cr === 'object') {
              const value = (cr as Record<string, unknown>)._;
              if (typeof value === 'string') refs.push(value);
            }
          }
        }
      }
    }

    // Recurse into common envelope wrappers (Assertion, Response).
    for (const key of ['Assertion', 'Response']) {
      const child = obj[key];
      if (child) visit(child);
    }
  };

  visit(parsedAssertion);
  return refs;
}

/**
 * Returns true if the SAML assertion's AuthnContext indicates the IdP
 * performed multi-factor authentication.
 *
 * `parsedAssertion` is the value returned by node-saml's `profile.getAssertion()`.
 */
export function samlAssertedMfa(parsedAssertion: unknown): {
  asserted: boolean;
  authnContextClassRefs: string[];
} {
  const refs = extractAuthnContextClassRefs(parsedAssertion);
  const asserted = refs.some((ref) => SAML_MFA_AUTHN_CONTEXTS.has(ref));
  return { asserted, authnContextClassRefs: refs };
}

/**
 * RFC 8176 Authentication Method Reference values, grouped by factor
 * category. Multi-factor authentication is indicated by either:
 *   - An explicit `"mfa"` value, OR
 *   - Two or more distinct categories represented in the amr array.
 *
 * IMPORTANT: `rba` (risk-based auth) and `wia` (Windows Integrated Auth) are
 * intentionally excluded here because they can appear in non-MFA single-factor
 * flows and are not sufficient proof of MFA.
 */
const AMR_KNOWLEDGE: ReadonlySet<string> = new Set(['pwd', 'pin', 'kba']);
const AMR_POSSESSION: ReadonlySet<string> = new Set([
  'otp',
  'hwk',
  'swk',
  'sms',
  'tel',
  'pop',
  'sc',
]);
const AMR_BIOMETRIC: ReadonlySet<string> = new Set([
  'face',
  'fpt',
  'iris',
  'vbm',
  'retina',
]);

/**
 * Returns true if the OIDC `amr` claim indicates the IdP performed MFA.
 *
 * `amrClaim` is the raw value of `id_token.amr` (per RFC 8176, an array of
 * strings - but we tolerate the common single-string and missing forms).
 */
export function oidcAssertedMfa(amrClaim: unknown): {
  asserted: boolean;
  amr: string[];
} {
  const amr: string[] = Array.isArray(amrClaim)
    ? amrClaim.filter((v): v is string => typeof v === 'string')
    : typeof amrClaim === 'string'
      ? [amrClaim]
      : [];

  if (amr.includes('mfa')) {
    return { asserted: true, amr };
  }

  let categories = 0;
  if (amr.some((v) => AMR_KNOWLEDGE.has(v))) categories += 1;
  if (amr.some((v) => AMR_POSSESSION.has(v))) categories += 1;
  if (amr.some((v) => AMR_BIOMETRIC.has(v))) categories += 1;

  return { asserted: categories >= 2, amr };
}
