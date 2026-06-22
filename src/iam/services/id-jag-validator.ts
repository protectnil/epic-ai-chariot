/**
 * IAM — ID-JAG (Identity Assertion JWT Authorization Grant) validator.
 *
 * Implements the Resource-Authorization-Server-side validation pipeline
 * for IETF draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4
 * (May 2026). The wire-level grant at the Resource AS token endpoint is
 * RFC 7523 JWT Bearer:
 *
 *   POST /token
 *     grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
 *     assertion=<ID-JAG JWT>
 *
 * (NOT RFC 8693 token-exchange — that's the §4.3 IdP-side grant at a
 * different endpoint owned by the IdP Authorization Server.)
 *
 * Validator scope (steps 2-11 of the pipeline):
 *   2.  Decode JWT header; require typ=oauth-id-jag+jwt and alg in the
 *       trusted-issuer's allowedAlgorithms allowlist; explicit reject of
 *       "none".
 *   3.  Resolve `iss` against the per-tenant trusted-issuer registry AND
 *       against the authenticated client's `allowedIssuers[]` allowlist.
 *   4.  Fetch JWKS for `iss` (delegated to JwksPort; cached upstream).
 *   5.  Verify signature.
 *   6.  Validate exp > now, nbf <= now (if present), iat within ±5min.
 *   7.  Client-continuity (draft-04 §4.4.1): assertion.client_id MUST
 *       equal the authenticated client_id.
 *   8.  Validate `aud` per draft-04 §4.4.1: MUST equal the trusted
 *       issuer's configured Resource AS identifier. If aud is an array
 *       it MUST contain EXACTLY one element — not "at least one matching
 *       element" — and that single element MUST equal the expected
 *       Resource AS identifier.
 *   9.  Validate ID-JAG multi-tenant claims + optional sub_id per
 *       draft-04 §3.1 / §3.2.1 / §3.2.2. `sub_id` is an RFC 9493 OBJECT
 *       carrying `format` plus format-specific fields, NOT a string.
 *       When the trusted issuer carries `requireSamlNameIdSubId`, an
 *       absent / malformed / wrong-format sub_id MUST be rejected with
 *       invalid_grant per §3.2.2. Subject-key resolution is keyed on
 *       (iss, tenant, aud_tenant, sub) or (iss, aud_sub) — `sub` remains
 *       the canonical subject identifier per §3.1. sub_id does not
 *       participate in the canonical subject key; it is surfaced on the
 *       validated envelope for downstream SAML-namespace resolution.
 *       Per §3.1 "When both sub and sub_id are present, they MUST
 *       identify the same End-User" — this is a contractual statement
 *       on the IdP that the Resource AS cannot algorithmically verify
 *       across namespaces; the signed assertion is authoritative.
 *   10. JTI present + atomic JTI cache write (Redis SET NX EX).
 *   11. Required claims present per draft-04 §3.1: `sub`, `iss`, `aud`,
 *       `jti`, `exp`, `iat`, `client_id`. `sub_id` is OPTIONAL.
 *
 * Step 0 (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
 * allowlist + `assertion` form-body parse), step 1 (client
 * authentication), step 1a (license + active-user) are the caller's
 * responsibility — they live in routes/oauth.ts and middleware. There
 * is no `subject_token_type` parameter under §4.4; RFC 7523 does not
 * define one.
 *
 * Step 12 (audit emission) is the caller's responsibility. The validator
 * returns a structured outcome the caller can audit.
 *
 * All registry / cache / JWKS dependencies are injected via ports so the
 * validator can be unit-tested without Mongo or Redis.
 */

import { createHash } from 'node:crypto';
import {
  decodeProtectedHeader,
  errors as joseErrors,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from 'jose';

/**
 * The shape jose@6 accepts as a verify key. Equivalent to the v4
 * `VerifyKey` that was removed in v5; we model it explicitly so the port
 * interface stays stable across jose minor versions.
 */
export type VerifyKey = CryptoKey | Uint8Array | JWK;

// ── Port interfaces (injected; concrete impls land in ID-JAG commit 2) ──────

/**
 * Read-projection of a trusted IdP entry for the calling tenant. Concrete
 * implementation lives in idp-trust-registry.ts (commit 2).
 */
export interface TrustedIssuerView {
  iss: string;
  audience: string;
  jwksUri: string;
  /** Allowlisted JWS algorithms. Default is ["RS256","ES256"]; "none" MUST never appear. */
  allowedAlgorithms: string[];
  /**
   * When true, draft-04 §3.2.2 strict-reject rules fire: an absent
   * sub_id, a malformed sub_id, or a sub_id with a format other than
   * `saml-nameid` MUST be rejected with invalid_grant. Default false
   * (sub_id is OPTIONAL per §3.1; the Resource AS does not require
   * SAML NameID subject resolution).
   */
  requireSamlNameIdSubId?: boolean;
  /**
   * Allowlist of SAML issuer entity identifiers (`sub_id.issuer`) that
   * the Resource AS associates with THIS ID-JAG issuer per draft-04
   * §9.5: "The Resource Authorization Server MUST use a SAML NameID
   * sub_id only when the validated ID-JAG issuer is explicitly
   * associated with the SAML issuer identified by sub_id.issuer through
   * local configuration or trusted federation metadata." When a
   * saml-nameid sub_id arrives whose `issuer` is not in this allowlist,
   * the validator rejects with invalid_grant. Absent (or empty) allowlist
   * means no SAML issuers are trusted under this ID-JAG issuer —
   * saml-nameid sub_id values will be rejected.
   */
  samlNameIdIssuers?: string[];
  /** draft-04 §6.1 conditional USE-gate. */
  requiresTenantContext?: boolean;
  /** draft-04 §6.4 conditional allowlist. */
  expectedTenants?: string[];
  /** draft-04 §6.2 tenant-scoped client_id binding. */
  tenantScopedClientIds?: Record<string, string[]>;
}

/**
 * Read-projection of a registered OAuth client for the calling tenant.
 * security-review Critical #1: each client carries an `allowedIssuers[]` allowlist;
 * the assertion's `iss` MUST be in that list. Concrete implementation
 * lives in oauth-client-registry.ts (commit 2).
 */
export interface OAuthClientView {
  clientId: string;
  allowedIssuers: string[];
}

export interface TrustRegistryPort {
  getTrustedIssuer(tenantId: string, iss: string): Promise<TrustedIssuerView | null>;
}

export interface ClientRegistryPort {
  getClient(tenantId: string, clientId: string): Promise<OAuthClientView | null>;
}

/**
 * Atomic JTI reservation keyed on (iss, jti). Returns true if the slot
 * was reserved (first sight) and false on replay collision. The
 * implementation MUST use Redis `SET key value NX EX ttl` or an
 * equivalent atomic primitive (plan §275, adversarial fix #8).
 */
export interface JtiCachePort {
  reserve(iss: string, jti: string, ttlSeconds: number): Promise<boolean>;
  /**
   * draft-04 §4.4.3: "When the access token has expired, clients MAY
   * re-submit the original Identity Assertion JWT Authorization Grant
   * to obtain a new Access Token." Strict single-use jti (RFC 7523 §3)
   * would reject conformant re-submission; the spec-safe semantics is
   * uniqueness PER DISTINCT ASSERTION, not per redemption attempt.
   *
   * `reserveOrMatch` keys on (iss, jti, assertionHash):
   *   - First sight of (iss, jti) → store the hash, return 'first-sight'.
   *   - (iss, jti) repeated with SAME hash within ttl → 'match' (accept).
   *   - (iss, jti) repeated with DIFFERENT hash → 'replay' (reject as
   *     true replay attack; same jti pointing at different bytes).
   */
  reserveOrMatch(
    iss: string,
    jti: string,
    assertionHash: string,
    ttlSeconds: number,
  ): Promise<'first-sight' | 'match' | 'replay'>;
}

/**
 * Fetches the public key for a given JWKS URI + kid + alg. The concrete
 * implementation in idp-trust-registry.ts (commit 2) caches keys per
 * issuer with TTL 1 hour, force-refreshes on kid cache miss, and caps at
 * 32 keys per issuer per plan §277. JWKS URIs MUST be HTTPS-only;
 * enforcement happens at trusted-issuer registration time, not here.
 */
export interface JwksPort {
  fetchKey(jwksUri: string, kid: string | undefined, alg: string): Promise<VerifyKey>;
}

// ── Outcome types ────────────────────────────────────────────────────────────

export type ValidationErrorCode =
  | 'invalid_request'
  | 'invalid_grant'
  | 'invalid_client'
  | 'unauthorized_client';

export interface ValidationError {
  ok: false;
  code: ValidationErrorCode;
  /** HTTP status the route should return. Per RFC 6749 §5.2 + security-review Medium #3. */
  status: 400 | 401;
  /** Human-readable failure reason; included in error_description. */
  reason: string;
  /** Which pipeline step rejected the assertion. */
  step: number;
  /**
   * draft-04 §-number citation for the spec text this rejection
   * enforces (e.g. "§4.4.1", "§9.8.1.2.2"). Auditors and operators use
   * this to cross-walk reject → spec text → eval gate. Optional only
   * for legacy internal errors that predate Phase 3.1 provenance.
   */
  specSection?: string;
}

/**
 * The shape of the resolved end-user identity key for JIT-upsert. Per
 * draft-04 §3.1: a public subject identifier MUST be unique scoped to
 * (iss + sub) for a single-tenant issuer and (iss + tenant + sub) for
 * a multi-tenant issuer. Resource-side scoping via aud_sub / aud_tenant
 * takes precedence when present.
 *
 * Precedence order (highest first):
 *   1. aud-sub                 — Resource AS owns the subject identifier.
 *   2. sub-with-aud-tenant     — Resource AS tenant scopes the sub.
 *   3. sub-with-tenant         — IdP-side multi-tenant issuer (§3.1).
 *   4. sub-only                — Single-tenant issuer.
 *
 * `sub_id` is an optional alias surfaced on the validated envelope but
 * never used as a standalone primary key.
 */
export type SubjectKey =
  | {
      kind: 'saml-nameid';
      tenantId: string;
      iss: string;
      samlIssuer: string;
      nameid: string;
      nameidFormat?: string;
      nameQualifier?: string;
      spNameQualifier?: string;
      spProvidedId?: string;
    }
  | { kind: 'aud-sub'; tenantId: string; iss: string; audSub: string; audTenant?: string }
  | { kind: 'sub-with-aud-tenant'; tenantId: string; iss: string; audTenant: string; sub: string }
  | { kind: 'sub-with-tenant'; tenantId: string; iss: string; tenant: string; sub: string }
  | { kind: 'sub-only'; tenantId: string; iss: string; sub: string };

/**
 * draft-04 §3.2.1 SAML NameID Subject Identifier Format. `format`,
 * `issuer`, and `nameid` are REQUIRED; the remaining fields are OPTIONAL
 * and MUST be present exactly when the corresponding SAML <NameID>
 * attribute is present per §3.2.2.
 */
export interface SamlNameIdSubId {
  format: 'saml-nameid';
  issuer: string;
  nameid: string;
  nameid_format?: string;
  name_qualifier?: string;
  sp_name_qualifier?: string;
  sp_provided_id?: string;
}

/**
 * RFC 9493 / draft-04 §3.1 sub_id. Always an OBJECT carrying `format`
 * plus format-specific fields — never a bare string.
 */
export type SubId = SamlNameIdSubId | { format: string; [field: string]: unknown };

export interface ValidatedAssertion {
  ok: true;
  iss: string;
  sub: string;
  /**
   * Optional RFC 9493 subject identifier (draft-04 §3.1). When present
   * the IdP MUST emit a value that identifies the same end-user as
   * `sub`; downstream subject-resolution layers MAY use either.
   */
  subId?: SubId;
  aud: string;
  jti: string;
  exp: number;
  iat: number;
  clientId: string;
  tenant?: string;
  audTenant?: string;
  audSub?: string;
  amr?: string[];
  /**
   * draft-04 §4.4.1: ID-JAG-asserted `scope` claim (RFC 6749 §3.3
   * space-separated string). The Resource AS MUST process this claim
   * when present and grant a (possibly narrowed) subset.
   */
  scope?: string;
  /**
   * draft-04 §4.4.1 + RFC 8707 §2: ID-JAG-asserted resource indicator.
   * Single URI string or array of URI strings.
   */
  resource?: string | string[];
  /**
   * draft-04 §4.4.1 + RFC 9396 §2: ID-JAG-asserted Rich Authorization
   * Requests. Array of objects, each carrying `type` plus type-specific
   * sub-fields. Per-element shape validation is the issuer's job.
   */
  authorizationDetails?: unknown[];
  /**
   * RFC 7800 `cnf` claim. Present iff the assertion carries a usable
   * jkt confirmation method. draft-04 §9.8.1.2 supports ONLY jkt
   * (the JWK SHA-256 Thumbprint per RFC 9449 §6.1); the validator
   * rejects cnf objects that lack jkt at step 11 before this field
   * is populated, so when cnf is defined here jkt is guaranteed
   * non-empty. The route enforces:
   *   - cnf present + DPoP absent → 400 invalid_grant (§9.8.1.2.2).
   *   - cnf present + DPoP present + thumbprint mismatch → 400
   *     invalid_grant (§9.8.1.2.1 step 4).
   *   - cnf present + DPoP present + thumbprint match → bound issuance.
   */
  cnf?: { jkt: string };
  /** Resolved subject identity for JIT-upsert. */
  subjectKey: SubjectKey;
  /** The full decoded payload, for downstream scope mapping / RAR / etc. */
  payload: JWTPayload;
}

// ── Input ────────────────────────────────────────────────────────────────────

export type ClientAuthMethod = 'basic' | 'post' | 'private_key_jwt';

export interface ValidateInput {
  /**
   * The raw ID-JAG assertion JWT as received in the `assertion` form
   * parameter of the §4.4 jwt-bearer token request (RFC 7523).
   */
  assertion: string;
  /** The client_id Chariot authenticated for this request. */
  authenticatedClientId: string;
  /**
   * The method the client used to authenticate. Determines whether a
   * missing client returns 401 (Basic per RFC 6749 §5.2) or 400 (post / JWT).
   */
  authMethod?: ClientAuthMethod;
  /** The Chariot tenant that owns the trust registry to consult. */
  tenantId: string;
  trustRegistry: TrustRegistryPort;
  clientRegistry: ClientRegistryPort;
  jtiCache: JtiCachePort;
  jwks: JwksPort;
  /**
   * Caller-supplied prefetched client view, skipping the validator's own
   * clientRegistry.getClient call. Used by routes/oauth.ts where the
   * client was already loaded during authenticateClient — avoids a
   * second Mongo round-trip on the same oauth_clients row per request.
   * When omitted, the validator falls back to clientRegistry.getClient.
   */
  prefetchedClient?: OAuthClientView;
  /**
   * Override the wall clock for jose's exp/nbf check and the manual iat
   * window. Tests use this. Default: Date.now(). Does NOT influence the
   * JTI cache TTL — that is always computed from real Date.now() so a
   * caller injecting a past timestamp cannot inflate replay retention.
   */
  nowMs?: number;
  /** Clock skew tolerance for iat. Default 300s (±5 minutes) per plan §110. */
  clockSkewSeconds?: number;
}

// ── Constants ────────────────────────────────────────────────────────────────

const ID_JAG_JWT_TYP = 'oauth-id-jag+jwt';
/**
 * Required string claims per draft-04 §3.1. `aud` is also REQUIRED but
 * is validated separately because it MAY be a string OR a single-element
 * array per §4.4.1. `exp` and `iat` are REQUIRED numbers and are checked
 * separately for numeric type + finiteness.
 */
const REQUIRED_STRING_CLAIMS = ['sub', 'iss', 'jti', 'client_id'] as const;
const DEFAULT_CLOCK_SKEW_S = 300;

// ── Validator ────────────────────────────────────────────────────────────────

export async function validateIdJagAssertion(
  input: ValidateInput,
): Promise<ValidatedAssertion | ValidationError> {
  const nowMs = input.nowMs ?? Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const skew = input.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_S;

  // Step 2 — header inspection BEFORE any signature work.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(input.assertion);
  } catch {
    return err('invalid_request', 400, 2, 'assertion is not a well-formed JWT');
  }
  if (header.typ !== ID_JAG_JWT_TYP) {
    return err('invalid_grant', 400, 2, `assertion typ must be "${ID_JAG_JWT_TYP}", got "${String(header.typ ?? 'missing')}"`);
  }
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!alg || alg.toLowerCase() === 'none') {
    return err('invalid_grant', 400, 2, 'alg "none" is rejected');
  }

  // Step 3 (partial — iss extraction needs decoded payload). We need the
  // payload before we can fetch JWKS, so peek at iss via a header-only
  // safe decode of the payload portion. jose's jwtVerify is the only safe
  // way to do this when combined with the signature check, but to look up
  // the trusted issuer we need iss BEFORE verification. We decode the
  // payload manually here, then re-verify with jose once we have the key.
  let unverifiedPayload: JWTPayload;
  try {
    unverifiedPayload = decodeUnverifiedPayload(input.assertion);
  } catch {
    return err('invalid_request', 400, 2, 'assertion payload is not parseable');
  }

  const iss = typeof unverifiedPayload.iss === 'string' ? unverifiedPayload.iss : '';
  if (!iss) {
    return err('invalid_grant', 400, 3, 'missing required claim: iss');
  }

  // Trust + client registry lookups. When the caller supplies
  // prefetchedClient (routes/oauth.ts after authenticateClient already
  // loaded the row), skip the registry's findOne entirely — saves one
  // Mongo round-trip on every token-exchange. Otherwise the two reads
  // are independent and run in parallel.
  //
  // try/catch wrapper: the function's declared return type is
  // Promise<ValidatedAssertion | ValidationError>. A Mongo timeout or
  // pool exhaustion thrown here would otherwise propagate past the
  // contract — the JWKS path at lines below is wrapped for the same
  // reason. Convert any storage-tier exception into a structured
  // ValidationError so the caller's `if (!validated.ok)` branch fires
  // and audit + rate-limit emission still happen.
  let trustedIssuer;
  let client;
  try {
    if (input.prefetchedClient) {
      trustedIssuer = await input.trustRegistry.getTrustedIssuer(input.tenantId, iss);
      client = input.prefetchedClient;
    } else {
      [trustedIssuer, client] = await Promise.all([
        input.trustRegistry.getTrustedIssuer(input.tenantId, iss),
        input.clientRegistry.getClient(input.tenantId, input.authenticatedClientId),
      ]);
    }
  } catch (e) {
    return err('invalid_grant', 400, 3, `registry lookup failed: ${(e as Error).message}`);
  }

  if (!trustedIssuer) {
    // Per RFC 6749 §5.2 + security-review Medium #3, "unauthorized_client" is 400, not 401.
    return err('unauthorized_client', 400, 3, `issuer "${iss}" is not trusted by tenant "${input.tenantId}"`);
  }

  // alg allowlist check now that we have the trusted-issuer config.
  if (!trustedIssuer.allowedAlgorithms.includes(alg)) {
    return err('invalid_grant', 400, 2, `alg "${alg}" is not in allowedAlgorithms for issuer "${iss}"`);
  }

  // Step 3 (client side) — issuer must be allowed by the authenticated client.
  if (!client) {
    // RFC 6749 §5.2: 401 invalid_client is the correct response ONLY when
    // the client authenticated via HTTP Basic and the server emits a
    // WWW-Authenticate challenge. For client_secret_post / private_key_jwt
    // the spec recommends 400. The caller signals which auth method was
    // used via authMethod; default to 400 unless explicitly 'basic'.
    const status: 400 | 401 = input.authMethod === 'basic' ? 401 : 400;
    return err('invalid_client', status, 1, `client "${input.authenticatedClientId}" is not registered for tenant "${input.tenantId}"`);
  }
  if (!client.allowedIssuers.includes(iss)) {
    return err('invalid_grant', 400, 3, `issuer "${iss}" is not in client "${input.authenticatedClientId}" allowedIssuers`);
  }

  // Steps 4 + 5 — fetch key + verify signature.
  let key: VerifyKey;
  try {
    key = await input.jwks.fetchKey(trustedIssuer.jwksUri, header.kid, alg);
  } catch (e) {
    return err('invalid_grant', 400, 4, `JWKS fetch failed: ${(e as Error).message}`);
  }
  const cryptoKey: CryptoKey | Uint8Array = isJwk(key) ? await importJWK(key, alg) : key;

  let verifiedPayload: JWTPayload;
  try {
    // No clockTolerance — plan §110 mandates strict `exp > now` and
    // `nbf <= now`. The ±skew window is reserved for `iat` only, which
    // is checked manually below per plan step 6. jose's clockTolerance
    // would relax exp and nbf too, opening a window where an expired
    // assertion still verifies but the JTI cache TTL (= exp - now)
    // has already elapsed (security-review).
    const result = await jwtVerify(input.assertion, cryptoKey, {
      algorithms: trustedIssuer.allowedAlgorithms,
      currentDate: new Date(nowMs),
      // jose enforces typ when supplied; we already checked above but
      // double-enforcing is defense-in-depth.
      typ: ID_JAG_JWT_TYP,
    });
    verifiedPayload = result.payload;
  } catch (e) {
    if (e instanceof joseErrors.JWTExpired) {
      return err('invalid_grant', 400, 6, 'assertion expired');
    }
    if (e instanceof joseErrors.JWTClaimValidationFailed) {
      return err('invalid_grant', 400, 6, `claim validation failed: ${e.message}`);
    }
    if (e instanceof joseErrors.JWSSignatureVerificationFailed) {
      return err('invalid_grant', 400, 5, 'signature verification failed');
    }
    return err('invalid_grant', 400, 5, `assertion verify failed: ${(e as Error).message}`);
  }

  // Step 6 — iat type + finiteness + ±skew window. jose enforces
  // exp/nbf strictly via currentDate; iat future-skew is not enforced
  // by jose's default validators. draft-04 §3.1 declares iat as a JWT
  // numeric date (number), not a coercible string.
  if (typeof verifiedPayload.iat !== 'number' || !Number.isFinite(verifiedPayload.iat)) {
    return err('invalid_grant', 400, 6, 'claim "iat" must be a finite number');
  }
  const iat = verifiedPayload.iat;
  if (iat > nowSec + skew || iat < nowSec - skew) {
    return err('invalid_grant', 400, 6, `iat outside ±${skew}s tolerance`);
  }

  // Step 11 (early — needed before step 7) — required claim presence
  // AND type. draft-04 §3.1 declares these as JSON strings; JWT/jose
  // permits numeric values to round-trip but the validator MUST reject
  // them rather than silently coerce via String(), which would weaken
  // jti replay-key integrity and client_id continuity. sub_id is
  // OPTIONAL and validated by its own block below.
  for (const claim of REQUIRED_STRING_CLAIMS) {
    const v = verifiedPayload[claim];
    if (v === undefined || v === null) {
      return err('invalid_grant', 400, 11, `missing required claim: ${claim}`);
    }
    if (typeof v !== 'string' || v === '') {
      return err('invalid_grant', 400, 11, `claim "${claim}" must be a non-empty string`);
    }
  }
  if (verifiedPayload.aud === undefined || verifiedPayload.aud === null) {
    return err('invalid_grant', 400, 11, 'missing required claim: aud');
  }
  if (typeof verifiedPayload.exp !== 'number' || !Number.isFinite(verifiedPayload.exp)) {
    return err('invalid_grant', 400, 11, 'claim "exp" must be a finite number');
  }
  // iat numeric type + finiteness already enforced in step 6.
  const sub = verifiedPayload.sub as string;
  // draft-04 §4.4.1: "The aud claim MAY be a string containing a single
  // issuer identifier, or an array containing a single issuer
  // identifier. If the aud claim is an array, it MUST contain exactly
  // one element, and that element MUST be the issuer identifier of the
  // Resource Authorization Server." Stricter than RFC 7519 §4.1.3:
  // multi-element arrays are REJECTED even when the expected audience
  // is one of the elements.
  let audMatch: string;
  if (Array.isArray(verifiedPayload.aud)) {
    if (verifiedPayload.aud.length !== 1) {
      return err(
        'invalid_grant',
        400,
        11,
        `aud array must contain exactly one element per draft-04 §4.4.1; got ${verifiedPayload.aud.length}`,
      );
    }
    const only = verifiedPayload.aud[0];
    if (typeof only !== 'string') {
      return err('invalid_grant', 400, 11, 'aud array element must be a string');
    }
    audMatch = only;
  } else if (typeof verifiedPayload.aud === 'string') {
    audMatch = verifiedPayload.aud;
  } else {
    return err('invalid_grant', 400, 11, 'aud must be a string or single-element array of strings');
  }
  const jti = verifiedPayload.jti as string;
  const exp = verifiedPayload.exp as number;
  const clientIdClaim = verifiedPayload['client_id'] as string;

  // Step 7 — client-continuity (security-review Critical #1).
  if (clientIdClaim !== input.authenticatedClientId) {
    return err(
      'invalid_grant',
      400,
      7,
      `client_id claim "${clientIdClaim}" does not match authenticated client "${input.authenticatedClientId}"`,
    );
  }

  // Step 8 — audience match per draft-04 §4.4.1. The (already-normalized)
  // single audience value MUST equal the trusted issuer's configured
  // Resource AS identifier exactly. No subset / "includes" semantics —
  // the spec is strict equality on the one element.
  if (audMatch !== trustedIssuer.audience) {
    return err(
      'invalid_grant',
      400,
      8,
      `aud "${audMatch}" does not equal expected "${trustedIssuer.audience}"`,
    );
  }
  const aud = audMatch;

  // Step 9 — multi-tenant + SAML claims (plan §115 revised round 5).
  const tenant = typeof verifiedPayload['tenant'] === 'string' ? verifiedPayload['tenant'] : undefined;
  const audTenant = typeof verifiedPayload['aud_tenant'] === 'string' ? verifiedPayload['aud_tenant'] : undefined;
  const audSub = typeof verifiedPayload['aud_sub'] === 'string' ? verifiedPayload['aud_sub'] : undefined;
  const amr = Array.isArray(verifiedPayload['amr'])
    ? verifiedPayload['amr'].filter((v): v is string => typeof v === 'string')
    : undefined;

  // draft-04 §6.1: when the Resource AS configures
  // requiresTenantContext=true for this trusted issuer (i.e. tenant
  // context is relevant to the AS), an assertion without `tenant`
  // MUST be rejected. The condition is gated on operator config —
  // when not set, the IdP-side MUST does not fire and an absent
  // `tenant` claim is permissive (RB-RI-3, plan Phase 1.6).
  if (trustedIssuer.requiresTenantContext === true && tenant === undefined) {
    return err(
      'invalid_grant',
      400,
      9,
      'tenant claim is required by Resource AS policy for this issuer per draft-04 §6.1',
      'draft-04 §6.1',
    );
  }
  // draft-04 §6.4: "The tenant identifier in the ID-JAG MUST match
  // the tenant context that the Resource Authorization Server
  // expects." When the operator configures expectedTenants (non-empty
  // allowlist), the AS expects a tenant. Two reject conditions:
  //   (a) tenant claim absent — the AS expects one but got none.
  //   (b) tenant claim present but not in the allowlist.
  // Undefined or empty allowlist means "no specific tenant expected"
  // and the gate is permissive (§6.1 governs presence-requirement).
  if (
    trustedIssuer.expectedTenants !== undefined
    && trustedIssuer.expectedTenants.length > 0
  ) {
    if (tenant === undefined) {
      return err(
        'invalid_grant',
        400,
        9,
        'tenant claim is required by Resource AS policy (expectedTenants is configured) per draft-04 §6.4',
        'draft-04 §6.4',
      );
    }
    if (!trustedIssuer.expectedTenants.includes(tenant)) {
      return err(
        'invalid_grant',
        400,
        9,
        `tenant "${tenant}" is not in the trusted issuer's expectedTenants allowlist per draft-04 §6.4`,
        'draft-04 §6.4',
      );
    }
  }
  // draft-04 §6.2: when tenantScopedClientIds is configured (non-empty
  // map) AND the assertion carries a tenant, the (client_id, tenant)
  // tuple MUST match an entry. An EMPTY map ({}) is treated identically
  // to "not configured" (per the §6.2 alternative model: AS treats
  // client_ids as globally unique). This matches the registry contract
  // where omitting the field is preserved via PATCH semantics; an
  // operator who EXPLICITLY clears the map to {} is opting back into
  // the alternative model rather than locking out every tenant.
  if (
    trustedIssuer.tenantScopedClientIds !== undefined
    && Object.keys(trustedIssuer.tenantScopedClientIds).length > 0
    && tenant !== undefined
  ) {
    const allowedForTenant = trustedIssuer.tenantScopedClientIds[tenant];
    if (!Array.isArray(allowedForTenant) || !allowedForTenant.includes(input.authenticatedClientId)) {
      return err(
        'invalid_grant',
        400,
        9,
        `client_id "${input.authenticatedClientId}" is not registered for tenant "${tenant}" per draft-04 §6.2`,
        'draft-04 §6.2',
      );
    }
  }

  // sub_id per draft-04 §3.1 + §3.2.1 + §3.2.2 + §9.5 and RFC 9493.
  //
  // sub_id is an OBJECT carrying `format` plus format-specific fields.
  // A bare string sub_id is malformed per RFC 9493. When the trusted
  // issuer's policy requires SAML NameID resolution
  // (requireSamlNameIdSubId=true), §3.2.2 mandates invalid_grant on
  // absent / malformed / wrong-format sub_id.
  //
  // §3.1: "When both sub and sub_id are present, they MUST identify the
  // same End-User." This is a contractual MUST on the IdP. The Resource
  // AS cannot algorithmically verify identity equivalence across two
  // distinct subject namespaces (OIDC iss/sub vs SAML issuer/nameid)
  // without an external alias-resolution mechanism, so claim-level
  // string-equality checks are structurally impossible. The defenses
  // available here are:
  //   - §9.5 SAML-issuer allowlist enforcement (below): only sub_id
  //     values whose `issuer` is explicitly associated with this
  //     ID-JAG issuer in local trust config are accepted.
  //   - Trust in the signed IdP assertion for the sub↔sub_id binding.
  //   - Downstream subject-resolution layer applies §3.2.2 "MUST
  //     compare every member" rules when sub_id is used for resolution.
  // Both identifiers are surfaced on the validated envelope so the
  // downstream subject-resolution layer can use whichever it needs.
  const subIdRaw = verifiedPayload['sub_id'];
  let subId: SubId | undefined;
  if (subIdRaw !== undefined && subIdRaw !== null) {
    if (typeof subIdRaw !== 'object' || Array.isArray(subIdRaw)) {
      return err('invalid_grant', 400, 9, 'sub_id must be a JSON object per RFC 9493');
    }
    const obj = subIdRaw as Record<string, unknown>;
    const format = obj.format;
    if (typeof format !== 'string' || format === '') {
      return err('invalid_grant', 400, 9, 'sub_id.format is required per RFC 9493');
    }
    if (format === 'saml-nameid') {
      // draft-04 §3.2.1 REQUIRED members — structural shape; always
      // enforced regardless of whether the AS uses sub_id for
      // resolution. A malformed saml-nameid sub_id is rejected even
      // when the AS would ignore it, because §3.2.1 defines the format
      // unconditionally.
      if (typeof obj.issuer !== 'string' || obj.issuer === '') {
        return err('invalid_grant', 400, 9, 'sub_id.issuer is required for saml-nameid format');
      }
      if (typeof obj.nameid !== 'string' || obj.nameid === '') {
        return err('invalid_grant', 400, 9, 'sub_id.nameid is required for saml-nameid format');
      }
      // §9.5 SAML-issuer allowlist enforcement is USE-gated, not
      // presence-gated (Phase 0.1 R3, reverting an earlier presence-gated
      // form). Spec §9.5 text: "The Resource Authorization Server MUST
      // USE a SAML NameID sub_id ONLY WHEN the validated ID-JAG issuer
      // is explicitly associated with the SAML issuer identified by
      // sub_id.issuer through local configuration or trusted federation
      // metadata." The trigger is USE. Today the only operator signal
      // that the AS will use sub_id for resolution is the trusted
      // issuer's `requireSamlNameIdSubId` flag — when false/undefined
      // the sub_id is informational metadata only and §9.5 does not
      // fire. When true, enforce the allowlist; absent/empty list means
      // no SAML issuers are trusted under this ID-JAG issuer — reject.
      if (trustedIssuer.requireSamlNameIdSubId) {
        const allowedSamlIssuers = trustedIssuer.samlNameIdIssuers ?? [];
        if (!allowedSamlIssuers.includes(obj.issuer)) {
          return err(
            'invalid_grant',
            400,
            9,
            `sub_id.issuer "${obj.issuer}" is not in the trusted SAML issuer allowlist for ID-JAG issuer "${trustedIssuer.iss}" per draft-04 §9.5`,
          );
        }
      }
      // §3.2.1 OPTIONAL members — type-check when present, omit when absent.
      const optionalFields = ['nameid_format', 'name_qualifier', 'sp_name_qualifier', 'sp_provided_id'] as const;
      for (const opt of optionalFields) {
        if (obj[opt] !== undefined && typeof obj[opt] !== 'string') {
          return err('invalid_grant', 400, 9, `sub_id.${opt} must be a string when present`);
        }
      }
      subId = {
        format: 'saml-nameid',
        issuer: obj.issuer,
        nameid: obj.nameid,
        ...(typeof obj.nameid_format === 'string' ? { nameid_format: obj.nameid_format } : {}),
        ...(typeof obj.name_qualifier === 'string' ? { name_qualifier: obj.name_qualifier } : {}),
        ...(typeof obj.sp_name_qualifier === 'string' ? { sp_name_qualifier: obj.sp_name_qualifier } : {}),
        ...(typeof obj.sp_provided_id === 'string' ? { sp_provided_id: obj.sp_provided_id } : {}),
      };
    } else {
      // Unknown format — preserve verbatim for downstream RFC 9493
      // registry expansion. §3.2.2 strict-reject below kicks in only
      // when the Resource AS requires saml-nameid specifically.
      subId = { ...obj, format } as SubId;
    }
  }

  // draft-04 §3.2.2 strict-reject rules. Only fire when the Resource AS
  // local policy requires SAML NameID resolution for this trusted issuer.
  if (trustedIssuer.requireSamlNameIdSubId) {
    if (!subId) {
      return err(
        'invalid_grant',
        400,
        9,
        'sub_id is required by Resource AS policy for this issuer but is not present',
      );
    }
    if (subId.format !== 'saml-nameid') {
      return err(
        'invalid_grant',
        400,
        9,
        `sub_id format "${subId.format}" is not supported; saml-nameid is required by Resource AS policy`,
      );
    }
  }

  // draft-04 §4.4.1 ID-JAG-asserted authorization-shaping claims.
  // The Resource AS MUST process scope / resource / authorization_details
  // when present; the issuer applies policy narrowing and includes the
  // granted shape in the response per §4.4.1 final bullet.
  let scope: string | undefined;
  const scopeRaw = verifiedPayload['scope'];
  if (scopeRaw !== undefined && scopeRaw !== null) {
    if (typeof scopeRaw !== 'string') {
      return err('invalid_grant', 400, 11, 'scope claim must be a string (RFC 6749 §3.3)', 'draft-04 §4.4.1 / RFC 6749 §3.3');
    }
    // RFC 6749 §3.3 — scope is space-delimited list of non-empty
    // scope-tokens. An empty-string scope is structurally invalid;
    // reject at validation time rather than letting it surface as a
    // 403 access_denied mid-issuance.
    if (scopeRaw.trim().length === 0) {
      return err('invalid_grant', 400, 11, 'scope claim must contain at least one non-empty token (RFC 6749 §3.3)', 'draft-04 §4.4.1 / RFC 6749 §3.3');
    }
    scope = scopeRaw;
  }
  let resource: string | string[] | undefined;
  const resourceRaw = verifiedPayload['resource'];
  if (resourceRaw !== undefined && resourceRaw !== null) {
    if (typeof resourceRaw === 'string') {
      resource = resourceRaw;
    } else if (Array.isArray(resourceRaw) && resourceRaw.every((v) => typeof v === 'string')) {
      resource = resourceRaw as string[];
    } else {
      return err('invalid_grant', 400, 11, 'resource claim must be a URI string or array of URI strings (RFC 8707 §2)', 'draft-04 §4.4.1 / RFC 8707 §2');
    }
  }
  let authorizationDetails: unknown[] | undefined;
  const adRaw = verifiedPayload['authorization_details'];
  if (adRaw !== undefined && adRaw !== null) {
    if (!Array.isArray(adRaw)) {
      return err('invalid_grant', 400, 11, 'authorization_details claim must be a JSON array (RFC 9396 §2)', 'draft-04 §4.4.1 / RFC 9396 §2');
    }
    authorizationDetails = adRaw;
  }

  // Subject-key resolution per draft-04 §3.1 uniqueness rules. When the
  // issuer is multi-tenant (tenant claim present) and the Resource AS
  // is not itself scoping via aud_sub / aud_tenant, the key MUST include
  // `tenant` so distinct IdP tenants are not collapsed onto one local
  // subject (security-review finding #3).
  //
  // §3.1 (lines 509-516): "When aud_tenant is present, the aud_sub
  // claim represents the identifier the Resource Authorization Server
  // has for the account within the context of that specific Resource
  // Authorization Server tenant. The combination of aud + aud_tenant
  // and aud_sub MUST be unique within the Resource Authorization
  // Server." When the assertion carries BOTH aud_sub AND aud_tenant,
  // the aud-sub key MUST include aud_tenant to preserve the spec's
  // (aud + aud_tenant + aud_sub) uniqueness domain. Without this,
  // two tokens with same aud_sub from different aud_tenant collapse
  // onto one local subject — cross-tenant access leak.
  // §3.2.2 multi-member SAML NameID resolution takes precedence when the
  // trusted issuer requires it (requireSamlNameIdSubId=true) OR the
  // assertion's sub_id is saml-nameid AND its `issuer` is in the
  // operator-configured samlNameIdIssuers allowlist. Configuring the
  // allowlist is itself an opt-in signal that the AS "uses" sub_id
  // for resolution for those SAML issuers (§9.5 USE semantics),
  // closing the silent same-`sub` cross-principal collision risk
  // that arises when an operator declares trusted SAML issuers but
  // forgets to set the strict-reject flag. The subject is resolved
  // over the FULL multi-member tuple (issuer + nameid + optional
  // members exactly as the IdP provided them) — §3.2.2 line 665:
  // "MUST compare every member of the SAML NameID Subject Identifier
  // that is part of the set of identifier fields it uses for subject
  // resolution for that SAML issuer". Missing optional members are
  // honoured as missing (not substituted), preserving the spec's
  // "compare every member" semantics exactly.
  const samlNameIdAllowlist = trustedIssuer.samlNameIdIssuers ?? [];
  const useSamlNameIdResolution =
    subId !== undefined
    && subId.format === 'saml-nameid'
    && (
      trustedIssuer.requireSamlNameIdSubId === true
      || samlNameIdAllowlist.includes((subId as SamlNameIdSubId).issuer)
    );
  const subjectKey: SubjectKey =
    useSamlNameIdResolution
      ? {
          kind: 'saml-nameid',
          tenantId: input.tenantId,
          iss,
          samlIssuer: (subId as SamlNameIdSubId).issuer,
          nameid: (subId as SamlNameIdSubId).nameid,
          ...((subId as SamlNameIdSubId).nameid_format !== undefined ? { nameidFormat: (subId as SamlNameIdSubId).nameid_format } : {}),
          ...((subId as SamlNameIdSubId).name_qualifier !== undefined ? { nameQualifier: (subId as SamlNameIdSubId).name_qualifier } : {}),
          ...((subId as SamlNameIdSubId).sp_name_qualifier !== undefined ? { spNameQualifier: (subId as SamlNameIdSubId).sp_name_qualifier } : {}),
          ...((subId as SamlNameIdSubId).sp_provided_id !== undefined ? { spProvidedId: (subId as SamlNameIdSubId).sp_provided_id } : {}),
        }
      : audSub !== undefined
        ? { kind: 'aud-sub', tenantId: input.tenantId, iss, audSub, ...(audTenant !== undefined ? { audTenant } : {}) }
        : audTenant !== undefined
          ? { kind: 'sub-with-aud-tenant', tenantId: input.tenantId, iss, audTenant, sub }
          : tenant !== undefined
            ? { kind: 'sub-with-tenant', tenantId: input.tenantId, iss, tenant, sub }
            : { kind: 'sub-only', tenantId: input.tenantId, iss, sub };

  // Step 10 — JTI uniqueness per RFC 7523 §3 + draft-04 §4.4.3.
  //
  // §4.4.3 (line 1658): "When the access token has expired, clients MAY
  // re-submit the original Identity Assertion JWT Authorization Grant
  // to obtain a new Access Token." Strict single-use jti would reject
  // a conformant re-submission. The spec-safe interpretation is
  // uniqueness PER DISTINCT ASSERTION, not per redemption attempt.
  //
  // reserveOrMatch keys on (iss, jti, SHA-256(assertion)):
  //   - first sight → accept and store.
  //   - re-submission of the same assertion bytes within original
  //     exp → accept ('match'); allows §4.4.3 re-redemption.
  //   - re-submission with the same (iss, jti) but DIFFERENT bytes →
  //     reject as a true replay attack.
  //
  // TTL is exp - REAL_now in seconds. Uses Date.now() (not the
  // caller-injected nowMs) so test/operator clock injection cannot
  // inflate replay-cache retention past the assertion's real
  // lifetime. We still pass at least 1 to satisfy positive-TTL APIs.
  const realNowSec = Math.floor(Date.now() / 1000);
  const ttl = Math.max(1, exp - realNowSec);
  const assertionHash = createHash('sha256').update(input.assertion).digest('hex');
  const reservation = await input.jtiCache.reserveOrMatch(iss, jti, assertionHash, ttl);
  if (reservation === 'replay') {
    return err('invalid_grant', 400, 10, `jti "${jti}" reused with different assertion bytes (replay attack)`);
  }
  // 'first-sight' and 'match' both accept; §4.4.3 re-submission of the
  // same bytes is the spec-permitted path.

  // RFC 7800 cnf claim extraction for draft-04 §9.8.1.2 DPoP
  // enforcement. The validator surfaces cnf.jkt; the caller (route)
  // enforces §9.8.1.2.2 (cnf present + DPoP absent → reject) and
  // §9.8.1.2.1 step 4 (DPoP thumbprint vs cnf.jkt match).
  //
  // draft-04 §9.8.1.2 uses ONLY the jkt confirmation method (the JWK
  // SHA-256 Thumbprint per RFC 9449 §6.1). A cnf object with no jkt
  // is either an IdP-side spec deviation OR uses a non-jkt RFC 7800
  // confirmation method (jwk, jwe, kid, x5t#S256) that this Resource
  // AS does not implement for ID-JAG binding. Either way the sender-
  // constraint contract cannot be enforced: reject with invalid_grant
  // so the failure surfaces at validation time rather than slipping
  // through to Bearer issuance via the route's cnf?.jkt fall-through.
  let cnf: { jkt: string } | undefined;
  const cnfRaw = verifiedPayload['cnf'];
  if (cnfRaw !== undefined && cnfRaw !== null) {
    if (typeof cnfRaw !== 'object' || Array.isArray(cnfRaw)) {
      return err('invalid_grant', 400, 11, 'cnf claim must be a JSON object (RFC 7800)');
    }
    const cnfObj = cnfRaw as Record<string, unknown>;
    const jkt = cnfObj.jkt;
    if (jkt === undefined) {
      return err(
        'invalid_grant',
        400,
        11,
        'cnf claim is present but missing jkt; draft-04 §9.8.1.2 supports only the RFC 9449 jkt confirmation method',
      );
    }
    if (typeof jkt !== 'string' || jkt === '') {
      return err('invalid_grant', 400, 11, 'cnf.jkt must be a non-empty string');
    }
    cnf = { jkt };
  }

  return {
    ok: true,
    iss,
    sub,
    subId,
    aud,
    jti,
    exp,
    iat,
    clientId: clientIdClaim,
    tenant,
    audTenant,
    audSub,
    amr,
    ...(scope !== undefined ? { scope } : {}),
    ...(resource !== undefined ? { resource } : {}),
    ...(authorizationDetails !== undefined ? { authorizationDetails } : {}),
    ...(cnf !== undefined ? { cnf } : {}),
    subjectKey,
    payload: verifiedPayload,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Default spec-section citation by pipeline step (Phase 3.1 / T23).
 * When a `specSection` arg is passed to `err()`, it wins. Otherwise the
 * step-default below is used so every reject path carries a §-number for
 * SOC 2 / SIEM cross-walk and the conformance eval traceability matrix.
 *
 * Step → section mapping is derived from the pipeline contract that the
 * inline step comments document:
 *   1  client auth                  → RFC 6749 §5.2 / draft-04 §4.4
 *   2  JWT structural / alg / typ   → RFC 7519 §7.2 / draft-04 §3
 *   3  trusted issuer + client trust→ draft-04 §9.4
 *   4  JWKS fetch                   → RFC 7517 §4
 *   5  signature verify             → draft-04 §4.4.1
 *   6  temporal (exp/iat/nbf)       → RFC 7519 §4.1
 *   8  aud match                    → draft-04 §4.4.1
 *   9  sub_id + §6.x tenant gates   → draft-04 §3.2 / §6.1 / §6.2 / §6.4 / §9.5
 *   10 jti uniqueness               → RFC 7523 §3 / draft-04 §4.4.3
 *   11 required claims              → draft-04 §3.1 / §4.4.1
 */
const SPEC_SECTION_BY_STEP: Record<number, string> = {
  1: 'RFC 6749 §5.2 / draft-04 §4.4',
  2: 'RFC 7519 §7.2 / draft-04 §3',
  3: 'draft-04 §9.4',
  4: 'RFC 7517 §4',
  5: 'draft-04 §4.4.1',
  6: 'RFC 7519 §4.1',
  8: 'draft-04 §4.4.1',
  9: 'draft-04 §3.2',
  10: 'RFC 7523 §3 / draft-04 §4.4.3',
  11: 'draft-04 §3.1',
};

function err(
  code: ValidationErrorCode,
  status: 400 | 401,
  step: number,
  reason: string,
  specSection?: string,
): ValidationError {
  const section = specSection ?? SPEC_SECTION_BY_STEP[step];
  return { ok: false, code, status, step, reason, ...(section !== undefined ? { specSection: section } : {}) };
}

/**
 * Decode the JWT payload WITHOUT signature verification. Used only to
 * extract `iss` so we can locate the trusted-issuer config and choose
 * the right key. The result MUST NOT be returned to the caller; the
 * authoritative payload comes from jwtVerify(). Every failure mode —
 * malformed segments, invalid base64url, invalid UTF-8, non-JSON, non-
 * object JSON — throws a generic Error the caller converts to
 * invalid_request.
 */
function decodeUnverifiedPayload(jwt: string): JWTPayload {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('malformed JWT');
  }
  // Node's 'base64url' encoding handles padding + character substitution
  // natively; the same one-liner is used elsewhere in this IAM module
  // (routes/oidc.ts, routes/mfa.ts, routes/saml.ts, routes/session.ts).
  const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf-8');
  const parsed: unknown = JSON.parse(payloadJson);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('payload is not an object');
  }
  return parsed as JWTPayload;
}

function isJwk(k: unknown): k is JWK {
  return typeof k === 'object' && k !== null && 'kty' in (k as Record<string, unknown>);
}
