/**
 * IAM — ID-JAG Client (Chariot acting as Client per draft-04 §2.1).
 *
 * Calls the enterprise IdP's Token Exchange endpoint (§4.3) to obtain
 * a per-audience ID-JAG on behalf of an authenticated user, then makes
 * that ID-JAG available to the MCP-dispatch layer for presentation at
 * a downstream Resource Authorization Server (§4.4).
 *
 * Spec authority: draft-ietf-oauth-identity-assertion-authz-grant-04
 * §4.3 / §4.3.1 / §4.3.3 / §4.3.4 / §4.3.4.3.
 *
 * Failure modes per the PRIVATE id-jag-client-spec.md §5; every
 * reject path emits an audit event with spec_section.
 */

import { createHash, randomBytes } from 'node:crypto';
import { decodeProtectedHeader, SignJWT, importPKCS8, jwtVerify, createRemoteJWKSet } from 'jose';

import { getCollection } from '../db.js';
import { decryptFields } from '../crypto.js';
import { ensureHttps } from '../utils/url.js';
import type { IdJagIdpClientDocument } from '../types.js';

// ── Constants ────────────────────────────────────────────────────────────────

const COLLECTION = 'iam_id_jag_idp_clients';
const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const REQUESTED_TOKEN_TYPE_ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';
const ID_JAG_TYP = 'oauth-id-jag+jwt';

const SUBJECT_TOKEN_TYPE_ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
const SUBJECT_TOKEN_TYPE_SAML2 = 'urn:ietf:params:oauth:token-type:saml2';
const SUBJECT_TOKEN_TYPE_REFRESH = 'urn:ietf:params:oauth:token-type:refresh_token';

const CLIENT_ASSERTION_TYPE_JWT = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const DEFAULT_NETWORK_TIMEOUT_MS = 10_000;

/**
 * Per-jwksUri jose RemoteJWKSet cache. jose stores fetched keys inside
 * the closure returned by createRemoteJWKSet; instantiating a fresh
 * getter on every exchangeForIdJag call would discard that cache and
 * issue an outbound JWKS HTTPS round-trip per MCP dispatch. Cache one
 * getter per jwksUri so kid lookups hit jose's in-process cache.
 * Cleared explicitly via clearIdpJwksCache() at IdP-rotation time.
 */
const _jwksGetters = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getOrCreateJwksGetter(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let g = _jwksGetters.get(jwksUri);
  if (!g) {
    g = createRemoteJWKSet(new URL(jwksUri));
    _jwksGetters.set(jwksUri, g);
  }
  return g;
}
export function clearIdpJwksCache(jwksUri?: string): void {
  if (jwksUri === undefined) {
    _jwksGetters.clear();
    return;
  }
  _jwksGetters.delete(jwksUri);
}

// ── Public surface ───────────────────────────────────────────────────────────

export type SubjectTokenType = 'id_token' | 'saml2' | 'refresh_token';

export interface ExchangeForIdJagInput {
  tenantId: string;
  /** IdP issuer URL — keys the iam_id_jag_idp_clients lookup. */
  idpIssuer: string;
  /** Downstream Resource AS issuer; carried as RFC 8693 `audience`. */
  audience: string;
  /** Optional RFC 8707 resource indicator (single URI). */
  resource?: string;
  /** Optional RFC 6749 §3.3 space-delimited scope list. */
  scope?: string;
  /** Optional RFC 9396 RAR objects. */
  authorizationDetails?: unknown[];
  /** The user's inbound SSO assertion. */
  subjectToken: string;
  subjectTokenType: SubjectTokenType;
  /** Per-call override of the global network timeout (ms). */
  timeoutMs?: number;
}

export type ClientErrorCode =
  | 'invalid_request'
  | 'invalid_idp_config'
  | 'unauthorized_audience'
  | 'idp_unreachable'
  | 'idp_rate_limited'
  | 'invalid_idp_response'
  | 'invalid_grant'
  | 'invalid_target'
  | 'invalid_scope'
  | 'invalid_authorization_details'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'access_denied'
  | 'audience_mismatch'
  | 'expired_assertion_at_receipt'
  | 'subject_token_expired'
  | 'invalid_id_jag_typ'
  | 'server_error';

export interface ClientError {
  ok: false;
  code: ClientErrorCode;
  /** HTTP status to surface to the MCP tool caller. */
  status: 400 | 401 | 403 | 500 | 502 | 504;
  reason: string;
  /** draft-04 §-number for SOC 2 / SIEM cross-walk. */
  specSection: string;
  /** Original IdP error body when the failure was an IdP 4xx. */
  idpError?: { error: string; error_description?: string };
}

export interface ExchangeResult {
  ok: true;
  /** The raw ID-JAG JWT string returned by the IdP. */
  idJag: string;
  /** NumericDate (seconds) — `exp` from the ID-JAG. */
  exp: number;
  /** The audience the IdP actually resolved (may differ from request if IdP did URN→URL resolution). */
  audience: string;
  /** Granted scope per §4.3.4 (echoed when narrowed). */
  scope?: string;
  /** Granted authorization_details per §4.3.4 (echoed when modified). */
  authorizationDetails?: unknown[];
  /** RFC 7800 jkt thumbprint, when the ID-JAG carries a cnf claim. */
  jkt?: string;
  /** Time-to-live in seconds at receipt. */
  expiresIn: number;
}

// ── Persisted IdP-Client lookup ──────────────────────────────────────────────

export interface IdpClientView {
  issuer: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  authMethod: IdJagIdpClientDocument['authMethod'];
  clientAssertionSigningAlg: 'RS256' | 'ES256';
  allowedAudiences: string[];
  /** Decrypted client secret (basic / post). */
  clientSecret?: string;
  /** Decrypted PKCS8 PEM private key (private_key_jwt). */
  clientPrivateKey?: string;
}

interface IdpRegistryPort {
  getIdpClient(tenantId: string, idpIssuer: string): Promise<IdpClientView | null>;
}

export const idpClientRegistry: IdpRegistryPort = {
  async getIdpClient(tenantId, idpIssuer) {
    const col = await getCollection<IdJagIdpClientDocument>(COLLECTION);
    const doc = await col.findOne({ tenantId, issuer: idpIssuer, active: true });
    if (!doc) return null;
    const view: IdpClientView = {
      issuer: doc.issuer,
      tokenEndpoint: doc.tokenEndpoint,
      jwksUri: doc.jwksUri,
      clientId: doc.clientId,
      authMethod: doc.authMethod,
      clientAssertionSigningAlg: doc.clientAssertionSigningAlg ?? 'RS256',
      allowedAudiences: doc.allowedAudiences,
    };
    if (doc.authMethod !== 'private_key_jwt' && doc.clientSecretEncrypted) {
      // The credential-loader encryption uses combined-blob format
      // {encrypted, iv}; decrypt via the same crypto.ts seam.
      const [encrypted, iv] = doc.clientSecretEncrypted.split(':');
      if (encrypted && iv) {
        const decrypted = decryptFields(encrypted, iv, tenantId);
        if (typeof decrypted.value === 'string') view.clientSecret = decrypted.value;
      }
    }
    if (doc.authMethod === 'private_key_jwt' && doc.clientPrivateKeyEncrypted) {
      const [encrypted, iv] = doc.clientPrivateKeyEncrypted.split(':');
      if (encrypted && iv) {
        const decrypted = decryptFields(encrypted, iv, tenantId);
        if (typeof decrypted.value === 'string') view.clientPrivateKey = decrypted.value;
      }
    }
    return view;
  },
};

// ── Public API ───────────────────────────────────────────────────────────────

export interface ExchangeDeps {
  /** Override the IdP-registry lookup (tests). */
  registry?: IdpRegistryPort;
  /** Override the network fetch (tests). */
  fetchImpl?: typeof fetch;
  /** Override Date.now (tests). */
  nowMs?: () => number;
}

/**
 * Call the enterprise IdP's Token Exchange endpoint per draft-04 §4.3 to
 * obtain an audience-scoped ID-JAG for the authenticated user.
 *
 * Returns ExchangeResult on success; ClientError on any deterministic
 * failure (network, IdP reject, structural validation). The MCP-dispatch
 * caller (toolHandlers.ts) decides whether to fall back to a static
 * credential or surface the failure based on the adapter manifest's
 * `idJagAuth.fallback` value.
 */
export async function exchangeForIdJag(
  input: ExchangeForIdJagInput,
  deps: ExchangeDeps = {},
): Promise<ExchangeResult | ClientError> {
  const registry = deps.registry ?? idpClientRegistry;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.nowMs ?? Date.now;

  // Step 1 — IdP registry lookup.
  if (!input.tenantId || !input.idpIssuer || !input.audience) {
    return err(
      'invalid_request',
      400,
      'tenantId, idpIssuer, and audience are required',
      'draft-04 §4.3',
    );
  }
  const idp = await registry.getIdpClient(input.tenantId, input.idpIssuer);
  if (!idp) {
    return err(
      'invalid_idp_config',
      400,
      `no active IdP registration for issuer "${input.idpIssuer}" under tenant "${input.tenantId}"`,
      'draft-04 §4.3',
    );
  }

  // Step 1a — audience-allowlist short-circuit. Operator controls which
  // downstream Resource ASes Chariot may fan out to under each IdP.
  if (!idp.allowedAudiences.includes(input.audience)) {
    return err(
      'unauthorized_audience',
      403,
      `audience "${input.audience}" is not in the allowedAudiences set for IdP "${input.idpIssuer}"`,
      'draft-04 §4.3 (audience)',
    );
  }

  // Step 2 — subject_token validation (presence only; the IdP validates
  // the assertion contents).
  if (typeof input.subjectToken !== 'string' || input.subjectToken.length === 0) {
    return err(
      'invalid_request',
      400,
      'subject_token is required',
      'draft-04 §4.3 (subject_token)',
    );
  }
  const subjectTokenType = mapSubjectTokenType(input.subjectTokenType);
  if (subjectTokenType === null) {
    return err(
      'invalid_request',
      400,
      `unsupported subjectTokenType "${input.subjectTokenType}"`,
      'draft-04 §4.3 (subject_token_type)',
    );
  }

  // Step 3 — build the form body per §4.3.1 worked example.
  const body = new URLSearchParams();
  body.set('grant_type', GRANT_TYPE_TOKEN_EXCHANGE);
  body.set('requested_token_type', REQUESTED_TOKEN_TYPE_ID_JAG);
  body.set('audience', input.audience);
  if (input.resource !== undefined) body.set('resource', input.resource);
  if (input.scope !== undefined) body.set('scope', input.scope);
  if (input.authorizationDetails !== undefined) {
    body.set('authorization_details', JSON.stringify(input.authorizationDetails));
  }
  body.set('subject_token', input.subjectToken);
  body.set('subject_token_type', subjectTokenType);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };

  // Client authentication.
  switch (idp.authMethod) {
    case 'client_secret_basic': {
      if (!idp.clientSecret) {
        return err('invalid_idp_config', 500, 'clientSecret missing for client_secret_basic', 'RFC 6749 §2.3.1');
      }
      const basic = Buffer.from(
        `${encodeURIComponent(idp.clientId)}:${encodeURIComponent(idp.clientSecret)}`,
        'utf8',
      ).toString('base64');
      headers.Authorization = `Basic ${basic}`;
      break;
    }
    case 'client_secret_post': {
      if (!idp.clientSecret) {
        return err('invalid_idp_config', 500, 'clientSecret missing for client_secret_post', 'RFC 6749 §2.3.1');
      }
      body.set('client_id', idp.clientId);
      body.set('client_secret', idp.clientSecret);
      break;
    }
    case 'private_key_jwt': {
      if (!idp.clientPrivateKey) {
        return err('invalid_idp_config', 500, 'clientPrivateKey missing for private_key_jwt', 'RFC 7523 §2.2');
      }
      let assertion: string;
      try {
        assertion = await buildClientAssertion(idp, input.idpIssuer, now);
      } catch (e) {
        return err(
          'invalid_idp_config',
          500,
          `failed to build private_key_jwt client_assertion: ${(e as Error).message}`,
          'RFC 7523 §2.2',
        );
      }
      body.set('client_assertion_type', CLIENT_ASSERTION_TYPE_JWT);
      body.set('client_assertion', assertion);
      break;
    }
    default: {
      const _exhaustive: never = idp.authMethod;
      return err(
        'invalid_idp_config',
        500,
        `unsupported authMethod ${String(_exhaustive)}`,
        'RFC 6749 §2.3',
      );
    }
  }

  // HTTPS-only enforcement at call time (the registry also enforces this
  // at registration, but defence in depth).
  try {
    ensureHttps(idp.tokenEndpoint, 'tokenEndpoint');
  } catch (e) {
    return err(
      'invalid_idp_config',
      500,
      `tokenEndpoint not https: ${(e as Error).message}`,
      'RFC 8414 §3',
    );
  }

  // Step 4 — issue the IdP request. The AbortController signal MUST
  // cover both the header phase AND the body read; a slow-body IdP
  // that sends headers quickly but stalls the body would otherwise
  // hang the call indefinitely (the previous code cleared the timer
  // before res.json()).
  const timeoutMs = input.timeoutMs ?? DEFAULT_NETWORK_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetchImpl(idp.tokenEndpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    const reason = (e as Error).name === 'AbortError'
      ? `IdP token endpoint timed out after ${timeoutMs}ms`
      : `IdP token endpoint unreachable: ${(e as Error).message}`;
    return err('idp_unreachable', 504, reason, 'draft-04 §4.3.3');
  }

  // Step 5 — response parse. Keep the timer armed so a stalled body
  // read aborts at the same deadline as the header phase.
  let json: unknown;
  try {
    json = await res.json();
  } catch (e) {
    // Body-phase abort is the same FAILURE CLASS as header-phase
    // abort — transient upstream timeout, retry-eligible. Return the
    // same code/status (idp_unreachable / 504) so retry middleware
    // keyed on `code` cannot misclassify a stalled body as a
    // permanent parse failure.
    if ((e as Error).name === 'AbortError') {
      return err('idp_unreachable', 504, `IdP body stream timed out after ${timeoutMs}ms`, 'draft-04 §4.3.3');
    }
    return err(
      'invalid_idp_response',
      502,
      `IdP token endpoint returned non-JSON body: ${(e as Error).message}`,
      'draft-04 §4.3.4',
    );
  } finally {
    clearTimeout(timer);
  }
  if (typeof json !== 'object' || json === null) {
    return err('invalid_idp_response', 502, 'IdP response body is not a JSON object', 'draft-04 §4.3.4');
  }
  const obj = json as Record<string, unknown>;

  if (res.status !== 200) {
    // Error response per §4.3.4.3. Propagate the IdP's HTTP class so
    // the caller can implement retry/backoff on transient failures:
    //   401  → IdP rejected Chariot's client auth (do not retry; alert).
    //   429  → rate limited (retry with backoff).
    //   5xx  → transient (retry with backoff).
    //   4xx  → permanent (do not retry; bubble as invalid_grant).
    const errorCode = typeof obj.error === 'string' ? obj.error : 'invalid_grant';
    const description = typeof obj.error_description === 'string' ? obj.error_description : undefined;
    let mappedStatus: ClientError['status'];
    let mappedCode: ClientErrorCode;
    if (res.status === 401) {
      mappedStatus = 401;
      mappedCode = mapIdpErrorCode(errorCode);
    } else if (res.status === 403) {
      mappedStatus = 403;
      mappedCode = mapIdpErrorCode(errorCode);
    } else if (res.status === 429) {
      // Rate-limited — transient. Surface as 504 + idp_rate_limited
      // so retry middleware can back off (and not be conflated with
      // a permanent 4xx grant failure).
      mappedStatus = 504;
      mappedCode = 'idp_rate_limited';
    } else if (res.status >= 500) {
      mappedStatus = 502;
      mappedCode = mapIdpErrorCode(errorCode);
    } else {
      mappedStatus = 400;
      mappedCode = mapIdpErrorCode(errorCode);
    }
    return {
      ok: false,
      code: mappedCode,
      status: mappedStatus,
      reason: description ?? `IdP returned ${res.status} ${errorCode}`,
      specSection: 'draft-04 §4.3.4.3',
      idpError: { error: errorCode, ...(description !== undefined ? { error_description: description } : {}) },
    };
  }

  // Step 6 — §4.3.4 success-response field checks.
  if (obj.issued_token_type !== REQUESTED_TOKEN_TYPE_ID_JAG) {
    return err(
      'invalid_idp_response',
      502,
      `IdP returned issued_token_type "${String(obj.issued_token_type)}"; expected "${REQUESTED_TOKEN_TYPE_ID_JAG}"`,
      'draft-04 §4.3.4',
    );
  }
  if (typeof obj.access_token !== 'string' || obj.access_token.length === 0) {
    return err(
      'invalid_idp_response',
      502,
      'IdP response missing access_token',
      'draft-04 §4.3.4',
    );
  }
  // token_type = "N_A" per §4.3.4. If the IdP returns anything else we
  // surface a warning via spec_section in the audit, but do not reject
  // — interop with mildly non-conformant IdPs.
  // (Audit emission is the route layer's job.)

  // Step 7 — verify the ID-JAG cryptographically against the IdP's JWKS.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(obj.access_token);
  } catch (e) {
    return err(
      'invalid_idp_response',
      502,
      `returned access_token is not a parseable JWT: ${(e as Error).message}`,
      'draft-04 §4.3.4.1',
    );
  }
  if (header.typ !== ID_JAG_TYP) {
    return err(
      'invalid_id_jag_typ',
      502,
      `returned access_token typ is "${String(header.typ)}"; expected "${ID_JAG_TYP}"`,
      'draft-04 §4.3.4.1 / §3 / RFC 8725 §3.11',
    );
  }
  try {
    ensureHttps(idp.jwksUri, 'jwksUri');
  } catch (e) {
    return err(
      'invalid_idp_config',
      500,
      `jwksUri not https: ${(e as Error).message}`,
      'RFC 7517',
    );
  }
  let verifyResult;
  try {
    const jwks = getOrCreateJwksGetter(idp.jwksUri);
    // Pass audience to jose so aud is validated by the library as
    // part of the signature verify (jose >=5.x rejects on aud
    // mismatch when this option is present). The manual step-8 gate
    // below is defence-in-depth.
    verifyResult = await jwtVerify(obj.access_token, jwks, {
      issuer: idp.issuer,
      audience: input.audience,
      typ: ID_JAG_TYP,
    });
  } catch (e) {
    return err(
      'invalid_idp_response',
      502,
      `ID-JAG signature verification failed: ${(e as Error).message}`,
      'draft-04 §4.3.4.1',
    );
  }
  const payload = verifyResult.payload;

  // Step 8 — defence-in-depth audience binding check. The returned
  // ID-JAG's `aud` MUST equal (or contain) the requested audience.
  // RFC 7519 §4.1.3 permits a multi-element aud array; we accept the
  // request as long as input.audience appears in the array.
  const audClaim = payload.aud;
  const audMatches =
    audClaim === input.audience
    || (Array.isArray(audClaim) && audClaim.includes(input.audience));
  if (!audMatches) {
    return err(
      'audience_mismatch',
      502,
      `returned ID-JAG aud "${JSON.stringify(audClaim)}" does not contain requested audience "${input.audience}"`,
      'draft-04 §4.3.4.1 (aud)',
    );
  }

  // Step 9 — temporal: exp must be in the future at receipt.
  const nowSec = Math.floor(now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
    return err(
      'expired_assertion_at_receipt',
      502,
      `returned ID-JAG exp ${String(payload.exp)} is not after receipt time ${nowSec}`,
      'draft-04 §4.3.4.1 / RFC 7519 §4.1.4',
    );
  }

  // Step 10 — RFC 7800 cnf.jkt thumbprint surfacing (optional, used by
  // the MCP-dispatch caller if it wants to bind the downstream call to
  // a DPoP key).
  let jkt: string | undefined;
  if (typeof payload.cnf === 'object' && payload.cnf !== null) {
    const cnf = payload.cnf as Record<string, unknown>;
    if (typeof cnf.jkt === 'string' && cnf.jkt.length > 0) {
      jkt = cnf.jkt;
    }
  }

  // Step 11 — assemble ExchangeResult. Carry the IdP-RESOLVED audience
  // value (which may be the canonical URL form of a URN the client
  // requested, per §4.3 audience resolution). For multi-element arrays
  // we return the first element matching input.audience (already known
  // to be present from the step-8 audCheck).
  const expiresIn = payload.exp - nowSec;
  // Surface the IdP-resolved audience (§4.3 URN→URL resolution). Step
  // 8 guarantees input.audience is present, so we always return it
  // verbatim when the IdP returned an array. Removing the dead else
  // branch defends against a future maintainer relaxing step 8 and
  // having an unverified array-element silently propagate.
  const resolvedAudience: string =
    typeof audClaim === 'string'
      ? audClaim
      : input.audience;
  const result: ExchangeResult = {
    ok: true,
    idJag: obj.access_token,
    exp: payload.exp,
    audience: resolvedAudience,
    expiresIn,
  };
  if (typeof obj.scope === 'string') result.scope = obj.scope;
  if (Array.isArray(obj.authorization_details)) {
    result.authorizationDetails = obj.authorization_details as unknown[];
  }
  if (jkt !== undefined) result.jkt = jkt;
  return result;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function err(
  code: ClientErrorCode,
  status: 400 | 401 | 403 | 500 | 502 | 504,
  reason: string,
  specSection: string,
): ClientError {
  return { ok: false, code, status, reason, specSection };
}

function mapSubjectTokenType(t: SubjectTokenType): string | null {
  switch (t) {
    case 'id_token':
      return SUBJECT_TOKEN_TYPE_ID_TOKEN;
    case 'saml2':
      return SUBJECT_TOKEN_TYPE_SAML2;
    case 'refresh_token':
      return SUBJECT_TOKEN_TYPE_REFRESH;
    default: {
      const _exhaustive: never = t;
      void _exhaustive;
      return null;
    }
  }
}

function mapIdpErrorCode(code: string): ClientErrorCode {
  switch (code) {
    case 'invalid_grant':
    case 'invalid_target':
    case 'invalid_scope':
    case 'invalid_authorization_details':
    case 'unauthorized_client':
    case 'unsupported_grant_type':
    case 'access_denied':
    case 'invalid_request':
    case 'server_error':
      // RFC 6749 defines server_error as a distinct error code meaning
      // the IdP encountered an internal error. Preserve it through to
      // the caller so retry middleware and SIEM rules can distinguish
      // transient IdP faults from permanent grant failures.
      return code;
    default:
      return 'invalid_grant';
  }
}

/**
 * Build a private_key_jwt client_assertion per RFC 7523 §2.2. Five-minute
 * lifetime; aud = IdP's token endpoint URL; iss / sub = the registered
 * client_id; jti = random per call to deter replay.
 */
async function buildClientAssertion(
  idp: IdpClientView,
  idpIssuer: string,
  now: () => number,
): Promise<string> {
  if (!idp.clientPrivateKey) {
    throw new Error('clientPrivateKey not loaded');
  }
  const key = await importPKCS8(idp.clientPrivateKey, idp.clientAssertionSigningAlg);
  const iat = Math.floor(now() / 1000);
  const exp = iat + 300;
  // jti must be unguessable to prevent replay. createHash collapses
  // 128 bits of cryptographic entropy into a 256-bit hex digest so the
  // wire format matches RFC 7523's "string" but the source of entropy
  // is crypto.randomBytes — never Math.random (non-cryptographic).
  const jti = createHash('sha256').update(randomBytes(16)).digest('hex');
  return new SignJWT({
    iss: idp.clientId,
    sub: idp.clientId,
    aud: idp.tokenEndpoint,
    iat,
    exp,
    jti,
  })
    .setProtectedHeader({ alg: idp.clientAssertionSigningAlg, typ: 'JWT' })
    .sign(key);
}

// ── Admin CRUD service layer (admin-trust route consumes these) ──────────────

export interface RegisterIdpClientInput {
  tenantId: string;
  issuer: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  authMethod: IdJagIdpClientDocument['authMethod'];
  /** Plaintext at the route boundary; encrypted before persist. */
  clientSecret?: string;
  /** Plaintext PKCS8 PEM at the route boundary; encrypted before persist. */
  clientPrivateKey?: string;
  clientAssertionSigningAlg?: 'RS256' | 'ES256';
  allowedAudiences: string[];
  createdBy: string;
}

export interface RegisterIdpClientResult {
  document: IdJagIdpClientDocument;
  upserted: boolean;
}

/**
 * Register or rotate a Chariot-as-Client IdP entry. Secrets are
 * encrypted before persist using the existing crypto.ts envelope
 * (combined-blob "<encrypted>:<iv>" string, mirroring the IAM credential
 * vault pattern). PATCH semantics on the credential-bearing fields:
 * omitted secret on an update preserves the prior on-disk value so an
 * operator rotating tokenEndpoint/jwksUri does not have to re-send
 * the secret material.
 */
export async function registerIdpClient(
  input: RegisterIdpClientInput,
): Promise<RegisterIdpClientResult> {
  ensureHttps(input.tokenEndpoint, 'tokenEndpoint');
  ensureHttps(input.jwksUri, 'jwksUri');
  if (input.allowedAudiences.length === 0) {
    throw new Error('allowedAudiences must not be empty');
  }
  if (input.authMethod !== 'private_key_jwt' && input.clientSecret !== undefined && input.clientSecret.length === 0) {
    throw new Error('clientSecret must not be empty when provided');
  }
  if (input.authMethod === 'private_key_jwt' && input.clientPrivateKey !== undefined && input.clientPrivateKey.length === 0) {
    throw new Error('clientPrivateKey must not be empty when provided');
  }

  // Lazy import to avoid a circular import between this service (which
  // imports decryptFields from crypto) and any future module that
  // re-imports this surface.
  const { encryptFields } = await import('../crypto.js');

  const setFields: Partial<IdJagIdpClientDocument> = {
    tokenEndpoint: input.tokenEndpoint,
    jwksUri: input.jwksUri,
    clientId: input.clientId,
    authMethod: input.authMethod,
    clientAssertionSigningAlg: input.clientAssertionSigningAlg ?? 'RS256',
    allowedAudiences: input.allowedAudiences,
    active: true,
  };
  if (input.authMethod !== 'private_key_jwt' && input.clientSecret !== undefined) {
    const { encrypted, iv } = encryptFields({ value: input.clientSecret }, input.tenantId);
    setFields.clientSecretEncrypted = `${encrypted}:${iv}`;
  }
  if (input.authMethod === 'private_key_jwt' && input.clientPrivateKey !== undefined) {
    const { encrypted, iv } = encryptFields({ value: input.clientPrivateKey }, input.tenantId);
    setFields.clientPrivateKeyEncrypted = `${encrypted}:${iv}`;
  }

  // authMethod rotation: $unset the inverse credential field so an
  // orphaned encrypted secret blob from a previous method cannot be
  // resurrected by a later rotation. (Without this, an operator who
  // rotates basic → private_key_jwt then back to basic would re-read
  // the stale secret, silently using a credential the IdP may have
  // already revoked.)
  const unsetFields: Record<string, ''> = {};
  if (input.authMethod === 'private_key_jwt') {
    unsetFields.clientSecretEncrypted = '';
  } else {
    unsetFields.clientPrivateKeyEncrypted = '';
  }

  const col = await getCollection<IdJagIdpClientDocument>(COLLECTION);
  const now = new Date();
  const doc = await col.findOneAndUpdate(
    { tenantId: input.tenantId, issuer: input.issuer },
    {
      $set: setFields,
      $unset: unsetFields,
      $setOnInsert: {
        tenantId: input.tenantId,
        issuer: input.issuer,
        createdAt: now,
        createdBy: input.createdBy,
      },
    },
    { upsert: true, returnDocument: 'after' },
  );
  if (!doc) {
    throw new Error('IdP client upsert did not persist');
  }
  const upserted = doc.createdAt instanceof Date && doc.createdAt.getTime() === now.getTime();
  return { document: doc, upserted };
}

/** List all active IdP client registrations for the tenant. */
export async function listIdpClients(tenantId: string): Promise<IdJagIdpClientDocument[]> {
  const col = await getCollection<IdJagIdpClientDocument>(COLLECTION);
  return col
    .find(
      { tenantId, active: true },
      {
        projection: {
          // Never project the encrypted secret material out of the DB
          // boundary — the admin GET response must not echo them, and
          // exchangeForIdJag re-fetches the full document via the
          // separate registry port that performs decrypt.
          clientSecretEncrypted: 0,
          clientPrivateKeyEncrypted: 0,
          tenantId: 0,
        },
      },
    )
    .toArray();
}

/** Soft-revoke an IdP client (active=false). */
export async function revokeIdpClient(tenantId: string, issuer: string): Promise<boolean> {
  const col = await getCollection<IdJagIdpClientDocument>(COLLECTION);
  const res = await col.updateOne({ tenantId, issuer }, { $set: { active: false } });
  return res.modifiedCount === 1;
}

// ── Audit-event payload helpers (used by the caller, not emitted here) ───────

export function clientExchangedAuditDetail(
  input: ExchangeForIdJagInput,
  result: ExchangeResult,
): Record<string, unknown> {
  return {
    idp: input.idpIssuer,
    audience: result.audience,
    resource: input.resource,
    scope: input.scope,
    granted_scope: result.scope,
    granted_authorization_details: result.authorizationDetails,
    ttl: result.expiresIn,
    jkt: result.jkt,
  };
}

export function clientRejectedAuditDetail(
  input: ExchangeForIdJagInput,
  error: ClientError,
): Record<string, unknown> {
  return {
    idp: input.idpIssuer,
    audience: input.audience,
    resource: input.resource,
    scope: input.scope,
    error: error.code,
    error_description: error.reason,
    spec_section: error.specSection,
    idp_error: error.idpError,
  };
}
