/**
 * Enterprise IAM Types
 */

import type { ObjectId } from 'mongodb';
import type { Request } from 'express';
import type { PrincipalType } from '../engine/trust/types.js';

// Re-exported so IAM-layer consumers (middleware, session, mapping admin)
// share the single canonical PrincipalType definition with the engine
// trust layer instead of growing a parallel union that could drift.
export type { PrincipalType } from '../engine/trust/types.js';

// --- SAML / OIDC Configuration -----------------------------------------------

export interface SamlConfig {
  entryPoint: string;
  issuer: string;
  cert: string;
  callbackUrl: string;
  /** §10.2::2 pins signature verification to the secure values; the zod
   *  samlConfigSchema rejects weaker ones and saml.ts enforces them at use. */
  signatureAlgorithm?: 'sha256';
  digestAlgorithm?: 'sha256' | 'sha512';
  wantAssertionsSigned?: true;
  wantAuthnResponseSigned?: true;
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  /**
   * Plaintext client secret. Accepted as INPUT to updateSso, which encrypts it
   * at rest (§10.3::1) and persists only `clientSecretEncrypted`. May still be
   * present on legacy tenant documents written before at-rest encryption.
   */
  clientSecret?: string;
  /**
   * §10.3::1 — client secret encrypted at rest: an AES-256-GCM "encrypted:iv"
   * blob bound to the tenant. Written by updateSso; read via decryptFields.
   */
  clientSecretEncrypted?: string;
  redirectUri: string;
  scopes?: string[];
  /**
   * @deprecated Legacy singular form. Use `scopes` (plural) instead.
   * Preserved for backward compatibility with older tenant documents.
   */
  scope?: string | string[];
  responseType?: string;
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';
}

// --- Tenant ------------------------------------------------------------------

export interface TenantSettings {
  sessionTimeoutMinutes: number;
  maxConcurrentSessions: number;
  mfaRequired: boolean;
  ipAllowList: string[];
  allowedAdapterIds: string[];
  scimEnabled: boolean;
  /** §10.8::2: idle-session timeout in minutes (0 = disabled). */
  idleTimeoutMinutes?: number;
  /** §10.8::2: enable Just-In-Time user provisioning on first SSO login. */
  jitProvisioningEnabled?: boolean;
  /** §10.8::2: audit-log retention in days. */
  logRetentionDays?: number;
  /**
   * Name of the IdP group whose members are tenant administrators.
   * Defaults to "EpicAI-Admins" when unset (see
   * `tenantSettingsSchema.adminGroupName` in schemas.ts). A user whose
   * `groups` array contains this exact string is granted `isAdmin: true`
   * at session-issue time.
   */
  adminGroupName?: string;
  /**
   * Per-tenant Resource Authorization Server audience identifier. Used
   * by the ID-JAG issuer to validate bare-audience `resource` claims
   * against the AS this tenant represents. Overrides
   * CHARIOT_AS_AUDIENCE env when both are set; falls back to
   * CHARIOT_PUBLIC_BASE_URL when neither is set.
   */
  audience?: string;
  /**
   * When true, an ID-JAG assertion that omits the `groups` claim leaves
   * the persisted user.groups untouched (operator-pre-seeded membership
   * survives). Default false: omitted-groups means revocation — the
   * safe posture for IdPs that federate group membership. Enable only
   * for IdPs that do not federate groups at all (e.g. an XAA sandbox
   * IdP that never carries the claim).
   */
  idJagPreserveGroupsWhenAbsent?: boolean;
  /**
   * draft-04 §9.8.1.2.4: when true, this Resource AS tenant requires
   * sender-constrained (DPoP) access tokens — an ID-JAG grant that
   * presents neither a `cnf` claim nor a DPoP proof is rejected with
   * invalid_grant rather than issued as a Bearer token. Default
   * (undefined/false) permits Bearer issuance per the §9.8.1.2.4 MAY.
   */
  requireSenderConstrainedTokens?: boolean;
  saml?: SamlConfig;
  oidc?: OidcConfig;
}

export interface TenantDocument {
  _id: ObjectId;
  tenantId: string;
  name: string;
  domain: string;
  settings: TenantSettings;
  sso?: {
    type: 'saml' | 'oidc' | 'none';
    saml?: SamlConfig;
    oidc?: OidcConfig;
  };
  scimBearerTokenHash?: string;
  /**
   * §10.8::4 — per-tenant encryption key reference: a KMS key pointer (e.g.
   * `arn:aws:kms:...` / `projects/…/cryptoKeys/…`) or an env-key ID (e.g.
   * `env:CHARIOT_MASTER_KEY`) identifying the material this tenant's data at
   * rest is encrypted under. Recorded so key rotation can be tracked per
   * tenant. Set at creation; never null once written.
   */
  encryptionKeyRef: string;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// --- Enterprise User ---------------------------------------------------------

export interface EnterpriseUserDocument {
  _id: ObjectId;
  tenantId: string;
  externalId: string;
  scimId?: string;
  userName: string;
  displayName: string;
  givenName?: string;
  familyName?: string;
  email: string;
  active: boolean;
  groups: string[];
  metadata: Record<string, unknown>;
  /**
   * SAML NameID (sub_id) alias recorded from an ID-JAG assertion that
   * carried a `sub_id`. Used for draft-04 §3.1 sub<->sub_id binding-
   * integrity checks (a subject's sub_id must stay consistent across
   * assertions). Object form per RFC 9493.
   */
  idJagSubIdAlias?: Record<string, unknown>;
  /**
   * Canonical (sorted-key, JSON-stringified) form of `idJagSubIdAlias`,
   * written at every upsert that records a `sub_id`. Enables the draft-04
   * §3.1 *reverse* binding check ("is this sub_id already bound to a
   * DIFFERENT subject?") to be an exact, indexed equality match on the
   * WHOLE alias rather than a subset of fields — the subset form
   * false-rejected legitimate distinct subjects. Indexed by
   * { tenantId, idJagSubIdAliasCanon } (partial) in indexes.ts.
   */
  idJagSubIdAliasCanon?: string;
  /**
   * CHARIOT::§16.2 (CHARIOT-SPEC.md:1360, rulings item 91(2)) — "Slack
   * adapter connected and admin has a known Slack user ID -> Slack DM."
   * The admin's Slack workspace member ID (e.g. "U0123456"), set when the
   * tenant's connected Slack adapter resolves this user's identity.
   * Optional: absent means "no known Slack user ID" per the clause's own
   * gating language, not a false/negative value — the channel-resolution
   * step-1 check in src/observability/alertChannels.ts treats it as
   * ABSENT (falls through to step 2), never as an error.
   */
  slackUserId?: string;
  createdAt: Date;
  updatedAt: Date;
}

// --- Enterprise Group --------------------------------------------------------

export interface EnterpriseGroupDocument {
  _id: ObjectId;
  tenantId: string;
  externalId: string;
  displayName: string;
  members: string[];
  createdAt: Date;
  updatedAt: Date;
}

// --- Group -> Adapter Mapping ------------------------------------------------

export interface GroupAdapterMappingDocument {
  _id: ObjectId;
  tenantId: string;
  groupId: string;
  /**
   * All adapters this group is entitled to. One mapping document per
   * (tenantId, groupId) — enforced by the conflict check in the admin
   * route — so multi-adapter entitlements live as an array on a single
   * document rather than one document per adapter.
   */
  adapterIds: string[];
  allowedOperations: string[];
  maxQueriesPerHour: number;
  /**
   * Principal-kind scope for this mapping (gap #3 — Wiz 2 human/agent/
   * service partition). Recognized values: 'human' | 'agent' | 'service'
   * (matched case-insensitively, same as native/src/rbac.rs).
   *
   * Absent or empty (every mapping authored before this field existed):
   * the mapping applies to ANY principal kind — identical to pre-existing
   * behavior, so legacy documents grant exactly as before.
   *
   * Non-empty: the mapping is honored ONLY for sessions whose
   * `principalType` is in the list, and ONLY on the principal-aware
   * enforcement path (`adapterFilterMiddleware` for agent/service
   * sessions via `filterAdapterIdsForPrincipal`). Set `['human']` to mark
   * a grant human-only: an agent/service principal then cannot inherit
   * it. Typed `string[]` (not PrincipalType[]) because documents are
   * operator-authored — an unrecognized value must survive normalization
   * unchanged so the mapping fails CLOSED (matches no principal kind on
   * the principal-aware path) rather than silently widening to
   * "matches everyone".
   */
  principalScope?: string[];
  createdAt: Date;
  updatedAt: Date;
}

// --- Adapter Credential Vault ------------------------------------------------

export type CredentialType = 'oauth2' | 'api_key' | 'basic_auth';
export type CredentialStatus = 'active' | 'expired' | 'revoked';

export interface AdapterCredentialDocument {
  _id: ObjectId;
  tenantId: string;
  adapterId: string;
  credentialType: CredentialType;
  status: CredentialStatus;
  encrypted: string;
  iv: string;
  connectedBy: string;
  connectedAt: Date;
  expiresAt?: Date;
  revokedAt?: Date;
  revokedBy?: string;
  /** Owning user id (`user.sub`); NULL for org-wide shared credentials (§10.5::3). */
  userId?: string | null;
  /** True when this credential is org-wide shared (admin-connected). */
  shared?: boolean;
  /**
   * CHARIOT §10.5::1 — "Token refresh: background job every 5 minutes
   * finds tokens within 10 minutes of expiry, refreshes via vendor
   * refresh endpoint, updates `lastRefreshedAt`." Set by
   * `src/iam/services/credentials.ts`'s refresh job on a successful
   * vendor refresh; absent on a credential that has never been refreshed
   * (a freshly-connected `oauth2` row, or any `api_key`/`basic_auth` row,
   * which the refresh job never touches).
   */
  lastRefreshedAt?: Date;
  /**
   * CHARIOT §10.5 (rulings item 98(2)) — confidential-client OAuth
   * credentials for the vendor refresh call, belonging to the TENANT's
   * own vendor OAuth app registration (distinct from `apiKey`/`apiSecret`,
   * which are the per-user access/refresh TOKENS). Plain (not encrypted):
   * a client_id is the vendor's public application identifier — routinely
   * visible in browser redirect URLs and vendor developer-console UIs —
   * not a secret in the same sense as a refresh token.
   *
   * There is deliberately NO sibling `clientSecret` field on this
   * document. The ruling text ("clientSecret (encrypted with the same
   * vault path as the token fields)") is read as: encrypt it via the SAME
   * `encryptFields`/`decryptFields` call this document already makes for
   * `apiKey`/`apiSecret` — i.e. `clientSecret` rides as a THIRD key
   * inside the existing single `encrypted`/`iv` blob, decrypted alongside
   * the token fields in `src/iam/services/credentials.ts`'s
   * `decrypted.fields.clientSecret`. This was chosen over adding a
   * second `encrypted`/`iv` field pair (a `clientSecretEncrypted` +
   * `clientSecretIv` sibling) because it reuses this document's existing
   * one-blob shape exactly rather than introducing a second AES-256-GCM
   * ciphertext lifecycle (its own IV uniqueness, its own CAS write-back
   * path) for one additional secret. Never persisted in plaintext either
   * way.
   */
  clientId?: string;
}

// --- Audit Events ------------------------------------------------------------

export type AuditEventType =
  | 'login'
  | 'logout'
  | 'login_failed'
  | 'session_expired'
  | 'session_force_revoked'
  | 'user_created'
  | 'user_updated'
  | 'user_deactivated'
  | 'user_deleted'
  | 'tenant_suspended'
  | 'tenant_activated'
  | 'tenant_deleted'
  | 'group_created'
  | 'group_updated'
  | 'group_deleted'
  | 'adapter_query'
  | 'adapter_query_denied'
  | 'mapping_created'
  | 'mapping_updated'
  | 'mapping_deleted'
  | 'credential_connected'
  | 'credential_revoked'
  | 'settings_updated'
  | 'token_refreshed'
  | 'token_refresh_failed'
  | 'adapter_connected'
  | 'adapter_disconnected'
  // ID-JAG (Identity Assertion JWT Authorization Grant) audit events.
  // Emitted by the /enterprise/oauth/token surface (commit 4) and the
  // admin-trust CRUD endpoints (commit 5) per IETF draft-04.
  | 'id_jag_assertion_received'
  | 'id_jag_assertion_rejected'
  | 'id_jag_token_issued'
  | 'id_jag_token_revoked'
  | 'id_jag_trust_added'
  | 'id_jag_trust_revoked'
  // C4AMD §8::6 — operational-telemetry consent versions (grant/revoke).
  // Appended via src/iam/services/telemetry-consent.ts; never emitted
  // directly by adapter-authorization code (§8::4 independence).
  | 'telemetry_consent_changed';

export type AuditTargetType =
  | 'user'
  | 'group'
  | 'mapping'
  | 'credential'
  | 'adapter'
  | 'tenant';

export interface AuditEventDocument {
  _id: ObjectId;
  tenantId: string;
  eventType: AuditEventType;
  actorId: string;
  actorEmail: string;
  targetType: AuditTargetType;
  targetId: string;
  detail: Record<string, unknown>;
  ip: string;
  userAgent: string;
  timestamp: Date;
}

// --- Session -----------------------------------------------------------------

export interface EnterpriseSessionPayload {
  /** JWT subject — always equal to `userId`. Present on every token issued by `issueToken()`. */
  sub: string;
  tenantId: string;
  userId: string;
  email: string;
  displayName: string;
  groups: string[];
  /**
   * Tenant-wide adapter allowlist from `TenantSettings.allowedAdapterIds`.
   * Used as a ceiling / fallback when the user has no group→adapter mapping
   * in `iam_group_adapter_mappings`.
   */
  allowedAdapterIds: string[];
  /**
   * Adapters this user is entitled to via group→adapter mappings, resolved
   * from `iam_group_adapter_mappings` at session-issue time. This is the
   * authoritative list the `adapterFilterMiddleware` consults for RBAC.
   * Populated via `resolveAdapterIds(tenantId, user.groups)` at token
   * issuance — NEVER hardcode an empty array here.
   */
  adapterIds: string[];
  /**
   * True when the user's `groups` contain the tenant's `adminGroupName`
   * (default `EpicAI-Admins`). Read by `enterpriseAdminGuard()` to gate
   * admin-only routes. Derived at session-issue time; not refreshed
   * mid-session — admin revocation requires session revocation.
   */
  isAdmin: boolean;
  /**
   * Per-(adapterId, operation) RBAC grants resolved at session-issue time
   * from `iam_group_adapter_mappings.allowedOperations`. Map of adapterId
   * to the set of operations (tool names) the user is permitted to invoke
   * on that adapter.
   *
 * This field is the authoritative per-operation RBAC surface
   * checked by `chariot_call`. **Deny-by-default**:
   *   - missing field (legacy token) → deny
   *   - missing adapterId key → deny
   *   - empty operation array → deny
   *   - operation not in array → deny
   *
   * Wildcards: an operation array containing the literal `'*'` grants the
   * user every operation on that adapter. This is the spec-allowed escape
   * hatch for admins who want group-level "full access" without listing
   * every tool name on every mapping document.
   */
  allowedOperations?: Record<string, string[]>;
  /**
   * True when the user has completed TOTP verification for this session, or
   * when the tenant does not require MFA (mfaRequired: false).
   * False when a token was issued for a tenant that requires MFA but TOTP was
   * not yet completed — enterpriseAuthMiddleware rejects such tokens with 401.
   * Undefined on legacy tokens issued before this field was added; middleware
   * treats undefined as true for backward compatibility. Admins enabling
   * mfaRequired on an existing tenant should call revokeAllTenantSessions to
   * force re-authentication.
   */
  mfaVerified?: boolean;
  iat: number;
  /**
   * Custom millisecond-precision issuance timestamp. Used by verifyToken to
   * compare against the tenant epoch (also milliseconds) without losing
   * sub-second precision that JWT's standard iat claim drops.
   */
  iatMs?: number;
  exp: number;
  /**
   * RFC 9449 DPoP confirmation claim. When present, the token is
   * sender-constrained: every protected-resource call MUST use the
   * `Authorization: DPoP <token>` scheme and carry a fresh DPoP proof
   * whose JWK SHA-256 thumbprint matches `cnf.jkt` and whose `ath` claim
   * equals base64url(SHA-256(token)). Issued by ID-JAG token exchange
   * (id-jag-issuer) and enforced by enterpriseAuthMiddleware.
   */
  cnf?: { jkt: string };
  /**
   * Principal kind of the session holder (gap #3 — Wiz 2 human/agent/
   * service partition). Stamped at issuance by `issueToken()`:
   *
   *   - Interactive SSO paths (SAML callback, OIDC callback, session
   *     refresh) do NOT set it — a human completed the login ceremony.
   *   - ID-JAG token exchange (id-jag-issuer) stamps 'agent': the token
   *     is minted for a client WORKLOAD presenting an identity assertion
   *     on a user's behalf, not for the user at a keyboard.
   *
   * Absent (every legacy token and every interactive session) or any
   * unrecognized value → consumers MUST treat as 'human', which keeps
   * pre-partition behavior byte-identical. Only 'agent' / 'service'
   * trigger the stricter principal-scope filtering in
   * `adapterFilterMiddleware`, and only against mappings explicitly
   * marked with a non-matching `principalScope`.
   */
  principalType?: PrincipalType;
}

// --- SCIM Types (RFC 7644) ---------------------------------------------------

export interface ScimUser {
  schemas: string[];
  id?: string;
  externalId: string;
  userName: string;
  displayName: string;
  name?: {
    givenName: string;
    familyName: string;
  };
  emails: Array<{ value: string; primary: boolean }>;
  active: boolean;
  groups?: Array<{ value: string; display: string }>;
  meta?: {
    resourceType: string;
    created: string;
    lastModified: string;
    location: string;
  };
}

export interface ScimGroup {
  schemas: string[];
  id?: string;
  externalId: string;
  displayName: string;
  members: Array<{ value: string; display: string }>;
  meta?: {
    resourceType: string;
    created: string;
    lastModified: string;
    location: string;
  };
}

export interface ScimPatchOp {
  schemas: string[];
  Operations: Array<{
    op: 'add' | 'remove' | 'replace';
    path?: string;
    value?: unknown;
  }>;
}

export interface ScimError {
  schemas: string[];
  status: string;
  detail: string;
}

export interface ScimListResponse<T> {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: T[];
}

// --- MFA Secret --------------------------------------------------------------

export interface MfaSecretDocument {
  _id: ObjectId;
  tenantId: string;
  userId: string;      // string form of EnterpriseUserDocument._id
  encrypted: string;   // AES-256-GCM ciphertext, base64
  iv: string;          // AES-GCM IV, base64
  enrolledAt: Date;
}

// --- ID-JAG: Identity Assertion JWT Authorization Grant ----------------------
// Document shapes for the per-tenant trust registry, scope mapping registry,
// and OAuth client registry that back the ID-JAG token-exchange endpoint
// (IETF draft-ietf-oauth-identity-assertion-authz-grant-04). The runtime
// validator at services/id-jag-validator.ts consumes read-projections of
// these documents via injected ports.

/**
 * Per-tenant trusted IdP. The tenant admin registers each enterprise IdP
 * (Okta, Auth0, Entra ID, Ping, Keycloak, etc.) that is permitted to
 * issue ID-JAG assertions exchangeable at this Chariot tenant's
 * /enterprise/oauth/token endpoint.
 *
 * `jwksUri` MUST be an https:// URL — enforced at registration time, not
 * at validation time. `allowedAlgorithms` is the JWS algorithm allowlist
 * for assertions from this issuer; default `["RS256", "ES256"]`. `alg:
 * none` MUST NEVER appear in this array.
 */
export interface TrustedIssuerDocument {
  _id: ObjectId;
  tenantId: string;
  /** The `iss` claim Chariot expects on assertions from this IdP. */
  issuer: string;
  /** The IdP's JWKS URI. Must be https. */
  jwksUri: string;
  /**
   * The audience value this IdP issues on assertions targeting THIS
   * Chariot tenant. Chariot's audience-match check uses this verbatim.
   */
  audience: string;
  /** JWS algorithm allowlist for this issuer. */
  allowedAlgorithms: string[];
  /**
   * draft-04 §3.2.2 USE-gate: when true the Resource AS resolves
   * subjects via SAML NameID and §3.2.2 strict-reject rules fire for
   * absent/malformed/wrong-format sub_id. The §9.5 SAML-issuer
   * allowlist check is also use-gated on this flag (Phase 0.1 R3).
   * Default (absent/false) means the AS does not require SAML
   * NameID resolution under this trusted issuer.
   */
  requireSamlNameIdSubId?: boolean;
  /**
   * draft-04 §9.5 SAML-issuer trust association list: when
   * `requireSamlNameIdSubId === true`, the sub_id.issuer MUST be
   * in this allowlist. Absent/empty means no SAML issuers are
   * trusted under this ID-JAG issuer — any saml-nameid sub_id will
   * be rejected when sub_id is being used for resolution.
   */
  samlNameIdIssuers?: string[];
  /**
   * draft-04 §6.1 conditional USE-gate: when true, the Resource AS
   * requires this trusted issuer to include the `tenant` claim on
   * every assertion. When false/undefined, the IdP's §6.1 MUST does
   * not fire and an absent `tenant` claim is accepted.
   */
  requiresTenantContext?: boolean;
  /**
   * draft-04 §6.4 conditional allowlist: when present AND the
   * assertion carries `tenant`, the value MUST be in this list.
   * When undefined, the AS does not enforce a specific tenant set.
   */
  expectedTenants?: string[];
  /**
   * draft-04 §6.2 tenant-scoped client identifiers: when present AND
   * the assertion carries `tenant`, the assertion's `client_id` MUST
   * appear in the array indexed by that tenant. When undefined, the
   * AS treats client_ids as globally unique (the §6.2 alternative
   * model) and does not enforce a tenant-scoped binding.
   */
  tenantScopedClientIds?: Record<string, string[]>;
  active: boolean;
  createdAt: Date;
  createdBy: string;
}

/**
 * IdP Client Registration (Chariot acting as Client per draft-04 §2.1).
 *
 * Operator-registered record naming an enterprise IdP that Chariot will
 * call as a Client to obtain ID-JAGs via Token Exchange (§4.3) on behalf
 * of an authenticated user when an MCP-integration adapter declares
 * idJagAuth. Distinct from `TrustedIssuerDocument` (Resource AS side,
 * inbound assertion validation): the IdP Client Registration carries
 * Chariot's OWN client credentials AT the IdP, plus the audience
 * allowlist of downstream Resource ASes Chariot may request ID-JAGs for.
 */
export interface IdJagIdpClientDocument {
  _id: ObjectId;
  tenantId: string;
  /** IdP issuer URL. Matches the `iss` of any ID-JAG produced. */
  issuer: string;
  /** HTTPS URL of the IdP's token-exchange endpoint per §4.3. */
  tokenEndpoint: string;
  /** HTTPS URL of the IdP's JWKS used to verify returned ID-JAGs. */
  jwksUri: string;
  /** Chariot's registered client_id at this IdP. */
  clientId: string;
  /** Client-authentication method used at the IdP's token endpoint. */
  authMethod: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';
  /**
   * Encrypted client secret (basic / post) — written via the existing
   * credential-loader.ts encryption layer; NEVER plaintext at rest.
   * Present iff `authMethod !== 'private_key_jwt'`.
   */
  clientSecretEncrypted?: string;
  /**
   * Encrypted private key (PEM PKCS8) for private_key_jwt client auth
   * (RFC 7523 §2.2). NEVER plaintext at rest. Present iff
   * `authMethod === 'private_key_jwt'`.
   */
  clientPrivateKeyEncrypted?: string;
  /** JWS alg for the client_assertion; RS256 default. */
  clientAssertionSigningAlg?: 'RS256' | 'ES256';
  /**
   * Audience allowlist — the set of downstream Resource AS issuer URLs
   * Chariot may request an ID-JAG for under this IdP. Used to short-
   * circuit reject BEFORE calling the IdP for an out-of-scope audience.
   */
  allowedAudiences: string[];
  active: boolean;
  createdAt: Date;
  createdBy: string;
}

/**
 * Per-tenant claim→scope mapping. Translates an IdP claim value (typically
 * a group name in the `groups` claim) to the chariot adapter IDs and
 * per-adapter operations the resulting Chariot session is granted.
 */
export interface ScopeMappingDocument {
  _id: ObjectId;
  tenantId: string;
  /** The claim name to read from the assertion (default "groups"). */
  fromClaim: string;
  /** The claim value to match (e.g. an Okta group name). */
  fromValue: string;
  /** Adapter IDs this mapping unlocks. */
  toAdapterIds: string[];
  /** Per-adapter operations grant. */
  toAllowedOperations: Record<string, string[]>;
  active: boolean;
  createdAt: Date;
  createdBy: string;
}

/**
 * Per-tenant registered OAuth client. The client authenticates at the
 * token endpoint using one of three RFC 6749 section 2.3 methods. Every
 * client carries an `allowedIssuers[]` allowlist; the assertion's `iss`
 * MUST be in that list, AND the assertion's `client_id` claim MUST equal
 * the authenticated client_id (client-continuity rule).
 */
export type OAuthClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt';

export interface OAuthClientDocument {
  _id: ObjectId;
  tenantId: string;
  clientId: string;
  authMethod: OAuthClientAuthMethod;
  /**
   * SHA-256 hex of the client secret. Present only when authMethod is
   * `client_secret_basic` or `client_secret_post`. The plaintext secret
   * is returned to the operator exactly once at registration time and
   * never persisted.
   */
  clientSecretHash?: string;
  /** The client's JWKS URI (for `private_key_jwt`). Must be https. */
  jwksUri?: string;
  /** Trusted-issuer allowlist for this client. */
  allowedIssuers: string[];
  /** Optional CORS-preflight allowlist; wildcard is never allowed. */
  redirectUris?: string[];
  active: boolean;
  createdAt: Date;
  createdBy: string;
}

// --- Request Extensions ------------------------------------------------------

export interface EnterpriseAuthenticatedRequest extends Request {
  session: EnterpriseSessionPayload;
  tenantId: string;
}

export interface ScimAuthenticatedRequest extends Request {
  tenantId: string;
  scimToken: string;
}

// --- RBAC Helpers ------------------------------------------------------------

/**
 * Per-(adapterId, operation) RBAC enforcement. Deny-by-default.
 *
 * Returns true ONLY when the session payload carries an `allowedOperations`
 * record AND that record contains the adapterId AND the array for that
 * adapterId either contains the operation or contains the literal `'*'`
 * wildcard. Every other case — missing claim (legacy token), missing
 * adapterId key, empty array, operation not present — denies.
 *
 * Admins (`isAdmin: true`) are NOT auto-granted: per-operation policy is
 * separate from admin status. An admin must still have a group→adapter
 * mapping that explicitly grants the operation.
 *
 * Lives in this module (not middleware.ts) to keep the import side-effect
 * free for the chariot_call dispatcher, which would otherwise pull in
 * license / catalog / redis modules just to check a string membership.
 */
export function isOperationAllowed(
  payload: Pick<EnterpriseSessionPayload, 'allowedOperations'> | null | undefined,
  adapterId: string,
  operation: string,
): boolean {
  if (!payload) return false;
  const grants = payload.allowedOperations;
  if (!grants || typeof grants !== 'object') return false;
  const ops = grants[adapterId];
  if (!Array.isArray(ops) || ops.length === 0) return false;
  return ops.includes(operation) || ops.includes('*');
}
