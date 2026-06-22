/**
 * IAM — ID-JAG token issuer.
 *
 * Consumes a ValidatedAssertion (from id-jag-validator) plus tenant
 * context, RFC 8707 `resource` narrowing, RFC 9396 `authorization_details`
 * (RAR), and an optional RFC 9449 DPoP proof's JWK thumbprint. Resolves
 * the JIT-upserted iam_users record on the assertion's canonical subject
 * key, derives MFA from `amr` (fail-closed when absent), applies scope
 * mapping + resource narrowing + RAR narrowing, calls session.issueToken
 * with `provisioningSource: 'id_jag'` and the DPoP `cnfJkt` when present,
 * and returns the issued envelope. NO refresh token is issued.
 *
 * Subject keying per draft-04 §3.1/§3.2:
 *   - sub-only:                (tenantId, iss, sub)
 *   - sub-with-aud-tenant:     (tenantId, iss, aud_tenant, sub)
 *   - aud-sub:                 (tenantId, iss, aud_sub)
 * `sub_id` is recorded as a SAML NameID alias on the upserted user
 * record when present; never used as a standalone primary key.
 *
 * Caller responsibilities (commit 4 — routes/oauth.ts):
 *   - DPoP proof verification (RFC 9449 §4.3) and JWK thumbprint
 *     computation; pass the thumbprint as `dpopJkt` here.
 *   - Audit emission for `id_jag_token_issued` using the returned
 *     `auditDetail`. The issuer does not write the audit row directly
 *     so the route can correlate it with IP / user-agent / proof jti
 *     observed only at the request boundary.
 */

import type { Collection, Db, ObjectId } from 'mongodb';

import { getCollection } from '../db.js';
import { resolveAdapterIds, resolveAllowedOperations } from './mapping.js';
import { issueToken, TOKEN_EXPIRY_SECONDS } from './session.js';
import { oidcAssertedMfa } from './idp-mfa.js';
import { subjectKeyAsExternalId } from './subject-key.js';
import { withSubjectLock } from './subject-mutex.js';
import type {
  EnterpriseUserDocument,
  TenantDocument,
} from '../types.js';
import type {
  ValidatedAssertion,
} from './id-jag-validator.js';

// ── Input ────────────────────────────────────────────────────────────────────

export interface IssueInput {
  validated: ValidatedAssertion;
  tenant: TenantDocument;
  /**
   * RFC 8707 resource indicator (caller-supplied). May be a single
   * URI string or an array of URI strings. When present, the issuer
   * intersects mapped scopes with adapters resolvable from each URI;
   * empty intersection → IssueError invalid_target.
   */
  requestedResource?: string | string[];
  /**
   * RFC 9396 Rich Authorization Requests. Currently the issuer only
   * supports the chariot.adapter_scope.v1 type advertised in
   * `authorization_details_types_supported`; any other type → returns
   * IssueError invalid_authorization_details.
   */
  requestedAuthorizationDetails?: unknown[];
  /**
   * JWK SHA-256 thumbprint (base64url) of the client's DPoP proof key.
   * When present, the issued JWT carries cnf:{jkt}; token_type is
   * 'DPoP' instead of 'Bearer'. The route validates the proof itself
   * per RFC 9449 §4.3 before passing the thumbprint here.
   */
  dpopJkt?: string;
}

// ── Output ───────────────────────────────────────────────────────────────────

export type IssueErrorCode =
  | 'access_denied'
  | 'invalid_grant'
  | 'invalid_target'
  | 'invalid_authorization_details'
  | 'server_error';

export interface IssueError {
  ok: false;
  code: IssueErrorCode;
  status: 400 | 403 | 500;
  reason: string;
  /**
   * draft-04 §-number citation for the spec text this rejection
   * enforces. Plumbed into the route's id_jag_assertion_rejected
   * audit event so SOC 2 / SIEM consumers can cross-walk rejection
   * → spec text → eval gate.
   */
  specSection?: string;
}

export interface IssuedTokenEnvelope {
  ok: true;
  /** RFC 6749 §5.1 / draft-04 §4.4.2 response field. */
  access_token: string;
  /** 'DPoP' when dpopJkt was supplied; 'Bearer' otherwise (RFC 9449 §5). */
  token_type: 'Bearer' | 'DPoP';
  expires_in: number;
  /** Space-separated granted adapter ids. */
  scope?: string;
  /**
   * draft-04 §4.4.1 / RFC 8707 §2 granted resource indicator. String
   * when only a single URI was honoured; string[] when the assertion
   * carried an array.
   */
  resource?: string | string[];
  /** Echoed when caller passed requestedAuthorizationDetails. */
  authorization_details?: unknown[];
  /**
   * Audit detail the route MUST include in its id_jag_token_issued event.
   * Includes the assertion jti for cross-referencing, the assertion's
   * client_id, the granted scope shape, and the provisioning source.
   */
  auditDetail: Record<string, unknown>;
  /** The internal user record this token authenticates as. */
  user: EnterpriseUserDocument;
}

// ── Constants ────────────────────────────────────────────────────────────────

const RAR_TYPE_SUPPORTED = 'chariot.adapter_scope.v1';

/**
 * Canonical string form of a `sub_id` object: sorted top-level keys,
 * JSON-stringified, so two structurally-equal aliases compare equal
 * regardless of key order. Used for the draft-04 §3.1 forward
 * (same-subject) AND reverse (different-subject) binding checks, and
 * persisted as `idJagSubIdAliasCanon` so the reverse check is an exact,
 * indexed equality match on the WHOLE alias.
 */
export function canonicalizeSubId(v: unknown): string {
  // Recurse at every level so nested / aggregate sub_ids (RFC 9493) with
  // differing inner key order canonicalize identically. Flat formats
  // (saml.nameid, email, opaque) are unaffected — a primitive value returns
  // itself, so a one-level object produces the same shape as before.
  const canon = (x: unknown): unknown => {
    if (x === null || typeof x !== 'object') return x;
    // Type-tag containers so an object and an array can never canonicalize to
    // the same string (e.g. {a:1} and [["a",1]] would otherwise both render
    // as [["a",1]] → cross-shape false-accept in the reverse binding check).
    if (Array.isArray(x)) return ['a', x.map(canon)];
    const o = x as Record<string, unknown>;
    return ['o', Object.keys(o).sort().map((k) => [k, canon(o[k])])];
  };
  return JSON.stringify(canon(v));
}

// ── Issuer ───────────────────────────────────────────────────────────────────

export async function issueIdJagToken(input: IssueInput): Promise<IssuedTokenEnvelope | IssueError> {
  const { validated, tenant } = input;

  // Step 13 — resolve canonical subject identifier from the validated
  // subjectKey. JIT-upsert iam_users on the key. The `sub_id` claim, when
  // present, is recorded as a SAML NameID alias on the user record but
  // never used as a standalone primary key (draft-04 §3.1/§3.2).
  let user: EnterpriseUserDocument | null;
  try {
    const col = await getCollection<EnterpriseUserDocument>('iam_users');
    // §4.4.3 defense: serialize per-(tenantId, subjectKey) so two concurrent
    // same-bytes assertions queue rather than race the (tenantId, externalId)
    // upsert + (tenantId, email) unique index. Inner-defense layer; multi-
    // replica deployments need a Redis-backed sibling.
    // Tenant opt-in for IdPs that do not federate groups at all
    // (preserve persisted groups when assertion omits the claim).
    // Default false so omitted-groups means revocation everywhere else.
    // draft-04 §3.1 binding integrity: a `sub_id` MUST stay bound to one
    // End-User. The Resource AS enforces trust-on-first-use consistency on
    // the (subjectKey <-> sub_id) pairing it has already observed: the first
    // assertion pinning a subjectKey to a sub_id fixes that binding, and a
    // later assertion pairing the same subjectKey with a DIFFERENT sub_id —
    // or the same sub_id with a DIFFERENT subjectKey — is the §3.1 splice
    // attack and is rejected invalid_grant. The guard is `sub_id present`
    // ALONE: a sub_id-only assertion (no OIDC `sub`) still writes the alias
    // in the upsert below, so it MUST be subject to the same forward+reverse
    // checks or it could splice/poison a binding while bypassing them. Read
    // BEFORE the upsert overwrites idJagSubIdAlias.
    const preserveGroupsWhenAbsent = tenant.settings?.idJagPreserveGroupsWhenAbsent === true;
    // The §3.1 read-check AND the JIT upsert run together INSIDE
    // withSubjectLock so the FORWARD (same-subject) read→check→write is atomic
    // per subjectKey — closing the TOCTOU where two concurrent assertions for
    // the same subject with different sub_ids both passed the check before
    // either wrote. The cross-subject REVERSE race (different subjectKey →
    // different lock) is closed by the UNIQUE (tenantId, idJagSubIdAliasCanon)
    // index, whose E11000 is caught here and surfaced as the §3.1
    // reverse-binding violation. Reverse pre-check stays as a fast,
    // friendly-error path; the index is the race-safe backstop.
    type LockOutcome =
      | { user: EnterpriseUserDocument | null }
      | { binding: 'forward' | 'reverse' };
    const outcome: LockOutcome = await withSubjectLock(
      tenant.tenantId,
      validated.subjectKey,
      async (): Promise<LockOutcome> => {
        if (validated.subId !== undefined) {
          const consistencyExternalId = subjectKeyAsExternalId(validated.subjectKey);
          const newAlias = canonicalizeSubId(validated.subId);
          const byKey = await col.findOne({ tenantId: tenant.tenantId, externalId: consistencyExternalId });
          if (
            byKey?.idJagSubIdAlias !== undefined
            && canonicalizeSubId(byKey.idJagSubIdAlias) !== newAlias
          ) {
            return { binding: 'forward' };
          }
          const byAlias = await col.findOne({
            tenantId: tenant.tenantId,
            externalId: { $ne: consistencyExternalId },
            idJagSubIdAliasCanon: newAlias,
          });
          if (byAlias) {
            return { binding: 'reverse' };
          }
        }
        try {
          return { user: await upsertUserForSubject(col, validated, tenant.tenantId, { preserveGroupsWhenAbsent }) };
        } catch (e) {
          const code = (e as { code?: number }).code;
          const msg = e instanceof Error ? e.message : String(e);
          if ((code === 11000 || msg.includes('E11000')) && msg.includes('idJagSubIdAliasCanon')) {
            return { binding: 'reverse' };
          }
          throw e;
        }
      },
    );
    if ('binding' in outcome) {
      return err(
        'invalid_grant',
        400,
        outcome.binding === 'forward'
          ? 'sub_id does not match the sub_id previously bound to this subject (draft-04 §3.1)'
          : 'sub_id is already bound to a different subject (draft-04 §3.1)',
        'draft-04 §3.1',
      );
    }
    user = outcome.user;
  } catch (e) {
    return err('server_error', 500, `JIT user provisioning failed: ${(e as Error).message}`);
  }
  if (!user) {
    return err('server_error', 500, 'JIT user provisioning returned no document');
  }

  // SCIM deprovision recheck — even though the licenseGate middleware
  // gates this at route entry, recheck at issuance time so a deprovision
  // landing between route entry and JIT-upsert fail-closes here too.
  if (user.active === false) {
    return err('access_denied', 403, `user "${user.email}" is deprovisioned (active: false)`);
  }

  // Steps 14–15 — scope mapping (groups → adapter ids + per-adapter ops).
  // The mapping service consumes the same `groups` claim shape as SAML/OIDC.
  // The two resolvers query the same iam_group_adapter_mappings filter
  // independently; run them in parallel to halve the round-trip cost.
  const groups = user.groups ?? [];
  const [mappedAdapterIds, mappedAllowedOps] = await Promise.all([
    resolveAdapterIds(tenant.tenantId, groups),
    resolveAllowedOperations(tenant.tenantId, groups),
  ]);

  // draft-04 §4.4.1 — process ID-JAG-asserted `scope` claim. RFC 6749
  // §3.3 space-separated scope tokens. The granted scope is the
  // intersection of the IdP-asserted scopes and the local group→adapter
  // mapping; the IdP can only narrow, never escalate.
  let grantedAdapterIds = mappedAdapterIds;
  let grantedAllowedOps = mappedAllowedOps;
  if (validated.scope !== undefined) {
    const assertedScopes = validated.scope.split(/\s+/).filter(Boolean);
    const intersected = mappedAdapterIds.filter((id) => assertedScopes.includes(id));
    if (intersected.length === 0) {
      return err(
        'access_denied',
        403,
        `ID-JAG scope claim "${validated.scope}" does not intersect with mapped adapters per draft-04 §4.4.1`,
      );
    }
    grantedAdapterIds = intersected;
    grantedAllowedOps = Object.fromEntries(
      Object.entries(mappedAllowedOps).filter(([k]) => intersected.includes(k)),
    );
  }

  // draft-04 §4.4.1 — process ID-JAG-asserted `resource` claim
  // (RFC 8707 §2). Single URI or URI[]; granted resources are the
  // intersection of asserted URIs with the adapters resolvable from
  // each URI. Independent of the form-body resource parameter; both
  // may narrow when present. The granted (echoed) resource value is
  // the asserted resource(s) that survived the intersection.
  let grantedResource: string | string[] | undefined;
  if (validated.resource !== undefined) {
    const assertedResList = Array.isArray(validated.resource) ? validated.resource : [validated.resource];
    // RFC 8707 §2 bare-audience case: when the asserted resource URI has
    // no path (e.g. `https://agents.epic-ai.io` or `.../`), it identifies
    // the whole audience rather than narrowing to one /adapters/<id>.
    // A bare audience is accepted as no-op narrowing ONLY when it matches
    // the configured AS audience identifier. An asserted bare URI that
    // does not equal the AS audience cannot stand in for narrowing — it
    // would otherwise grant the full group-mapped adapter set against a
    // resource the AS does not represent.
    // Expected AS audience resolution order:
    //   1. CHARIOT_AS_AUDIENCE env (explicit override, multi-tenant case)
    //   2. tenant.settings.audience (per-tenant override)
    //   3. CHARIOT_PUBLIC_BASE_URL env (the same value oauth.ts uses for
    //      the RFC 8414 discovery doc's `issuer`) — backward-compat
    //      fallback so existing deployments that don't explicitly set
    //      CHARIOT_AS_AUDIENCE still validate bare-audience claims
    //      against the canonical AS identifier.
    const expectedAudienceRaw =
      process.env.CHARIOT_AS_AUDIENCE
        ?? tenant.settings?.audience
        ?? process.env.CHARIOT_PUBLIC_BASE_URL
        ?? '';
    // Parse each asserted/configured URI at most once per issuance.
    // isBareAudience and normalizeAud both run over the same resource
    // list (RFC 8707 allows an unbounded resource[] array in the signed
    // assertion); without this memo each URI is re-parsed by new URL()
    // on every predicate. Request-scoped, bounded by distinct-URI count.
    const urlCache = new Map<string, URL | null>();
    const parseUrl = (s: string): URL | null => {
      const cached = urlCache.get(s);
      if (cached !== undefined) return cached;
      let u: URL | null;
      try { u = new URL(s); } catch { u = null; }
      urlCache.set(s, u);
      return u;
    };
    const normalizeAud = (s: string): string => {
      const u = parseUrl(s);
      // Unparseable — return '' so matchesAsAudience returns false.
      if (!u) return '';
      // For http(s) URIs: scheme + case-insensitive host + byte-exact
      // pathname. Origin-only normalization would collapse
      // `https://as.example.com/tenant-a` and `https://as.example.com`
      // to the same value, allowing a bare asserted URI to match a
      // tenant-scoped configured audience — over-matching the
      // intended RFC 8707 §2 narrowing. The asserted-URI side is
      // already constrained by isBareAudience to empty path or '/',
      // so a configured audience with a path can only match an
      // asserted URI whose path is byte-identical (`/` matches `/`,
      // tenant-scoped path matches nothing on the bare-audience
      // route).
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}`;
      }
      // Non-http URIs (urn:, api://, ...): byte-exact href. The
      // asserted-URI side is constrained to http(s) by isBareAudience,
      // so non-http expectedAudience never matches a bare-audience
      // claim — fail-closed by design.
      return u.href;
    };
    const expectedAudience = expectedAudienceRaw ? normalizeAud(expectedAudienceRaw) : '';
    const isBareAudience = (uri: string): boolean => {
      const u = parseUrl(uri);
      if (!u) return false;
      // Bare audience MUST be:
      //   - http(s) only (RFC 8414 §2 / RFC 8707 §2 — non-http schemes
      //     like `javascript:`, `urn:`, `ftp:` are not legitimate AS
      //     identifiers and would be echoed verbatim into the issued
      //     token's `resource` claim + audit log).
      //   - empty userinfo (no `user:pass@` — embedded credentials
      //     survive into the token's resource claim and persist in the
      //     audit row even though normalizeAud strips them for the
      //     equality check).
      //   - empty path (or '/'), empty query, empty fragment — any
      //     non-empty value smuggles attacker-controlled state.
      return (u.protocol === 'https:' || u.protocol === 'http:')
        && u.username === ''
        && u.password === ''
        && (u.pathname === '' || u.pathname === '/')
        && u.search === ''
        && u.hash === '';
    };
    const matchesAsAudience = (uri: string): boolean => {
      if (!expectedAudience) return false;
      return normalizeAud(uri) === expectedAudience;
    };
    const allBare = assertedResList.every(isBareAudience);
    if (allBare) {
      // Reject when no AS audience is configured OR any bare URI does
      // not match it. Closes the privilege-widening hole where a caller
      // could send any bare URI and skip all narrowing.
      if (!expectedAudience || !assertedResList.every(matchesAsAudience)) {
        return err(
          'invalid_target',
          400,
          'bare-audience ID-JAG resource claim does not match the configured Resource AS audience',
        );
      }
      grantedResource = Array.isArray(validated.resource) ? assertedResList : assertedResList[0];
    } else {
      const matchedSet = new Set<string>();
      const survivors: string[] = [];
      for (const uri of assertedResList) {
        if (isBareAudience(uri)) {
          // Bare URI in a mixed list still must match the AS audience.
          if (!matchesAsAudience(uri)) {
            return err(
              'invalid_target',
              400,
              `bare-audience ID-JAG resource claim "${uri}" does not match the configured Resource AS audience`,
            );
          }
          survivors.push(uri);
          continue;
        }
        const ids = adaptersForResource(uri, grantedAdapterIds);
        if (ids.length > 0) survivors.push(uri);
        for (const id of ids) matchedSet.add(id);
      }
      if (matchedSet.size === 0) {
        return err(
          'invalid_target',
          400,
          `ID-JAG resource claim does not resolve to any mapped adapter (asserted: ${assertedResList.join(', ')})`,
        );
      }
      grantedAdapterIds = grantedAdapterIds.filter((id) => matchedSet.has(id));
      grantedAllowedOps = Object.fromEntries(
        Object.entries(grantedAllowedOps).filter(([k]) => matchedSet.has(k)),
      );
      grantedResource = Array.isArray(validated.resource) ? survivors : survivors[0];
    }
  }

  // Step 16 — RFC 8707 form-body resource narrowing. Independent of the
  // ID-JAG resource claim; can further narrow. Accepts a single URI
  // or an array of URIs (per RFC 8707 §2). The form-body resource MUST
  // resolve to at least one of the currently-granted adapter ids.
  if (input.requestedResource !== undefined) {
    const formResList = Array.isArray(input.requestedResource)
      ? input.requestedResource
      : [input.requestedResource];
    const matchedSet = new Set<string>();
    const survivors: string[] = [];
    for (const uri of formResList) {
      const ids = adaptersForResource(uri, grantedAdapterIds);
      if (ids.length > 0) survivors.push(uri);
      for (const id of ids) matchedSet.add(id);
    }
    if (matchedSet.size === 0) {
      return err(
        'invalid_target',
        400,
        `form-body resource ${JSON.stringify(formResList)} does not resolve to any mapped adapter`,
      );
    }
    grantedAdapterIds = grantedAdapterIds.filter((id) => matchedSet.has(id));
    grantedAllowedOps = Object.fromEntries(
      Object.entries(grantedAllowedOps).filter(([k]) => matchedSet.has(k)),
    );
    grantedResource = Array.isArray(input.requestedResource) ? survivors : survivors[0];
  }

  // Step 17 — RFC 9396 RAR narrowing. We only honour the single advertised
  // type today; unknown types fail closed. The `chariot.adapter_scope.v1`
  // type permits an optional `adapter_ids: string[]` sub-claim that
  // FURTHER NARROWS the granted scope; the issuer intersects it against
  // `grantedAdapterIds` so a client cannot use RAR to escalate privilege
  // beyond what the group→adapter mapping already permits. Any
  // adapter_id in the RAR sub-claim that is not in `grantedAdapterIds`
  // is rejected (NOT silently dropped) so the client gets a clear error.
  //
  // draft-04 §4.4.1 — process ID-JAG-asserted `authorization_details`
  // claim AND form-body authorization_details together with spec-intent
  // "IdP narrows; form-body further narrows" semantics. Concatenation
  // of the two arrays would WIDEN the grant (each entry echoed
  // independently), so we INTERSECT instead:
  //
  //   - Only IdP claim present     → use it (after per-entry validation).
  //   - Only form-body present     → use it (after per-entry validation).
  //   - Both present               → for each (type) bucket, intersect
  //                                  the adapter_ids set (form-body
  //                                  further narrows IdP claim);
  //                                  reject empty intersection.
  //
  // Each entry is then validated against grantedAdapterIds to guard
  // against escalation outside the group→adapter mapping.
  let grantedAuthorizationDetails: unknown[] | undefined;
  const idpClaim = validated.authorizationDetails;
  const formBody = input.requestedAuthorizationDetails;
  let combined: unknown[] | undefined;
  if (idpClaim !== undefined && formBody !== undefined) {
    // §4.4.1 intersect: for each type in form-body, find the matching
    // IdP-claim entry; intersect their adapter_ids sets. Form-body
    // types not present in IdP claim are rejected (operator-side
    // policy MUST authorise the IdP-claim shape first).
    if (!Array.isArray(idpClaim) || !Array.isArray(formBody)) {
      return err('invalid_authorization_details', 400, 'authorization_details must be a JSON array');
    }
    const idpByType = new Map<string, Record<string, unknown>>();
    for (const e of idpClaim) {
      if (typeof e !== 'object' || e === null) {
        return err('invalid_authorization_details', 400, 'authorization_details entries must be objects');
      }
      const obj = e as Record<string, unknown>;
      const t = obj.type;
      if (typeof t !== 'string') {
        return err('invalid_authorization_details', 400, 'authorization_details entry missing required "type" string');
      }
      if (idpByType.has(t)) {
        // RFC 9396 §2.1 allows multiple entries per type, but intersecting
        // them against a single form-body counterpart is ambiguous (which
        // IdP entry narrows?). Reject so the IdP collapses its own entries
        // before issuance; silent last-write-wins would either under-grant
        // (intersecting against the second restrictive entry) or be exploited
        // (a permissive entry following a restrictive one overwriting it).
        return err(
          'invalid_authorization_details',
          400,
          `IdP-asserted authorization_details contains duplicate type "${t}"; merge before issuance per draft-04 §4.4.1`,
        );
      }
      idpByType.set(t, obj);
    }
    const intersected: unknown[] = [];
    for (const e of formBody) {
      if (typeof e !== 'object' || e === null) {
        return err('invalid_authorization_details', 400, 'authorization_details entries must be objects');
      }
      const fb = e as Record<string, unknown>;
      const t = fb.type;
      if (typeof t !== 'string') {
        return err('invalid_authorization_details', 400, 'authorization_details entry missing required "type" string');
      }
      const idpEntry = idpByType.get(t);
      if (idpEntry === undefined) {
        return err(
          'invalid_authorization_details',
          400,
          `authorization_details type "${t}" is in the form-body request but not asserted by the IdP — form-body MUST be a subset of the IdP claim per draft-04 §4.4.1`,
        );
      }
      const merged: Record<string, unknown> = { ...idpEntry, ...fb };
      if (Array.isArray(idpEntry.adapter_ids) && Array.isArray(fb.adapter_ids)) {
        const ids = (fb.adapter_ids as unknown[]).filter((id) => (idpEntry.adapter_ids as unknown[]).includes(id));
        if (ids.length === 0) {
          return err(
            'invalid_authorization_details',
            400,
            `authorization_details intersection empty for type "${t}" between IdP claim and form-body`,
          );
        }
        merged.adapter_ids = ids;
      } else if (Array.isArray(idpEntry.adapter_ids) && fb.adapter_ids === undefined) {
        merged.adapter_ids = idpEntry.adapter_ids;
      }
      intersected.push(merged);
    }
    combined = intersected;
  } else {
    combined = idpClaim ?? formBody;
  }
  if (combined !== undefined) {
    const details = combined;
    if (!Array.isArray(details) || details.length === 0) {
      return err('invalid_authorization_details', 400, 'authorization_details must be a non-empty array');
    }
    const echoedDetails: unknown[] = [];
    // Per-type duplicate guard fires regardless of which source produced
    // the array (IdP-only, form-body-only, or pre-intersected). RFC 9396
    // §2.1 allows multiple per-type entries, but this AS cannot
    // unambiguously process two conflicting same-type entries; reject
    // upstream rather than silently flattening or echoing both.
    const seenTypes = new Set<string>();
    for (const entry of details) {
      if (typeof entry !== 'object' || entry === null) {
        return err('invalid_authorization_details', 400, 'authorization_details entries must be objects');
      }
      const obj = entry as Record<string, unknown>;
      if (typeof obj.type === 'string') {
        if (seenTypes.has(obj.type)) {
          return err(
            'invalid_authorization_details',
            400,
            `duplicate authorization_details type "${obj.type}" — collapse before issuance per draft-04 §4.4.1`,
          );
        }
        seenTypes.add(obj.type);
      }
      if (obj.type !== RAR_TYPE_SUPPORTED) {
        return err(
          'invalid_authorization_details',
          400,
          `unsupported authorization_details type "${String(obj.type)}"; only "${RAR_TYPE_SUPPORTED}" is supported`,
        );
      }
      // adapter_ids sub-claim: optional; when present MUST be a string[]
      // and every member MUST be in grantedAdapterIds.
      if (obj.adapter_ids !== undefined) {
        if (!Array.isArray(obj.adapter_ids) || obj.adapter_ids.some((v) => typeof v !== 'string')) {
          return err('invalid_authorization_details', 400, 'authorization_details.adapter_ids must be string[]');
        }
        const requested = obj.adapter_ids as string[];
        const escalation = requested.filter((id) => !grantedAdapterIds.includes(id));
        if (escalation.length > 0) {
          return err(
            'invalid_authorization_details',
            400,
            `authorization_details.adapter_ids requests adapters outside mapped scope: ${escalation.join(', ')}`,
          );
        }
        // Echo the entry with adapter_ids intersected (defensive — already
        // a subset, but explicit so a downstream consumer sees the granted
        // shape verbatim).
        echoedDetails.push({ ...obj, adapter_ids: requested });
      } else {
        echoedDetails.push(obj);
      }
    }
    grantedAuthorizationDetails = echoedDetails;
  }

  // MFA derivation from the assertion's `amr` claim. When `amr` is absent
  // the issued token is mfaVerified:false and the tenant's MFA-step-up
  // flow is required on first protected-resource call. Fail-closed: we
  // do NOT infer MFA from issuer registration alone.
  const idpMfa = oidcAssertedMfa(validated.amr);
  const mfaVerified = idpMfa.asserted;

  // Step 19 — issue Chariot session token. provisioningSource is audit
  // metadata; cnfJkt binds the JWT to the client's DPoP key per RFC 9449.
  // The resolver overrides deliver `grantedAdapterIds` / `grantedAllowedOps`
  // directly into the JWT-stamping path; no need to mutate `user`.
  const accessToken = await issueToken(user, tenant, {
    mfaVerified,
    provisioningSource: 'id_jag',
    cnfJkt: input.dpopJkt,
    resolveAdapterIds: async () => grantedAdapterIds,
    resolveAllowedOperations: async () => grantedAllowedOps,
  });

  return {
    ok: true,
    access_token: accessToken,
    token_type: input.dpopJkt ? 'DPoP' : 'Bearer',
    expires_in: TOKEN_EXPIRY_SECONDS,
    ...(grantedAdapterIds.length > 0 ? { scope: grantedAdapterIds.join(' ') } : {}),
    ...(grantedResource !== undefined ? { resource: grantedResource } : {}),
    ...(grantedAuthorizationDetails !== undefined ? { authorization_details: grantedAuthorizationDetails } : {}),
    auditDetail: {
      iss: validated.iss,
      assertion_jti: validated.jti,
      assertion_client_id: validated.clientId,
      sub: validated.sub,
      sub_id: validated.subId,
      tenant: validated.tenant,
      aud_tenant: validated.audTenant,
      aud_sub: validated.audSub,
      subject_key_kind: validated.subjectKey.kind,
      granted_scope: grantedAdapterIds,
      granted_resource: grantedResource,
      granted_authorization_details: grantedAuthorizationDetails,
      provisioning_source: 'id_jag',
      mfa_asserted_by_idp: idpMfa.asserted,
      amr_present: validated.amr !== undefined && validated.amr.length > 0,
      dpop_bound: input.dpopJkt !== undefined,
    },
    user,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Default spec-section citation by issuer reject code (Phase 3.1 / T23).
 * When a `specSection` arg is passed it wins; otherwise the code-default
 * below populates `IssueError.specSection` so the route's
 * id_jag_assertion_rejected audit event always carries a §-number for
 * SOC 2 / SIEM cross-walk and the conformance eval traceability matrix.
 */
const SPEC_SECTION_BY_ISSUER_CODE: Partial<Record<IssueErrorCode, string>> = {
  access_denied: 'draft-04 §4.4.1',
  invalid_target: 'RFC 8707 §2 / draft-04 §4.4.1',
  invalid_authorization_details: 'RFC 9396 §2 / draft-04 §4.4.1',
};

function err(code: IssueErrorCode, status: 400 | 403 | 500, reason: string, specSection?: string): IssueError {
  const section = specSection ?? SPEC_SECTION_BY_ISSUER_CODE[code];
  return { ok: false, code, status, reason, ...(section !== undefined ? { specSection: section } : {}) };
}

/**
 * JIT-upsert the iam_users record for the assertion's canonical subject
 * key. Three cases handled explicitly:
 *
 *   1. A row already exists with this (tenantId, externalId) → in-place
 *      $set update of displayName/email/groups + sub_id alias. Fast path
 *      for repeat issuance.
 *
 *   2. No externalId match BUT a SCIM-provisioned row exists at
 *      (tenantId, email) → ADOPT the SCIM row by attaching externalId +
 *      idJagSubjectKey + idJagSubIdAlias to it. The same physical
 *      person logging in via SCIM and via ID-JAG resolves to one
 *      iam_users record. This is the cross-protocol identity-merge that
 *      avoids the unique (tenantId, email) index E11000 collision.
 *
 *   3. No externalId match AND no SCIM row → insertOne a fresh ID-JAG-
 *      provisioned row carrying every required EnterpriseUserDocument
 *      field (active:true, metadata:{}, etc.).
 *
 * `active` is never written by $set on existing rows — a SCIM deprovision
 * (active:false) landing between route entry and this upsert is therefore
 * preserved, and the caller's post-upsert active-check fail-closes.
 */
/**
 * Options controlling JIT-upsert behavior. `preserveGroupsWhenAbsent`
 * MUST default to false: omitted-groups MUST be treated as "the IdP
 * federates zero groups for this user right now" — i.e. revocation —
 * unless the operator has explicitly opted into preservation for IdPs
 * that do not federate group membership at all. The preservation path
 * is a privilege-retention hazard against IdPs that omit-instead-of-
 * empty-array on revocation; default-false is the safe posture.
 */
export interface UpsertOptions {
  preserveGroupsWhenAbsent?: boolean;
}

export async function upsertUserForSubject(
  col: Collection<EnterpriseUserDocument>,
  validated: ValidatedAssertion,
  tenantId: string,
  opts: UpsertOptions = {},
): Promise<EnterpriseUserDocument | null> {
  const now = new Date();
  const externalId = subjectKeyAsExternalId(validated.subjectKey);
  const preserveGroupsWhenAbsent = opts.preserveGroupsWhenAbsent === true;

  // Email is best-effort from the assertion; some IdPs omit it.
  // When absent, synthesize a placeholder using the .invalid TLD reserved
  // by RFC 2606 — guarantees the synthesized address never collides with
  // a real SCIM-provisioned email at the unique (tenantId, email) index.
  const claims = validated.payload as Record<string, unknown>;
  const email = typeof claims.email === 'string'
    ? claims.email
    : `${externalId}@id-jag.chariot.invalid`;
  const displayName = typeof claims.name === 'string' ? claims.name : email;
  // Groups handling — privilege-retention defense.
  //
  // - Assertion carries `groups`: $set.groups to the asserted array on
  //   every upsert (insert and update). Revocation propagates.
  // - Assertion omits `groups` AND tenant did NOT opt into preservation:
  //   treat omitted as revocation; $set.groups = []. Default-safe path.
  // - Assertion omits `groups` AND tenant opted into preservation: leave
  //   the persisted groups untouched, so operator-pre-seeded membership
  //   survives. Only enable for IdPs that do not federate groups at all
  //   (e.g. an XAA sandbox IdP with no groups claim) — opting in for an
  //   IdP that federates inconsistently re-opens the privilege-retention
  //   hazard.
  const assertedGroupsRaw = Array.isArray(claims.groups)
    ? (claims.groups as unknown[]).filter((v): v is string => typeof v === 'string')
    : null;
  const effectiveGroups: string[] | null = assertedGroupsRaw !== null
    ? assertedGroupsRaw
    : (preserveGroupsWhenAbsent ? null : []);
  const givenName = typeof claims.given_name === 'string' ? claims.given_name : '';
  const familyName = typeof claims.family_name === 'string' ? claims.family_name : '';

  const $set: Record<string, unknown> = {
    displayName,
    email,
    updatedAt: now,
  };
  if (effectiveGroups !== null) {
    $set.groups = effectiveGroups;
  }
  if (validated.subId !== undefined) {
    $set.idJagSubIdAlias = validated.subId;
    // Canonical form for the indexed reverse §3.1 binding lookup. Written
    // on every insert/update via the $set spread in all three upsert
    // branches below.
    $set.idJagSubIdAliasCanon = canonicalizeSubId(validated.subId);
  }

  // Case 1: existing ID-JAG row.
  const existingByExternal = await col.findOne({ tenantId, externalId });
  if (existingByExternal) {
    // §4.4.3 re-submission idempotency: when the existing row carries a
    // synthetic .invalid email (the case-3 collision-avoidance path
    // wrote it), do NOT overwrite back to the assertion's real email —
    // that would hit the (tenantId, email) unique index because the
    // original Real-email row still exists. Preserve the row's stored
    // email; refresh metadata.idJagAssertedEmail so forensic search by
    // the CURRENT IdP-asserted email finds the row even after the IdP
    // changes the user's email.
    const isSyntheticEmail = existingByExternal.email.endsWith('@id-jag.chariot.invalid');
    const updateSet: Record<string, unknown> = { ...$set };
    if (isSyntheticEmail) {
      delete updateSet.email;
      // Refresh the forensic alias only when the IdP-asserted email
      // changed since the row was created.
      if (existingByExternal.metadata?.idJagAssertedEmail !== email) {
        updateSet['metadata.idJagAssertedEmail'] = email;
      }
    }
    await col.updateOne({ _id: existingByExternal._id }, { $set: updateSet });
    return col.findOne({ _id: existingByExternal._id });
  }

  // Case 2: existing SCIM (or other-protocol) row at same email — adopt it.
  // The adoption $set additionally writes externalId and idJagSubjectKey
  // so subsequent ID-JAG issuance for this person takes the case-1 fast
  // path. We do NOT overwrite active here.
  //
  // Eval gate #16 (multi-tenant keying) 2026-05-25: skip adoption when
  // the email-matched row ALREADY carries an idJagSubjectKey claim from
  // a prior ID-JAG flow. The adoption branch writes the key at TOP
  // LEVEL (`$set.idJagSubjectKey` below), while fresh inserts (case 3)
  // store it under `metadata.idJagSubjectKey`. The guard MUST check
  // BOTH locations or an already-adopted row gets re-adopted by a
  // different subject key — and the production unique (tenantId,email)
  // index would then reject the case-3 fallback insert. Two distinct
  // ID-JAG subjects sharing an email (multi-tenant alice across
  // aud_tenant=team-1 vs aud_tenant=team-2 per draft-04 §3.2) must
  // resolve to distinct iam_users rows; this guard preserves that.
  const existingByEmail = await col.findOne({ tenantId, email });
  const alreadyClaimedByIdJag = !!(
    existingByEmail
    && ((existingByEmail as Record<string, unknown>).idJagSubjectKey
        || existingByEmail.metadata?.idJagSubjectKey)
  );
  if (existingByEmail && !alreadyClaimedByIdJag) {
    await col.updateOne(
      { _id: existingByEmail._id },
      {
        $set: {
          ...$set,
          externalId,
          idJagSubjectKey: validated.subjectKey,
        },
      },
    );
    return col.findOne({ _id: existingByEmail._id });
  }

  // Case 3: fresh ID-JAG provisioning — insert a full EnterpriseUserDocument
  // satisfying every required field of the type contract.
  //
  // Email-collision avoidance: when case-2 detected that an existing
  // row at the assertion's `email` is ALREADY ID-JAG-claimed by a
  // different subject key (e.g. multi-tenant alice across aud_tenant=
  // team-1 vs aud_tenant=team-2 sharing alice@example.test), the
  // unique (tenantId, email) index in iam_users would reject this
  // insert. Synthesize a unique per-(externalId) email in that case.
  const freshEmail = alreadyClaimedByIdJag ? `${externalId}@id-jag.chariot.invalid` : email;

  // §4.4.3 re-submission idempotency: the read-then-insert sequence
  // above is racy under same-bytes re-submission (the validator's
  // reserveOrMatch 'match' path lets the second call through to the
  // issuer, where it lands here a second time). Use an atomic
  // findOneAndUpdate keyed on (tenantId, externalId) so the second
  // call hits the matched row instead of re-inserting and tripping
  // the (tenantId, email) unique index.
  try {
    // Mongo disallows the same field path appearing in both $set and
    // $setOnInsert. When the assertion carries `groups`, $set.groups is
    // already populated above (line 555) and applies on insert + update.
    // When the assertion omits `groups`, default to an empty array via
    // $setOnInsert so the field exists on first insert without
    // overwriting any pre-seeded value on subsequent updates.
    const upsertResult = await col.findOneAndUpdate(
      { tenantId, externalId },
      {
        $set: {
          ...$set,
          userName: freshEmail,
          email: freshEmail,
          givenName,
          familyName,
        },
        $setOnInsert: {
          tenantId,
          externalId,
          active: true,
          ...(effectiveGroups === null ? { groups: [] } : {}),
          metadata: {
            idJagSubjectKey: validated.subjectKey,
            ...(validated.subId !== undefined ? { idJagSubIdAlias: validated.subId } : {}),
            ...(freshEmail !== email ? { idJagAssertedEmail: email } : {}),
          },
          createdAt: now,
        },
      },
      { upsert: true, returnDocument: 'after' },
    );
    if (upsertResult) return upsertResult;
  } catch (e) {
    // §4.4.3 re-submission idempotency: if the upsert hit the (tenantId, email)
    // unique index instead of the (tenantId, externalId) index (an existing
    // SCIM / OIDC row at the same email that wasn't ID-JAG-claimed), retry
    // with the synthetic email so the ID-JAG flow gets its own row.
    const code = (e as { code?: number }).code;
    const msg = e instanceof Error ? e.message : String(e);
    const isDup = code === 11000 || msg.includes('E11000') || msg.includes('duplicate key');
    if (!isDup) throw e;
    // A dup on the unique (tenantId, idJagSubIdAliasCanon) index is a
    // DIFFERENT subject already holding this sub_id — a §3.1 reverse-binding
    // collision, NOT an email collision. Rethrow so issueIdJagToken's lock
    // wrapper translates it to invalid_grant; the synthetic-email retry below
    // only resolves (tenantId, email) collisions.
    if (msg.includes('idJagSubIdAliasCanon')) throw e;
    const syntheticEmail = `${externalId}@id-jag.chariot.invalid`;
    const retry = await col.findOneAndUpdate(
      { tenantId, externalId },
      {
        $set: {
          ...$set,
          userName: syntheticEmail,
          email: syntheticEmail,
          givenName,
          familyName,
        },
        $setOnInsert: {
          tenantId,
          externalId,
          active: true,
          ...(effectiveGroups === null ? { groups: [] } : {}),
          metadata: {
            idJagSubjectKey: validated.subjectKey,
            ...(validated.subId !== undefined ? { idJagSubIdAlias: validated.subId } : {}),
            idJagAssertedEmail: email,
          },
          createdAt: now,
        },
      },
      { upsert: true, returnDocument: 'after' },
    );
    if (retry) return retry;
  }
  return null;
}

// subjectKeyAsExternalId lives in ./subject-key.js to break the import
// cycle with ./subject-mutex.js. Re-exported here for back-compat with
// existing callers that already import from this module.
export { subjectKeyAsExternalId } from './subject-key.js';

/**
 * Resolve which mapped adapter ids a `resource` URI refers to. Convention:
 * the bare adapter id appears as the last path segment of the URI
 * (e.g. https://chariot/adapters/github). When the URI does not match any
 * mapped adapter id, returns [].
 *
 * Exported as a hook for unit tests; not part of the route's surface.
 */
export function adaptersForResource(resource: string, mapped: string[]): string[] {
  let url: URL;
  try {
    url = new URL(resource);
  } catch {
    return [];
  }
  const lastSegment = url.pathname.split('/').filter(Boolean).pop() ?? '';
  if (mapped.includes(lastSegment)) {
    return [lastSegment];
  }
  return [];
}

// Re-export the Db type so callers that build test fixtures don't need a
// second mongodb import side-by-side with this module.
export type { Db, ObjectId };

/**
 * One-time, idempotent backfill: recompute idJagSubIdAliasCanon for every
 * iam_users row carrying idJagSubIdAlias. Required (a) for DBs upgraded from
 * before the canon field existed, and (b) after any canon-format change, so
 * the reverse §3.1 lookup and the UNIQUE (tenantId, idJagSubIdAliasCanon)
 * index see correct, current values. MUST run BEFORE ensureEnterpriseIndexes
 * so the unique-canon build validates the corrected values rather than stale
 * ones. No-op when every row already matches. Returns the rows updated.
 */
export async function backfillSubIdAliasCanon(db: Db): Promise<number> {
  const col = db.collection('iam_users');
  const cursor = col.find(
    { idJagSubIdAlias: { $exists: true } },
    { projection: { _id: 1, idJagSubIdAlias: 1, idJagSubIdAliasCanon: 1 } },
  );
  let updated = 0;
  for await (const row of cursor) {
    const r = row as { _id: ObjectId; idJagSubIdAlias?: unknown; idJagSubIdAliasCanon?: unknown };
    const want = canonicalizeSubId(r.idJagSubIdAlias);
    if (r.idJagSubIdAliasCanon !== want) {
      await col.updateOne({ _id: r._id }, { $set: { idJagSubIdAliasCanon: want } });
      updated++;
    }
  }
  return updated;
}
