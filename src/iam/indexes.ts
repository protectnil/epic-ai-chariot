/**
 * Enterprise IAM -- MongoDB Index Definitions
 *
 * Creates all required indexes for the six IAM collections.
 * Intended to be called once at application startup.
 *
 * @module iam/indexes
 */

import type { Db } from 'mongodb';

/**
 * Ensure all indexes exist for the enterprise IAM collections.
 *
 * Accepts a `Db` handle directly (caller resolves it).
 * Safe to call repeatedly -- `createIndex` is a no-op when the index
 * already exists with the same key and options.
 */
export async function ensureEnterpriseIndexes(db: Db): Promise<void> {
  // -- iam_tenants -----------------------------------------------------------
  const tenants = db.collection('iam_tenants');
  await tenants.createIndex({ tenantId: 1 }, { unique: true });
  await tenants.createIndex({ domain: 1 }, { unique: true });

  // -- iam_users -------------------------------------------------------------
  const users = db.collection('iam_users');
  await users.createIndex({ tenantId: 1, email: 1 }, { unique: true });
  await users.createIndex({ tenantId: 1, scimId: 1 }, { unique: true });
  await users.createIndex({ tenantId: 1, active: 1 });
  await users.createIndex({ tenantId: 1, groups: 1 });
  // ID-JAG (Identity Assertion JWT Authorization Grant) hot-path filter:
  //   { tenantId, externalId }
  // Per-(tenant, externalId) uniqueness so the issuer's JIT-upsert never
  // silently creates a duplicate row. externalId is the ID-JAG canonical
  // subject tuple string (id-jag:<iss>:sub=<sub> | aud_tenant=...:sub=... |
  // aud_sub=...). Partial filter so the unique constraint only applies to
  // rows that actually carry externalId (i.e. ID-JAG-provisioned rows;
  // pre-existing SCIM rows without externalId are unaffected).
  await users.createIndex(
    { tenantId: 1, externalId: 1 },
    { unique: true, partialFilterExpression: { externalId: { $type: 'string' } } },
  );
  // draft-04 §3.1 reverse sub_id binding: a sub_id MUST map to exactly one
  // subject per tenant. A UNIQUE partial index makes that an atomic DB
  // invariant, closing the cross-subject TOCTOU race that the per-subject
  // withSubjectLock cannot (different subjects take different locks). The
  // same subject re-presenting its sub_id updates its own (tenantId,
  // externalId) row → no collision; a DIFFERENT subject inserting the same
  // canon trips the index, which id-jag-issuer translates to the §3.1
  // reverse-binding invalid_grant. Migrate from the earlier NON-unique index
  // (changing uniqueness in place is an IndexOptionsConflict): drop then
  // recreate. Fail-closed — if the DB already holds a duplicate canon (a
  // pre-existing splice) the unique build throws and startup stops, surfacing
  // the integrity violation instead of silently permitting it. Run AFTER the
  // canon backfill so legacy/old-format alias rows carry the current canon.
  try {
    await users.dropIndex('tenantId_1_idJagSubIdAliasCanon_1');
  } catch {
    /* non-unique predecessor absent (fresh DB) — nothing to migrate */
  }
  await users.createIndex(
    { tenantId: 1, idJagSubIdAliasCanon: 1 },
    { unique: true, partialFilterExpression: { idJagSubIdAliasCanon: { $type: 'string' } } },
  );

  // -- iam_groups ------------------------------------------------------------
  const groups = db.collection('iam_groups');
  await groups.createIndex({ tenantId: 1, scimId: 1 }, { unique: true });
  await groups.createIndex({ tenantId: 1, displayName: 1 });

  // -- iam_group_adapter_mappings --------------------------------------------
  const mappings = db.collection('iam_group_adapter_mappings');
  await mappings.createIndex({ tenantId: 1, groupId: 1 }, { unique: true });

  // -- iam_adapter_credentials -----------------------------------------------
  const credentials = db.collection('iam_adapter_credentials');
  await credentials.createIndex(
    { tenantId: 1, userId: 1, adapterId: 1 },
    { unique: true },
  );
  await credentials.createIndex({ tenantId: 1, status: 1, tokenExpiry: 1 });

  // -- iam_audit_events ------------------------------------------------------
  const audit = db.collection('iam_audit_events');
  await audit.createIndex({ tenantId: 1, seq: 1 }, { unique: true });
  await audit.createIndex({ tenantId: 1, timestamp: -1 });
  await audit.createIndex({ tenantId: 1, eventType: 1, timestamp: -1 });
  // Audit retention: iam_audit_events is a SHA-256 hash chain verified
  // from genesis (verifyChain in services/audit.ts walks seq 0..n and
  // checks each row's previousHash against the preceding row's hash).
  // A background TTL is therefore INTENTIONALLY NOT applied: deleting any
  // aged row severs the chain at that seq, so verify() of everything that
  // remains would break (classic hash chains do not permit skipping — see
  // Crosby & Wallach, USENIX Security 2009). Retention/space management
  // for this collection is an anchor-then-archive-then-prune operation
  // (seal a Merkle root / signed checkpoint, archive the pruned segment +
  // its anchor to immutable storage, and resume verification from the
  // anchor) — a deliberate, attributable, audited action, never a silent
  // TTL. A prior `audit_retention_ttl` index keyed on a never-written
  // `retainable` field with a Mongo-invalid `$ne` partial filter never
  // built and is removed.

  // -- iam_auth_failures (rate-limiting failed login attempts) ----------------
  const authFailures = db.collection('iam_auth_failures');
  await authFailures.createIndex({ key: 1 }, { unique: true });
  // Auto-expire failure records 15 minutes after the LAST attempt (SLIDING
  // window). A fixed window keyed on firstAttempt expired the whole record
  // 900s after the first hit regardless of ongoing activity, letting a
  // steady-rate attacker reset every bucket (per-IP, per-client, IP-probe)
  // before reaching the lockout threshold. Migrate: drop the legacy
  // firstAttempt TTL if present (no-op on a fresh DB), then create the
  // lastAttempt TTL. Both recordX writers already $set lastAttempt.
  try {
    await authFailures.dropIndex('firstAttempt_1');
  } catch {
    /* legacy index absent (fresh DB) — nothing to migrate */
  }
  await authFailures.createIndex({ lastAttempt: 1 }, { expireAfterSeconds: 900 });

  // -- iam_id_jag_trusted_issuers (ID-JAG trust registry) ---------------------
  // Hot-path read on every ID-JAG token-exchange:
  //   { tenantId, issuer, active: true }
  // Per-(tenantId, issuer) uniqueness so registerTrustedIssuer's upsert
  // never silently creates a duplicate row.
  const idJagTrust = db.collection('iam_id_jag_trusted_issuers');
  await idJagTrust.createIndex({ tenantId: 1, issuer: 1 }, { unique: true });
  await idJagTrust.createIndex({ tenantId: 1, active: 1 });

  // -- iam_id_jag_oauth_clients (ID-JAG OAuth client registry) ----------------
  // Hot-path read on every ID-JAG token-exchange:
  //   { tenantId, clientId, active: true }
  // Per-(tenantId, clientId) uniqueness so registerClient's upsert never
  // silently creates a duplicate row.
  const idJagClients = db.collection('iam_id_jag_oauth_clients');
  await idJagClients.createIndex({ tenantId: 1, clientId: 1 }, { unique: true });
  await idJagClients.createIndex({ tenantId: 1, active: 1 });
  // Hot-path read on every POST /token + /revoke: findCandidateTenantIdsForClient
  // resolves the candidate Resource-AS tenants from the presented client_id
  // alone (draft-04 §6.2), so clientId must be an index prefix or the lookup
  // COLLSCANs the whole registry on each token request.
  await idJagClients.createIndex({ clientId: 1, active: 1 });

  // -- iam_id_jag_scope_mappings (ID-JAG claim→scope registry) ----------------
  // Hot-path read on every ID-JAG token-exchange:
  //   { tenantId, fromClaim, fromValue, active: true }
  // Per-(tenantId, fromClaim, fromValue) uniqueness so registerScopeMapping's
  // upsert never silently creates a duplicate row.
  const idJagScopes = db.collection('iam_id_jag_scope_mappings');
  await idJagScopes.createIndex(
    { tenantId: 1, fromClaim: 1, fromValue: 1 },
    { unique: true },
  );
  await idJagScopes.createIndex({ tenantId: 1, active: 1 });

  // -- iam_id_jag_idp_clients (Chariot-as-Client IdP registry) ----------------
  // Hot-path read every MCP tool dispatch that declares idJagAuth:
  //   { tenantId, issuer, active: true }
  // Holds Chariot's OWN credentials AT each enterprise IdP (distinct
  // from iam_id_jag_trusted_issuers, which holds the IdPs Chariot
  // accepts assertions FROM on its Resource AS side).
  const idJagIdpClients = db.collection('iam_id_jag_idp_clients');
  await idJagIdpClients.createIndex({ tenantId: 1, issuer: 1 }, { unique: true });
  await idJagIdpClients.createIndex({ tenantId: 1, active: 1 });
}
