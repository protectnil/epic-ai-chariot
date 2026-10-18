/**
 * IAM — Tenant Service
 *
 * CRUD operations for enterprise tenants including SSO configuration
 * and SCIM token management.
 */

import { getCollection } from '../db.js';
import { generateScimToken, verifyToken, encryptFields } from '../crypto.js';
import type { TenantDocument, TenantSettings, SamlConfig, OidcConfig } from '../types.js';

export const COLLECTION = 'iam_tenants';

// ── Read ────────────────────────────────────────────────────────────────────

export async function getByTenantId(tenantId: string): Promise<TenantDocument | null> {
  const col = await getCollection<TenantDocument>(COLLECTION);
  return col.findOne({ tenantId });
}

// ── Create ──────────────────────────────────────────────────────────────────

export async function create(
  tenantId: string,
  name: string,
  domain: string,
  settings?: Partial<TenantSettings>,
  encryptionKeyRef?: string,
): Promise<TenantDocument> {
  const col = await getCollection<TenantDocument>(COLLECTION);
  const now = new Date();

  const defaultSettings: TenantSettings = {
    sessionTimeoutMinutes: 480,
    maxConcurrentSessions: 5,
    mfaRequired: false,
    ipAllowList: [],
    allowedAdapterIds: [],
    scimEnabled: false,
    ...settings,
  };

  const tenant: Omit<TenantDocument, '_id'> = {
    tenantId,
    name,
    domain,
    settings: defaultSettings,
    // §10.8::4 — record the per-tenant encryption key reference. Defaults to
    // the env-key ID of the master key this deployment encrypts under; a
    // KMS-backed deployment passes its own key pointer.
    encryptionKeyRef: encryptionKeyRef ?? 'env:ENTERPRISE_MASTER_KEY',
    active: true,
    createdAt: now,
    updatedAt: now,
  };

  const result = await col.insertOne(tenant as TenantDocument);
  return { ...tenant, _id: result.insertedId };
}

// ── Update Settings ─────────────────────────────────────────────────────────

export async function updateSettings(
  tenantId: string,
  settings: Partial<TenantSettings>,
): Promise<TenantDocument | null> {
  const col = await getCollection<TenantDocument>(COLLECTION);

  const setFields: Record<string, unknown> = { updatedAt: new Date() };
  for (const [key, value] of Object.entries(settings)) {
    setFields[`settings.${key}`] = value;
  }

  const result = await col.findOneAndUpdate(
    { tenantId },
    { $set: setFields },
    { returnDocument: 'after' },
  );

  return result ?? null;
}

// ── Update SSO ──────────────────────────────────────────────────────────────

export async function updateSso(
  tenantId: string,
  sso: { saml?: SamlConfig; oidc?: OidcConfig },
): Promise<TenantDocument | null> {
  const col = await getCollection<TenantDocument>(COLLECTION);

  const setFields: Record<string, unknown> = { updatedAt: new Date() };
  if (sso.saml) setFields['settings.saml'] = sso.saml;
  if (sso.oidc) setFields['settings.oidc'] = encryptOidcSecretAtRest(sso.oidc, tenantId);

  const result = await col.findOneAndUpdate(
    { tenantId },
    { $set: setFields },
    { returnDocument: 'after' },
  );

  return result ?? null;
}

/**
 * §10.3::1 — the OIDC client secret SHALL be encrypted at rest. Given an OIDC
 * config carrying a plaintext `clientSecret`, encrypt it with the tenant-bound
 * master key (AES-256-GCM) and return a config that persists ONLY the
 * `encrypted:iv` blob in `clientSecretEncrypted`, with the plaintext removed.
 * An already-encrypted config (no plaintext) is returned unchanged.
 */
function encryptOidcSecretAtRest(oidc: OidcConfig, tenantId: string): OidcConfig {
  if (!oidc.clientSecret) return oidc;
  // CH-10 (§12.2) AAD binding. This config carries exactly one OIDC client
  // secret per tenant (no adapterId concept here), so a fixed record-type
  // identifier — matched byte-for-byte in oidc.ts's resolveOidcClientSecret
  // — provides the same anti-relocation binding a real adapterId would.
  const { encrypted, iv } = encryptFields({ value: oidc.clientSecret }, tenantId, 'oidc-client-secret');
  const { clientSecret: _plaintext, ...rest } = oidc;
  void _plaintext;
  return { ...rest, clientSecretEncrypted: `${encrypted}:${iv}` };
}

// ── SCIM Token ──────────────────────────────────────────────────────────────

/**
 * Generate a new SCIM bearer token for the tenant.
 * The plaintext token is returned ONCE — only the hash is persisted.
 */
export async function generateScimTokenForTenant(tenantId: string): Promise<string> {
  const col = await getCollection<TenantDocument>(COLLECTION);
  const { token, hash } = generateScimToken();

  const result = await col.updateOne(
    { tenantId },
    { $set: { scimBearerTokenHash: hash, updatedAt: new Date() } },
  );

  // If no tenant row matched, the returned token was never persisted. Refusing
  // to hand out an unstored credential is the only correct behavior — the
  // caller will see a clear error instead of a silently useless token. The
  // tenantId is intentionally omitted from the thrown message so a naive
  // caller that serializes `err.message` to a client response cannot leak
  // the identifier; callers with structured logging already have tenantId
  // in scope from the call site.
  if (result.matchedCount === 0) {
    throw new Error('Tenant not found');
  }

  return token;
}

/**
 * Verify a SCIM bearer token against the stored hash for a tenant.
 */
export async function verifyScimToken(
  tenantId: string,
  candidateToken: string,
): Promise<boolean> {
  const tenant = await getByTenantId(tenantId);
  if (!tenant?.scimBearerTokenHash) return false;
  return verifyToken(candidateToken, tenant.scimBearerTokenHash);
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

export async function suspend(tenantId: string): Promise<TenantDocument | null> {
  const col = await getCollection<TenantDocument>(COLLECTION);

  const result = await col.findOneAndUpdate(
    { tenantId },
    { $set: { active: false, updatedAt: new Date() } },
    { returnDocument: 'after' },
  );

  return result ?? null;
}

export async function activate(tenantId: string): Promise<TenantDocument | null> {
  const col = await getCollection<TenantDocument>(COLLECTION);

  const result = await col.findOneAndUpdate(
    { tenantId },
    { $set: { active: true, updatedAt: new Date() } },
    { returnDocument: 'after' },
  );

  return result ?? null;
}

// ── Delete (§10.8::1 — completes tenant CRUD) ────────────────────────────────

/**
 * Hard-delete the tenant record. Returns true when a row was removed. Admin-
 * initiated and irreversible; owned collections (users/creds/audit) are keyed
 * by tenantId and are pruned by their own retention/cleanup paths.
 */
export async function deleteTenant(tenantId: string): Promise<boolean> {
  const col = await getCollection<TenantDocument>(COLLECTION);
  const result = await col.deleteOne({ tenantId });
  return result.deletedCount > 0;
}
