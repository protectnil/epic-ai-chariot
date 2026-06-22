/**
 * IAM — Tenant Service
 *
 * CRUD operations for enterprise tenants including SSO configuration
 * and SCIM token management.
 */

import { getCollection } from '../db.js';
import { generateScimToken, verifyToken } from '../crypto.js';
import type { TenantDocument, TenantSettings, SamlConfig, OidcConfig } from '../types.js';

const COLLECTION = 'iam_tenants';

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
  if (sso.oidc) setFields['settings.oidc'] = sso.oidc;

  const result = await col.findOneAndUpdate(
    { tenantId },
    { $set: setFields },
    { returnDocument: 'after' },
  );

  return result ?? null;
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
