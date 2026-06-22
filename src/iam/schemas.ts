/**
 * Enterprise IAM Zod Validation Schemas
 */

import { z } from 'zod';

// --- SAML / OIDC / Settings --------------------------------------------------

export const samlConfigSchema = z.object({
  entryPoint: z.string().url(),
  issuer: z.string().min(1).max(256),
  cert: z.string().min(100).max(8192),
  callbackUrl: z.string().url(),
  signatureAlgorithm: z.literal('sha256'),
  wantAssertionsSigned: z.boolean().default(true),
  wantAuthnResponseSigned: z.boolean().default(true),
}).strict();

export const oidcConfigSchema = z.object({
  issuer: z.string().url(),
  clientId: z.string().min(1).max(256),
  clientSecret: z.string().min(1).max(1024),
  redirectUri: z.string().url(),
  scopes: z.array(z.string().max(64)).min(1).max(20).default(['openid', 'profile', 'email', 'groups']),
  responseType: z.literal('code'),
  codeChallengeMethod: z.literal('S256'),
}).strict();

export const tenantSettingsSchema = z.object({
  sessionTtlMs: z.number().int().min(300_000).max(86_400_000).default(28_800_000),
  idleTimeoutMs: z.number().int().min(60_000).max(28_800_000).default(1_800_000),
  maxConcurrentSessions: z.number().int().min(0).max(100).default(0),
  adminGroupName: z.string().min(1).max(128).default('EpicAI-Admins'),
  jitProvisioningEnabled: z.boolean().default(true),
  logRetentionDays: z.number().int().min(90).max(2555).default(365),
}).strict();

// --- Tenant CRUD -------------------------------------------------------------

export const createTenantSchema = z.object({
  tenantId: z.string().regex(/^[a-z0-9-]{2,64}$/, 'URL-safe slug required'),
  displayName: z.string().min(1).max(256),
  domain: z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/i, 'Valid domain required'),
  sso: z.object({
    type: z.enum(['saml', 'oidc', 'none']),
    saml: samlConfigSchema.optional(),
    oidc: oidcConfigSchema.optional(),
  }).strict(),
  settings: tenantSettingsSchema.optional(),
}).strict();

export const updateTenantSettingsSchema = tenantSettingsSchema.partial().strict();

// --- SCIM Schemas (RFC 7644) -------------------------------------------------

export const scimCreateUserSchema = z.object({
  schemas: z.array(z.string()).min(1),
  userName: z.string().email().max(256),
  displayName: z.string().min(1).max(256).optional(),
  name: z.object({
    givenName: z.string().min(1).max(128),
    familyName: z.string().min(1).max(128),
  }).strict().optional(),
  emails: z.array(z.object({
    value: z.string().email().max(256),
    primary: z.boolean(),
  }).strict()).min(1).max(5).optional(),
  active: z.boolean().default(true),
}).strict();

export const scimPatchOpSchema = z.object({
  schemas: z.array(z.string()).min(1),
  Operations: z.array(z.object({
    op: z.enum(['add', 'remove', 'replace']),
    path: z.string().max(256).optional(),
    value: z.unknown().optional(),
  }).strict()).min(1).max(50),
}).strict();

export const scimListQuerySchema = z.object({
  filter: z.string().max(512).optional(),
  startIndex: z.coerce.number().int().min(1).default(1),
  count: z.coerce.number().int().min(1).max(200).default(100),
}).strict();

export const scimCreateGroupSchema = z.object({
  schemas: z.array(z.string()).min(1),
  displayName: z.string().min(1).max(256),
  members: z.array(z.object({
    value: z.string().min(1).max(128),
    display: z.string().max(256).optional(),
  }).strict()).max(10000).optional(),
}).strict();

// --- Adapter Mapping ---------------------------------------------------------

export const createMappingSchema = z.object({
  groupId: z.string().min(1).max(128),
  adapterIds: z.array(z.string().regex(/^[a-z0-9-]+$/).max(64)).min(1).max(100),
}).strict();

export const updateMappingSchema = z.object({
  adapterIds: z.array(z.string().regex(/^[a-z0-9-]+$/).max(64)).min(1).max(100),
}).strict();

// --- Adapter Credential Connect ----------------------------------------------

export const connectAdapterApiKeySchema = z.object({
  apiKey: z.string().min(1).max(2048),
  apiSecret: z.string().min(1).max(2048).optional(),
}).strict();

export const connectSharedAdapterSchema = z.object({
  credentialType: z.enum(['api_key', 'basic_auth']),
  apiKey: z.string().min(1).max(2048).optional(),
  apiSecret: z.string().min(1).max(2048).optional(),
  username: z.string().min(1).max(256).optional(),
  password: z.string().min(1).max(2048).optional(),
}).strict();

// --- Audit Log Query ---------------------------------------------------------

export const auditLogQuerySchema = z.object({
  since: z.coerce.date().optional(),
  until: z.coerce.date().optional(),
  eventType: z.string().max(64).optional(),
  actorId: z.string().max(128).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  offset: z.coerce.number().int().min(0).default(0),
  format: z.enum(['json', 'csv']).default('json'),
}).strict();

// --- Session Management ------------------------------------------------------

export const forceLogoutSchema = z.object({
  reason: z.string().max(512).optional(),
}).strict();

// --- Inferred Types ----------------------------------------------------------

export type CreateTenantInput = z.infer<typeof createTenantSchema>;
export type UpdateTenantSettingsInput = z.infer<typeof updateTenantSettingsSchema>;
export type ScimCreateUserInput = z.infer<typeof scimCreateUserSchema>;
export type ScimPatchOpInput = z.infer<typeof scimPatchOpSchema>;
export type ScimListQueryInput = z.infer<typeof scimListQuerySchema>;
export type ScimCreateGroupInput = z.infer<typeof scimCreateGroupSchema>;
export type CreateMappingInput = z.infer<typeof createMappingSchema>;
export type UpdateMappingInput = z.infer<typeof updateMappingSchema>;
export type ConnectAdapterApiKeyInput = z.infer<typeof connectAdapterApiKeySchema>;
export type ConnectSharedAdapterInput = z.infer<typeof connectSharedAdapterSchema>;
export type AuditLogQueryInput = z.infer<typeof auditLogQuerySchema>;
export type ForceLogoutInput = z.infer<typeof forceLogoutSchema>;
