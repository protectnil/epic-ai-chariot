/**
 * Epic AI® Chariot — Enterprise IAM Module
 *
 * Re-exports all IAM components for use by Chariot CLI and integrators.
 */

// Bootstrap — single entry point for enterprise startup validation
export {
  bootstrapEnterprise,
  isEnterpriseModeRequested,
  type EnterpriseConfig,
  type BootstrapResult,
} from './bootstrap.js';

// Middleware
export {
  licenseGateMiddleware,
  seatLimitMiddleware,
  enterpriseAuthMiddleware,
  scimAuthMiddleware,
  enterpriseAdminGuard,
  adapterFilterMiddleware,
  verifiedCatalogEnforcementMiddleware,
  tenantResolutionMiddleware,
  requireTlsMiddleware,
} from './middleware.js';

// Routes
export { createEnterpriseRoutes } from './routes/index.js';

// Services
export * as sessionService from './services/session.js';
export * as tenantService from './services/tenant.js';
export * as auditService from './services/audit.js';
export * as scimService from './services/scim.js';
export * as mappingService from './services/mapping.js';

// Crypto (vault operations)
export { encryptFields, decryptFields, validateMasterKey } from './crypto.js';

// Database
export { getDb, getCollection, setMongoClient } from './db.js';
export { getRedisClient, setRedisClient } from './redis.js';
export { ensureEnterpriseIndexes } from './indexes.js';

// Types
export type {
  TenantDocument,
  TenantSettings,
  SamlConfig,
  OidcConfig,
  EnterpriseUserDocument,
  EnterpriseGroupDocument,
  GroupAdapterMappingDocument,
  AdapterCredentialDocument,
  AuditEventDocument,
  AuditEventType,
  AuditTargetType,
  EnterpriseSessionPayload,
  CredentialType,
  CredentialStatus,
  ScimUser,
  ScimGroup,
  ScimPatchOp,
  ScimListResponse,
} from './types.js';

// Schemas
export {
  createTenantSchema,
  updateTenantSettingsSchema,
  scimCreateUserSchema,
  scimPatchOpSchema,
  scimListQuerySchema,
  scimCreateGroupSchema,
  createMappingSchema,
  updateMappingSchema,
  connectAdapterApiKeySchema,
  connectSharedAdapterSchema,
  auditLogQuerySchema,
} from './schemas.js';
