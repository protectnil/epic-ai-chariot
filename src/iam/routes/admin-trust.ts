/**
 * ID-JAG Admin Trust Routes (plan §172-183).
 *
 * Per-tenant CRUD for the three ID-JAG registries that back the
 * /enterprise/oauth/token endpoint:
 *
 *   - Trusted IdP issuers (`iam_id_jag_trusted_issuers`)
 *   - Claim→scope mappings (`iam_id_jag_scope_mappings`)
 *   - OAuth clients (`iam_id_jag_oauth_clients`)
 *
 * All endpoints require enterprise auth + admin role, and the host
 * mount applies `licenseGateMiddleware` so a tenant whose license has
 * lapsed cannot mutate these registries. Audit events
 * `id_jag_trust_added` / `id_jag_trust_revoked` are emitted on every
 * write per the AuditEventType union in iam/types.ts.
 *
 * Routes (mounted at /enterprise/admin/trust):
 *   POST   /issuers                  -- register a trusted IdP
 *   GET    /issuers                  -- list trusted IdPs
 *   DELETE /issuers/:iss             -- revoke a trusted IdP
 *   POST   /scope-mappings           -- register a claim→scope mapping
 *   GET    /scope-mappings           -- list mappings
 *   DELETE /scope-mappings/:id       -- revoke by ObjectId
 *   POST   /clients                  -- register OAuth client; secret returned ONCE
 *   GET    /clients                  -- list (server-side projection drops secret hash)
 *   DELETE /clients/:client_id       -- revoke
 *
 * @module iam/routes/admin-trust
 */

import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';

import {
  enterpriseAuthMiddleware,
  enterpriseAdminGuard,
  requireEnterpriseAuth,
} from '../middleware.js';
import * as audit from '../services/audit.js';
import { getStringParam, parseObjectId, detailFromZod } from './helpers.js';
import {
  listTrustedIssuers,
  registerTrustedIssuer,
  revokeTrustedIssuer,
} from '../services/idp-trust-registry.js';
import {
  listClients,
  registerClient,
  revokeClient,
} from '../services/oauth-client-registry.js';
import {
  listScopeMappings,
  registerScopeMapping,
  revokeScopeMapping,
} from '../services/scope-mapping-registry.js';
import {
  clearIdpJwksCache,
  listIdpClients,
  registerIdpClient,
  revokeIdpClient,
} from '../services/id-jag-client.js';
import type { OAuthClientDocument } from '../types.js';

const router = Router();

// All admin-trust routes require authentication + admin role.
router.use(enterpriseAuthMiddleware());
router.use(enterpriseAdminGuard());

// ── Shared schemas ───────────────────────────────────────────────────────────

/**
 * RFC 3986 §7.4 — issuer values are bounded to keep audit log records
 * size-bounded. 4 KiB is the project-wide convention for adapter-id-
 * shaped opaque strings.
 */
const ISSUER_MAX = 4096;
const URL_MAX = 4096;
const ADAPTER_ID_MAX = 128;
const CLAIM_MAX = 256;
const CLAIM_VALUE_MAX = 1024;
const ALG_MAX = 64;
const CLIENT_ID_MAX = 256;

const httpsUrlSchema = z
  .string()
  .min(8)
  .max(URL_MAX)
  .refine((v) => v.startsWith('https://'), { message: 'must be https://' });

const registerIssuerBodySchema = z
  .object({
    issuer: z.string().min(1).max(ISSUER_MAX),
    jwksUri: httpsUrlSchema,
    audience: z.string().min(1).max(ISSUER_MAX),
    allowedAlgorithms: z
      .array(z.string().min(1).max(ALG_MAX))
      .min(1)
      .max(16)
      .optional(),
    // draft-04 §3.2.2 USE-gate + §9.5 SAML-issuer allowlist. Operator
    // config for the AS's SAML NameID enforcement path. Both optional;
    // absent/false means the AS does not use sub_id for resolution.
    requireSamlNameIdSubId: z.boolean().optional(),
    samlNameIdIssuers: z
      .array(z.string().min(1).max(ISSUER_MAX))
      .max(100)
      .optional(),
    // draft-04 §6.1 / §6.2 / §6.4 Resource-AS tenant MUSTs (conditional
    // per spec text). Each is optional; absence means the AS does not
    // enforce that specific tenant rule.
    requiresTenantContext: z.boolean().optional(),
    expectedTenants: z
      .array(z.string().min(1).max(ISSUER_MAX))
      .max(500)
      .optional(),
    tenantScopedClientIds: z
      .record(
        z.string().min(1).max(ISSUER_MAX),
        z.array(z.string().min(1).max(CLIENT_ID_MAX)).max(500),
      )
      .optional(),
  })
  .strict();

const registerScopeMappingBodySchema = z
  .object({
    fromClaim: z.string().min(1).max(CLAIM_MAX),
    fromValue: z.string().min(1).max(CLAIM_VALUE_MAX),
    toAdapterIds: z.array(z.string().min(1).max(ADAPTER_ID_MAX)).min(1).max(500),
    toAllowedOperations: z
      .record(z.string().min(1).max(ADAPTER_ID_MAX), z.array(z.string().min(1).max(128)).max(200))
      .optional(),
  })
  .strict();

const registerClientBodySchema = z
  .object({
    clientId: z.string().min(1).max(CLIENT_ID_MAX),
    authMethod: z.enum(['client_secret_basic', 'client_secret_post', 'private_key_jwt']),
    jwksUri: httpsUrlSchema.optional(),
    allowedIssuers: z.array(z.string().min(1).max(ISSUER_MAX)).min(1).max(100),
    redirectUris: z.array(httpsUrlSchema).max(20).optional(),
  })
  .strict();

// Chariot-as-Client IdP registration body (per the PRIVATE id-jag-client-spec.md §4.1).
// The clientSecret / clientPrivateKey fields are PLAINTEXT at the route
// boundary and encrypted before persist by registerIdpClient(). They are
// NEVER echoed in any GET response or audit emission.
const SECRET_MAX = 8192;
const PRIVATE_KEY_PEM_MAX = 16384;
const registerIdpClientBodySchema = z
  .object({
    issuer: z.string().min(1).max(ISSUER_MAX),
    tokenEndpoint: httpsUrlSchema,
    jwksUri: httpsUrlSchema,
    clientId: z.string().min(1).max(CLIENT_ID_MAX),
    authMethod: z.enum(['client_secret_basic', 'client_secret_post', 'private_key_jwt']),
    clientSecret: z.string().min(1).max(SECRET_MAX).optional(),
    clientPrivateKey: z.string().min(1).max(PRIVATE_KEY_PEM_MAX).optional(),
    clientAssertionSigningAlg: z.enum(['RS256', 'ES256']).optional(),
    allowedAudiences: z.array(z.string().min(1).max(ISSUER_MAX)).min(1).max(100),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.authMethod === 'private_key_jwt') {
      if (val.clientPrivateKey === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'clientPrivateKey required when authMethod=private_key_jwt',
          path: ['clientPrivateKey'],
        });
      }
      if (val.clientSecret !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'clientSecret must not be set when authMethod=private_key_jwt',
          path: ['clientSecret'],
        });
      }
    } else {
      if (val.clientSecret === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'clientSecret required when authMethod=client_secret_basic|post',
          path: ['clientSecret'],
        });
      }
      if (val.clientPrivateKey !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'clientPrivateKey must not be set when authMethod=client_secret_basic|post',
          path: ['clientPrivateKey'],
        });
      }
    }
  });

// ── Trusted Issuers ─────────────────────────────────────────────────────────

/** POST /issuers — register or upsert a trusted IdP. */
router.post('/issuers', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = registerIssuerBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', detail: detailFromZod(parsed.error) });
    return;
  }

  try {
    const result = await registerTrustedIssuer({
      tenantId,
      issuer: parsed.data.issuer,
      jwksUri: parsed.data.jwksUri,
      audience: parsed.data.audience,
      allowedAlgorithms: parsed.data.allowedAlgorithms,
      requireSamlNameIdSubId: parsed.data.requireSamlNameIdSubId,
      samlNameIdIssuers: parsed.data.samlNameIdIssuers,
      requiresTenantContext: parsed.data.requiresTenantContext,
      expectedTenants: parsed.data.expectedTenants,
      tenantScopedClientIds: parsed.data.tenantScopedClientIds,
      createdBy: user.sub,
    });
    const { document: doc, upserted } = result;
    await audit.log(tenantId, 'id_jag_trust_added', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: {
        kind: 'trusted_issuer',
        issuer: doc.issuer,
        audience: doc.audience,
        jwksUri: doc.jwksUri,
        allowedAlgorithms: doc.allowedAlgorithms,
        // Distinguishes a fresh registration (upserted:true) from a
        // credential / config rotation (upserted:false) so SOC 2
        // change-management evidence is unambiguous.
        upserted,
      },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(201).json({ issuer: doc });
  } catch (err) {
    // Service-layer Errors (e.g. ensureHttps, `alg none`) surface as 400
    // — they reflect bad input, not server failure. Anything else is 500.
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (
      msg.includes('https')
      || msg.includes('allowedAlgorithms')
    ) {
      res.status(400).json({ error: msg });
      return;
    }

    console.error('[iam/admin-trust] register issuer failed', err);
    res.status(500).json({ error: 'Failed to register trusted issuer' });
  }
});

/** GET /issuers — list trusted IdPs for the tenant. */
router.get('/issuers', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    const issuers = await listTrustedIssuers(tenantId);
    res.json({ issuers });
  } catch (err) {

    console.error('[iam/admin-trust] list issuers failed', err);
    res.status(500).json({ error: 'Failed to list trusted issuers' });
  }
});

/** DELETE /issuers/:iss — revoke a trusted IdP (soft, sets active=false). */
router.delete('/issuers/:iss', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const iss = getStringParam(req, 'iss');
  if (!iss) {
    res.status(400).json({ error: 'Missing issuer' });
    return;
  }
  // Belt-and-braces defense: reject any issuer path-param that starts
  // with `$` (Mongo operator prefix — defends against a future code
  // path that might splat the value into a query key position) OR
  // contains ANY C0 control byte / DEL (\x00–\x1f, \x7f). Audit-log
  // exporters serialise records as JSON / CSV / syslog; embedded
  // \n / \r / \x00 can produce newline injection, field truncation,
  // or syslog framing errors. The dispatcher gate only consumes
  // active rows so display-side bytes don't influence dispatch, but
  // the audit trail MUST stay clean for SOC 2 evidentiary integrity.
  if (iss.startsWith('$') || /[\x00-\x1f\x7f]/.test(iss)) {
    res.status(400).json({ error: 'Invalid issuer' });
    return;
  }

  try {
    const ok = await revokeTrustedIssuer(tenantId, iss);
    if (!ok) {
      res.status(404).json({ error: 'Trusted issuer not found' });
      return;
    }
    await audit.log(tenantId, 'id_jag_trust_revoked', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: { kind: 'trusted_issuer', issuer: iss },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(204).send();
  } catch (err) {

    console.error('[iam/admin-trust] revoke issuer failed', err);
    res.status(500).json({ error: 'Failed to revoke trusted issuer' });
  }
});

// ── Scope Mappings ──────────────────────────────────────────────────────────

/** POST /scope-mappings — register or upsert a claim→scope mapping. */
router.post('/scope-mappings', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = registerScopeMappingBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', detail: detailFromZod(parsed.error) });
    return;
  }

  try {
    const result = await registerScopeMapping({
      tenantId,
      fromClaim: parsed.data.fromClaim,
      fromValue: parsed.data.fromValue,
      toAdapterIds: parsed.data.toAdapterIds,
      toAllowedOperations: parsed.data.toAllowedOperations ?? {},
      createdBy: user.sub,
    });
    const { document: doc, upserted } = result;
    await audit.log(tenantId, 'id_jag_trust_added', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: {
        kind: 'scope_mapping',
        mappingId: doc._id.toString(),
        fromClaim: doc.fromClaim,
        fromValue: doc.fromValue,
        toAdapterIds: doc.toAdapterIds,
        // review-flagged: the audit trail must carry the
        // FULL entitlement set so SOC 2 change-management evidence can
        // reconstruct what was authorised at write time. Per-adapter
        // operation grants (toAllowedOperations) are the "effective
        // entitlement" half of a scope mapping — omitting them makes
        // the audit record incomplete for forensic reconstruction.
        toAllowedOperations: doc.toAllowedOperations,
        upserted,
      },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(201).json({ scopeMapping: doc });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (
      msg.includes('must not be empty')
      || msg.includes('non-empty string')
    ) {
      res.status(400).json({ error: msg });
      return;
    }

    console.error('[iam/admin-trust] register scope mapping failed', err);
    res.status(500).json({ error: 'Failed to register scope mapping' });
  }
});

/** GET /scope-mappings — list mappings for the tenant. */
router.get('/scope-mappings', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    const scopeMappings = await listScopeMappings(tenantId);
    res.json({ scopeMappings });
  } catch (err) {

    console.error('[iam/admin-trust] list scope mappings failed', err);
    res.status(500).json({ error: 'Failed to list scope mappings' });
  }
});

/** DELETE /scope-mappings/:id — revoke a scope mapping by ObjectId. */
router.delete('/scope-mappings/:id', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const id = getStringParam(req, 'id');
  const objectId = parseObjectId(id);
  if (!objectId) {
    res.status(404).json({ error: 'Scope mapping not found' });
    return;
  }

  try {
    const ok = await revokeScopeMapping(tenantId, objectId);
    if (!ok) {
      res.status(404).json({ error: 'Scope mapping not found' });
      return;
    }
    await audit.log(tenantId, 'id_jag_trust_revoked', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: { kind: 'scope_mapping', mappingId: id ?? '' },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(204).send();
  } catch (err) {

    console.error('[iam/admin-trust] revoke scope mapping failed', err);
    res.status(500).json({ error: 'Failed to revoke scope mapping' });
  }
});

// ── OAuth Clients ───────────────────────────────────────────────────────────

/**
 * POST /clients — register or upsert an OAuth client.
 *
 * For `client_secret_basic` / `client_secret_post` the registry
 * generates a 32-byte random secret server-side and returns the
 * plaintext in the response body ONCE. Only the SHA-256 hash is
 * persisted (via crypto.ts:hashToken). Subsequent reads via
 * `listClients` strip the hash via a server-side Mongo projection.
 *
 * `clientSecretHash` is also stripped from the document echoed in
 * this response — the operator only ever sees the plaintext
 * `client_secret` field, never the hash.
 */
router.post('/clients', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = registerClientBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', detail: detailFromZod(parsed.error) });
    return;
  }

  // Schema-level cross-field validation: jwksUri is REQUIRED for
  // private_key_jwt and MUST be omitted for client_secret_* methods.
  // The service layer (registerClient) enforces the same invariant
  // but checking here lets us produce a 400 with the precise error.
  if (parsed.data.authMethod === 'private_key_jwt' && !parsed.data.jwksUri) {
    res.status(400).json({ error: 'jwksUri is required for private_key_jwt' });
    return;
  }
  if (parsed.data.authMethod !== 'private_key_jwt' && parsed.data.jwksUri !== undefined) {
    res.status(400).json({ error: 'jwksUri MUST be omitted for client_secret_* methods' });
    return;
  }

  try {
    const result = await registerClient({
      tenantId,
      clientId: parsed.data.clientId,
      authMethod: parsed.data.authMethod,
      jwksUri: parsed.data.jwksUri,
      allowedIssuers: parsed.data.allowedIssuers,
      redirectUris: parsed.data.redirectUris,
      createdBy: user.sub,
    });

    // Strip the hash from the echoed document so the operator never
    // sees the persisted form. The plaintext secret (when present)
    // travels back in `client_secret` per RFC 6749 §2.3.1 naming.
    const { clientSecretHash: _stripped, ...safeDoc } = result.document as OAuthClientDocument
      & { clientSecretHash?: string };
    void _stripped;

    await audit.log(tenantId, 'id_jag_trust_added', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: {
        kind: 'oauth_client',
        clientId: result.document.clientId,
        authMethod: result.document.authMethod,
        // NEVER include result.clientSecret in the audit detail — the
        // plaintext leaves the process only via the HTTP response body.
        secretIssued: result.clientSecret !== undefined,
        allowedIssuers: result.document.allowedIssuers,
        upserted: result.upserted,
      },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });

    res.status(201).json({
      client: safeDoc,
      ...(result.clientSecret !== undefined ? { client_secret: result.clientSecret } : {}),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (
      msg.includes('allowedIssuers')
      || msg.includes('jwksUri')
      || msg.includes('redirectUris')
      || msg.includes('https')
    ) {
      res.status(400).json({ error: msg });
      return;
    }

    console.error('[iam/admin-trust] register client failed', err);
    res.status(500).json({ error: 'Failed to register OAuth client' });
  }
});

/** GET /clients — list (server-side projection strips clientSecretHash). */
router.get('/clients', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;

  try {
    const clients = await listClients(tenantId);
    res.json({ clients });
  } catch (err) {

    console.error('[iam/admin-trust] list clients failed', err);
    res.status(500).json({ error: 'Failed to list OAuth clients' });
  }
});

/** DELETE /clients/:client_id — revoke OAuth client. */
router.delete('/clients/:client_id', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const clientId = getStringParam(req, 'client_id');
  if (!clientId) {
    res.status(400).json({ error: 'Missing client_id' });
    return;
  }

  try {
    const ok = await revokeClient(tenantId, clientId);
    if (!ok) {
      res.status(404).json({ error: 'OAuth client not found' });
      return;
    }
    await audit.log(tenantId, 'id_jag_trust_revoked', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: { kind: 'oauth_client', clientId },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(204).send();
  } catch (err) {

    console.error('[iam/admin-trust] revoke client failed', err);
    res.status(500).json({ error: 'Failed to revoke OAuth client' });
  }
});

// ── Chariot-as-Client IdP registry (P5 — outbound ID-JAG fan-out) ────────────

/** POST /idp-clients — register or rotate Chariot's Client credentials at an enterprise IdP. */
router.post('/idp-clients', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const parsed = registerIdpClientBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid request body', detail: detailFromZod(parsed.error) });
    return;
  }

  try {
    const result = await registerIdpClient({
      tenantId,
      issuer: parsed.data.issuer,
      tokenEndpoint: parsed.data.tokenEndpoint,
      jwksUri: parsed.data.jwksUri,
      clientId: parsed.data.clientId,
      authMethod: parsed.data.authMethod,
      clientSecret: parsed.data.clientSecret,
      clientPrivateKey: parsed.data.clientPrivateKey,
      clientAssertionSigningAlg: parsed.data.clientAssertionSigningAlg,
      allowedAudiences: parsed.data.allowedAudiences,
      createdBy: user.sub,
    });
    const { document: doc, upserted } = result;
    // Force re-fetch of the IdP's JWKS on the next exchangeForIdJag call.
    // Mandatory on a rotation: the operator may have rotated keys at the
    // IdP and we cannot wait for jose's internal cache TTL to expire.
    // Clear the entire cache so a jwksUri *change* (URI-A → URI-B) also
    // evicts URI-A's stale getter — otherwise the per-URI clear only
    // hits the new URI, leaving the old getter in memory forever.
    clearIdpJwksCache();
    // Audit — never include secret material. Field allowlist on detail.
    await audit.log(tenantId, 'id_jag_trust_added', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: {
        kind: 'id_jag_idp_client',
        issuer: doc.issuer,
        tokenEndpoint: doc.tokenEndpoint,
        jwksUri: doc.jwksUri,
        clientId: doc.clientId,
        authMethod: doc.authMethod,
        clientAssertionSigningAlg: doc.clientAssertionSigningAlg,
        allowedAudiences: doc.allowedAudiences,
        upserted,
      },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    // Response — never echo secret material.
    res.status(201).json({
      idpClient: {
        issuer: doc.issuer,
        tokenEndpoint: doc.tokenEndpoint,
        jwksUri: doc.jwksUri,
        clientId: doc.clientId,
        authMethod: doc.authMethod,
        clientAssertionSigningAlg: doc.clientAssertionSigningAlg,
        allowedAudiences: doc.allowedAudiences,
        active: doc.active,
        createdAt: doc.createdAt,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    if (msg.includes('https') || msg.includes('allowedAudiences') || msg.includes('clientSecret') || msg.includes('clientPrivateKey')) {
      res.status(400).json({ error: msg });
      return;
    }
    console.error('[iam/admin-trust] register idp-client failed', err);
    res.status(500).json({ error: 'Failed to register IdP client' });
  }
});

/** GET /idp-clients — list IdP client registrations for the tenant. */
router.get('/idp-clients', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId } = auth;
  try {
    const idpClients = await listIdpClients(tenantId);
    res.json({ idpClients });
  } catch (err) {
    console.error('[iam/admin-trust] list idp-clients failed', err);
    res.status(500).json({ error: 'Failed to list IdP clients' });
  }
});

/** DELETE /idp-clients/:iss — soft-revoke an IdP client registration. */
router.delete('/idp-clients/:iss', async (req: Request, res: Response): Promise<void> => {
  const auth = requireEnterpriseAuth(req, res);
  if (!auth) return;
  const { tenantId, user } = auth;

  const iss = getStringParam(req, 'iss');
  if (!iss) {
    res.status(400).json({ error: 'Missing issuer' });
    return;
  }
  if (iss.startsWith('$') || /[\x00-\x1f\x7f]/.test(iss)) {
    res.status(400).json({ error: 'Invalid issuer' });
    return;
  }
  try {
    const ok = await revokeIdpClient(tenantId, iss);
    if (!ok) {
      res.status(404).json({ error: 'IdP client not found' });
      return;
    }
    // Drop any cached JWKS getter so a re-registration cannot pick up
    // stale keys; we don't know the prior jwksUri without re-reading
    // the doc, so clear the whole cache (safe — getters are rebuilt
    // lazily on the next exchangeForIdJag call).
    clearIdpJwksCache();
    await audit.log(tenantId, 'id_jag_trust_revoked', {
      actorId: user.sub,
      actorEmail: user.email,
      targetType: 'tenant',
      targetId: tenantId,
      detail: { kind: 'id_jag_idp_client', issuer: iss },
      ip: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
    res.status(204).send();
  } catch (err) {
    console.error('[iam/admin-trust] revoke idp-client failed', err);
    res.status(500).json({ error: 'Failed to revoke IdP client' });
  }
});

export default router;
