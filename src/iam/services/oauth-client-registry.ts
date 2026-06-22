/**
 * IAM — ID-JAG OAuth client registry.
 *
 * Per-tenant CRUD for OAuth clients registered with Chariot's token
 * endpoint (POST /enterprise/oauth/token). security-review Critical #1: the
 * assertion's `iss` MUST be in the client's `allowedIssuers[]` list,
 * AND the assertion's `client_id` claim MUST equal the authenticated
 * client_id (client-continuity rule enforced in id-jag-validator.ts).
 *
 * Three auth methods supported per RFC 6749 §2.3 and RFC 7523:
 *   client_secret_basic, client_secret_post, private_key_jwt
 *
 * Plan §284 + Security Posture #10: client secrets MUST be ≥ 32 random
 * bytes generated server-side. Plaintext is returned exactly once at
 * registration time and never persisted; only the SHA-256 hash (via
 * crypto.ts:hashToken) is stored. Caller-supplied secrets are refused.
 */

import { randomBytes } from 'node:crypto';
import type { Filter } from 'mongodb';

import { getCollection } from '../db.js';
import { hashToken, verifyToken } from '../crypto.js';
import { ensureHttps } from '../utils/url.js';
import type {
  OAuthClientAuthMethod,
  OAuthClientDocument,
} from '../types.js';
import type {
  ClientRegistryPort,
  OAuthClientView,
} from './id-jag-validator.js';

const COLLECTION = 'iam_id_jag_oauth_clients';
const CLIENT_SECRET_BYTES = 32; // 256 bits of entropy per plan §284.

function projectView(doc: OAuthClientDocument): OAuthClientView {
  return {
    clientId: doc.clientId,
    allowedIssuers: doc.allowedIssuers,
  };
}

// ── ClientRegistryPort (validator-facing) ────────────────────────────────────

export const clientRegistry: ClientRegistryPort = {
  async getClient(tenantId, clientId) {
    const doc = await findClient(tenantId, clientId);
    return doc ? projectView(doc) : null;
  },
};

/**
 * Internal lookup returning the full active OAuthClientDocument. Used by
 * routes/oauth.ts authenticateClient so a single Mongo read serves both
 * the client-auth check and the validator's prefetchedClient hand-off,
 * avoiding the two-findOne pattern that the per-request hot path would
 * otherwise pay (a second read of the same row via clientRegistry.getClient).
 */
export async function findClient(
  tenantId: string,
  clientId: string,
): Promise<OAuthClientDocument | null> {
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  return col.findOne({ tenantId, clientId, active: true });
}

/**
 * Return EVERY active tenant that has registered the given client_id.
 *
 * draft-04 §6.2 permits the same client_id to exist in more than one
 * tenant. When it does, the authoritative tenant for a token/revoke
 * request cannot be chosen by client_id alone — it is the tenant whose
 * registration the PRESENTED client credential authenticates against.
 * routes/oauth.ts:resolveClientTenant performs that credential-based
 * disambiguation over this candidate set. Returns [] for an absent
 * client_id. Backed by the { clientId, active } index.
 */
export async function findCandidateTenantIdsForClient(
  clientId: string,
): Promise<string[]> {
  if (!clientId) return [];
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  const matches = await col
    .find({ clientId, active: true }, { projection: { tenantId: 1 } })
    .toArray();
  return matches.map((m) => m.tenantId);
}

/**
 * Project the public view (clientId + allowedIssuers) from an already-
 * loaded document — used to feed prefetchedClient to the validator.
 */
export function clientViewFromDoc(doc: OAuthClientDocument): OAuthClientView {
  return projectView(doc);
}

// ── Client authentication helpers (used by routes/oauth.ts in commit 4) ─────

/**
 * Verify a client_secret_basic or client_secret_post secret against the
 * registered client. Returns true on success; false on unknown client,
 * inactive client, wrong method, or hash mismatch. Timing-safe via
 * crypto.ts:verifyToken.
 */
export async function verifyClientSecret(
  tenantId: string,
  clientId: string,
  presentedSecret: string,
): Promise<boolean> {
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  const doc = await col.findOne({ tenantId, clientId, active: true });
  if (!doc) return false;
  if (doc.authMethod !== 'client_secret_basic' && doc.authMethod !== 'client_secret_post') {
    return false;
  }
  if (!doc.clientSecretHash) return false;
  return verifyToken(presentedSecret, doc.clientSecretHash);
}

/**
 * Look up the jwks_uri for a private_key_jwt client. The actual JWT
 * verification of the client_assertion lives in routes/oauth.ts (commit
 * 4) using jose; this helper just resolves the URI.
 */
export async function getClientJwksUri(
  tenantId: string,
  clientId: string,
): Promise<string | null> {
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  const doc = await col.findOne({ tenantId, clientId, active: true });
  if (!doc) return null;
  if (doc.authMethod !== 'private_key_jwt') return null;
  return doc.jwksUri ?? null;
}

// ── CRUD (admin-facing; consumed by routes/admin-trust.ts in commit 5) ──────

export interface RegisterClientInput {
  tenantId: string;
  clientId: string;
  authMethod: OAuthClientAuthMethod;
  /**
   * Required for `private_key_jwt`. MUST be omitted for the
   * `client_secret_*` methods (the registry generates the secret).
   */
  jwksUri?: string;
  allowedIssuers: string[];
  redirectUris?: string[];
  createdBy: string;
}

export interface RegisterClientResult {
  /** Persisted document. */
  document: OAuthClientDocument;
  /**
   * Plaintext client secret. Present iff authMethod is
   * `client_secret_basic` or `client_secret_post`. Returned to the
   * operator exactly once at registration time and never persisted.
   */
  clientSecret?: string;
  /**
   * True when this call inserted a new row; false on a rotation
   * (upsert matched an existing row). Surfaced in the audit detail so
   * SOC 2 change-management evidence distinguishes a fresh client
   * registration from a credential rotation.
   */
  upserted: boolean;
}

export async function registerClient(input: RegisterClientInput): Promise<RegisterClientResult> {
  if (input.allowedIssuers.length === 0) {
    throw new Error('allowedIssuers must not be empty');
  }
  if (input.authMethod === 'private_key_jwt') {
    if (!input.jwksUri) {
      throw new Error('jwksUri is required for private_key_jwt');
    }
    ensureHttps(input.jwksUri, 'jwksUri');
  } else {
    if (input.jwksUri !== undefined) {
      throw new Error('jwksUri MUST be omitted for client_secret_* methods');
    }
  }
  for (const uri of input.redirectUris ?? []) {
    ensureHttps(uri, 'redirectUris[]');
  }

  let plaintextSecret: string | undefined;
  let secretHash: string | undefined;
  if (input.authMethod !== 'private_key_jwt') {
    plaintextSecret = randomBytes(CLIENT_SECRET_BYTES).toString('base64url');
    secretHash = hashToken(plaintextSecret);
  }

  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  // Per-(tenant, clientId) uniqueness via upsert. Re-registration rotates
  // the secret (or jwksUri) and reactivates the client. createdAt and
  // createdBy are preserved via $setOnInsert so re-registration audit
  // attribution lives in the audit trail, not on the document.
  //
  // Mongo's $set silently ignores fields set to `undefined`, so we
  // explicitly $unset the field that the new auth method doesn't use
  // (a switch from private_key_jwt → client_secret_* would otherwise
  // leave a stale jwksUri behind, and vice-versa). Both registries hit
  // verifyClientSecret / getClientJwksUri at runtime so stale fields
  // would let a prior auth method's credential remain comparable.
  const now = new Date();
  const $set: Record<string, unknown> = {
    authMethod: input.authMethod,
    allowedIssuers: input.allowedIssuers,
    redirectUris: input.redirectUris ?? [],
    active: true,
  };
  const $unset: Record<string, ''> = {};
  if (secretHash !== undefined) {
    $set.clientSecretHash = secretHash;
  } else {
    $unset.clientSecretHash = '';
  }
  if (input.jwksUri !== undefined) {
    $set.jwksUri = input.jwksUri;
  } else {
    $unset.jwksUri = '';
  }
  const update: Record<string, unknown> = {
    $set,
    $setOnInsert: {
      tenantId: input.tenantId,
      clientId: input.clientId,
      createdAt: now,
      createdBy: input.createdBy,
    },
  };
  if (Object.keys($unset).length > 0) {
    update.$unset = $unset;
  }
  const doc = await col.findOneAndUpdate(
    { tenantId: input.tenantId, clientId: input.clientId },
    update,
    { upsert: true, returnDocument: 'after' },
  );
  if (!doc) {
    throw new Error('oauth client upsert did not persist');
  }
  // Detect insert vs rotation by comparing the post-write createdAt
  // to the value we passed via $setOnInsert: equal → just inserted;
  // different → existed already and $setOnInsert was a no-op.
  const upserted = doc.createdAt instanceof Date && doc.createdAt.getTime() === now.getTime();
  return plaintextSecret !== undefined
    ? { document: doc, clientSecret: plaintextSecret, upserted }
    : { document: doc, upserted };
}

/**
 * List OAuth clients for the tenant. Active-only by default — the
 * server-side projection drops `clientSecretHash` so it never crosses
 * any internal boundary. Pass `{ includeInactive: true }` to view the
 * full history (audit tooling only).
 */
export async function listClients(
  tenantId: string,
  opts?: { includeInactive?: boolean },
): Promise<OAuthClientDocument[]> {
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  const filter: Filter<OAuthClientDocument> = opts?.includeInactive
    ? ({ tenantId } as Filter<OAuthClientDocument>)
    : ({ tenantId, active: true } as Filter<OAuthClientDocument>);
  // tenantId also dropped from the projection — the caller's session
  // is already tenant-scoped so re-shipping the field on every row is
  // redundant wire bytes.
  return col.find(filter, { projection: { clientSecretHash: 0, tenantId: 0 } }).toArray();
}

export async function revokeClient(
  tenantId: string,
  clientId: string,
): Promise<boolean> {
  const col = await getCollection<OAuthClientDocument>(COLLECTION);
  const res = await col.updateOne({ tenantId, clientId }, { $set: { active: false } });
  return res.modifiedCount === 1;
}

/**
 * Test seam: in-memory client registry honoring the same port contract.
 * Production code consumes `clientRegistry` above.
 */
export function buildInMemoryClientRegistry(
  entries: Array<{
    tenantId: string;
    clientId: string;
    allowedIssuers: string[];
    active?: boolean;
  }>,
): ClientRegistryPort {
  return {
    async getClient(tenantId, clientId) {
      const hit = entries.find(
        (e) => e.tenantId === tenantId && e.clientId === clientId && e.active !== false,
      );
      if (!hit) return null;
      return { clientId: hit.clientId, allowedIssuers: hit.allowedIssuers };
    },
  };
}
