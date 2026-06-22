/**
 * @epicai/chariot — IAM Credential Loader (Phase R.4)
 *
 * Bridges the encrypted-at-rest IAM credential vault
 * (Mongo collection `iam_adapter_credentials`) into the runtime credential
 * map consumed by `toolHandlers.ts` Cases 1 / 2 / 4 / 5 dispatch.
 *
 * Multi-tenant flow:
 *   1. `handleCall` detects Enterprise IAM mode (`context.auth` populated).
 *   2. Calls `loadIamCredentialsForTenant(tenantId, state.allAdapters)`.
 *   3. Decrypts each per-tenant credential row via `decryptFields`.
 *   4. Maps the vault's `apiKey` / `apiSecret` fields onto the env-var name
 *      declared by the matching adapter (`rest.envKey`,
 *      `mcp.authEnvKey`, `mcp.envKeys[0]`, or `cli.envKeys[0]`).
 *   5. Returns a flat `Record<string, string>` that `handleCall` overlays
 *      on top of `state.credentials` for the duration of the call.
 *
 * Single-user flow: this loader is never invoked. The OSS path loads
 * `~/.epic-ai/.env` once at server start via `cli/credentials.ts` and
 * the dispatcher reads `state.credentials` directly.
 *
 * Fail-closed: per-row decrypt failures are logged and skipped (the row
 * does not silently become an empty credential). `handleCall` treats a
 * thrown error from this function as a hard deny — see spec §15 risk
 * "IAM vault decryption fails open instead of closed".
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { getCollection } from './db.js';
import { decryptFields } from './crypto.js';
import { createLogger } from '../engine/logger.js';
import type { AdapterCredentialDocument } from './types.js';
import type { AdapterEntry } from '../engine/server/ChariotState.js';

const log = createLogger('iam.credential-loader');

/**
 * Resolve the primary env-var name an adapter expects for its credential.
 * Walks the adapter shape in priority order:
 *   1. `rest.envKey`           — REST module dispatch (Case 1)
 *   2. `mcp.authEnvKey`        — streamable-http dispatch (Case 4)
 *   3. `mcp.envKeys[0]`        — stdio dispatch (Case 2)
 *   4. `cli.envKeys[0]`        — cli-bridge dispatch (Case 5)
 * Returns null when the adapter declares no credential surface
 * (public, unauthenticated adapters).
 */
function primaryEnvKey(adapter: AdapterEntry): string | null {
  return (
    adapter.rest?.envKey ??
    adapter.mcp?.authEnvKey ??
    adapter.mcp?.envKeys?.[0] ??
    adapter.cli?.envKeys?.[0] ??
    null
  );
}

/**
 * Resolve the secondary env-var name for two-field credentials
 * (`apiSecret` companions). Prefers an explicit declaration when present
 * (`mcp.envKeys[1]` or `cli.envKeys[1]`), otherwise derives a
 * `<PRIMARY>_SECRET` sibling.
 */
function secondaryEnvKey(adapter: AdapterEntry, primary: string): string {
  return (
    adapter.mcp?.envKeys?.[1] ??
    adapter.cli?.envKeys?.[1] ??
    (primary.endsWith('_KEY') ? primary.replace(/_KEY$/, '_SECRET') : `${primary}_SECRET`)
  );
}

/**
 * Load and decrypt all active IAM credentials for a tenant, returning a
 * flat env-var → value map ready to overlay onto `state.credentials`.
 *
 * @param tenantId The tenant whose credentials to load. Decryption is
 *   keyed on this tenant id via HKDF-SHA256; using a wrong tenant id
 *   produces a `decryptFields` exception (fail-closed).
 * @param adapters The shipped adapter catalog — needed to translate
 *   each IAM row's `adapterId` into the env-var name(s) the dispatcher
 *   will look up at call time.
 */
export async function loadIamCredentialsForTenant(
  tenantId: string,
  adapters: AdapterEntry[],
  userId?: string,
): Promise<Record<string, string>> {
  if (!tenantId) {
    throw new Error('loadIamCredentialsForTenant: tenantId is required');
  }

  const adapterById = new Map<string, AdapterEntry>();
  for (const a of adapters) adapterById.set(a.id, a);

  const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
  // distinguish per-user vs shared. Per-user credentials match
  // when `connectedBy === userId`; org-wide shared credentials (an admin
  // attached the credential for all users) match when `shared === true`.
  // A per-user row connected by a DIFFERENT user must NOT be loaded into
  // this caller's env — that was the silent cross-user leak.
  const baseFilter: Record<string, unknown> = { tenantId, status: 'active' };
  const filter: Record<string, unknown> = userId
    ? { ...baseFilter, $or: [{ shared: true }, { connectedBy: userId }] }
    : { ...baseFilter, shared: true };
  const rows = await col.find(filter).toArray();

  const creds: Record<string, string> = {};

  for (const row of rows) {
    const adapter = adapterById.get(row.adapterId);
    if (!adapter) {
      // Orphan IAM row pointing at an adapter no longer in the catalog.
      // Skip — the dispatcher would have no path for this adapter anyway.
      continue;
    }
    const primary = primaryEnvKey(adapter);
    if (!primary) {
      // Adapter declares no credential surface; nothing to map onto.
      continue;
    }

    let decrypted: Record<string, string>;
    try {
      decrypted = decryptFields(row.encrypted, row.iv, tenantId);
    } catch (err) {
      // FAIL CLOSED — must throw so handleCall denies the call. Silently
      // skipping an active row would let dispatch proceed with no/partial
      // credentials, which is exactly the open-fail mode Phase R was added
      // to prevent. Log first, then propagate.
      log.error('iam credential decrypt failed — denying call', {
        adapterId: row.adapterId,
        tenantId,
        error: err instanceof Error ? err.message : String(err),
      });
      throw new Error(
        `IAM credential decrypt failed for tenant=${tenantId} adapter=${row.adapterId}: ` +
          (err instanceof Error ? err.message : String(err)),
      );
    }

    if (typeof decrypted.apiKey === 'string' && decrypted.apiKey.length > 0) {
      creds[primary] = decrypted.apiKey;
    }
    if (typeof decrypted.apiSecret === 'string' && decrypted.apiSecret.length > 0) {
      creds[secondaryEnvKey(adapter, primary)] = decrypted.apiSecret;
    }
  }

  return creds;
}
