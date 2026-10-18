/**
 * @epicai/chariot — Per-user OAuth vendor-token refresh job (CHARIOT §10.5)
 *
 * CHARIOT-SPEC.md:1063 — "**Per-user OAuth** — each user authorizes Chariot
 * inside the vendor (Salesforce, GitHub, Google Workspace). Tokens stored
 * encrypted per user. Token refresh: background job every 5 minutes finds
 * tokens within 10 minutes of expiry, refreshes via vendor refresh
 * endpoint, updates `lastRefreshedAt`. On refresh failure (vendor revoked
 * the token), marks `status: 'expired'` and emits an alert."
 *
 * Ruling item 88(6): "The refresh job lands at src/iam/services/
 * credentials.ts as the spec cites, delegating decrypt/CAS to
 * credential-loader.ts." Delegation here means: the SAME decrypt call
 * (`decryptFields` from `./crypto.js`, AAD-bound to `{tenantId,
 * adapterId}`) and the SAME compare-and-set write-back pattern
 * `credential-loader.ts`'s CH-10 upgrade-on-decrypt path establishes —
 * `credential-loader.ts` itself is a pure read-at-dispatch-time function
 * with no timer and nothing to call into for a write path, so this file
 * reimplements the identical CAS shape against the same collection rather
 * than importing a (nonexistent) write helper from it.
 *
 * Ruling item 98 (W3839-B5b, accept-all on the item-88(1) premise finding
 * that no token-endpoint field existed on the adapter record): the catalog
 * record now carries an OPTIONAL `auth.oauth2.tokenUrl` (added to
 * `AdapterEntry` in ChariotState.ts and `ChariotRegistryEntry` in
 * artifacts.ts, top-level, mirroring the existing `tier` field — see both
 * files' doc comments). Absent = non-refreshable; the skip+audit path
 * below is unchanged from the B5 build. `resolveAdapterTokenEndpoint()`
 * reads exactly this field, nothing else — no more `rest.tokenUrl`/
 * `mcp.tokenUrl` guessing.
 *
 * Ruling item 98(2): confidential-client credentials (the TENANT's own
 * vendor OAuth app registration) live on the vault credential document:
 * `clientId` (plain field on `AdapterCredentialDocument`) and
 * `clientSecret` (encrypted with the same vault path as the token
 * fields — folded into the SAME `encrypted`/`iv` blob as `apiKey`/
 * `apiSecret` via `encryptFields`/`decryptFields`'s `fields` object,
 * exactly like this document already does for its other two secret
 * fields, rather than a second `encrypted`/`iv` pair; `AdapterCredentialDocument`
 * itself never carries a plaintext `clientSecret` field — see types.ts's
 * doc comment on `clientId` for why this shape was chosen over a
 * `clientSecretEncrypted` sibling field). The refresh call sends HTTP
 * Basic client auth when both are present (decrypted from the blob) and
 * the bare public-client form (RFC 6749 §4.3.2 second paragraph —
 * `grant_type=refresh_token&refresh_token=...` with no client
 * authentication) otherwise.
 *
 * Ruling item 106 (W3839-B5c): the populate path is now wired. `POST
 * /:id/connect` (src/iam/routes/adapters.ts) validates `clientId`/
 * `clientSecret` via `connectAdapterSchemaWithClientAuth` (both-or-neither,
 * length-bounded, control-char rejected), then writes them through the
 * SAME single `encryptFields` call as `apiKey`/`apiSecret` — one
 * `encrypted`/`iv` blob, never a second ciphertext, never plaintext.
 * `clientId` is `$set` alongside the rest of the document when provided;
 * on a reconnect that omits it, it is explicitly `$unset` (not merely left
 * unset) so a stale `clientId` can never survive paired with a freshly
 * rebuilt blob that no longer carries a matching `clientSecret`. The
 * connect route's audit event carries only a `hasClientAuth` boolean
 * derived from `clientId !== undefined` — never the id or secret values
 * (adapters.ts:258). `/admin/:id/connect-shared` deliberately still uses
 * the base `connectAdapterSchema` — this population path was scoped to
 * the per-user connect route only.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { getCollection } from '../db.js';
import { decryptFields, encryptFields, VaultUpgradePersistFailedError, type DecryptedCredentialResult } from '../crypto.js';
import { chariotEmitter } from '../../observability/emitter.js';
import * as audit from './audit.js';
import { createLogger } from '../../engine/logger.js';
import type { AdapterCredentialDocument } from '../types.js';
import type { AdapterEntry } from '../../engine/server/ChariotState.js';

const log = createLogger('iam.credentials.refresh');

/** §10.5::1 — "background job every 5 minutes". */
export const REFRESH_JOB_INTERVAL_MS = 5 * 60 * 1000;

/** §10.5::1 — "finds tokens within 10 minutes of expiry". */
export const REFRESH_WINDOW_MS = 10 * 60 * 1000;

/**
 * Resolve the vendor OAuth token-refresh endpoint declared for an adapter,
 * or `undefined` when none is declared (credential is non-refreshable).
 *
 * Ruling item 98: reads `adapter.auth.oauth2.tokenUrl` — the field added
 * to `AdapterEntry` in this unit. Absent (the field itself missing, or an
 * empty string) means non-refreshable; the caller's skip+audit path
 * (ruling item 88(1)'s explicit fallback) is unchanged.
 */
export function resolveAdapterTokenEndpoint(adapter: AdapterEntry | undefined): string | undefined {
  const tokenUrl = adapter?.auth?.oauth2?.tokenUrl;
  return typeof tokenUrl === 'string' && tokenUrl.length > 0 ? tokenUrl : undefined;
}

export interface RefreshJobResult {
  scanned: number;
  refreshed: number;
  skippedNonRefreshable: number;
  failed: number;
}

/**
 * Vendor OAuth refresh-endpoint response shape (RFC 6749 §5.1). Vendors
 * commonly omit `refresh_token` on a refresh response (the existing
 * refresh token stays valid) — this is read as "keep the current
 * refresh_token" per RFC 6749 §6, not a missing-field failure.
 */
interface VendorRefreshResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

/**
 * Ruling item 98(2): "the refresh call sends HTTP Basic client auth when
 * both are present and the bare public-client form otherwise." Per
 * RFC 6749 §2.3.1, HTTP Basic auth applies percent-encoding to client_id
 * and client_secret before colon-joining and base64-encoding — done here
 * via `encodeURIComponent`, matching the RFC's `application/
 * x-www-form-urlencoded` component encoding requirement for these values.
 */
export function buildClientAuthHeader(clientId: string, clientSecret: string): string {
  const encoded = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
  return `Basic ${Buffer.from(encoded, 'utf-8').toString('base64')}`;
}

async function callVendorRefreshEndpoint(
  tokenEndpoint: string,
  refreshToken: string,
  fetchImpl: typeof fetch,
  clientAuth?: { clientId: string; clientSecret: string },
): Promise<VendorRefreshResponse | null> {
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (clientAuth) {
    headers.Authorization = buildClientAuthHeader(clientAuth.clientId, clientAuth.clientSecret);
  }
  const res = await fetchImpl(tokenEndpoint, {
    method: 'POST',
    headers,
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken }).toString(),
  });
  if (!res.ok) return null;
  const body: unknown = await res.json().catch(() => null);
  if (
    !body ||
    typeof body !== 'object' ||
    typeof (body as Record<string, unknown>).access_token !== 'string'
  ) {
    return null;
  }
  const b = body as Record<string, unknown>;
  return {
    access_token: b.access_token as string,
    refresh_token: typeof b.refresh_token === 'string' ? b.refresh_token : undefined,
    expires_in: typeof b.expires_in === 'number' ? b.expires_in : undefined,
  };
}

/**
 * §10.5::1/::2 — the background refresh job. Scans every ACTIVE `oauth2`
 * credential row whose `expiresAt` falls within `REFRESH_WINDOW_MS`,
 * refreshes it via the adapter's declared vendor token endpoint (see
 * `resolveAdapterTokenEndpoint`), and on success updates the encrypted
 * fields + `lastRefreshedAt`; on a vendor-revoked failure marks
 * `status: 'expired'` and emits `credential.refresh_failed`; on no
 * declared endpoint, skips with an audit event (ruling item 88(1)'s
 * explicit fallback — never silently drops the row).
 *
 * Intended caller: a `setInterval` in `src/engine/bin/setup.ts`'s HTTP/REST
 * keep-alive block (mirrors the §11.4::2 6-hour license-renewal timer),
 * passed the currently-loaded adapter catalog so `resolveAdapterTokenEndpoint`
 * can look up each row's adapter.
 */
export async function refreshExpiringCredentials(
  adapters: AdapterEntry[],
  options: { fetchImpl?: typeof fetch; now?: Date } = {},
): Promise<RefreshJobResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? new Date();
  const windowEnd = new Date(now.getTime() + REFRESH_WINDOW_MS);

  const adapterById = new Map<string, AdapterEntry>();
  for (const a of adapters) adapterById.set(a.id, a);

  const col = await getCollection<AdapterCredentialDocument>('iam_adapter_credentials');
  const rows = await col
    .find({
      credentialType: 'oauth2',
      status: 'active',
      expiresAt: { $exists: true, $lte: windowEnd },
    })
    .toArray();

  const result: RefreshJobResult = { scanned: rows.length, refreshed: 0, skippedNonRefreshable: 0, failed: 0 };

  for (const row of rows) {
    const adapter = adapterById.get(row.adapterId);
    const tokenEndpoint = resolveAdapterTokenEndpoint(adapter);

    if (!tokenEndpoint) {
      // Ruling item 88(1) fallback: no declared endpoint -> non-refreshable,
      // skip with an audit event. This is the path every adapter takes
      // today (see the file-level doc comment) — never a silent no-op.
      result.skippedNonRefreshable++;
      await audit.log(row.tenantId, 'token_refresh_failed', {
        actorId: 'credential-refresh-job',
        actorEmail: 'credential-refresh-job',
        targetType: 'adapter',
        targetId: row.adapterId,
        detail: {
          skipped: true,
          reason: adapter
            ? 'adapter declares no OAuth token-refresh endpoint'
            : 'adapter not found in the current catalog',
        },
        ip: 'internal',
        userAgent: 'credential-refresh-job',
      });
      continue;
    }

    let decrypted: DecryptedCredentialResult;
    try {
      decrypted = await decryptFields(row.encrypted, row.iv, row.tenantId, row.adapterId);
    } catch (err) {
      // Fail-closed: cannot refresh a row we cannot decrypt. Do not touch
      // status — a transient decrypt failure (e.g. KMS hiccup) is not
      // evidence the vendor revoked the token, so §10.5::2's
      // status:'expired' branch does not apply here.
      log.error('credential refresh: decrypt failed, skipping this cycle', {
        adapterId: row.adapterId,
        tenantId: row.tenantId,
        error: err instanceof Error ? err.message : String(err),
      });
      result.failed++;
      continue;
    }

    const refreshToken = decrypted.fields.apiSecret;
    if (!refreshToken) {
      // No refresh_token stored for this row (e.g. a vendor that issued
      // an access-token-only grant) — nothing this job can do; not a
      // vendor-revoked failure, so status is left untouched.
      result.failed++;
      continue;
    }

    // Ruling item 98(2): confidential-client auth is used ONLY when BOTH
    // clientId (plain document field) and clientSecret (decrypted from
    // the SAME blob as apiKey/apiSecret) are present. Either alone is
    // not enough to construct valid HTTP Basic credentials, so it falls
    // through to the public-client form — never sends a malformed
    // "id:" or ":secret" Authorization header.
    const clientSecret = decrypted.fields.clientSecret;
    const clientAuth =
      row.clientId && clientSecret ? { clientId: row.clientId, clientSecret } : undefined;

    let vendorResponse: VendorRefreshResponse | null;
    try {
      vendorResponse = await callVendorRefreshEndpoint(tokenEndpoint, refreshToken, fetchImpl, clientAuth);
    } catch (err) {
      log.error('credential refresh: vendor endpoint call threw', {
        adapterId: row.adapterId,
        tenantId: row.tenantId,
        error: err instanceof Error ? err.message : String(err),
      });
      vendorResponse = null;
    }

    if (!vendorResponse) {
      // §10.5::2 — "On refresh failure (vendor revoked the token), marks
      // status:'expired' and emits an alert."
      try {
        const casFilter = { _id: row._id, encrypted: row.encrypted };
        await col.updateOne(casFilter, { $set: { status: 'expired' } });
      } catch (writeErr) {
        log.error('credential refresh: failed to mark status expired after a failed vendor refresh', {
          adapterId: row.adapterId,
          tenantId: row.tenantId,
          error: writeErr instanceof Error ? writeErr.message : String(writeErr),
        });
      }
      chariotEmitter.send('credential.refresh_failed', {
        severity: 'warning',
        alertWorthy: true,
        data: { tenantId: row.tenantId, adapterId: row.adapterId },
        message: `Vendor OAuth refresh failed for adapter ${row.adapterId} — credential marked expired.`,
      });
      await audit.log(row.tenantId, 'token_refresh_failed', {
        actorId: 'credential-refresh-job',
        actorEmail: 'credential-refresh-job',
        targetType: 'adapter',
        targetId: row.adapterId,
        detail: { skipped: false, reason: 'vendor refresh endpoint rejected the refresh_token' },
        ip: 'internal',
        userAgent: 'credential-refresh-job',
      });
      result.failed++;
      continue;
    }

    // Success: re-encrypt the new access_token (and refresh_token, if the
    // vendor rotated it — else keep the existing one per RFC 6749 §6) and
    // CAS write-back against the SAME `encrypted` value we just decrypted,
    // exactly like credential-loader.ts's CH-10 upgrade-on-decrypt path —
    // a concurrent writer (another refresh cycle, or a user reconnecting
    // this adapter) that already changed the row makes the CAS match zero
    // documents, an idempotent no-op rather than a clobber.
    const newFields: Record<string, string | undefined> = {
      apiKey: vendorResponse.access_token,
      apiSecret: vendorResponse.refresh_token ?? refreshToken,
      // Carry clientSecret forward unchanged, re-encrypted into the new
      // blob. A refresh cycle never rotates the confidential-client
      // secret itself (that would need a separate vendor-app-management
      // flow, out of scope here) — omitting it from newFields would
      // silently DROP it from the document on the very next refresh,
      // turning a confidential client back into a public one.
      clientSecret,
    };
    const { encrypted, iv } = encryptFields(newFields, row.tenantId, row.adapterId);
    const newExpiresAt = vendorResponse.expires_in
      ? new Date(now.getTime() + vendorResponse.expires_in * 1000)
      : row.expiresAt;

    try {
      const casFilter = { _id: row._id, encrypted: row.encrypted };
      const update = await col.updateOne(casFilter, {
        $set: { encrypted, iv, expiresAt: newExpiresAt, lastRefreshedAt: now, status: 'active' },
      });
      if (update.matchedCount === 0) {
        // CAS miss — another writer already moved this row this cycle.
        // Not a failure; the row is refreshed by whoever won the race.
        continue;
      }
      result.refreshed++;
      await audit.log(row.tenantId, 'token_refreshed', {
        actorId: 'credential-refresh-job',
        actorEmail: 'credential-refresh-job',
        targetType: 'adapter',
        targetId: row.adapterId,
        ip: 'internal',
        userAgent: 'credential-refresh-job',
      });
    } catch (writeErr) {
      log.error('credential refresh: CAS write-back of refreshed token failed', {
        adapterId: row.adapterId,
        tenantId: row.tenantId,
        error: writeErr instanceof Error ? writeErr.message : String(writeErr),
      });
      throw new VaultUpgradePersistFailedError('credentials.refresh', row.adapterId, writeErr);
    }
  }

  return result;
}
