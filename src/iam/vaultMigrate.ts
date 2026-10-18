/**
 * @epicai/chariot — CH-10 (§12.2) vault legacy-ciphertext migration.
 *
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: "One-shot
 * MIGRATION — `chariot vault migrate --tenant <id>|--all [--dry-run]` ...
 * walks every stored ciphertext, upgrades legacy ones, reports counts
 * {legacy, upgraded, failed, alreadyV2}, refuses to run without
 * ENTERPRISE_MASTER_KEY, and writes a migration marker record (per
 * tenant) when zero legacy records remain."
 *
 * Extracted from `src/bin/chariot.ts`'s `cmdVault` into its own module
 * (gate finding F1, 2026-09-04) so `migrateTenant`/`discoverAllTenantIds`
 * are directly importable and unit-testable with fake/in-memory Mongo and
 * Redis clients — `chariot.ts` itself auto-runs `main()` at import time
 * (a CLI entry point, not a library), which made testing this logic
 * in-process impossible while it lived there. `chariot.ts`'s `cmdVault`
 * now only parses argv, connects the real Mongo/Redis clients, calls
 * these exports, and formats the human/agent-mode report.
 *
 * See `src/iam/vaultMigrationSites.ts` for the registered-site manifest
 * this module's walk is derived from, and that file's coverage test for
 * the anti-drift enforcement.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { EPIC_AI_DIR } from '../cli/paths.js';
import { createClient, type RedisClientType } from 'redis';

export interface VaultMigrateCounts {
  legacy: number;
  upgraded: number;
  failed: number;
  alreadyV2: number;
}

export function emptyVaultMigrateCounts(): VaultMigrateCounts {
  return { legacy: 0, upgraded: 0, failed: 0, alreadyV2: 0 };
}

export function addVaultMigrateCounts(a: VaultMigrateCounts, b: VaultMigrateCounts): VaultMigrateCounts {
  return {
    legacy: a.legacy + b.legacy,
    upgraded: a.upgraded + b.upgraded,
    failed: a.failed + b.failed,
    alreadyV2: a.alreadyV2 + b.alreadyV2,
  };
}

/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: "walks every
 * stored ciphertext, upgrades legacy ones, reports counts {legacy,
 * upgraded, failed, alreadyV2}", and the marker is written "when zero
 * legacy records remain" — per gate finding F1, that claim is now proven
 * by walking EVERY site `src/iam/vaultMigrationSites.ts` registers, not
 * only the three Mongo collections. Walks, for ONE tenantId:
 *   1. iam_adapter_credentials, iam_tenants (settings.oidc / sso.oidc),
 *      iam_id_jag_idp_clients — inline, sharing this function's Mongo
 *      connection (per-tenant-mongo-inline sites).
 *   2. src/iam/services/session.ts::walkLegacyIdJagSubjectTokens — Redis
 *      ID-JAG subject_token records, ONLY when `redis` is a connected
 *      client (never the in-process shim — see cmdVault below for why).
 *      When Redis is unavailable, `redisSkipped: true` is reported and
 *      the marker is refused for THIS tenant, because "zero remain" is
 *      then an unproven claim, not a walked fact.
 *   3. src/engine/recovery/SqliteCheckpointStore.ts::walkLegacyCheckpointCiphertexts
 *      — always walked (local file, no connectivity precondition); a
 *      missing db file walks as vacuously clean (0 rows), not skipped.
 *   4. src/engine/audit/chainSigner.ts::walkSealedStoreLegacyArtifacts —
 *      ONLY when `tenantId === SEALED_TENANT_ID` ('chariot-audit'), the
 *      pseudo-tenant `createSealedStoreSigner`'s own upgrade-on-decrypt
 *      already uses for this non-tenant-scoped artifact. `--all` always
 *      includes this pseudo-tenant (discoverAllTenantIds below); a bare
 *      `--tenant <id>` sweep of a REAL tenant never touches it, and never
 *      needs to — it is not that tenant's data.
 */
export async function migrateTenant(
  db: import('mongodb').Db,
  tenantId: string,
  dryRun: boolean,
  redis: RedisClientType | null,
  checkpointDbPath: string,
): Promise<VaultMigrateCounts & { markerWritten: boolean; markerRefusedReason?: string }> {
  const {
    encryptFields,
    decryptFieldsForVaultMigration,
    isLegacyCiphertext,
    splitEncryptedIv,
    VAULT_MIGRATIONS_COLLECTION,
  } = await import('./crypto.js');
  const counts = emptyVaultMigrateCounts();

  const upgradeCombinedBlob = async (
    combined: string,
    recordId: string,
  ): Promise<{ newCombined: string } | null> => {
    const parts = splitEncryptedIv(combined);
    if (!parts) return null; // malformed — not counted as legacy or v2; left untouched.
    if (!isLegacyCiphertext(parts.encrypted)) {
      counts.alreadyV2++;
      return null;
    }
    counts.legacy++;
    try {
      const { fields } = await decryptFieldsForVaultMigration(parts.encrypted, parts.iv, tenantId, recordId);
      const { encrypted, iv } = encryptFields(fields, tenantId, recordId);
      counts.upgraded++;
      return { newCombined: `${encrypted}:${iv}` };
    } catch {
      counts.failed++;
      return null;
    }
  };

  // ── iam_adapter_credentials — {encrypted, iv} as SEPARATE fields ────────
  {
    const col = db.collection('iam_adapter_credentials');
    const rows = await col.find({ tenantId }).toArray();
    for (const row of rows) {
      const recordId: string = row.adapterId;
      if (isLegacyCiphertext(row.encrypted)) {
        counts.legacy++;
        try {
          const { fields } = await decryptFieldsForVaultMigration(row.encrypted, row.iv, tenantId, recordId);
          const { encrypted, iv } = encryptFields(fields, tenantId, recordId);
          counts.upgraded++;
          if (!dryRun) {
            // CAS: only replace a row that still holds exactly the legacy
            // ciphertext read — a concurrent upgrader's write is a no-op.
            await col.updateOne({ _id: row._id, encrypted: row.encrypted }, { $set: { encrypted, iv } });
          }
        } catch {
          counts.failed++;
        }
      } else {
        counts.alreadyV2++;
      }
    }
  }

  // ── iam_tenants — settings.oidc / sso.oidc clientSecretEncrypted, COMBINED "encrypted:iv" blob ──
  {
    const col = db.collection('iam_tenants');
    const tenantDoc = await col.findOne({ tenantId });
    if (tenantDoc) {
      for (const field of ['settings.oidc.clientSecretEncrypted', 'sso.oidc.clientSecretEncrypted'] as const) {
        const parts = field.split('.');
        let value: unknown = tenantDoc as unknown;
        for (const p of parts) value = (value as Record<string, unknown> | undefined)?.[p];
        if (typeof value !== 'string' || value.length === 0) continue;
        const result = await upgradeCombinedBlob(value, 'oidc-client-secret');
        if (result && !dryRun) {
          // CAS: only replace if this field still holds the exact legacy blob read.
          await col.updateOne({ tenantId, [field]: value }, { $set: { [field]: result.newCombined } });
        }
      }
    }
  }

  // ── iam_id_jag_idp_clients — clientSecretEncrypted / clientPrivateKeyEncrypted, COMBINED blobs ──
  {
    const col = db.collection('iam_id_jag_idp_clients');
    const rows = await col.find({ tenantId }).toArray();
    for (const row of rows) {
      if (typeof row.clientSecretEncrypted === 'string' && row.clientSecretEncrypted.length > 0) {
        const result = await upgradeCombinedBlob(row.clientSecretEncrypted, `${row.issuer}:client-secret`);
        if (result && !dryRun) {
          await col.updateOne(
            { _id: row._id, clientSecretEncrypted: row.clientSecretEncrypted },
            { $set: { clientSecretEncrypted: result.newCombined } },
          );
        }
      }
      if (typeof row.clientPrivateKeyEncrypted === 'string' && row.clientPrivateKeyEncrypted.length > 0) {
        const result = await upgradeCombinedBlob(row.clientPrivateKeyEncrypted, `${row.issuer}:client-private-key`);
        if (result && !dryRun) {
          await col.updateOne(
            { _id: row._id, clientPrivateKeyEncrypted: row.clientPrivateKeyEncrypted },
            { $set: { clientPrivateKeyEncrypted: result.newCombined } },
          );
        }
      }
    }
  }

  // ── src/engine/recovery/SqliteCheckpointStore.ts (always walked) ───────
  {
    const { walkLegacyCheckpointCiphertexts } = await import('../engine/recovery/SqliteCheckpointStore.js');
    const sqliteCounts = await walkLegacyCheckpointCiphertexts(checkpointDbPath, tenantId, { dryRun });
    Object.assign(counts, addVaultMigrateCounts(counts, sqliteCounts));
  }

  // ── src/iam/services/session.ts Redis subject_token records ────────────
  let redisSkipped = false;
  if (redis) {
    const { walkLegacyIdJagSubjectTokens, setRedisClient } = await import('./services/session.js');
    setRedisClient(redis);
    const redisCounts = await walkLegacyIdJagSubjectTokens(tenantId, dryRun);
    Object.assign(counts, addVaultMigrateCounts(counts, redisCounts));
  } else {
    redisSkipped = true;
  }

  // ── src/engine/audit/chainSigner.ts sealed-store artifact (pseudo-tenant only) ──
  {
    const { SEALED_TENANT_ID, walkSealedStoreLegacyArtifacts } = await import('../engine/audit/chainSigner.js');
    if (tenantId === SEALED_TENANT_ID) {
      const sealedCounts = await walkSealedStoreLegacyArtifacts(EPIC_AI_DIR, dryRun);
      Object.assign(counts, addVaultMigrateCounts(counts, sealedCounts));
    }
  }

  const remaining = counts.legacy - counts.upgraded;
  let markerWritten = false;
  let markerRefusedReason: string | undefined;
  if (dryRun) {
    markerRefusedReason = 'dry-run — never writes a marker';
  } else if (redisSkipped) {
    // F1: a marker claiming "zero legacy remain" is unproven if an entire
    // registered site (Redis) could not be walked — refuse rather than
    // write an unproven marker, even if every OTHER site is clean.
    markerRefusedReason = 'Redis unreachable/unconfigured — session-idjag-subject-token site was not walked, so "zero remain" is unproven';
  } else if (remaining !== 0) {
    markerRefusedReason = `${remaining} legacy record(s) remain across walked sites`;
  } else {
    const col = db.collection<import('./crypto.js').VaultMigrationMarkerDocument>(VAULT_MIGRATIONS_COLLECTION);
    await col.updateOne(
      { _id: tenantId },
      { $set: { tenantId, migratedAt: new Date(), counts: { ...counts } } },
      { upsert: true },
    );
    markerWritten = true;
  }

  return { ...counts, markerWritten, markerRefusedReason };
}

export async function discoverAllTenantIds(db: import('mongodb').Db): Promise<string[]> {
  const { SEALED_TENANT_ID } = await import('../engine/audit/chainSigner.js');
  const [a, b, c] = await Promise.all([
    db.collection('iam_tenants').distinct('tenantId'),
    db.collection('iam_adapter_credentials').distinct('tenantId'),
    db.collection('iam_id_jag_idp_clients').distinct('tenantId'),
  ]);
  // SEALED_TENANT_ID ('chariot-audit') is not a real tenant, but --all
  // must still sweep the sealed-store artifact registered under it
  // (src/iam/vaultMigrationSites.ts) — otherwise a full-fleet migration
  // could never prove that site clean and could never write its marker.
  return [...new Set([...a, ...b, ...c, SEALED_TENANT_ID] as string[])];
}

/**
 * Connect to Redis for the migration's session-token walk. Deliberately
 * NOT `resolveEnterpriseRedisClient` (src/iam/resolveEnterpriseRedis.ts):
 * that helper falls back to an EMPTY in-process shim when `REDIS_URL` is
 * unset or unreachable — silently walking zero keys and reporting "0
 * legacy" as if the real store were clean. For THIS command that false
 * negative is exactly the F1 failure mode (a marker proven clean by an
 * empty stand-in, not a walk), so an unset/unreachable REDIS_URL here
 * means "could not walk", not "nothing to walk" — see `redisSkipped` in
 * migrateTenant above.
 */
export async function connectVaultRedis(): Promise<RedisClientType | null> {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl || redisUrl.trim() === '') return null;
  // `createClient(options)` infers its generic (module/function/script/
  // RESP-version) type parameters from `options`'s shape rather than
  // defaulting them the same way the bare `RedisClientType` alias does
  // (RESP defaults to '2' either way, but TS still treats the inferred
  // instantiation and the bare alias as structurally distinct types here)
  // — the SAME cast `src/iam/resolveEnterpriseRedis.ts` already uses for
  // an identical `createClient(...)` call, not a widen-through-any/unknown.
  const client = createClient({ url: redisUrl, socket: { reconnectStrategy: false } }) as RedisClientType;
  client.on('error', () => { /* swallow post-connect errors; caller treats unusable as null */ });
  try {
    await client.connect();
    return client;
  } catch {
    return null;
  }
}

