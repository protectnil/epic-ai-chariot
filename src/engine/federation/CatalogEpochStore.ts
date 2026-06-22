/**
 * @epicai/chariot — Catalog Epoch Store (/ closure)
 *
 * The catalog epoch is Chariot's anti-rollback root: a monotonic
 * (epoch, catalogVersion) pair persisted on accept. Every subsequent
 * bundle load must strictly exceed the persisted epoch; downgrades and
 * replays are rejected.
 *
 * Two backing stores ship in this module:
 *   - FileEpochStore (default) — per-instance file at
 *     <packageRoot>/.chariot-catalog-epoch.json. Single-host / Free-tier
 * deployments use this. The same code path that landed under  *     remains correct here; this class is a thin object-oriented wrapper.
 *   - MongoEpochStore — shared across replicas via the IAM Mongo client.
 *     Multi-replica enterprise deployments select this with
 *     CHARIOT_EPOCH_STORE=mongo. Closes the eval 08 Test 14 finding that
 * 's defense is per-instance only — a fresh replica with no
 *     local epoch file would accept a historically-signed bundle even
 *     when a newer one had already been accepted on a sibling replica.
 *
 * Store selection:
 *   CHARIOT_EPOCH_STORE=file (default)
 *   CHARIOT_EPOCH_STORE=mongo
 *
 * The Mongo store reuses the existing IAM Mongo client from
 * src/iam/db.ts (setMongoClient is called by bootstrapEnterprise).
 * Collection name: `chariot_catalog_epoch`. Keyed by an opaque
 * deployment-family identifier (default "default" — operators with
 * multiple catalog families per cluster set CHARIOT_EPOCH_STORE_KEY).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { getCollection } from '../../iam/db.js';
import { loadPersistedEpoch, persistEpoch, type CatalogEpochState } from './AdapterCatalog.js';
import { createLogger } from '../logger.js';

const log = createLogger('epicai.federation.catalog');

export const EPOCH_COLLECTION_NAME = 'chariot_catalog_epoch';
export const DEFAULT_EPOCH_STORE_KEY = 'default';

/**
 * Returned by load(). null when no prior baseline exists (fresh install
 * or replica with no shared-store row yet).
 */
export type LoadedEpoch = CatalogEpochState | null;

/**
 * The contract every backing store implements. Implementations MUST
 * preserve the /invariants:
 *   - load() returns the highest-water-mark visible to this instance
 *   - persistIfNewer() only persists when the incoming envelope is
 *     strictly newer (epoch > persisted OR equal-epoch with
 *     catalogVersion >= persisted) and returns the post-write state
 */
export interface CatalogEpochStore {
  load(): Promise<LoadedEpoch>;
  /**
   * Persist envelope unconditionally. Monotonicity is enforced by the
   * caller (AdapterCatalog.enforceMonotonicityAndPersist) before this is
   * invoked. Implementations are free to add a defense-in-depth CAS guard
   * but the canonical accept path is: load() → check → persist().
   */
  persist(envelope: CatalogEpochState): Promise<void>;
  /** Human-readable label for log lines (e.g. "file:/path", "mongo:default"). */
  describe(): string;
}

/**
 * File-backed store — wraps the existing loadPersistedEpoch /
 * persistEpoch functions. Single-host correctness; not safe across
 * replicas because each replica writes to its own filesystem.
 */
export class FileEpochStore implements CatalogEpochStore {
  constructor(private readonly epochPath: string) {}

  load(): Promise<LoadedEpoch> {
    return Promise.resolve(loadPersistedEpoch(this.epochPath));
  }

  persist(envelope: CatalogEpochState): Promise<void> {
    persistEpoch(this.epochPath, envelope);
    return Promise.resolve();
  }

  describe(): string {
    return `file:${this.epochPath}`;
  }
}

interface EpochDoc {
  _id: string;
  epoch: number;
  catalogVersion: number;
  updatedAt: Date;
}

/**
 * Mongo-backed store — single document per deployment family. Every
 * replica that boots against the same Mongo cluster shares this single
 * row. A bundle accepted on replica A becomes immediately visible to
 * replica B's next catalog load, closing the cross-instance rollback
 * gap that eval 08 Test 14 reports.
 *
 * Concurrency posture: the canonical accept path in
 * AdapterCatalog.enforceMonotonicityAndPersist does load → compare →
 * persist. Two replicas accepting concurrently could otherwise race
 * (T1 reads epoch=5, T2 reads epoch=5, both writeOne with $set, the
 * later writer wins regardless of which envelope was newer). persist()
 * uses a monotonic CAS predicate via findOneAndUpdate so the write
 * only lands when the candidate is strictly newer than the persisted
 * row. The caller still does the load-compare-persist sequence; the
 * CAS is a defense-in-depth guard that prevents a sibling-replica
 * write from regressing this replica's accepted state.
 */
export class MongoEpochStore implements CatalogEpochStore {
  constructor(private readonly key: string) {}

  async load(): Promise<LoadedEpoch> {
    try {
      const coll = await getCollection<EpochDoc>(EPOCH_COLLECTION_NAME);
      const doc = await coll.findOne({ _id: this.key });
      if (!doc) return null;
      if (!Number.isInteger(doc.epoch) || !Number.isInteger(doc.catalogVersion)) {
        log.warn('adapter-catalog.mongo_epoch_malformed', {
          key: this.key,
          epoch: doc.epoch,
          catalogVersion: doc.catalogVersion,
        });
        return null;
      }
      return { epoch: doc.epoch, catalogVersion: doc.catalogVersion };
    } catch (err) {
      log.error('adapter-catalog.mongo_epoch_read_failed', {
        key: this.key,
        error: String(err),
      });
      throw err;
    }
  }

  async persist(envelope: CatalogEpochState): Promise<void> {
    const coll = await getCollection<EpochDoc>(EPOCH_COLLECTION_NAME);
    // First attempt: upsert the row when no document yet exists for
    // this key (fresh deployment). The upsert is constrained to "row
    // absent" so it cannot stomp an existing higher epoch on a
    // concurrent replica.
    const upsert = await coll.updateOne(
      { _id: this.key, epoch: { $exists: false } },
      {
        $setOnInsert: {
          _id: this.key,
          epoch: envelope.epoch,
          catalogVersion: envelope.catalogVersion,
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );
    if (upsert.upsertedCount === 1) return;

    // Row already exists. Apply a strict-newer CAS update.
    const cas = await coll.updateOne(
      {
        _id: this.key,
        $or: [
          { epoch: { $lt: envelope.epoch } },
          { epoch: envelope.epoch, catalogVersion: { $lt: envelope.catalogVersion } },
        ],
      },
      {
        $set: {
          epoch: envelope.epoch,
          catalogVersion: envelope.catalogVersion,
          updatedAt: new Date(),
        },
      },
    );
    if (cas.modifiedCount === 0) {
      // Another replica already persisted an equal-or-newer envelope.
      // This is not an error — the higher water mark is correctly
      // preserved — but we surface it as a debug event for audit.
      log.info('adapter-catalog.mongo_epoch_cas_skipped', {
        key: this.key,
        candidateEpoch: envelope.epoch,
        candidateCatalogVersion: envelope.catalogVersion,
      });
    }
  }

  describe(): string {
    return `mongo:${EPOCH_COLLECTION_NAME}:${this.key}`;
  }
}

/**
 * Resolve which store backs this Chariot instance based on env config.
 * Default is file mode — every existing single-host installation
 * continues to work unchanged. Mongo mode is opt-in via env var.
 *
 *   CHARIOT_EPOCH_STORE=file   (default)
 *     epochPath argument is used.
 *
 *   CHARIOT_EPOCH_STORE=mongo
 *     CHARIOT_EPOCH_STORE_KEY (default "default") names the row.
 *     Requires IAM Mongo client to have been initialized via
 *     bootstrapEnterprise / setMongoClient before any catalog load.
 */
export function createEpochStore(opts: {
  epochPath: string;
  mode?: string;
  key?: string;
}): CatalogEpochStore {
  const mode = (opts.mode ?? process.env.CHARIOT_EPOCH_STORE ?? 'file').toLowerCase();
  if (mode === 'mongo') {
    const key = opts.key ?? process.env.CHARIOT_EPOCH_STORE_KEY ?? DEFAULT_EPOCH_STORE_KEY;
    return new MongoEpochStore(key);
  }
  // FileEpochStore is per-instance — each replica writes to its
  // own file with no CAS. In a multi-replica deployment that's silent
  // monotonicity loss (a restarted replica with empty FS rolls the epoch
  // back to 0). Operators who set CHARIOT_REPLICAS>1 are claiming a
  // multi-replica deployment; refuse to start in that posture unless
  // they explicitly accept the risk via CHARIOT_ALLOW_FILE_EPOCH_MULTI_REPLICA=true.
  const replicas = parseInt(process.env.CHARIOT_REPLICAS ?? '1', 10);
  const allowFileMultiReplica = process.env.CHARIOT_ALLOW_FILE_EPOCH_MULTI_REPLICA === 'true';
  if (Number.isFinite(replicas) && replicas > 1 && !allowFileMultiReplica) {
    throw new Error(
      `Refusing to use FileEpochStore with CHARIOT_REPLICAS=${replicas}. ` +
      'FileEpochStore is per-instance with no cross-replica CAS, so a ' +
      'restarted replica silently rolls the catalog epoch back to 0. ' +
      'Set CHARIOT_EPOCH_STORE=mongo for production multi-replica ' +
      'deployments, or CHARIOT_ALLOW_FILE_EPOCH_MULTI_REPLICA=true to ' +
      'explicitly accept the rollback risk.',
    );
  }
  return new FileEpochStore(opts.epochPath);
}
