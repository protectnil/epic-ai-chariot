/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Test-only fake for the exact
 * Mongo `Collection` surface CH-10's upgrade-on-decrypt write-backs use
 * (`findOne`, `updateOne` with a compare-and-set filter, dotted-path
 * `$set`). Supports MongoDB's nested dotted-field `$set` semantics (the
 * OIDC site writes `settings.oidc.clientSecretEncrypted`) and an
 * injectable failure mode so a genuine write error can be simulated
 * without a live MongoDB — used by the per-site CAS-concurrency and
 * write-failure tests (credential-loader, oidc, id-jag-client).
 *
 * NOT a test itself — a shared fixture, colocated under src/iam/ per this
 * repo's existing pattern of colocated (not /test/-only) TS unit tests.
 */
import type { MongoClient } from 'mongodb';

export type FakeDoc = Record<string, unknown> & { _id: unknown };

export function getPath(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, k) => (acc as Record<string, unknown> | undefined)?.[k], obj);
}

function setPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.');
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i]!;
    if (typeof cur[k] !== 'object' || cur[k] === null) cur[k] = {};
    cur = cur[k] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1]!] = value;
}

function matches(doc: FakeDoc, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([k, v]) => getPath(doc, k) === v);
}

export interface FakeCollection {
  find(filter: Record<string, unknown>): { toArray(): Promise<FakeDoc[]> };
  findOne(filter: Record<string, unknown>): Promise<FakeDoc | null>;
  updateOne(
    filter: Record<string, unknown>,
    update: { $set: Record<string, unknown> },
    opts?: { upsert?: boolean },
  ): Promise<{ matchedCount: number }>;
  /** Test hook: the exact documents currently stored, for direct assertion. */
  readonly docs: FakeDoc[];
  /** Test hook: make the NEXT updateOne call reject with this error (once). */
  failNextUpdateOnce(err: Error): void;
}

export function makeFakeCollection(initialDocs: FakeDoc[] = []): FakeCollection {
  const docs: FakeDoc[] = [...initialDocs];
  let pendingFailure: Error | null = null;
  return {
    docs,
    find(filter) {
      return { toArray: async () => docs.filter((d) => matches(d, filter)) };
    },
    findOne: async (filter) => docs.find((d) => matches(d, filter)) ?? null,
    updateOne: async (filter, update, opts) => {
      if (pendingFailure) {
        const err = pendingFailure;
        pendingFailure = null;
        throw err;
      }
      const existing = docs.find((d) => matches(d, filter));
      if (existing) {
        for (const [k, v] of Object.entries(update.$set)) setPath(existing, k, v);
        return { matchedCount: 1 };
      }
      if (opts?.upsert) {
        const created: FakeDoc = { _id: (filter as { _id?: unknown })._id ?? Math.random().toString(36) } as FakeDoc;
        for (const [k, v] of Object.entries(update.$set)) setPath(created, k, v);
        docs.push(created);
        return { matchedCount: 0 };
      }
      return { matchedCount: 0 };
    },
    failNextUpdateOnce(err: Error) {
      pendingFailure = err;
    },
  };
}

/**
 * Wrap one or more named fake collections as a `MongoClient`-shaped object
 * suitable for `setMongoClient()` (src/iam/db.ts) — every module under
 * test that reads via `getCollection(name)` will see these fakes.
 */
export function makeFakeMongoClient(named: Record<string, FakeCollection>): MongoClient {
  const dbObj = {
    collection: (name: string) => named[name] ?? makeFakeCollection(),
  };
  return { db: () => dbObj } as unknown as MongoClient;
}
