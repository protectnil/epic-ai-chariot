/**
 * IAM Module — MongoDB Helper
 *
 * Provides convenience accessors for the IAM database and its collections.
 * The MongoClient is injected from bootstrap (pre-validated).
 * No lazy-connect. No permissive defaults.
 */

import type { MongoClient, Db, Collection, Document } from 'mongodb';

let _client: MongoClient | null = null;
let _dbName: string = 'epicai';

/**
 * Inject the MongoDB client from bootstrap. Must be called before any
 * database operation in enterprise mode.
 */
export function setMongoClient(client: MongoClient, dbName: string): void {
  _client = client;
  _dbName = dbName;
}

/**
 * Return the IAM database handle.
 * Throws if the client has not been injected via setMongoClient().
 *
 * Returned as `Promise<Db>` (even though there is no internal async work)
 * so callers can continue using `await getDb()` as the idiomatic pattern
 * without a future async implementation forcing a type change.
 */
export function getDb(): Promise<Db> {
  if (!_client) {
    return Promise.reject(new Error(
      'IAM database: MongoDB client not initialized. ' +
      'Call setMongoClient() during enterprise bootstrap before accessing IAM data.'
    ));
  }
  return Promise.resolve(_client.db(_dbName));
}

/**
 * Return a typed collection handle by name.
 */
export async function getCollection<T extends Document = Document>(
  name: string,
): Promise<Collection<T>> {
  const db = await getDb();
  return db.collection<T>(name);
}
