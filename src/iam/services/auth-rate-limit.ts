/**
 * IAM — Authentication Rate Limiting
 *
 * SOC 2: Tracks failed authentication attempts per IP+tenant and blocks
 * after a configurable threshold. Records auto-expire via MongoDB TTL index.
 */

import { getCollection } from '../db.js';

const MAX_FAILURES = parseInt(process.env.AUTH_MAX_FAILURES || '5', 10);
/**
 * Rate-limit window in seconds. Records auto-expire via a MongoDB TTL
 * index on `iam_auth_failures.lastAttempt` — the index is declared in
 * `indexes.ts` with this value. Change here requires updating the index.
 */
const _WINDOW_SECONDS = 900; // 15 minutes (documentation; TTL index lives in indexes.ts)
void _WINDOW_SECONDS;

interface AuthFailureRecord {
  key: string;          // ip:tenantId
  count: number;
  firstAttempt: Date;
  lastAttempt: Date;
}

/**
 * Check if the given IP+tenant is currently rate-limited.
 * Returns true if blocked (too many failures), false if allowed.
 */
export async function isAuthRateLimited(
  ip: string,
  tenantId: string,
): Promise<boolean> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const key = `${ip}:${tenantId}`;
  const record = await col.findOne({ key });
  if (!record) return false;
  return record.count >= MAX_FAILURES;
}

/**
 * Record a failed authentication attempt.
 * Increments the counter; MongoDB TTL index auto-expires after 15 minutes.
 */
export async function recordAuthFailure(
  ip: string,
  tenantId: string,
): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const key = `${ip}:${tenantId}`;
  const now = new Date();
  await col.updateOne(
    { key },
    {
      $inc: { count: 1 },
      $set: { lastAttempt: now },
      $setOnInsert: { key, firstAttempt: now },
    },
    { upsert: true },
  );
}

/**
 * Clear failure records after a successful login.
 */
export async function clearAuthFailures(
  ip: string,
  tenantId: string,
): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  await col.deleteOne({ key: `${ip}:${tenantId}` });
}

// ── Per-client_id rate limiting (ID-JAG token endpoint) ─────────────────────
// A rotating-IP attacker defeats the per-IP bucket by churning addresses.
// The per-client_id bucket on the token endpoint catches this: failed
// exchanges from the same client_id within the same TTL window trigger 429
// regardless of source IP. Backed by the same iam_auth_failures collection
// with a `client:<id>` key prefix so the existing TTL index applies unchanged.

const MAX_CLIENT_FAILURES = parseInt(process.env.AUTH_MAX_CLIENT_FAILURES || '100', 10);
// Tenant-scoped key — two tenants can legitimately reuse the same
// clientId without one's failures bleeding into the other's bucket.
// The `client::` prefix + `::` separator both contain a double colon
// which the per-IP+tenant key format (`<ip>:<tenantId>`) cannot produce
// (`isValidTenantId` rejects ':'), so the two key shapes coexist in
// iam_auth_failures without collision.
const CLIENT_KEY_PREFIX = 'client::';

function clientKey(tenantId: string, clientId: string): string {
  return `${CLIENT_KEY_PREFIX}${tenantId}::${clientId}`;
}

export async function isClientRateLimited(
  tenantId: string,
  clientId: string,
): Promise<boolean> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const record = await col.findOne({ key: clientKey(tenantId, clientId) });
  if (!record) return false;
  return record.count >= MAX_CLIENT_FAILURES;
}

export async function recordAuthFailureForClient(
  tenantId: string,
  clientId: string,
): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const now = new Date();
  const key = clientKey(tenantId, clientId);
  await col.updateOne(
    { key },
    {
      $inc: { count: 1 },
      $set: { lastAttempt: now },
      $setOnInsert: { key, firstAttempt: now },
    },
    { upsert: true },
  );
}

// ── Per-IP probe limiting (pre-tenant-resolution) ───────────────────────────
// The /token and /revoke endpoints must resolve the tenant from the presented
// client_id BEFORE any tenant-scoped bucket exists. An attacker can therefore
// probe for valid client_ids unauthenticated and pre-rate-limit. This per-IP
// bucket throttles that enumeration: it is checked at the top of both routes
// and incremented whenever client resolution fails (unknown / no credential
// match). The `ipprobe::` prefix cannot collide with the per-IP+tenant key
// (`<ip>:<tenantId>`) or the per-client key (`client::...`).
const IP_PROBE_PREFIX = 'ipprobe::';
// Separate, higher-by-default threshold from the per-IP+tenant bucket
// (MAX_FAILURES). The probe bucket fires on unknown-client enumeration, which
// a shared-NAT / corporate-egress IP can trip with legitimate-but-misconfigured
// clients; a dedicated knob lets operators tune enumeration throttling without
// loosening the credential-brute-force gate.
const MAX_IP_PROBE_FAILURES = parseInt(process.env.AUTH_MAX_IP_PROBE_FAILURES || '20', 10);

function ipProbeKey(ip: string): string {
  return `${IP_PROBE_PREFIX}${ip}`;
}

export async function isIpProbeRateLimited(ip: string): Promise<boolean> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const record = await col.findOne({ key: ipProbeKey(ip) });
  if (!record) return false;
  return record.count >= MAX_IP_PROBE_FAILURES;
}

export async function recordIpProbeFailure(ip: string): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  const now = new Date();
  const key = ipProbeKey(ip);
  await col.updateOne(
    { key },
    {
      $inc: { count: 1 },
      $set: { lastAttempt: now },
      $setOnInsert: { key, firstAttempt: now },
    },
    { upsert: true },
  );
}

export async function clearClientFailures(
  tenantId: string,
  clientId: string,
): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  await col.deleteOne({ key: clientKey(tenantId, clientId) });
}

/**
 * Clear the per-IP probe bucket after a client successfully authenticates
 * from that IP. Without this a shared-NAT / corporate-egress IP that tripped
 * the probe threshold stays blocked for the full TTL window even while
 * legitimate clients behind it authenticate successfully.
 */
export async function clearIpProbeFailures(ip: string): Promise<void> {
  const col = await getCollection<AuthFailureRecord>('iam_auth_failures');
  await col.deleteOne({ key: ipProbeKey(ip) });
}
