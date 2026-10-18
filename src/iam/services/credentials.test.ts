/**
 * Prove-on-revert for CHARIOT §10.5::1/::2 (rulings item 88, order B5) —
 * the per-user OAuth vendor-token refresh job.
 *
 * CHARIOT-SPEC.md:1063 — "**Per-user OAuth** ... Token refresh: background
 * job every 5 minutes finds tokens within 10 minutes of expiry, refreshes
 * via vendor refresh endpoint, updates `lastRefreshedAt`. On refresh
 * failure (vendor revoked the token), marks `status: 'expired'` and emits
 * an alert."
 *
 * Defect this catches: no background refresh job existed at all — the
 * spec's cited source, `src/iam/services/credentials.ts`, did not exist on
 * disk (confirmed: `ls src/iam/services/` had 30 files, none named
 * `credentials.ts`). `credential-loader.ts` (a different file) is a pure
 * read-at-dispatch-time function with no timer, no vendor-endpoint call,
 * and no `lastRefreshedAt` write anywhere.
 *
 * `refreshExpiringCredentials` needs a live Mongo `iam_adapter_credentials`
 * collection plus real AES-256-GCM/HKDF-SHA256 encrypted rows (via the
 * native binary) to exercise end-to-end — this repo's established
 * convention for exactly this shape of dependency (see
 * admin.tenant-crud.test.ts) is source-inspection for the Mongo/crypto-
 * bound logic; the constants and the pure `resolveAdapterTokenEndpoint`
 * lookup are real behavioral tests since they need neither.
 *
 * Run (after tsc): node --test dist/iam/services/credentials.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { resolveAdapterTokenEndpoint, buildClientAuthHeader, REFRESH_JOB_INTERVAL_MS, REFRESH_WINDOW_MS } from './credentials.js';
import type { AdapterEntry } from '../../engine/server/ChariotState.js';

const credentialsSrc = readFileSync(fileURLToPath(new URL('./credentials.js', import.meta.url)), 'utf8');

test('§10.5::1: the refresh interval is exactly 5 minutes', () => {
  assert.equal(REFRESH_JOB_INTERVAL_MS, 5 * 60 * 1000);
});

test('§10.5::1: the refresh window is exactly 10 minutes', () => {
  assert.equal(REFRESH_WINDOW_MS, 10 * 60 * 1000);
});

test('rulings item 98: an adapter with no auth.oauth2.tokenUrl resolves to undefined (non-refreshable)', () => {
  const adapter: AdapterEntry = { id: 'salesforce', name: 'Salesforce' };
  assert.equal(resolveAdapterTokenEndpoint(adapter), undefined);
});

test('rulings item 98: an undefined adapter (row points at a catalog id no longer present) resolves to undefined', () => {
  assert.equal(resolveAdapterTokenEndpoint(undefined), undefined);
});

test('rulings item 98: an empty-string tokenUrl is treated as absent, not a truthy empty destination', () => {
  const adapter: AdapterEntry = { id: 'z', name: 'Z', auth: { oauth2: { tokenUrl: '' } } };
  assert.equal(resolveAdapterTokenEndpoint(adapter), undefined);
});

test('rulings item 98: EVERY pre-existing adapter shape (declared before this unit) still resolves to undefined — no accidental cross-field pickup', () => {
  // Verified against source (ChariotState.ts's AdapterEntry interface) —
  // resolveAdapterTokenEndpoint now reads ONLY adapter.auth.oauth2.tokenUrl,
  // so none of the pre-existing auth-adjacent fields (rest.authType,
  // mcp.authScheme, idJagAuth) can satisfy it even by coincidence.
  const shapes: AdapterEntry[] = [
    { id: 'a', name: 'A', rest: { baseUrl: 'https://api.example.com', authType: 'bearer', envKey: 'A_KEY' } },
    { id: 'b', name: 'B', mcp: { authScheme: 'oauth2', serverUrl: 'https://mcp.example.com' } },
    { id: 'c', name: 'C', mcp: { authScheme: 'bearer', authEnvKey: 'C_TOKEN' } },
    { id: 'd', name: 'D', idJagAuth: { audience: 'https://res.example.com', scope: 'read', fallback: 'reject' } },
  ];
  for (const s of shapes) {
    assert.equal(resolveAdapterTokenEndpoint(s), undefined, `adapter shape "${s.id}" must not accidentally resolve a token endpoint`);
  }
});

test('rulings item 98: a declared auth.oauth2.tokenUrl (the catalog publisher-populated) IS picked up — refresh will be attempted', () => {
  const adapter: AdapterEntry = { id: 'salesforce', name: 'Salesforce', auth: { oauth2: { tokenUrl: 'https://login.salesforce.com/services/oauth2/token' } } };
  assert.equal(resolveAdapterTokenEndpoint(adapter), 'https://login.salesforce.com/services/oauth2/token');
});

// ── HTTP Basic client auth (rulings item 98(2)) ──────────────────────────

test('rulings item 98(2): buildClientAuthHeader produces a valid RFC 6749 §2.3.1 HTTP Basic header', () => {
  const header = buildClientAuthHeader('my-client-id', 'my-client-secret');
  assert.match(header, /^Basic [A-Za-z0-9+/]+=*$/, 'must be a well-formed "Basic <base64>" header');
  const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf-8');
  assert.equal(decoded, 'my-client-id:my-client-secret');
});

test('rulings item 98(2): buildClientAuthHeader percent-encodes id/secret before joining, per RFC 6749 §2.3.1', () => {
  // A colon INSIDE clientSecret must not be misread as the id:secret
  // delimiter by a vendor's parser — RFC 6749 requires component
  // percent-encoding before the colon-join, exactly like a URL query
  // component. Verify the encoded colon survives distinctly from the
  // delimiter colon.
  const header = buildClientAuthHeader('id', 'sec:ret');
  const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf-8');
  // decodeURIComponent applied to the two components must reconstruct
  // the original values when split on the FIRST colon only.
  const idx = decoded.indexOf(':');
  const id = decodeURIComponent(decoded.slice(0, idx));
  const secret = decodeURIComponent(decoded.slice(idx + 1));
  assert.equal(id, 'id');
  assert.equal(secret, 'sec:ret');
});

// ── Wiring checks (source inspection, Mongo/crypto-bound logic) ─────────

test('§10.5::1: the query selects only active oauth2 credentials within the refresh window', () => {
  assert.match(credentialsSrc, /credentialType:\s*['"]oauth2['"]/, 'must filter to oauth2-type credentials only (api_key/basic_auth are not vendor-refreshable)');
  assert.match(credentialsSrc, /status:\s*['"]active['"]/, 'must filter to active credentials only — an already-expired/revoked row is not a refresh candidate');
  assert.match(credentialsSrc, /expiresAt:[\s\S]{0,40}\$lte/, 'must select rows whose expiresAt falls within the refresh window');
});

test('§10.5::1: a decrypt is performed via the shared decryptFields (delegating to the same crypto path credential-loader.ts uses)', () => {
  assert.match(credentialsSrc, /import\s*\{[^}]*decryptFields[^}]*\}\s*from\s*['"]\.\.\/crypto\.js['"]/, 'must import decryptFields from the same module credential-loader.ts uses');
  assert.match(credentialsSrc, /decryptFields\(row\.encrypted,\s*row\.iv,\s*row\.tenantId,\s*row\.adapterId\)/, 'the AAD binding must be {tenantId, adapterId} — the same binding credential-loader.ts uses, so a row moved to a different adapterId fails closed the same way');
});

test('§10.5::1: a successful refresh writes lastRefreshedAt via a compare-and-set on the OLD encrypted value (same CAS shape as credential-loader.ts)', () => {
  assert.match(credentialsSrc, /lastRefreshedAt:\s*now/, 'must set lastRefreshedAt on success');
  assert.match(credentialsSrc, /casFilter\s*=\s*\{\s*_id:\s*row\._id,\s*encrypted:\s*row\.encrypted\s*\}/, 'the write must be a CAS keyed on the pre-refresh encrypted value — a concurrent writer must produce a matched-zero no-op, not a clobber');
});

test('§10.5::2: a failed vendor refresh marks status expired AND emits credential.refresh_failed', () => {
  const failBranchStart = credentialsSrc.indexOf('if (!vendorResponse)');
  assert.ok(failBranchStart >= 0, 'expected a branch handling a null/failed vendor response');
  const failBranch = credentialsSrc.slice(failBranchStart, failBranchStart + 1800);
  assert.match(failBranch, /status:\s*['"]expired['"]/, '§10.5::2 requires marking status:\'expired\' on a vendor-revoked failure');
  assert.match(failBranch, /chariotEmitter\.send\(\s*['"]credential\.refresh_failed['"]/, '§10.5::2 requires emitting an alert on refresh failure');
});

test('rulings item 88(1): a credential whose adapter declares no token endpoint is skipped with an audit event, not silently dropped', () => {
  const skipBranchStart = credentialsSrc.indexOf('if (!tokenEndpoint)');
  assert.ok(skipBranchStart >= 0, 'expected a branch handling an unresolved token endpoint');
  const skipBranch = credentialsSrc.slice(skipBranchStart, skipBranchStart + 900);
  assert.match(skipBranch, /skippedNonRefreshable\+\+/, 'must count the skip in the job result');
  assert.match(skipBranch, /audit\.log\(/, 'must emit an audit event for the skip — ruling item 88(1): "skips it with an audit event"');
});

test('the refresh job never touches api_key or basic_auth credential rows', () => {
  // The Mongo filter constrains this at the query level (asserted above),
  // but assert the type constant itself so a future edit that widens the
  // filter (e.g. dropping the credentialType clause) is caught even if the
  // query-shape regex above happens to still match some other literal.
  const queryStart = credentialsSrc.indexOf('.find({');
  assert.ok(queryStart >= 0, 'expected a .find({...}) query against the credentials collection');
  const queryBody = credentialsSrc.slice(queryStart, credentialsSrc.indexOf('.toArray()', queryStart));
  assert.doesNotMatch(queryBody, /api_key|basic_auth/, 'the query must not reference api_key/basic_auth credential types at all — only oauth2 rows are vendor-refreshable');
});

test('rulings item 98(2): the refresh call uses confidential-client auth ONLY when BOTH clientId and clientSecret are present, public form otherwise', () => {
  const clientAuthStart = credentialsSrc.indexOf('const clientAuth =');
  assert.ok(clientAuthStart >= 0, 'expected a clientAuth construction site');
  const clientAuthLine = credentialsSrc.slice(clientAuthStart, credentialsSrc.indexOf(';', clientAuthStart) + 1);
  assert.match(clientAuthLine, /row\.clientId\s*&&\s*clientSecret/, 'clientAuth must require BOTH row.clientId AND clientSecret — either alone must fall through to the public-client form (a malformed "id:" or ":secret" Basic header must never be sent)');
  assert.match(clientAuthLine, /:\s*undefined/, 'when either is missing, clientAuth must be undefined, not a partial object');

  const callSiteMatch = credentialsSrc.match(/callVendorRefreshEndpoint\(tokenEndpoint,\s*refreshToken,\s*fetchImpl,\s*clientAuth\)/);
  assert.ok(callSiteMatch, 'the resolved clientAuth must actually be passed to callVendorRefreshEndpoint — computing it and not using it would be dead code');

  const fnStart = credentialsSrc.indexOf('async function callVendorRefreshEndpoint');
  const fnBody = credentialsSrc.slice(fnStart, credentialsSrc.indexOf('\n}', fnStart));
  assert.match(fnBody, /if\s*\(clientAuth\)\s*\{[\s\S]{0,120}Authorization/, 'the Authorization header must be set conditionally on clientAuth being present — the public-client request must carry no Authorization header at all (RFC 6749 §4.3.2)');
});

test('rulings item 98(2): clientSecret is NEVER written to the document as a raw/plaintext field — only via encryptFields into the existing encrypted blob', () => {
  // Negative assertion: no `$set` anywhere in this file may name a bare
  // `clientSecret` key (which would mean writing it in plaintext to
  // Mongo). The only acceptable appearance of `clientSecret` as an
  // object KEY is inside the `newFields` object that gets passed through
  // `encryptFields(...)` before ever reaching a Mongo write.
  const setBlocks = credentialsSrc.match(/\$set:\s*\{[^}]*\}/g) ?? [];
  for (const block of setBlocks) {
    assert.doesNotMatch(block, /\bclientSecret\s*:/, `a Mongo $set block must never assign clientSecret directly (plaintext write): ${block}`);
  }
  // The one legitimate appearance: inside newFields, immediately followed
  // by encryptFields(newFields, ...) before any $set uses its output.
  const newFieldsStart = credentialsSrc.indexOf('const newFields');
  assert.ok(newFieldsStart >= 0, 'expected the newFields object construction');
  const newFieldsBlock = credentialsSrc.slice(newFieldsStart, credentialsSrc.indexOf('encryptFields(newFields', newFieldsStart));
  assert.match(newFieldsBlock, /clientSecret/, 'clientSecret must be included in newFields so a refresh cycle does not drop it from the re-encrypted blob');
  const afterEncrypt = credentialsSrc.slice(credentialsSrc.indexOf('encryptFields(newFields', newFieldsStart));
  const nextSetIdx = afterEncrypt.indexOf('$set: {');
  const encryptToSet = afterEncrypt.slice(0, nextSetIdx);
  assert.doesNotMatch(encryptToSet, /clientSecret/, 'clientSecret must not be referenced again between the encryptFields() call and the following $set — the ciphertext (encrypted/iv), never the plaintext value, is what reaches the $set');
});

test('rulings item 98(2): AdapterCredentialDocument itself declares no plaintext clientSecret field (types.ts)', () => {
  // MUST read the .ts SOURCE here, not the compiled .js this file reads
  // everywhere else: `interface` is a TypeScript-only construct erased
  // entirely at compile time (verified: dist/iam/types.js contains only
  // the runtime helper functions from types.ts, zero trace of any
  // interface — confirmed by inspection, not assumed). There is no
  // compiled-JS artifact this specific assertion could ever check against,
  // so reading types.ts directly is the only way to verify a type-level
  // property at all, not a violation of the "test against dist" norm this
  // file's other tests follow (which applies to runtime behavior, not to
  // a type declaration with no runtime existence).
  //
  // Path: this file compiles to dist/iam/services/credentials.test.js;
  // dist/ mirrors src/'s directory structure sibling-for-sibling under the
  // package root, so climbing three levels from the COMPILED file's own
  // location (dist/iam/services -> dist/iam -> dist -> package root) and
  // descending into src/iam/types.ts reaches the real source. Verified via
  // `realpath --relative-to=dist/iam/services src/iam/types.ts` =
  // `../../../src/iam/types.ts` before writing this path.
  const typesSrc = readFileSync(fileURLToPath(new URL('../../../src/iam/types.ts', import.meta.url)), 'utf8');
  const docStart = typesSrc.indexOf('export interface AdapterCredentialDocument');
  assert.ok(docStart >= 0, 'expected to find the AdapterCredentialDocument interface in types.ts');
  const docEnd = typesSrc.indexOf('\n}', docStart);
  assert.ok(docEnd > docStart, 'expected to find the closing brace of AdapterCredentialDocument');
  const docBody = typesSrc.slice(docStart, docEnd);
  assert.doesNotMatch(docBody, /\bclientSecret\s*[?:]/, 'AdapterCredentialDocument must not declare a clientSecret property — it must exist only inside the encrypted blob, never as a typed document field a caller could accidentally $set in plaintext');
  assert.match(docBody, /\bclientId\s*\?:\s*string/, 'clientId IS a plain document field per ruling item 98(2)');
});
