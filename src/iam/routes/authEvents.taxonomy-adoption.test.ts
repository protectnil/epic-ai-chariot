/**
 * CHARIOT::§16.1 IAM (CHARIOT-SPEC.md:1346, rulings item 91/105) — "IAM:
 * `auth.success`, `auth.failure`, `auth.brute_force_lockout`,
 * `mfa.enrolled`, `mfa.skipped_via_idp`, `scim.user_provisioned`,
 * `scim.user_deprovisioned`, `scim.group_synced`."
 *
 * One test per remaining IAM emit site this unit wired: auth.success /
 * auth.failure across the three completion protocols (SAML, OIDC,
 * mfa-totp), mfa.skipped_via_idp (SAML + OIDC IdP-asserted-MFA branch),
 * and scim.group_synced (PUT + PATCH /Groups/:id).
 *
 * SOURCE INSPECTION (this repo's established convention for Express
 * routes with no supertest/mongodb-memory-server — see
 * admin.audit-logs-export.test.ts's header comment): each of these sites
 * requires a live Mongo + signed session + (for SAML/OIDC) a real IdP
 * assertion/token response to exercise end-to-end. This proves each site
 * is wired, at the RIGHT place (not double-firing on the MFA-required
 * branch, correctly gated on the skip condition), by inspecting the
 * compiled route bodies directly.
 *
 * Run (after tsc): node --test dist/iam/routes/authEvents.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const samlSrc = readFileSync(fileURLToPath(new URL('./saml.js', import.meta.url)), 'utf8');
const oidcSrc = readFileSync(fileURLToPath(new URL('./oidc.js', import.meta.url)), 'utf8');
const mfaSrc = readFileSync(fileURLToPath(new URL('./mfa.js', import.meta.url)), 'utf8');
const scimSrc = readFileSync(fileURLToPath(new URL('./scim.js', import.meta.url)), 'utf8');

test('§16.1 IAM: saml.ts callback emits auth.success AFTER the MFA-required early-return branch (no double-fire with mfa.ts)', () => {
  const mfaGateIdx = samlSrc.indexOf("res.redirect(enrolled ? '/auth/mfa/verify' : '/auth/mfa/setup')");
  const successIdx = samlSrc.indexOf("chariotEmitter.send('auth.success'");
  assert.ok(mfaGateIdx >= 0, 'the MFA-pending redirect must exist');
  assert.ok(successIdx > mfaGateIdx, 'auth.success must be emitted strictly after the MFA-pending early-return branch');
});

test('§16.1 IAM: saml.ts callback emits auth.failure in the catch block', () => {
  // Regex, not a literal "} catch {" substring — tsc emits the closing
  // brace and `catch` on separate lines in compiled output.
  let catchIdx = -1;
  const catchRegex = /\}\s*catch\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = catchRegex.exec(samlSrc)) !== null) catchIdx = m.index;
  const failIdx = samlSrc.indexOf("chariotEmitter.send('auth.failure'", catchIdx);
  assert.ok(catchIdx >= 0 && failIdx > catchIdx, 'auth.failure must be emitted inside the callback catch block');
});

test('§16.1 IAM: saml.ts emits mfa.skipped_via_idp only when mfaRequired AND idpMfa.asserted are both true', () => {
  const skipIdx = samlSrc.indexOf("chariotEmitter.send('mfa.skipped_via_idp'");
  assert.ok(skipIdx >= 0, 'mfa.skipped_via_idp must be emitted somewhere');
  const before = samlSrc.slice(Math.max(0, skipIdx - 300), skipIdx);
  assert.match(before, /tenant\.settings\?\.mfaRequired\s*&&\s*idpMfa\.asserted/, 'must be gated on BOTH mfaRequired and idpMfa.asserted, not either alone');
});

test('§16.1 IAM: oidc.ts callback emits auth.success AFTER the MFA-required early-return branch', () => {
  const mfaGateIdx = oidcSrc.indexOf("res.redirect(enrolled ? '/auth/mfa/verify' : '/auth/mfa/setup')");
  const successIdx = oidcSrc.indexOf("chariotEmitter.send('auth.success'");
  assert.ok(mfaGateIdx >= 0, 'the MFA-pending redirect must exist');
  assert.ok(successIdx > mfaGateIdx, 'auth.success must be emitted strictly after the MFA-pending early-return branch');
});

test('§16.1 IAM: oidc.ts emits auth.failure from the shared recordAuthFailureSafe() helper (every failure branch)', () => {
  const helperIdx = oidcSrc.indexOf('recordAuthFailureSafe');
  const failIdx = oidcSrc.indexOf("chariotEmitter.send('auth.failure'", helperIdx);
  assert.ok(helperIdx >= 0 && failIdx > helperIdx && failIdx < helperIdx + 2000, 'auth.failure must be emitted inside recordAuthFailureSafe, the single helper every OIDC failure branch calls');
});

test('§16.1 IAM: oidc.ts emits mfa.skipped_via_idp only when mfaRequired AND idpMfa.asserted are both true', () => {
  const skipIdx = oidcSrc.indexOf("chariotEmitter.send('mfa.skipped_via_idp'");
  assert.ok(skipIdx >= 0);
  const before = oidcSrc.slice(Math.max(0, skipIdx - 300), skipIdx);
  assert.match(before, /tenant\.settings\?\.mfaRequired\s*&&\s*idpMfa\.asserted/);
});

test('§16.1 IAM: mfa.ts emits auth.success in completeMfaLogin (the shared MFA-completion path)', () => {
  const fnIdx = mfaSrc.indexOf('completeMfaLogin');
  const successIdx = mfaSrc.indexOf("chariotEmitter.send('auth.success'", fnIdx);
  assert.ok(fnIdx >= 0 && successIdx > fnIdx, 'auth.success must be emitted inside completeMfaLogin');
});

test('§16.1 IAM: mfa.ts emits auth.failure ONLY at the login-completing /mfa/verify TOTP check, not the /mfa/setup/verify enrollment-confirmation check', () => {
  const setupVerifyIdx = mfaSrc.indexOf("router.post('/mfa/setup/verify'");
  const loginVerifyIdx = mfaSrc.indexOf("router.post('/mfa/verify'");
  assert.ok(setupVerifyIdx >= 0 && loginVerifyIdx > setupVerifyIdx, 'both routes must exist, in this order');
  const setupVerifyBody = mfaSrc.slice(setupVerifyIdx, loginVerifyIdx);
  const loginVerifyBody = mfaSrc.slice(loginVerifyIdx);
  assert.doesNotMatch(setupVerifyBody, /chariotEmitter\.send\('auth\.failure'/, 'enrollment confirmation is not a login attempt and must not emit auth.failure');
  assert.match(loginVerifyBody, /chariotEmitter\.send\('auth\.failure'/, 'the login-completing TOTP check must emit auth.failure on an invalid code');
});

test('§16.1 IAM: scim.ts emits scim.group_synced on both PUT and PATCH /Groups/:id', () => {
  const putIdx = scimSrc.indexOf("router.put('/Groups/:id'");
  const patchIdx = scimSrc.indexOf("router.patch('/Groups/:id'");
  assert.ok(putIdx >= 0 && patchIdx > putIdx, 'both routes must exist, in this order');
  const putBody = scimSrc.slice(putIdx, patchIdx);
  const patchBody = scimSrc.slice(patchIdx);
  assert.match(putBody, /chariotEmitter\.send\('scim\.group_synced'/, 'PUT /Groups/:id (full resync) must emit scim.group_synced');
  assert.match(patchBody, /chariotEmitter\.send\('scim\.group_synced'/, 'PATCH /Groups/:id (incremental resync) must emit scim.group_synced');
});
