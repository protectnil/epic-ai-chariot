/**
 * Prove-on-revert for CHARIOT §10.4::4 — "WHEN an IdP sends PATCH {active:false}
 * the IAM service SHALL revoke all adapter OAuth tokens for that user."
 *
 * Defect this catches: before the fix, the SCIM PATCH {active:false} handler
 * revoked sessions + refresh tokens but NEVER revoked the user's adapter OAuth
 * credentials (revocation lived only in the hard-DELETE handler), and the two
 * inline copies that did exist diverged — the DELETE handler matched only
 * `status:'active'` (missing 'expired' rows) while the services path matched
 * only `connectedBy: userId` (missing legacy email-keyed rows). A deprovisioned
 * user's upstream credentials could keep dispatching.
 *
 * `userAdapterCredentialMatch` is the single, shared targeting used by every
 * deprovisioning path. This asserts its security properties directly (no DB):
 *   - revokes rows keyed on the user id AND every email the user has held
 *     (a rename-then-deactivate PATCH must still revoke prior-email rows)
 *   - revokes EVERY non-revoked row (status $ne 'revoked'), not just 'active'
 *   - dedupes and drops empty terms; never widens to another tenant's rows
 *
 * Run (after tsc): node --test dist/iam/services/scim.deprovision-match.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { userAdapterCredentialMatch } from './scim.js';

test('§10.4::4: match targets the user id and the current email', () => {
  const m = userAdapterCredentialMatch('507f1f77bcf86cd799439011', ['alice@example.com']);
  assert.deepEqual(
    m.connectedBy.$in,
    ['507f1f77bcf86cd799439011', 'alice@example.com'],
    'credentials keyed on either the id string OR the email must both be revoked — ' +
      'dropping the email leaves legacy user-scoped rows live',
  );
});

test('§10.4::4: rename-then-deactivate revokes rows keyed on the PRIOR email too', () => {
  const m = userAdapterCredentialMatch('u1', ['new@example.com', 'old@example.com']);
  assert.deepEqual(
    m.connectedBy.$in,
    ['u1', 'new@example.com', 'old@example.com'],
    'a PATCH that both renames and deactivates must revoke credentials keyed on ' +
      'the old address, not only the new one',
  );
});

test('§10.4::4: match revokes EVERY non-revoked row, not only active ones', () => {
  const m = userAdapterCredentialMatch('u1');
  assert.deepEqual(
    m.status,
    { $ne: 'revoked' },
    'must revoke active AND expired (any non-revoked) credentials; matching only ' +
      'status:"active" would leave a deprovisioned user\'s expired-but-reissuable rows live',
  );
});

test('§10.4::4: dedupes ids/emails and drops empty terms', () => {
  const m = userAdapterCredentialMatch('u1', ['a@b.co', 'a@b.co', '', 'u1']);
  assert.deepEqual(m.connectedBy.$in, ['u1', 'a@b.co'], 'duplicate and empty match terms must be removed');
});

test('§10.4::4: with no emails, only the id is targeted (no accidental widening)', () => {
  const m = userAdapterCredentialMatch('u1');
  assert.deepEqual(m.connectedBy.$in, ['u1'], 'absent emails must not add an undefined/empty match term');
});

test('§10.4::4: match carries no tenant term — callers MUST scope to a tenant', () => {
  const m = userAdapterCredentialMatch('u1', ['a@b.co']) as Record<string, unknown>;
  assert.equal('tenantId' in m, false, 'the pure match is tenant-agnostic; a missing caller-side tenant scope must be visible, not hidden here');
});
