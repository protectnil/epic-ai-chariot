/**
 * Regression eval for CHARIOT::§1.4::12 (the retired §19 procurement row restated this obligation).
 *
 * "In connected mode Chariot SHALL restrict outbound network connections
 * exclusively to license.epic-ai.io/renew" / "the Chariot system's only
 * outbound network destination SHALL be license.epic-ai.io/renew."
 *
 * The defect this catches: DEFAULT_RENEW_URL pointed at
 * `https://epic-ai.io/api/license/renew` — host `epic-ai.io`, path
 * `/api/license/renew` — neither the required host (`license.epic-ai.io`)
 * nor the required path (`/renew`). This test asserts the exact host+path
 * and would FAIL against the pre-fix constant.
 *
 * Run (after tsc):
 *   node --test dist/license/renew-client.destination.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_RENEW_URL } from './renew-client.js';

test('DEFAULT_RENEW_URL is exactly license.epic-ai.io/renew (§1.4::12)', () => {
  const u = new URL(DEFAULT_RENEW_URL);
  assert.equal(u.protocol, 'https:');
  assert.equal(u.hostname, 'license.epic-ai.io');
  assert.equal(u.pathname, '/renew');
});
