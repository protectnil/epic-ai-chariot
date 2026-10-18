/**
 * CHARIOT rulings item 126 (unit W-IAM-REDACT) — connection-string
 * redaction. Root cause: the shipped 3.1.1 gateway logged a full Mongo
 * URI (including the password) at startup; the 4.0 tree independently
 * repeated the same class of leak by interpolating the RAW `mongoUri`
 * directly into a thrown `Error` message in `src/iam/bootstrap.ts` (a
 * different call site than the one two pre-existing, never-applied
 * redaction helpers covered).
 *
 * REAL BEHAVIORAL test of the pure, exported `redactConnectionString()`.
 *
 * Run (after tsc): node --test dist/iam/redactConnectionString.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactConnectionString } from './redactConnectionString.js';

const SECRET = 's3cr3t-p@ssw0rd';

const CASES: Array<{ label: string; uri: string; expected: string }> = [
  {
    label: 'mongodb:// with userinfo, port, and db',
    uri: `mongodb://admin:${SECRET}@localhost:27017/chariot?authSource=admin`,
    expected: 'mongodb://<redacted>@localhost:27017/chariot',
  },
  {
    label: 'mongodb+srv:// with userinfo, no explicit port, db + query',
    uri: `mongodb+srv://admin:${SECRET}@cluster0.abc123.mongodb.net/chariot?retryWrites=true&w=majority`,
    expected: 'mongodb+srv://<redacted>@cluster0.abc123.mongodb.net/chariot',
  },
  {
    label: 'redis:// with userinfo and a numeric db path',
    uri: `redis://admin:${SECRET}@127.0.0.1:6379/0`,
    expected: 'redis://<redacted>@127.0.0.1:6379/0',
  },
  {
    label: 'rediss:// with password-only userinfo (no username)',
    uri: `rediss://:${SECRET}@redis.example.com:6380`,
    expected: 'rediss://<redacted>@redis.example.com:6380',
  },
  {
    label: 'redis:// with NO userinfo at all — no <redacted> marker needed',
    uri: 'redis://localhost:6379',
    expected: 'redis://localhost:6379',
  },
  {
    label: 'mongodb:// with no explicit db path (bare root)',
    uri: `mongodb://admin:${SECRET}@localhost:27017/`,
    expected: 'mongodb://<redacted>@localhost:27017',
  },
];

for (const { label, uri, expected } of CASES) {
  test(`§rulings-126: redactConnectionString — ${label}`, () => {
    const result = redactConnectionString(uri);
    assert.equal(result, expected);
    assert.ok(!result.includes(SECRET), `redacted output must never contain the original secret: ${result}`);
  });
}

test('§rulings-126: the original userinfo NEVER appears in the output, for every scheme this helper claims to handle', () => {
  const schemes = ['mongodb', 'mongodb+srv', 'redis', 'rediss'];
  for (const scheme of schemes) {
    const uri = `${scheme}://user123:${SECRET}@host.example.com:1234/db`;
    const result = redactConnectionString(uri);
    assert.ok(!result.includes('user123'), `${scheme}: username leaked`);
    assert.ok(!result.includes(SECRET), `${scheme}: password leaked`);
    assert.ok(result.includes('<redacted>'), `${scheme}: expected the <redacted> marker for a URI carrying userinfo`);
  }
});

test('§rulings-126: query-string parameters are dropped entirely, not merely left unredacted', () => {
  const uri = `mongodb://user:${SECRET}@localhost:27017/chariot?authMechanism=SCRAM-SHA-256&someParam=value`;
  const result = redactConnectionString(uri);
  assert.ok(!result.includes('authMechanism'), 'query string must not survive redaction');
  assert.ok(!result.includes('?'), 'no query-string separator should remain');
});

test('§rulings-126: an unparseable string never throws and never echoes fragments of the input', () => {
  const garbage = `not a url at all but maybe contains ${SECRET}`;
  const result = redactConnectionString(garbage);
  assert.equal(result, '<uri-redacted>');
  assert.ok(!result.includes(SECRET));
});

test('§rulings-126: an empty string is handled without throwing', () => {
  assert.equal(redactConnectionString(''), '<uri-redacted>');
});
