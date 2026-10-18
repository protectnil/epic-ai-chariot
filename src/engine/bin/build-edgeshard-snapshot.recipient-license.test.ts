import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readRecipientLicense } from './build-edgeshard-snapshot.js';

// CHARIOT §5.7: a sealed shard is produced for one recipient licence. These
// cover every refusal reachable without a production licence-signing key; the
// accept path is exercised by the producer's mandatory read-back unseal.

const dir = mkdtempSync(join(tmpdir(), 'recipient-license-'));
let n = 0;
function envelopeFile(envelope: unknown): string {
  const path = join(dir, `lic-${n++}.json`);
  writeFileSync(path, typeof envelope === 'string' ? envelope : JSON.stringify(envelope));
  return path;
}
const forged = (payload: object): string =>
  `${Buffer.from('{"alg":"EdDSA"}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`;

test('envelope without a usable jwt is refused', () => {
  for (const env of [{}, { jwt: '' }, { jwt: '   ' }, { jwt: 42 }]) {
    assert.throws(() => readRecipientLicense(envelopeFile(env)), /must contain jwt/);
  }
  assert.throws(() => readRecipientLicense(envelopeFile('not json')));
});

test('seal_secret must be canonical standard base64 of exactly 32 bytes', () => {
  const jwt = forged({ catalog_version: '1' });
  const bad: unknown[] = [
    '',
    Buffer.alloc(31).toString('base64'),
    Buffer.alloc(33).toString('base64'),
    Buffer.alloc(32, 0xfb).toString('base64url'),
    Buffer.alloc(32).toString('base64').replace(/=+$/, ''),
    32,
    null,
  ];
  for (const seal_secret of bad) {
    assert.throws(() => readRecipientLicense(envelopeFile({ jwt, seal_secret })), /seal_secret/);
  }
});

test('a jwt that does not verify against the accepted licence keys is refused, even with a matching claim', () => {
  const path = envelopeFile({ jwt: forged({ iss: 'license.epic-ai.io', sub: 'x', catalog_version: '1' }), seal_secret: Buffer.alloc(32, 7).toString('base64') });
  assert.throws(() => readRecipientLicense(path), /does not verify/);
});
