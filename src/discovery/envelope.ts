/**
 * @epicai/chariot — Discovered-Adapter Signing Envelope
 *
 * Per-host Ed25519 keypair generated on first use (private 0600, public
 * 0644 in ~/.epic-ai/). Every discovered-adapter JSON is wrapped in
 * `{ payload, _signature, _signedBy }` so a tampered file under
 * ~/.epic-ai/discovered-adapters/ is rejected at load time.
 *
 * The signing input is a canonical JSON serialization (lexicographic
 * object-key sort, undefined dropped) so signer and verifier produce
 * byte-identical bytes across re-serialization.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_EPIC_AI_DIR = join(homedir(), '.epic-ai');

export interface EnvelopePaths {
  epicAiDir: string;
  discoveredDir: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

export function defaultEnvelopePaths(epicAiDir: string = DEFAULT_EPIC_AI_DIR): EnvelopePaths {
  return {
    epicAiDir,
    discoveredDir: join(epicAiDir, 'discovered-adapters'),
    privateKeyPath: join(epicAiDir, 'discovery-key.private.pem'),
    publicKeyPath: join(epicAiDir, 'discovery-key.public.pem'),
  };
}

export interface SignedAdapterEnvelope {
  payload: Record<string, unknown>;
  _signature: string;
  _signedBy: string;
}

/**
 * Canonical JSON form used by both signer and verifier so the signed
 * bytes are stable across re-serialization. Sorts object keys
 * lexicographically and drops undefined values.
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    // Mirror JSON.stringify: array slots that are undefined OR sparse
    // (missing) serialize to null so signer/verifier byte-output stays
    // identical after a disk round-trip through JSON.parse(JSON.stringify).
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      parts.push(canonicalJson(value[i]));
    }
    return '[' + parts.join(',') + ']';
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',') + '}';
}

export function discoveryHostKeyId(publicPem: string): string {
  return createHash('sha256').update(publicPem).digest('hex').slice(0, 16);
}

export function ensureDiscoveryKeyPair(paths: EnvelopePaths = defaultEnvelopePaths()): { privateKey: KeyObject; publicPem: string } {
  mkdirSync(paths.epicAiDir, { recursive: true });
  if (existsSync(paths.privateKeyPath) && existsSync(paths.publicKeyPath)) {
    const stPriv = statSync(paths.privateKeyPath);
    if ((stPriv.mode & 0o077) !== 0) {
      try {
        chmodSync(paths.privateKeyPath, 0o600);
      } catch (err) {
        throw new Error(
          `discovery private key ${paths.privateKeyPath} has loose permissions (mode=${(stPriv.mode & 0o777).toString(8)}) and could not be tightened to 0600: ${(err as Error).message}`
        );
      }
    }
    const privatePem = readFileSync(paths.privateKeyPath, 'utf-8');
    const publicPem = readFileSync(paths.publicKeyPath, 'utf-8');
    return { privateKey: createPrivateKey(privatePem), publicPem };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  writeFileSync(paths.privateKeyPath, privatePem, { encoding: 'utf-8', mode: 0o600 });
  writeFileSync(paths.publicKeyPath, publicPem, { encoding: 'utf-8', mode: 0o644 });
  return { privateKey, publicPem };
}

export function signDiscoveredAdapter(payload: Record<string, unknown>, paths: EnvelopePaths = defaultEnvelopePaths()): SignedAdapterEnvelope {
  const { privateKey, publicPem } = ensureDiscoveryKeyPair(paths);
  const canonical = Buffer.from(canonicalJson(payload), 'utf-8');
  const signature = cryptoSign(null, canonical, privateKey).toString('base64');
  return { payload, _signature: signature, _signedBy: discoveryHostKeyId(publicPem) };
}

export function verifyDiscoveredAdapter(envelope: unknown, paths: EnvelopePaths = defaultEnvelopePaths()): Record<string, unknown> {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('discovered-adapter envelope is not an object');
  }
  const env = envelope as { payload?: unknown; _signature?: unknown; _signedBy?: unknown };
  if (!env.payload || typeof env.payload !== 'object' || Array.isArray(env.payload)) {
    throw new Error('discovered-adapter envelope missing payload object');
  }
  if (typeof env._signature !== 'string' || env._signature.length === 0) {
    throw new Error('discovered-adapter envelope missing _signature');
  }
  if (typeof env._signedBy !== 'string' || env._signedBy.length === 0) {
    throw new Error('discovered-adapter envelope missing _signedBy');
  }
  if (!existsSync(paths.publicKeyPath)) {
    throw new Error(`discovery public key not found at ${paths.publicKeyPath}; refusing to trust adapter`);
  }
  const publicPem = readFileSync(paths.publicKeyPath, 'utf-8');
  const expectedId = discoveryHostKeyId(publicPem);
  if (env._signedBy !== expectedId) {
    throw new Error(`discovered-adapter signed by ${env._signedBy} but host key is ${expectedId}; refusing to trust adapter`);
  }
  const publicKey = createPublicKey(publicPem);
  const canonical = Buffer.from(canonicalJson(env.payload), 'utf-8');
  const sigBytes = Buffer.from(env._signature, 'base64');
  if (!cryptoVerify(null, canonical, publicKey, sigBytes)) {
    throw new Error('discovered-adapter signature did not verify against host public key');
  }
  return env.payload as Record<string, unknown>;
}

export function loadVerifiedDiscoveredAdapters(paths: EnvelopePaths = defaultEnvelopePaths()): Array<Record<string, unknown>> {
  if (!existsSync(paths.discoveredDir)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const fname of readdirSync(paths.discoveredDir)) {
    if (!fname.endsWith('.json')) continue;
    const fpath = join(paths.discoveredDir, fname);
    try {
      const raw = readFileSync(fpath, 'utf-8');
      const parsed = JSON.parse(raw) as unknown;
      out.push(verifyDiscoveredAdapter(parsed, paths));
    } catch (err) {
      process.stderr.write(`chariot: rejecting ${fpath}: ${(err as Error).message}\n`);
    }
  }
  return out;
}
