/**
 * Enterprise IAM Credential Vault Cryptography
 *
 * Delegates AES-256-GCM encryption to the compiled Rust binary when available.
 * Falls back to Node.js crypto for SCIM token hashing (non-sensitive, no Rust needed).
 *
 * Epic AI® Chariot — Enterprise IAM Module
 */

import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { loadNativeBinding } from '../license/binding.js';

const SCIM_TOKEN_LENGTH = 48;

// ── Credential Vault (Rust binary) ──────────────────────────────────────────

/**
 * Returns the master key, validated at every call.
 * The bootstrap function validates this at startup; this is a defense-in-depth check.
 */
function getMasterKeyB64(): string {
  const raw = process.env.ENTERPRISE_MASTER_KEY;
  if (!raw || raw.trim() === '' || raw === 'change-me' || raw === 'changeme') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY is not set or is an insecure default. ' +
      'Credential vault operations require a real master key. ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
    );
  }
  const decoded = Buffer.from(raw, 'base64');
  // AES-256 takes a 32-byte key — accept exactly 32 bytes only.
  // A `< 32` check let a 33-byte (or longer) key through; HKDF would
  // then derive from a key the operator may have generated with the
  // wrong tool and silently truncate / expand surprising bytes. Refuse
  // anything that isn't exactly 32 bytes so the failure surfaces at
  // bootstrap (where the operator can fix it) rather than after rows
  // have been encrypted under the wrong material.
  if (decoded.length !== 32) {
    throw new Error(
      `ENTERPRISE_MASTER_KEY must decode to exactly 32 bytes (got ${decoded.length}). ` +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"'
    );
  }
  return raw;
}

/**
 * Validate the master key eagerly at startup (called from bootstrap).
 * Throws immediately if missing or insecure.
 */
export function validateMasterKey(): void {
  getMasterKeyB64();
}

/**
 * Encrypt a record of credential fields into a single encrypted blob.
 * Uses the Rust binary for AES-256-GCM with HKDF-SHA256 key derivation.
 */
export function encryptFields(
  fields: Record<string, string | undefined>,
  tenantId: string,
): { encrypted: string; iv: string } {
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Credential vault requires the Chariot native binary. ' +
      'Install @epicai/chariot to enable credential encryption.'
    );
  }

  // Strip undefined values before encrypting
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) clean[k] = v;
  }

  const plaintext = JSON.stringify(clean);
  return binding.encryptCredential(plaintext, tenantId, getMasterKeyB64());
}

/**
 * Decrypt a combined encrypted blob back into credential fields.
 * Uses the Rust binary for AES-256-GCM with HKDF-SHA256 key derivation.
 */
export function decryptFields(
  encrypted: string,
  iv: string,
  tenantId: string,
): Record<string, string> {
  const binding = loadNativeBinding();
  if (!binding) {
    throw new Error(
      'Credential vault requires the Chariot native binary. ' +
      'Install @epicai/chariot to enable credential decryption.'
    );
  }

  const json = binding.decryptCredential(encrypted, iv, tenantId, getMasterKeyB64());
  return JSON.parse(json) as Record<string, string>;
}

// ── SCIM Token Management (Node.js crypto — no Rust needed) ─────────────────

/**
 * Hash a token using SHA-256, returned as hex.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Verify a token against a SHA-256 hash using timing-safe comparison.
 */
export function verifyToken(token: string, hash: string): boolean {
  const computed = Buffer.from(hashToken(token), 'hex');
  const expected = Buffer.from(hash, 'hex');
  if (computed.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(computed, expected);
}

/**
 * Generate a cryptographically random SCIM bearer token and its SHA-256 hash.
 */
export function generateScimToken(): { token: string; hash: string } {
  const token = randomBytes(SCIM_TOKEN_LENGTH).toString('base64url');
  const hash = hashToken(token);
  return { token, hash };
}
