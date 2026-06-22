/**
 * IAM — MFA Service (TOTP)
 *
 * TOTP enrollment and verification via otplib.
 * TOTP secrets are AES-256-GCM encrypted at rest using ENTERPRISE_MASTER_KEY
 * with a per-tenant-feature key derived via SHA-256(masterKey || "mfa:" || tenantId).
 *
 * Does NOT use the Rust native binding so this works without the compiled binary.
 */

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import { TOTP, NobleCryptoPlugin, ScureBase32Plugin } from 'otplib';
import { getCollection } from '../db.js';
import type { MfaSecretDocument } from '../types.js';

const ISSUER = 'Epic AI® Chariot';

// Shared TOTP instance with the required crypto/base32 plugins for otplib 13.x
const totp = new TOTP({
  crypto: new NobleCryptoPlugin(),
  base32: new ScureBase32Plugin(),
});

// ── Key derivation ───────────────────────────────────────────────────────────

function getMasterKey(): Buffer {
  const raw = process.env.ENTERPRISE_MASTER_KEY;
  if (!raw || raw.trim() === '' || raw === 'change-me' || raw === 'changeme') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY is not set or is an insecure default. ' +
      'MFA secret encryption requires a real master key.',
    );
  }
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length < 32) {
    throw new Error(
      `ENTERPRISE_MASTER_KEY is too short (${decoded.length} bytes, minimum 32 for AES-256).`,
    );
  }
  return decoded;
}

// Per-tenant AES-256 key derived via HKDF-SHA256 (RFC 5869) from the master
// key. We use HKDF rather than SHA-256(masterKey || tenantId) because:
//   1. SHA-256 of concatenated values is theoretically vulnerable to length-
//      extension and offers no formal key-derivation guarantees.
//   2. HKDF is the standardized KDF expected by SOC 2 / cryptographic review.
//   3. The salt+info parameters bind the derived key to the MFA feature and
//      tenant, preventing key reuse across features even if the same input
//      key material is shared.
const MFA_HKDF_SALT = Buffer.from('epic-ai/chariot/iam/mfa', 'utf8');

function deriveMfaKey(tenantId: string): Buffer {
  const master = getMasterKey();
  const info = Buffer.from(`mfa:${tenantId}`, 'utf8');
  // hkdfSync returns ArrayBuffer; wrap in Buffer for AES-256 (32 bytes).
  return Buffer.from(hkdfSync('sha256', master, MFA_HKDF_SALT, info, 32));
}

// ── Crypto: encrypt / decrypt ────────────────────────────────────────────────

export function encryptTotpSecret(
  plaintext: string,
  tenantId: string,
): { encrypted: string; iv: string } {
  const key = deriveMfaKey(tenantId);
  const iv = randomBytes(12); // 96-bit IV for AES-256-GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 128-bit GCM tag
  return {
    encrypted: Buffer.concat([body, tag]).toString('base64'),
    iv: iv.toString('base64'),
  };
}

export function decryptTotpSecret(
  encrypted: string,
  ivB64: string,
  tenantId: string,
): string {
  const key = deriveMfaKey(tenantId);
  const iv = Buffer.from(ivB64, 'base64');
  const combined = Buffer.from(encrypted, 'base64');
  const tag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(0, combined.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

/**
 * Generate a new TOTP secret and the otpauth:// URI for QR enrollment.
 */
export async function generateTotpSecret(
  accountLabel: string,
): Promise<{ secret: string; otpauthUrl: string }> {
  const secret = await totp.generateSecret();
  const otpauthUrl = await totp.toURI({ secret, label: accountLabel, issuer: ISSUER });
  return { secret, otpauthUrl };
}

/**
 * Verify a TOTP code against a known secret. Returns true if valid.
 * otplib allows a 1-step window (±30 s) by default.
 */
export async function verifyTotpCode(secret: string, token: string): Promise<boolean> {
  try {
    const result = await totp.verify(token, { secret });
    return result.valid;
  } catch {
    return false;
  }
}

// ── MongoDB ──────────────────────────────────────────────────────────────────

export async function getUserMfaSecret(
  tenantId: string,
  userId: string,
): Promise<MfaSecretDocument | null> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  return col.findOne({ tenantId, userId }) as Promise<MfaSecretDocument | null>;
}

export async function isMfaEnrolled(tenantId: string, userId: string): Promise<boolean> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  return (await col.countDocuments({ tenantId, userId }, { limit: 1 })) > 0;
}

export async function saveMfaSecret(
  tenantId: string,
  userId: string,
  plaintextSecret: string,
): Promise<void> {
  const { encrypted, iv } = encryptTotpSecret(plaintextSecret, tenantId);
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  await col.updateOne(
    { tenantId, userId },
    { $set: { tenantId, userId, encrypted, iv, enrolledAt: new Date() } },
    { upsert: true },
  );
}

export async function deleteMfaSecret(tenantId: string, userId: string): Promise<void> {
  const col = await getCollection<MfaSecretDocument>('iam_mfa_secrets');
  await col.deleteOne({ tenantId, userId });
}
