// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use napi::bindgen_prelude::*;
use napi_derive::napi;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;

/// Derive a 32-byte AES key from the master key using HKDF-SHA256 with a tenant-specific salt.
/// Matches the Node.js crypto.ts pattern: salt = "tenant:{tenantId}".
///
/// ## HKDF `info` parameter rationale
///
/// The `info` parameter to `hk.expand` is intentionally empty (`b""`). NIST
/// SP 800-56C Rev. 2 Section 5.4 recommends a context-specific, non-empty
/// `info` string to provide cross-context domain separation when the same
/// input keying material (IKM) is used to derive keys for multiple purposes.
///
/// `ENTERPRISE_MASTER_KEY` is single-purpose: it is consumed ONLY by
/// `encrypt_credential` and `decrypt_credential` in this file, and by no
/// other HKDF-SHA256 derivation in this binary or in the TypeScript layer.
/// Cross-context separation via `info` is therefore not applicable — there
/// is exactly one context, the credential vault. The tenant-scoped `salt`
/// (`tenant:{tenantId}`) provides the per-tenant domain separation that
/// matters for this use case.
///
/// If a future change introduces a SECOND consumer of
/// `ENTERPRISE_MASTER_KEY` with a different purpose (e.g., signing, a
/// separate encryption context, or a KDF for a distinct data type), that
/// new consumer MUST supply a non-empty `info` string such as
/// `b"chariot-signing-v1"` and this function's callers must migrate to a
/// non-empty `info` such as `b"chariot-credential-vault-v1"`. Introducing
/// that change requires a migration: every credential currently in the
/// `iam_adapter_credentials` collection was encrypted with this empty-info
/// derivation, so the new code must either (a) re-encrypt existing vault
/// records on first read, or (b) keep the old derivation available under
/// a version tag for backward-compatible decryption.
///
/// Do not change this to a non-empty `info` without also handling that
/// migration. Silent divergence breaks every vaulted credential.
fn derive_key(master_key: &[u8], tenant_id: &str) -> Result<[u8; 32]> {
    let salt = format!("tenant:{}", tenant_id);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master_key);
    let mut okm = [0u8; 32];
    // Empty info is intentional — see `derive_key` doc comment above.
    hk.expand(b"", &mut okm)
        .map_err(|e| Error::from_reason(format!("HKDF expansion failed: {}", e)))?;
    Ok(okm)
}

#[napi(object)]
#[derive(Debug)]
pub struct EncryptedBlob {
    /// Base64-encoded ciphertext (includes AES-GCM auth tag)
    pub encrypted: String,
    /// Base64-encoded 12-byte IV
    pub iv: String,
}

/// Encrypt credential fields using AES-256-GCM with HKDF-SHA256 key derivation.
/// Compatible with the existing IAM crypto.ts encryption scheme.
///
/// `plaintext`: the JSON string of credential fields to encrypt
/// `tenant_id`: tenant identifier for key derivation salt
/// `master_key_b64`: base64-encoded 32-byte master key (from ENTERPRISE_MASTER_KEY env)
#[napi]
pub fn encrypt_credential(
    plaintext: String,
    tenant_id: String,
    master_key_b64: String,
) -> Result<EncryptedBlob> {
    let master_key = BASE64
        .decode(&master_key_b64)
        .map_err(|e| Error::from_reason(format!("Invalid master key encoding: {}", e)))?;

    let derived_key = derive_key(&master_key, &tenant_id)?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| Error::from_reason(format!("Cipher init failed: {}", e)))?;

    // Generate random 12-byte IV
    let mut iv_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| Error::from_reason(format!("Encryption failed: {}", e)))?;

    Ok(EncryptedBlob {
        encrypted: BASE64.encode(&ciphertext),
        iv: BASE64.encode(&iv_bytes),
    })
}

/// Decrypt credential fields using AES-256-GCM with HKDF-SHA256 key derivation.
/// Compatible with the existing IAM crypto.ts decryption scheme.
///
/// `encrypted_b64`: base64-encoded ciphertext (includes auth tag)
/// `iv_b64`: base64-encoded 12-byte IV
/// `tenant_id`: tenant identifier for key derivation salt
/// `master_key_b64`: base64-encoded 32-byte master key
#[napi]
pub fn decrypt_credential(
    encrypted_b64: String,
    iv_b64: String,
    tenant_id: String,
    master_key_b64: String,
) -> Result<String> {
    let master_key = BASE64
        .decode(&master_key_b64)
        .map_err(|e| Error::from_reason(format!("Invalid master key encoding: {}", e)))?;

    let derived_key = derive_key(&master_key, &tenant_id)?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| Error::from_reason(format!("Cipher init failed: {}", e)))?;

    let ciphertext = BASE64
        .decode(&encrypted_b64)
        .map_err(|e| Error::from_reason(format!("Invalid ciphertext encoding: {}", e)))?;

    let iv_bytes = BASE64
        .decode(&iv_b64)
        .map_err(|e| Error::from_reason(format!("Invalid IV encoding: {}", e)))?;

    if iv_bytes.len() != 12 {
        return Err(Error::from_reason(format!(
            "Invalid IV length: expected 12, got {}",
            iv_bytes.len()
        )));
    }

    let nonce = Nonce::from_slice(&iv_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| Error::from_reason(format!("Decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| Error::from_reason(format!("Decrypted data is not valid UTF-8: {}", e)))
}
