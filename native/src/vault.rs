// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use sha2::Sha256;

/// Envelope prefix marking a ciphertext produced under the CH-10 AAD contract
/// (§12.2, amended 2026-09-02: AAD = LE_u32(len(tenantId_bytes)) ‖ tenantId_bytes
/// ‖ adapterId_bytes — see `build_aad`). Standard base64
/// (RFC 4648 §4, the alphabet this module uses via `BASE64`) never contains
/// a `:` byte, so a legacy pre-AAD ciphertext — raw base64 with no prefix —
/// can never collide with this marker. `decrypt_credential` uses the
/// presence/absence of this prefix to choose the correct decrypt path:
/// records tagged `V2_PREFIX` are ALWAYS decrypted AAD-bound (a mismatch is
/// a hard failure, never retried without AAD — that retry would silently
/// re-open the relocation attack this change closes). Untagged records
/// predate this change and are decrypted with the legacy empty-AAD path.
const V2_PREFIX: &str = "v2:";

/// CH-10 hard-cutover error code (CHARIOT §12.2, rulings item 59). Returned
/// (as a prefix on the error reason) by `decrypt_credential` when a legacy
/// (unprefixed, empty-AAD) ciphertext is presented with `legacy_allowed =
/// false`. Distinct from every other decrypt failure so callers can branch
/// on cutover state without string-matching the underlying AES-GCM error.
const ERR_LEGACY_REFUSED: &str = "VAULT_LEGACY_CIPHERTEXT_REFUSED";

/// CH-10 (rulings item 59) native capability probe. Absent entirely on any
/// binary compiled before this change (a pre-upgrade `.node` built under
/// the Sep-1 signature has no such export). Callers MUST treat the absence
/// of this export as "the legacy-ciphertext gate is unsupported" and refuse
/// legacy decryption outright rather than assume permissive old behavior —
/// see `src/iam/crypto.ts`'s `hasVaultLegacyGate()`.
#[napi]
pub fn vault_protocol_version() -> u32 {
    2
}

/// Build the CH-10 AAD bytes for a credential record.
///
/// Wire form pinned by CHARIOT §12.2 (CH-10, amended 2026-09-02):
///
///   AAD = LE_u32(len(tenant_id_bytes)) ‖ tenant_id_bytes ‖ adapter_id_bytes
///
/// The 4-byte little-endian byte-length prefix of the tenant id makes the
/// split point unambiguous: bare `tenant_id.as_bytes() ++ adapter_id.as_bytes()`
/// would admit the boundary collision tenant `"a"` + adapter `"bc"` ==
/// tenant `"ab"` + adapter `"c"`. `tenant_id` and `adapter_id` are UTF-8
/// strings; their `.as_bytes()` are concatenated verbatim after the prefix,
/// and the same encoding is used on encrypt and decrypt (§12.2).
fn build_aad(tenant_id: &str, adapter_id: &str) -> Vec<u8> {
    let tenant_bytes = tenant_id.as_bytes();
    let adapter_bytes = adapter_id.as_bytes();
    let mut aad = Vec::with_capacity(4 + tenant_bytes.len() + adapter_bytes.len());
    aad.extend_from_slice(&(tenant_bytes.len() as u32).to_le_bytes());
    aad.extend_from_slice(tenant_bytes);
    aad.extend_from_slice(adapter_bytes);
    aad
}

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
/// `ENTERPRISE_MASTER_KEY` is NOT single-purpose: it is shared input keying
/// material for more than one HKDF-SHA256 derivation. The other shipped
/// consumers are the IAM MFA TOTP-secret store (`src/iam/services/mfa.ts`,
/// salt `epic-ai/chariot/iam/mfa`, info `mfa:{tenantId}`) and, when rooted in
/// `ENTERPRISE_MASTER_KEY` rather than a per-license secret, the §5.7 sealed
/// EdgeShard data key (`edge_snapshot.rs`, salt = catalog version, info
/// `chariot-edge-snapshot-seal-v1`). Domain separation across consumers is
/// achieved by giving each a DISTINCT `(salt, info)` pair — governed by
/// CHARIOT-SPEC §12.2 "Master-key domain separation (CH-10)".
///
/// CHARIOT::§12.2::11/12 — this vault's empty `info` is admissible
/// precisely because its salt (`tenant:{tenantId}`) is disjoint from every
/// other consumer's salt: HKDF-Extract is keyed by the salt, so disjoint
/// salts yield independent PRKs regardless of `info`. Empty `info` would
/// NOT be admissible for any consumer whose salt could equal
/// `tenant:{tenantId}` (§12.2::12). Every consumer and its `(salt, info)`
/// pair is enumerated, and this invariant is mechanically enforced, in
/// `src/iam/masterKeyConsumers.ts` / `masterKeyConsumers.test.ts`.
///
/// A NEW consumer of `ENTERPRISE_MASTER_KEY` MUST, before it derives any key,
/// either use a salt disjoint from every existing consumer's salt, or use a
/// distinct secret root instead of `ENTERPRISE_MASTER_KEY`. No consumer's
/// derivation depends on another's, so the disjointness invariant carries no
/// cross-consumer re-encryption obligation; placing two consumers on the same
/// salt would introduce one and is prohibited.
fn derive_key(master_key: &[u8], tenant_id: &str) -> Result<[u8; 32]> {
    // CHARIOT::§12.2::10 — "The vault key-derivation function SHALL reject a
    // master_key shorter than 32 bytes." HKDF-SHA256 accepts empty/short IKM
    // (RFC 5869 zero-pads the HMAC key), so without this guard an
    // unset/empty ENTERPRISE_MASTER_KEY silently "succeeds" and every
    // vaulted credential is encrypted under a publicly computable key (the
    // tenant salt is not secret). Fail closed instead — same missing-
    // length-check class as the snapshot seal (edge_snapshot.rs).
    if master_key.len() < 32 {
        return Err(Error::from_reason(format!(
            "master key must be at least 32 bytes of secret material (got {} bytes); \
             check ENTERPRISE_MASTER_KEY",
            master_key.len()
        )));
    }
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
/// `adapter_id`: CH-10 AAD binding — the record's adapter/binding identity
///   (see `build_aad`). Required so a ciphertext cannot be relocated from
///   one adapter's row to another within the same tenant and still decrypt.
/// `master_key_b64`: base64-encoded 32-byte master key (from ENTERPRISE_MASTER_KEY env)
#[napi]
pub fn encrypt_credential(
    plaintext: String,
    tenant_id: String,
    adapter_id: String,
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

    let aad = build_aad(&tenant_id, &adapter_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| Error::from_reason(format!("Encryption failed: {}", e)))?;

    // v2: prefix marks this record as AAD-bound (CH-10). See V2_PREFIX doc.
    Ok(EncryptedBlob {
        encrypted: format!("{}{}", V2_PREFIX, BASE64.encode(&ciphertext)),
        iv: BASE64.encode(&iv_bytes),
    })
}

/// Decrypt credential fields using AES-256-GCM with HKDF-SHA256 key derivation.
/// Compatible with the existing IAM crypto.ts decryption scheme.
///
/// `encrypted_b64`: the `encrypted` field as returned by `encrypt_credential`
///   — either `v2:`-prefixed (AAD-bound, base64 ciphertext+tag after the
///   prefix) or, for records written before this change, raw base64 with no
///   prefix (legacy, empty-AAD).
/// `iv_b64`: base64-encoded 12-byte IV
/// `tenant_id`: tenant identifier for key derivation salt
/// `adapter_id`: CH-10 AAD binding — MUST match the `adapter_id` the record
///   was encrypted under. Ignored for legacy (unprefixed) records, which
///   predate the AAD contract and carry no adapter binding to verify.
/// `master_key_b64`: base64-encoded 32-byte master key
/// `legacy_allowed`: rulings item 59 (CH-10 hard cutover) — the caller's
///   already-computed decision on whether an UNPREFIXED (legacy, empty-AAD)
///   ciphertext may be decrypted at all in the current context (tenant
///   migration marker absent, `CHARIOT_VAULT_LEGACY_DECRYPT` not "0", and
///   either not enterprise mode or `CHARIOT_VAULT_LEGACY_DECRYPT=1`
///   explicitly set — see `src/iam/crypto.ts` `resolveLegacyDecryptPolicy`).
///   Checked ONLY on the legacy path; a `v2:`-tagged record's AAD-bound
///   decrypt does not consult it. This makes the refusal enforceable at
///   the native layer itself (defense in depth) rather than solely a
///   TypeScript-side convention a future caller could forget to apply.
///
/// Migration note (CH-10): a `v2:`-tagged record is ALWAYS decrypted
/// AAD-bound; on auth failure this function returns the typed error below —
/// it never falls back to an empty-AAD retry, because that fallback would
/// let a relocated `v2:` ciphertext (wrong `adapter_id`, right tenant key)
/// decrypt anyway, defeating this fix. Only records with NO `v2:` prefix
/// (written by the pre-CH-10 binary) take the legacy empty-AAD path; the
/// prefix and standard base64's byte alphabet (never contains `:`) make the
/// two cases unambiguous — see `V2_PREFIX`. A record that fails its
/// applicable path (tampered, wrong tenant, or a genuine relocation attack)
/// fails explicitly; it is never silently skipped. When the legacy path is
/// taken with `legacy_allowed = false` the record is refused before any
/// decrypt attempt — `ERR_LEGACY_REFUSED` — and is never silently skipped
/// either.
#[napi]
pub fn decrypt_credential(
    encrypted_b64: String,
    iv_b64: String,
    tenant_id: String,
    adapter_id: String,
    master_key_b64: String,
    legacy_allowed: bool,
) -> Result<String> {
    let master_key = BASE64
        .decode(&master_key_b64)
        .map_err(|e| Error::from_reason(format!("Invalid master key encoding: {}", e)))?;

    let derived_key = derive_key(&master_key, &tenant_id)?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| Error::from_reason(format!("Cipher init failed: {}", e)))?;

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

    let plaintext = if let Some(v2_body) = encrypted_b64.strip_prefix(V2_PREFIX) {
        // AAD-bound (CH-10) path — the only path for records written by
        // this or any later version of encrypt_credential.
        let ciphertext = BASE64
            .decode(v2_body)
            .map_err(|e| Error::from_reason(format!("Invalid ciphertext encoding: {}", e)))?;
        let aad = build_aad(&tenant_id, &adapter_id);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| Error::from_reason(format!("Decryption failed: {}", e)))?
    } else {
        // Legacy pre-CH-10 path (empty AAD) — records written before the
        // AAD contract shipped. Not retried on the v2 path above and not
        // silently skipped on failure; see migration note above.
        //
        // CH-10 hard cutover (rulings item 59): a legacy record is refused
        // BEFORE any decrypt attempt when the caller has determined legacy
        // decryption is not currently permitted. This must run before the
        // base64-decode/decrypt below, not after — the refusal is a policy
        // gate, not a decrypt-failure classification, and must apply even
        // to a legacy record whose ciphertext would otherwise decrypt fine.
        if !legacy_allowed {
            return Err(Error::from_reason(format!(
                "{}: legacy (pre-CH-10, empty-AAD) credential decryption is refused in this context",
                ERR_LEGACY_REFUSED
            )));
        }
        let ciphertext = BASE64
            .decode(&encrypted_b64)
            .map_err(|e| Error::from_reason(format!("Invalid ciphertext encoding: {}", e)))?;
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| Error::from_reason(format!("Decryption failed: {}", e)))?
    };

    String::from_utf8(plaintext)
        .map_err(|e| Error::from_reason(format!("Decrypted data is not valid UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 32-byte fixture master key, base64-encoded. Test-only —
    /// never derived from or compared against a real ENTERPRISE_MASTER_KEY.
    const MASTER_KEY_B64: &str = "cUaHwigBoCGnkqXmpywJRlhMePCPs974XZ/7gZ2uCq0=";

    /// §12.2/CH-10 round-trip: (tenant, adapter) encrypt -> decrypt returns
    /// the original plaintext.
    #[test]
    fn round_trip_same_tenant_same_adapter() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");

        let plaintext = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
            true,
        )
        .expect("decrypt with the SAME (tenant, adapter) must succeed");

        assert_eq!(plaintext, "{\"apiKey\":\"secret-123\"}");
    }

    /// THE core CH-10 fix: a ciphertext encrypted under (tenantA, adapterX)
    /// MUST fail to decrypt when presented under (tenantA, adapterY) — an
    /// intra-tenant relocation attack. Must fail with a typed error, not
    /// panic. Prove-on-revert: this test fails if `build_aad`'s adapter_id
    /// component is removed (or decrypt_credential stops passing it), because
    /// then both calls would derive the same (empty or tenant-only) AAD and
    /// the relocated ciphertext would decrypt successfully.
    #[test]
    fn relocation_attack_same_tenant_different_adapter_fails() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");

        let result = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "tenant-a".to_string(),
            "adapter-y".to_string(), // relocated to a DIFFERENT adapter row
            MASTER_KEY_B64.to_string(),
            true,
        );

        assert!(
            result.is_err(),
            "relocating a ciphertext to a different adapter within the same \
             tenant must fail to decrypt, not succeed"
        );
    }

    /// Regression guard on the existing per-tenant key derivation: a
    /// ciphertext encrypted under tenantA MUST still fail to decrypt under
    /// tenantB, even with the correct adapter id (the derived key itself
    /// differs, independent of the AAD fix).
    #[test]
    fn cross_tenant_still_fails() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");

        let result = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "tenant-b".to_string(), // different tenant, same adapter id
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
            true,
        );

        assert!(
            result.is_err(),
            "decrypting under a different tenant must fail"
        );
    }

    /// Boundary/collision case for the length-prefixed AAD encoding: tenant
    /// "a" + adapter "bc" must NOT decrypt under tenant "ab" + adapter "c",
    /// even though bare concatenation of the two id pairs produces identical
    /// bytes ("abc"). Proves `build_aad`'s length prefix, not bare
    /// concatenation, is what's actually bound into the AAD.
    #[test]
    fn aad_boundary_collision_is_rejected() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "a".to_string(),
            "bc".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");

        let result = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "ab".to_string(),
            "c".to_string(),
            MASTER_KEY_B64.to_string(),
            true,
        );

        assert!(
            result.is_err(),
            "tenant \"a\"+adapter \"bc\" ciphertext must not decrypt as \
             tenant \"ab\"+adapter \"c\" — bare-concat AAD would collide here"
        );
    }

    /// `build_aad` itself must not collide on the same boundary case,
    /// independent of the full encrypt/decrypt round trip above.
    #[test]
    fn build_aad_no_boundary_collision() {
        assert_ne!(build_aad("a", "bc"), build_aad("ab", "c"));
    }

    /// Migration path: a pre-CH-10 record (no `v2:` prefix, encrypted with
    /// empty AAD — the exact shape the old `encrypt_credential` produced)
    /// still decrypts correctly. Simulates the legacy format directly since
    /// this binary no longer has code that PRODUCES unprefixed ciphertext.
    #[test]
    fn legacy_unprefixed_record_still_decrypts() {
        use aes_gcm::aead::Aead;

        let master_key = BASE64.decode(MASTER_KEY_B64).unwrap();
        let derived_key = derive_key(&master_key, "tenant-a").unwrap();
        let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();
        let iv_bytes = [9u8; 12];
        let nonce = Nonce::from_slice(&iv_bytes);
        // Legacy path: `.encrypt(nonce, msg)` — equivalent to Payload with
        // an empty AAD, exactly what the pre-CH-10 code did.
        let ciphertext = cipher
            .encrypt(nonce, b"{\"apiKey\":\"legacy-secret\"}".as_ref())
            .unwrap();
        let legacy_encrypted_b64 = BASE64.encode(&ciphertext); // NO v2: prefix

        let plaintext = decrypt_credential(
            legacy_encrypted_b64,
            BASE64.encode(iv_bytes),
            "tenant-a".to_string(),
            "adapter-x".to_string(), // ignored on the legacy path
            MASTER_KEY_B64.to_string(),
            true, // legacy_allowed — this test proves the ALLOWED case
        )
        .expect("legacy unprefixed record must still decrypt, not fail closed with no error");

        assert_eq!(plaintext, "{\"apiKey\":\"legacy-secret\"}");
    }

    /// A relocated v2 (AAD-bound) ciphertext must NOT be rescued by falling
    /// back to the legacy empty-AAD path — that fallback would defeat the
    /// whole fix, because the tenant-scoped key alone (no AAD) would still
    /// decrypt a relocated record successfully.
    #[test]
    fn v2_record_relocation_is_not_rescued_by_legacy_fallback() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");
        assert!(
            blob.encrypted.starts_with(V2_PREFIX),
            "encrypt_credential must always tag new records with the v2: prefix"
        );

        let result = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "tenant-a".to_string(),
            "adapter-y".to_string(),
            MASTER_KEY_B64.to_string(),
            false, // legacy_allowed=false must NOT affect the v2 (AAD-bound) path
        );
        assert!(result.is_err(), "a v2 record must never fall back to legacy empty-AAD decryption");
    }

    /// CHARIOT::§12.2::10 — "The vault key-derivation function SHALL reject
    /// a master_key shorter than 32 bytes." Failure enumeration: 0 bytes
    /// (unset/empty), 16 bytes (AES-128-sized, a plausible operator
    /// mistake), and 31 bytes (one byte short of the floor — the exact
    /// boundary). Exercised through the public API (encrypt_credential AND
    /// decrypt_credential), not derive_key directly, so this proves the
    /// guard actually gates both entry points.
    #[test]
    fn master_key_shorter_than_32_bytes_is_rejected_by_encrypt_and_decrypt() {
        for short_len in [0usize, 16, 31] {
            let short_key = vec![0x42u8; short_len];
            let short_key_b64 = BASE64.encode(&short_key);

            let encrypt_result = encrypt_credential(
                "{\"apiKey\":\"secret-123\"}".to_string(),
                "tenant-a".to_string(),
                "adapter-x".to_string(),
                short_key_b64.clone(),
            );
            assert!(
                encrypt_result.is_err(),
                "encrypt_credential must reject a {short_len}-byte master key, not succeed"
            );

            // decrypt_credential must also reject the same short key,
            // independent of any specific ciphertext (the guard lives in
            // derive_key, shared by both entry points — this proves it is
            // not bypassable by calling decrypt directly with a fabricated
            // blob/iv).
            let decrypt_result = decrypt_credential(
                format!("{V2_PREFIX}AAAA"),
                BASE64.encode([0u8; 12]),
                "tenant-a".to_string(),
                "adapter-x".to_string(),
                short_key_b64,
                true,
            );
            assert!(
                decrypt_result.is_err(),
                "decrypt_credential must reject a {short_len}-byte master key, not succeed"
            );
        }
    }

    /// Boundary check the other direction: exactly 32 bytes (the floor
    /// itself) MUST be accepted — §12.2::10 rejects "shorter than 32
    /// bytes", not "32 bytes or shorter".
    #[test]
    fn master_key_of_exactly_32_bytes_is_accepted() {
        let exact_key = vec![0x7Au8; 32];
        let exact_key_b64 = BASE64.encode(&exact_key);
        let result = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            exact_key_b64,
        );
        assert!(result.is_ok(), "a master key of exactly 32 bytes must be accepted, not rejected");
    }
    /// CH-10 hard cutover (rulings item 59): a legacy (unprefixed, empty-AAD)
    /// record MUST be refused — not decrypted, not silently skipped — when
    /// the caller passes `legacy_allowed = false`. Distinct error code so
    /// callers can branch on cutover state.
    #[test]
    fn legacy_record_refused_when_not_allowed() {
        use aes_gcm::aead::Aead;

        let master_key = BASE64.decode(MASTER_KEY_B64).unwrap();
        let derived_key = derive_key(&master_key, "tenant-a").unwrap();
        let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();
        let iv_bytes = [9u8; 12];
        let nonce = Nonce::from_slice(&iv_bytes);
        let ciphertext = cipher
            .encrypt(nonce, b"{\"apiKey\":\"legacy-secret\"}".as_ref())
            .unwrap();
        let legacy_encrypted_b64 = BASE64.encode(&ciphertext);

        let result = decrypt_credential(
            legacy_encrypted_b64,
            BASE64.encode(iv_bytes),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
            false, // legacy_allowed=false — cutover engaged
        );

        let err = result.expect_err("legacy decrypt must be refused, not silently skipped or succeed");
        assert!(
            err.to_string().contains(ERR_LEGACY_REFUSED),
            "refusal must carry the {} code, got: {}",
            ERR_LEGACY_REFUSED,
            err
        );
    }

    /// The refusal check runs BEFORE any decrypt attempt: even a WRONG-KEY
    /// legacy ciphertext (which would also fail decrypt) must surface the
    /// distinct refusal code when legacy_allowed=false, proving the gate is
    /// a policy check, not merely a relabeling of a decrypt failure.
    #[test]
    fn legacy_refusal_precedes_decrypt_attempt() {
        // A syntactically-valid base64 blob that is NOT a genuine ciphertext
        // for this key/IV — decrypting it would fail on its own merits, but
        // the refusal must fire first regardless.
        let bogus_encrypted_b64 = BASE64.encode(vec![0u8; 32]);
        let iv_b64 = BASE64.encode([1u8; 12]);

        let result = decrypt_credential(
            bogus_encrypted_b64,
            iv_b64,
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
            false,
        );

        let err = result.expect_err("must be refused");
        assert!(err.to_string().contains(ERR_LEGACY_REFUSED));
    }

    /// The v2 (AAD-bound) path never consults `legacy_allowed` — a v2
    /// record decrypts successfully with legacy_allowed=false exactly as it
    /// does with legacy_allowed=true (already covered above); this test
    /// pins that positive case explicitly.
    #[test]
    fn v2_record_decrypts_regardless_of_legacy_allowed_value() {
        let blob = encrypt_credential(
            "{\"apiKey\":\"secret-123\"}".to_string(),
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
        )
        .expect("encrypt should succeed");

        let plaintext = decrypt_credential(
            blob.encrypted,
            blob.iv,
            "tenant-a".to_string(),
            "adapter-x".to_string(),
            MASTER_KEY_B64.to_string(),
            false, // legacy_allowed=false — irrelevant to the v2 path
        )
        .expect("v2 record must decrypt regardless of legacy_allowed");

        assert_eq!(plaintext, "{\"apiKey\":\"secret-123\"}");
    }

    /// CH-10 (rulings item 59) capability probe: a new-enough binary
    /// reports protocol version 2. Callers use this to detect whether the
    /// legacy-ciphertext gate is enforceable at all before trusting it.
    #[test]
    fn vault_protocol_version_is_2() {
        assert_eq!(vault_protocol_version(), 2);
    }
}
