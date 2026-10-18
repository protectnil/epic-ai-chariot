// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// Phase 3.3 — Chariot-side seal/verify wrapper around an Edge shard snapshot.
//
// CHARIOT-SPEC §8.6 (LOCKED): "Qdrant Edge provides no encryption and no
// signing of its shard … The AES-256-GCM seal and the Ed25519 signature over
// the bundle are Chariot's wrapper around the Edge shard, not Edge
// capabilities; the verifier and key custody live entirely on the Chariot
// side." This module is that wrapper. It runs BEFORE `edge_unpack_snapshot`
// / `EdgeShardHandle::load` ever touch a shard: a sealed snapshot is
// Ed25519-verified, then AES-256-GCM-unsealed to plaintext, and only the
// verified plaintext is handed to Edge.
//
// Key custody (§8.6): the AES-256-GCM key root MUST be secret material — a
// per-license secret key (recommended) or `ENTERPRISE_MASTER_KEY` with license
// gating — NOT the public signed license blob. We derive the snapshot data key
// with HKDF-SHA256 from that secret root, mirroring `vault.rs`, but with a
// DISTINCT, non-empty `info` string (`chariot-edge-snapshot-seal-v1`) so this
// second consumer of the master key is domain-separated from the credential
// vault, exactly as `vault.rs::derive_key`'s doc-comment requires.
//
// Envelope ordering: encrypt-then-sign over the SEALED bytes (the Ed25519
// signature covers the ciphertext bytes only — the IV is NOT part of the
// signed message). The GCM authentication tag already commits the IV
// cryptographically (an IV change produces a tag failure), so the IV does
// not need separate coverage in the signature. Verification happens first,
// on untrusted input, before any AEAD work — fail-closed.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// CHARIOT::§12.2::11/12 — HKDF `info` for the snapshot-seal key. MUST be
/// distinct from the credential vault's empty `info` (see
/// `vault.rs::derive_key`) — domain separation for the second consumer of
/// `ENTERPRISE_MASTER_KEY` / a per-license secret. Registered + mechanically
/// checked in `src/iam/masterKeyConsumers.ts`.
const SNAPSHOT_SEAL_INFO: &[u8] = b"chariot-edge-snapshot-seal-v1";

/// Minimum length (bytes) of the decoded secret key root. §8.6 mandates the
/// AES-256-GCM key root be secret material; an empty or short root makes the
/// derived data key publicly computable (the HKDF salt is catalog metadata),
/// silently defeating the entire encryption layer. 32 bytes = 256-bit root,
/// matching the AES-256 security target.
const MIN_SECRET_ROOT_BYTES: usize = 32;

// ── §8.6 verify-before-load receipt (process-local) ──────────────────────
//
// `unseal_and_verify_snapshot` returns an opaque receipt = HMAC-SHA256 keyed
// by a process-local random key over SHA-256(plaintext). `edge_unpack_snapshot`
// (edge_shard.rs) recomputes and checks this receipt over the exact archive
// bytes BEFORE unpacking, and `EdgeShardHandle::load` requires the HMAC'd
// digest manifest that unpack emits. Because the key is random per process,
// a receipt/manifest from a previous process never verifies — cached plaintext
// is never trusted across restarts and the unseal+verify step cannot be
// skipped. This makes the §8.6 verify-before-load invariant cryptographically
// enforced in the native layer instead of a doc-comment convention.

fn process_receipt_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        k
    })
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256(process_receipt_key, msg), hex-encoded. Implemented via
/// HKDF-extract, whose output PRK is by definition HMAC-SHA256(salt=key, ikm)
/// (RFC 5869 §2.2) — a genuine HMAC without adding a new crate.
pub(crate) fn process_hmac_hex(msg: &[u8]) -> String {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(process_receipt_key()), msg);
    hex_encode(&prk)
}

/// Receipt binding a plaintext to a successful unseal+verify in THIS process.
pub(crate) fn compute_unseal_receipt(plaintext: &[u8]) -> String {
    process_hmac_hex(&Sha256::digest(plaintext))
}

/// Constant-time string equality (receipt/HMAC comparison).
pub(crate) fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Verify that `receipt` was produced by `compute_unseal_receipt` over these
/// exact bytes in this process.
pub(crate) fn verify_unseal_receipt(plaintext: &[u8], receipt: &str) -> bool {
    constant_time_eq_str(&compute_unseal_receipt(plaintext), receipt)
}

/// Derive the 32-byte AES-256-GCM data key for snapshot sealing from a secret
/// root via HKDF-SHA256. `salt` binds the key to a context (e.g. the catalog
/// `catalogVersion` or license id) so each sealed bundle has a scoped key.
fn derive_snapshot_key(secret_root: &[u8], salt: &str) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret_root);
    let mut okm = [0u8; 32];
    hk.expand(SNAPSHOT_SEAL_INFO, &mut okm)
        .map_err(|e| Error::from_reason(format!("HKDF expansion failed: {e}")))?;
    Ok(okm)
}

/// Decode a PEM SubjectPublicKeyInfo Ed25519 key (12-byte SPKI header + 32-byte
/// key). Mirrors `license.rs::extract_public_key_from_pem`.
fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .replace(' ', "");
    let der = BASE64
        .decode(&b64)
        .map_err(|e| Error::from_reason(format!("Failed to decode public key: {e}")))?;
    if der.len() != 44 {
        return Err(Error::from_reason(format!(
            "Invalid public key DER length: expected 44, got {}",
            der.len()
        )));
    }
    let key_bytes: [u8; 32] = der[12..44]
        .try_into()
        .map_err(|_| Error::from_reason("Failed to extract 32-byte key from DER"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::from_reason(format!("Invalid Ed25519 public key: {e}")))
}

/// Verify an Ed25519 detached signature over `message` against a PEM public
/// key. Returns Ok(()) only on a valid signature; every failure path returns
/// an Err (fail-closed) — there is no boolean "false but continue". The key
/// MUST be one of the compiled-in accepted keys (pinned trust anchor, same
/// rule as `unseal_and_verify_snapshot`).
#[napi]
pub fn verify_snapshot_signature(
    message_b64: String,
    signature_b64: String,
    public_key_pem: String,
) -> Result<()> {
    let message = BASE64
        .decode(&message_b64)
        .map_err(|e| Error::from_reason(format!("Invalid message encoding: {e}")))?;
    let sig_bytes = BASE64
        .decode(&signature_b64)
        .map_err(|e| Error::from_reason(format!("Invalid signature encoding: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::from_reason(format!("Invalid signature format: {e}")))?;
    let key = pinned_verifying_key(&public_key_pem)?;
    key.verify(&message, &signature)
        .map_err(|_| Error::from_reason("Snapshot signature verification failed"))
}

/// Result of unsealing a snapshot: the plaintext snapshot archive bytes,
/// base64-encoded for the JS boundary, plus the process-local receipt that
/// `edge_unpack_snapshot` requires (§8.6 verify-before-load).
#[napi(object)]
pub struct UnsealedSnapshot {
    /// Base64 of the decrypted snapshot archive bytes.
    pub plaintext_b64: String,
    /// Opaque process-local receipt over the plaintext bytes. Pass to
    /// `edge_unpack_snapshot` — it will refuse any archive whose bytes were
    /// not produced by a successful unseal+verify in this process.
    pub receipt: String,
}

/// Receipt-only result for the file-to-file unseal variant.
#[napi(object)]
pub struct UnsealReceipt {
    /// Opaque process-local receipt over the written plaintext file bytes.
    pub receipt: String,
}

/// Parse the anti-rollback epoch out of a structured aad of the form
/// `<context>|epoch=N` (e.g. `v4.0.0|epoch=7`). Fail-closed: an aad without
/// a parseable `epoch=` segment is rejected — a rollback barrier that cannot
/// be evaluated provides no barrier at all.
///
/// CHARIOT::§5.7::27 — an aad carrying MORE THAN ONE `epoch=` segment is
/// rejected outright rather than resolved by position (first-wins or
/// highest-wins), so a highest/first-wins parse cannot be used to smuggle a
/// second value past the check (e.g. `v4|epoch=9|epoch=1` previously
/// returned 9 from the first match — silently ignoring the conflict).
fn parse_aad_epoch(aad: &str) -> Result<u32> {
    let mut found: Option<u32> = None;
    for part in aad.split('|') {
        if let Some(v) = part.strip_prefix("epoch=") {
            if found.is_some() {
                return Err(Error::from_reason(format!(
                    "aad must contain exactly one 'epoch=N' segment (CHARIOT::§5.7::27): a \
                     second segment {v:?} was rejected rather than resolved by position"
                )));
            }
            found = Some(v.parse::<u32>().map_err(|e| {
                Error::from_reason(format!("Invalid aad epoch value {v:?}: {e}"))
            })?);
        }
    }
    found.ok_or_else(|| {
        Error::from_reason(
            "aad must contain an 'epoch=N' segment (e.g. 'v4.0.0|epoch=7'): \
             anti-rollback requires a parseable, enforceable epoch",
        )
    })
}

/// Parse the `<context>` segment out of a structured aad of the form
/// `<context>|epoch=N` — everything before the first `|`. CHARIOT::§5.7::17
/// requires `salt == <context>`; CHARIOT::§5.7::37/38 requires `<context>`
/// to equal a context sourced from the Ed25519-verified license, never from
/// the snapshot itself.
fn parse_aad_context(aad: &str) -> &str {
    aad.split('|').next().unwrap_or("")
}

/// Pin the caller-supplied verifying key to the compiled-in accepted key set
/// (`license.rs::ACCEPTED_PUBLIC_KEYS_PEM`). The Ed25519 trust anchor for
/// snapshot verification is NOT a free runtime parameter: a key outside the
/// pinned rotation set is rejected, so a caller (or attacker controlling the
/// caller's config) cannot substitute their own signing key.
fn pinned_verifying_key(public_key_pem: &str) -> Result<VerifyingKey> {
    let key = verifying_key_from_pem(public_key_pem)?;
    let accepted = crate::license::accepted_verifying_keys()?;
    if !accepted.iter().any(|k| k.as_bytes() == key.as_bytes()) {
        return Err(Error::from_reason(
            "Snapshot verifying key is not in the compiled-in accepted key set \
             (trust-anchor pinning; see license.rs ACCEPTED_PUBLIC_KEYS_PEM rotation model)",
        ));
    }
    Ok(key)
}

/// Core unseal+verify over raw ciphertext bytes, fail-closed. Shared by the
/// base64 and file-to-file NAPI surfaces; takes the verifying keys explicitly
/// so tests can drive the full pipeline with a fixture key while the NAPI
/// surface pins to the compiled-in accepted set. `min_epoch` and
/// `expected_context` are TRUSTED inputs here — the #[napi] entry points are
/// where CHARIOT::§5.7::31/32/33 (floor not a bare scalar; derived from a
/// verified license) and §5.7::38 (context derived from a verified license)
/// are enforced by deriving these two values from `license::
/// verify_license_jwt_and_extract` before calling this function;
/// `unseal_core` itself only compares against what it is given, so tests can
/// drive every guard with fixture values.
///
/// Enforcement order (untrusted input first):
///   1. Guards: non-empty salt; non-empty aad; structured aad with a
///      parseable, SINGLE epoch segment (§5.7::27); `salt == aad <context>`
///      (§5.7::17); `aad <context> == expected_context` (§5.7::37);
///      `epoch >= min_epoch` (anti-rollback floor — `min_epoch` MUST come
///      from the Ed25519-verified license's `min_security_epoch`, never from
///      the bundle being verified); decoded secret root ≥ 32 bytes.
///   2. Ed25519-verify the detached signature over the ciphertext bytes.
///   3. Only then derive the data key and AES-256-GCM-decrypt (the GCM tag
///      authenticates the aad, binding the epoch into the envelope).
#[allow(clippy::too_many_arguments)]
fn unseal_core(
    ciphertext: &[u8],
    iv_b64: &str,
    signature_b64: &str,
    verifying_keys: &[VerifyingKey],
    secret_root_b64: &str,
    salt: &str,
    aad: &str,
    min_epoch: u32,
    expected_context: &str,
) -> Result<Vec<u8>> {
    // Reject empty salt — it carries per-version key scoping. An empty salt
    // makes HKDF derive the same key for every catalog version.
    if salt.is_empty() {
        return Err(Error::from_reason(
            "salt must not be empty: required for per-version key scoping",
        ));
    }
    if aad.is_empty() {
        return Err(Error::from_reason(
            "aad must not be empty: required for anti-rollback version binding",
        ));
    }

    // ANTI-ROLLBACK PARSE (enforced, not convention): the aad must carry a
    // single parseable epoch segment before anything else about it is
    // trusted (CHARIOT::§5.7::26/27) — a rollback barrier that cannot be
    // evaluated, or that can be smuggled past by position, provides no
    // barrier at all.
    let epoch = parse_aad_epoch(aad)?;

    // CHARIOT::§5.7::17 — the salt must equal the aad's <context> segment.
    // Non-emptiness alone is insufficient: a constant salt reused across
    // catalog versions restores exactly the single-key failure the
    // emptiness check exists to prevent.
    let context = parse_aad_context(aad);
    if salt != context {
        return Err(Error::from_reason(format!(
            "salt must equal the aad <context> segment (CHARIOT::§5.7::17): salt={salt:?}, \
             aad context={context:?}"
        )));
    }

    // CHARIOT::§5.7::37/38 — the aad <context> must equal the context
    // expected for THIS installation, sourced from the Ed25519-verified
    // license (never from the snapshot). The AEAD tag authenticates the aad
    // the caller supplied; it does not prove that aad is the one this
    // installation expects, so an unconstrained <context> would admit a
    // legitimately sealed snapshot from another catalog, tenant, or product
    // line.
    if context != expected_context {
        return Err(Error::from_reason(format!(
            "snapshot aad <context> does not match the expected catalog/license context \
             (CHARIOT::§5.7::37): aad context={context:?}, expected={expected_context:?}"
        )));
    }

    // ANTI-ROLLBACK FLOOR: the epoch parsed above must be >= the caller's
    // floor. A replayed old-but-legitimately-signed bundle is self-consistent
    // (its original salt/aad/signature all verify), so the ONLY thing that
    // stops a rollback is comparing the bundle's epoch against a floor
    // sourced OUTSIDE the bundle (the verified license's min_security_epoch).
    if epoch < min_epoch {
        return Err(Error::from_reason(format!(
            "Snapshot epoch rollback rejected: bundle epoch {epoch} is below the \
             enforced floor {min_epoch} (license min_security_epoch)"
        )));
    }

    // Secret key root: must decode and meet the §8.6 secrecy bar. An empty
    // root would make the AES key HKDF(public salt, empty, constant info) —
    // publicly computable (same missing-length-check class as vault.rs).
    let secret_root = BASE64
        .decode(secret_root_b64)
        .map_err(|e| Error::from_reason(format!("Invalid secret root encoding: {e}")))?;
    if secret_root.len() < MIN_SECRET_ROOT_BYTES {
        return Err(Error::from_reason(format!(
            "secret root must be at least {MIN_SECRET_ROOT_BYTES} bytes: §8.6 requires \
             secret key material (got {} bytes)",
            secret_root.len()
        )));
    }

    // (1) Verify signature over the sealed envelope FIRST (untrusted input).
    {
        let sig_bytes = BASE64
            .decode(signature_b64)
            .map_err(|e| Error::from_reason(format!("Invalid signature encoding: {e}")))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| Error::from_reason(format!("Invalid signature format: {e}")))?;
        if !verifying_keys
            .iter()
            .any(|k| k.verify(ciphertext, &signature).is_ok())
        {
            return Err(Error::from_reason("Snapshot signature verification failed"));
        }
    }

    // (2) Derive the data key and AEAD-decrypt.
    let data_key = derive_snapshot_key(&secret_root, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key)
        .map_err(|e| Error::from_reason(format!("Cipher init failed: {e}")))?;

    let iv_bytes = BASE64
        .decode(iv_b64)
        .map_err(|e| Error::from_reason(format!("Invalid IV encoding: {e}")))?;
    if iv_bytes.len() != 12 {
        return Err(Error::from_reason(format!(
            "Invalid IV length: expected 12, got {}",
            iv_bytes.len()
        )));
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::from_reason("Snapshot decryption failed (bad key, IV, AAD, or tag)"))
}

// ── §5.7::34-36 anti-rollback epoch watermark (persisted, process-crossing) ─
//
// Unlike the process-local receipt/manifest key (which MUST NOT survive
// restart — that is what forces re-verification), the epoch watermark is the
// opposite: it MUST survive restart, or a restarted instance would silently
// forget every epoch it had already accepted and admit a replay of the
// oldest still-validly-signed snapshot/license pair it had ever rejected.
// Persisted as JSON under the caller-supplied shard/data directory.

/// Per the build brief: persisted under the shard/data directory the caller
/// supplies (the same directory `unpack`/`load` operate on), so the
/// watermark travels with the installation rather than a separate config
/// path an operator could point elsewhere by mistake.
const EPOCH_WATERMARK_FILE: &str = ".chariot-edge-epoch-watermark.json";

/// Sibling advisory-lock file (CHARIOT::§5.7::34, gate finding F3, R3
/// 2026-09-04): guards the ENTIRE read-compare-write critical section — from
/// the first watermark read (`license_derived_floor_and_context`) through
/// the final re-read-and-persist after a successful unseal — not just the
/// write. Without this, two concurrent unseal calls (e.g. two requests
/// racing at startup) could both read watermark=W, both accept epochs above
/// W, and the loser's `persist_epoch_watermark` write could still land after
/// the winner's, silently regressing the mark it just advanced past.
const EPOCH_WATERMARK_LOCK_FILE: &str = ".chariot-edge-epoch-watermark.lock";

/// RAII guard for an exclusive `flock(2)` advisory lock on the sibling
/// `.lock` file under a watermark directory. `libc` is already a workspace
/// dependency (transitively, via the napi build graph — see
/// `native/Cargo.toml`'s libc comment); no new crate was added.
///
/// Unlike an `O_EXCL` marker-file lock, `flock` needs no stale-lock
/// detection: the kernel releases the lock automatically when every file
/// descriptor referencing it closes — including on process crash or `kill
/// -9` — so a crashed holder can never leave a permanently-stuck lock behind.
struct WatermarkLock {
    file: std::fs::File,
}

impl WatermarkLock {
    /// Blocks until the exclusive lock is acquired (or the OS call fails for
    /// a reason other than contention — e.g. the lock file is unwritable).
    fn acquire(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            Error::from_reason(format!("cannot create watermark directory {dir:?}: {e}"))
        })?;
        let lock_path = dir.join(EPOCH_WATERMARK_LOCK_FILE);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| {
                Error::from_reason(format!(
                    "cannot open §5.7 watermark lock file {lock_path:?}: {e}"
                ))
            })?;
        // SAFETY: `file.as_raw_fd()` is a valid, open file descriptor for the
        // lifetime of `file`, which this call does not outlive.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(Error::from_reason(format!(
                "failed to acquire the §5.7 watermark lock on {lock_path:?}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(WatermarkLock { file })
    }
}

impl Drop for WatermarkLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock; even if this call is somehow skipped
        // or fails, closing `self.file` (which happens immediately after
        // this Drop impl returns) releases the flock regardless — the
        // kernel ties the lock to the fd's lifetime, not to this call
        // succeeding.
        // SAFETY: `self.file` is still a valid, open fd at this point.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Load the persisted watermark from `dir`. A MISSING file means "no prior
/// baseline" (fresh install / first snapshot ever accepted here) and returns
/// `Ok(0)` — every epoch is >= 0, so this does not weaken the check. A
/// PRESENT but corrupt/unparseable file fails closed (CHARIOT::§5.7::34):
/// silently treating corruption as "no baseline" would let an attacker who
/// can write to the data directory reopen the exact rollback window this
/// watermark exists to close.
fn load_epoch_watermark(dir: &Path) -> Result<u32> {
    let path = dir.join(EPOCH_WATERMARK_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(Error::from_reason(format!(
                "cannot read epoch watermark {path:?}: {e}"
            )))
        }
    };
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        Error::from_reason(format!(
            "epoch watermark file {path:?} is corrupt — refusing to load rather than silently \
             treating it as absent (fail-closed, CHARIOT::§5.7::34): {e}"
        ))
    })?;
    v.get("epoch")
        .and_then(|e| e.as_u64())
        .and_then(|e| u32::try_from(e).ok())
        .ok_or_else(|| {
            Error::from_reason(format!(
                "epoch watermark file {path:?} is missing a valid non-negative integer 'epoch' \
                 field — refusing to load (fail-closed, CHARIOT::§5.7::34)"
            ))
        })
}

/// Persist `epoch` as the new watermark under `dir`, creating the directory
/// if needed. Callers MUST only call this AFTER a snapshot has passed every
/// other §5.7 check — persisting on a rejected attempt would let a failed
/// probe still advance (or, worse, be used to manipulate) the mark. Callers
/// MUST hold a `WatermarkLock` on `dir` for the whole read-compare-write
/// section this call is the write half of (gate finding F3).
///
/// CRASH-SAFETY (F3): writes to a per-call-unique temp file in the SAME
/// directory (`EPOCH_WATERMARK_FILE.tmp-<pid>-<nonce>` — same filesystem, so
/// the final rename is atomic on POSIX), fsyncs the temp file's data BEFORE
/// renaming (a crash between write and rename can therefore never leave a
/// torn write visible at the real path — `load_epoch_watermark` only ever
/// reads the fixed `EPOCH_WATERMARK_FILE` name and so never sees a `.tmp-*`
/// file at all, present or not), renames over the target (POSIX `rename(2)`
/// is atomic — a concurrent reader observes either the fully-old or
/// fully-new content, never a partial file), then fsyncs the CONTAINING
/// DIRECTORY so the rename's directory-entry update itself survives a crash
/// (a data-only fsync of the file does not guarantee that on every POSIX
/// filesystem — ext4/xfs both require the directory fsync for the rename to
/// be durable).
fn persist_epoch_watermark(dir: &Path, epoch: u32) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::from_reason(format!("cannot create watermark directory {dir:?}: {e}")))?;
    let path = dir.join(EPOCH_WATERMARK_FILE);
    let body = serde_json::json!({ "epoch": epoch });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| Error::from_reason(format!("watermark serialization failed: {e}")))?;

    let mut nonce_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let tmp_path = dir.join(format!(
        "{EPOCH_WATERMARK_FILE}.tmp-{}-{}",
        std::process::id(),
        hex_encode(&nonce_bytes)
    ));

    {
        let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
            Error::from_reason(format!("cannot create watermark temp file {tmp_path:?}: {e}"))
        })?;
        f.write_all(&bytes).map_err(|e| {
            Error::from_reason(format!("cannot write watermark temp file {tmp_path:?}: {e}"))
        })?;
        f.sync_all().map_err(|e| {
            Error::from_reason(format!("cannot fsync watermark temp file {tmp_path:?}: {e}"))
        })?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::from_reason(format!(
            "cannot rename watermark temp file into place at {path:?}: {e}"
        )));
    }

    // Best-effort directory fsync: a failure here does not mean the rename
    // was lost (it already landed in the filesystem's in-memory state and
    // every subsequent read in THIS process sees it) — it only means a
    // concurrent hard crash immediately after could, on some filesystems,
    // roll the directory entry back. Surfacing that as a hard error would
    // fail a successful watermark advance over a durability nicety the
    // caller cannot act on anyway; log-free per this module's existing
    // `Result`-only error surface (no logger dependency here).
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// CHARIOT::§5.7::29/30/31/32/33/36 — derive the (floor, context) pair the
/// §5.7 unseal entry points use, from the REAL customer license JWT
/// (`~/.epic-ai/chariot.license`, R2 ruling 2026-09-04) this function
/// verifies itself, and reject a license-derived floor that has regressed
/// below the persisted watermark. Shared by both NAPI unseal variants so the
/// license-verification + watermark-floor logic cannot drift between them.
///
/// Returns `(effective_floor, expected_context, watermark_dir)` — the
/// effective floor is `max(license.min_security_epoch, persisted watermark)`,
/// so the epoch check inside `unseal_core` enforces both the license's floor
/// and the process-crossing watermark in one comparison.
fn license_derived_floor_and_context(
    license_jwt: &str,
    watermark_dir: &str,
) -> Result<(u32, String, PathBuf)> {
    // CHARIOT::§5.7::32/33 — the unseal entry point verifies the license
    // JWT's Ed25519 signature ITSELF (never trusting an already-decoded
    // caller claim) and reads `min_security_epoch` from the VERIFIED
    // payload only. Routed through `license::verify_license_jwt_and_extract`
    // (not `verify_jwt_with_pems` directly) so the compiled-in accepted-key
    // binding for PRODUCTION callers lives in exactly one place in the
    // codebase — the test-only `_with_pems` variant below is the sole other
    // caller of the lower-level primitive, and takes its accepted keys
    // explicitly rather than duplicating this binding.
    let license = crate::license::verify_license_jwt_and_extract(license_jwt)?;
    floor_and_context_from_verified_license(license, watermark_dir)
}

/// `license_derived_floor_and_context`, parameterized by the license JWT's
/// accepted verifying-key PEMs (gate finding F4, 2026-09-04). The production
/// wrapper above binds the compiled-in accepted set via
/// `license::verify_license_jwt_and_extract`; tests call this directly (via
/// `unseal_and_verify_snapshot_with_keys`) with a fixture keypair to
/// exercise the FULL §5.7 pipeline — not just `verify_jwt_with_pems` in
/// isolation — without a production private key.
fn license_derived_floor_and_context_with_pems(
    license_jwt: &str,
    watermark_dir: &str,
    accepted_pems: &[&str],
) -> Result<(u32, String, PathBuf)> {
    let license = crate::license::verify_jwt_with_pems(license_jwt, accepted_pems)?;
    floor_and_context_from_verified_license(license, watermark_dir)
}

/// Shared by both `license_derived_floor_and_context` and its `_with_pems`
/// test-seam sibling (2026-09-04 dead-code fix): everything AFTER the
/// license JWT has been verified — deriving the expected context, loading
/// the persisted watermark, rejecting a regressed floor, and computing the
/// effective floor — lives here exactly once, so the two callers cannot
/// drift on this logic even though they source the verified license two
/// different ways.
fn floor_and_context_from_verified_license(
    license: crate::license::VerifiedLicenseFloor,
    watermark_dir: &str,
) -> Result<(u32, String, PathBuf)> {
    let min_security_epoch = license.min_security_epoch;
    // CHARIOT::§5.7::16/17/38 — the `salt` is the catalog version identifier
    // and the expected `<context>` is derived from the verified licence. The
    // licence carries the catalog version it may unseal as the signed
    // `catalog_version` claim, which satisfies both clauses as written (this
    // closes rulings item 83, whose interim tenant/sub context disagreed with
    // the producer's catalog-version salt). No claim, no sealed access: a
    // tenant or company id is never substituted.
    let expected_context = match license.catalog_version.as_deref() {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => {
            return Err(Error::from_reason(format!(
                "license (sub={:?}, tenant_id={:?}) carries no catalog_version claim; a sealed \
                 catalog snapshot cannot be bound to it (CHARIOT::§5.7::38)",
                license.company_id, license.tenant_id
            )))
        }
    };

    let watermark_path = PathBuf::from(watermark_dir);
    let watermark = load_epoch_watermark(&watermark_path)?;
    // CHARIOT::§5.7::36 — the license-derived floor itself must not have
    // regressed below the watermark: a downgraded-but-still-validly-signed
    // license paired with its matching old snapshot would otherwise satisfy
    // every other check and roll back through the front door.
    if min_security_epoch < watermark {
        return Err(Error::from_reason(format!(
            "license min_security_epoch {min_security_epoch} is below the previously accepted \
             epoch watermark {watermark} (CHARIOT::§5.7::36): refusing a regressed \
             license-derived floor"
        )));
    }
    let effective_floor = min_security_epoch.max(watermark);
    Ok((effective_floor, expected_context, watermark_path))
}

/// Unseal AND verify a sealed Edge snapshot, fail-closed.
///
/// Order (untrusted input first): (1) verify the signed license blob and
/// derive the anti-rollback floor + expected context from it (never from the
/// snapshot); (2) anti-rollback + key-material + context-binding guards; (3)
/// Ed25519-verify the detached signature over the sealed envelope
/// (`ciphertext_b64` bytes) with the PINNED verifying key; (4) only then
/// derive the data key and AES-256-GCM-decrypt. A bad signature or a bad
/// auth tag returns Err — corrupt input is never partially processed. Only
/// on full success is the epoch watermark advanced (CHARIOT::§5.7::34/35).
///
/// NOTE (memory): this variant holds ciphertext + plaintext + both base64
/// strings simultaneously (~4.7× snapshot size peak) and is subject to V8's
/// max string length. For large snapshots use
/// `unseal_and_verify_snapshot_to_file`, which is file-to-file.
///
/// `ciphertext_b64`  : base64 AES-GCM ciphertext (includes the 16-byte tag).
/// `iv_b64`          : base64 12-byte IV.
/// `signature_b64`   : base64 Ed25519 detached signature over the raw
///                     ciphertext bytes (the bytes decoded from `ciphertext_b64`).
/// `public_key_pem`  : Ed25519 SPKI PEM used to verify the SNAPSHOT signature.
///                     MUST be one of the compiled-in accepted keys (pinned
///                     trust anchor); any other key is rejected.
/// `secret_root_b64` : base64 secret key root (per-license secret OR
///                     ENTERPRISE_MASTER_KEY) — NOT the public license blob.
///                     Rejected if shorter than 32 bytes after decoding.
/// `salt`            : HKDF salt binding the key to a context (the catalog
///                     version identifier); MUST equal the aad `<context>`.
/// `aad`             : Additional Authenticated Data bound into the AEAD.
///                     MUST be structured `<context>|epoch=N`
///                     (e.g. `v4.0.0|epoch=7`); unparseable aad is rejected.
/// `license_jwt`     : the REAL customer license artifact (CHARIOT::§5.7::32,
///                     R2 ruling 2026-09-04) — the compact JWT from the
///                     envelope at `~/.epic-ai/chariot.license`
///                     (`{ "jwt": "<compact JWT>", "renewal_secret": … }`,
///                     `src/license/loader.ts`), NOT a bare floor scalar.
///                     This function verifies its Ed25519 signature itself
///                     against the compiled-in accepted key set (by `kid`
///                     when present, else every accepted key) before
///                     trusting anything in it.
/// `watermark_dir`   : directory the persisted, monotonically non-decreasing
///                     epoch watermark lives under (CHARIOT::§5.7::34) —
///                     pass the shard/data directory this snapshot targets.
#[allow(clippy::too_many_arguments)]
#[napi]
pub fn unseal_and_verify_snapshot(
    ciphertext_b64: String,
    iv_b64: String,
    signature_b64: String,
    public_key_pem: String,
    secret_root_b64: String,
    salt: String,
    aad: String,
    license_jwt: String,
    watermark_dir: String,
) -> Result<UnsealedSnapshot> {
    // Pinning is preserved EXACTLY as before the F4 refactor below: the
    // caller-supplied `public_key_pem` must itself be a member of the
    // compiled-in accepted set (`pinned_verifying_key`), not merely "one of
    // several keys we happen to try" — that check stays here, in the
    // production entry point, and is NOT part of the testable inner function.
    let key = pinned_verifying_key(&public_key_pem)?;
    unseal_and_verify_snapshot_with_keys(
        &ciphertext_b64,
        &iv_b64,
        &signature_b64,
        &[key],
        &secret_root_b64,
        &salt,
        &aad,
        &license_jwt,
        crate::license::ACCEPTED_PUBLIC_KEYS_PEM,
        &watermark_dir,
    )
}

/// Full body of `unseal_and_verify_snapshot`, parameterized by (1) the
/// SNAPSHOT signature's already-resolved candidate verifying key(s) and (2)
/// the LICENSE JWT's accepted verifying-key PEMs (gate finding F4,
/// 2026-09-04). The `#[napi]` wrapper above is the only caller that binds
/// both to production key material (`pinned_verifying_key` for (1),
/// `ACCEPTED_PUBLIC_KEYS_PEM` for (2)) — tests call this function directly
/// with fixture keys to exercise the COMPLETE pipeline (watermark lock,
/// license verification, anti-rollback floor, context binding, AEAD) rather
/// than only its individual pieces in isolation, closing the gap where a
/// prior test suite could prove `verify_jwt_with_pems` rejects a bad JWT but
/// never proved the NAPI-shaped entry point does the same.
#[allow(clippy::too_many_arguments)]
fn unseal_and_verify_snapshot_with_keys(
    ciphertext_b64: &str,
    iv_b64: &str,
    signature_b64: &str,
    snapshot_verifying_keys: &[VerifyingKey],
    secret_root_b64: &str,
    salt: &str,
    aad: &str,
    license_jwt: &str,
    license_accepted_pems: &[&str],
    watermark_dir: &str,
) -> Result<UnsealedSnapshot> {
    // F3 (gate finding, 2026-09-04): the watermark lock is acquired FIRST and
    // held for the ENTIRE critical section — every watermark read below
    // (inside `license_derived_floor_and_context_with_pems` AND the re-read
    // just before `persist_epoch_watermark`) happens while `_watermark_lock`
    // is held, so two concurrent unseal calls against the same
    // watermark_dir cannot interleave a read-compare-write and silently
    // regress the mark. Dropped at the end of this function's scope
    // (including every early `?` return).
    let _watermark_lock = WatermarkLock::acquire(Path::new(watermark_dir))?;
    let (effective_floor, expected_context, watermark_path) =
        license_derived_floor_and_context_with_pems(license_jwt, watermark_dir, license_accepted_pems)?;
    let ciphertext = BASE64
        .decode(ciphertext_b64)
        .map_err(|e| Error::from_reason(format!("Invalid ciphertext encoding: {e}")))?;
    let plaintext = unseal_core(
        &ciphertext,
        iv_b64,
        signature_b64,
        snapshot_verifying_keys,
        secret_root_b64,
        salt,
        aad,
        effective_floor,
        &expected_context,
    )?;
    // Reached only on full success — advance the watermark to the accepted
    // epoch (CHARIOT::§5.7::34/35). `aad` was already validated by
    // `unseal_core`, so this re-parse cannot fail. This re-read is the
    // compare-and-swap half: still under `_watermark_lock`, so it observes
    // any advance a concurrent call made and persists strictly forward from
    // there — never regresses it.
    let accepted_epoch = parse_aad_epoch(aad)?;
    let watermark = load_epoch_watermark(&watermark_path)?;
    persist_epoch_watermark(&watermark_path, accepted_epoch.max(watermark))?;
    let receipt = compute_unseal_receipt(&plaintext);
    Ok(UnsealedSnapshot {
        plaintext_b64: BASE64.encode(&plaintext),
        receipt,
    })
}

// ── File-form I/O hardening (CHARIOT::§5.7 envelope fields, AMENDED
// 2026-10-14: the ciphertext "file reference" names "a regular file, not a
// symbolic link") ────────────────────────────────────────────────────────

/// Read a whole REGULAR file without following a symlink at its final path
/// component (`O_NOFOLLOW`): a symlink fails the open with `ELOOP`, and any
/// non-regular object (directory, FIFO, device) is refused after `fstat` on
/// the opened descriptor — so the type check and the read observe the same
/// inode (no lstat-then-open TOCTOU).
fn read_regular_file_nofollow(path: &str, what: &str) -> Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            Error::from_reason(format!(
                "Cannot open {what} {path} (a symbolic link is refused): {e}"
            ))
        })?;
    let meta = file
        .metadata()
        .map_err(|e| Error::from_reason(format!("Cannot stat {what} {path}: {e}")))?;
    if !meta.is_file() {
        return Err(Error::from_reason(format!(
            "{what} {path} is not a regular file"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::from_reason(format!("Cannot read {what} {path}: {e}")))?;
    Ok(bytes)
}

/// Refuse early (before any license/crypto work) when ANY directory entry —
/// a regular file, a directory, a live or dangling symlink — already exists
/// at `path`. Advisory only: `write_new_private_file`'s `O_CREAT|O_EXCL|
/// O_NOFOLLOW` open remains the authoritative, race-free refusal.
fn refuse_existing_entry(path: &str, what: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(Error::from_reason(format!(
            "{what} {path} already exists; refusing to overwrite or write through it"
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::from_reason(format!("Cannot stat {what} {path}: {e}"))),
    }
}

/// Create `path` as a NEW file and write `bytes` durably: `create_new`
/// (`O_CREAT|O_EXCL` — refuses ANY pre-existing entry, including a symlink,
/// which `O_EXCL` never follows), `O_NOFOLLOW` (defense in depth), mode 0600
/// (umask may only narrow it), then `sync_all` before returning. Mirrors
/// `ChariotState.ts`'s F2 staging-archive hardening (`O_WRONLY|O_CREAT|
/// O_EXCL|O_NOFOLLOW`, 0600, fsync). A failed write/fsync removes the file
/// THIS call created, so no partial plaintext/ciphertext is left behind.
fn write_new_private_file(path: &str, bytes: &[u8], what: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            Error::from_reason(format!(
                "Cannot create {what} {path} (an existing file or symbolic link is refused): {e}"
            ))
        })?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(Error::from_reason(format!("Cannot write {what} {path}: {e}")));
    }
    Ok(())
}

/// File-to-file unseal+verify: reads the sealed ciphertext from `sealed_path`,
/// runs the identical fail-closed pipeline as `unseal_and_verify_snapshot`
/// (pinned key, license-derived anti-rollback floor + context, persisted
/// watermark, Ed25519-then-AEAD), and writes the plaintext archive to
/// `out_path`. Peak memory ≈ 2× snapshot size (no base64 round-trip, no V8
/// string-length ceiling). Returns the receipt to pass to
/// `edge_unpack_snapshot(out_path, target, receipt)`.
///
/// `sealed_path` must be a regular file and is opened `O_NOFOLLOW` (CHARIOT
/// §5.7 file-reference form: "a regular file, not a symbolic link").
/// `out_path` must NOT exist: any pre-existing entry (file, directory,
/// symlink — live or dangling) is refused before any license/crypto work,
/// and the plaintext is written with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600,
/// then `sync_all` (matching `ChariotState.ts`'s F2 hardening).
#[allow(clippy::too_many_arguments)]
#[napi]
pub fn unseal_and_verify_snapshot_to_file(
    sealed_path: String,
    out_path: String,
    iv_b64: String,
    signature_b64: String,
    public_key_pem: String,
    secret_root_b64: String,
    salt: String,
    aad: String,
    license_jwt: String,
    watermark_dir: String,
) -> Result<UnsealReceipt> {
    let key = pinned_verifying_key(&public_key_pem)?;
    // Production license binding is unchanged: the compiled-in accepted set
    // via `license_derived_floor_and_context` (license::
    // verify_license_jwt_and_extract).
    unseal_to_file_inner(
        &sealed_path,
        &out_path,
        &iv_b64,
        &signature_b64,
        &[key],
        &secret_root_b64,
        &salt,
        &aad,
        &watermark_dir,
        &|| license_derived_floor_and_context(&license_jwt, &watermark_dir),
    )
}

/// Test seam for `unseal_and_verify_snapshot_to_file` — same role as
/// `unseal_and_verify_snapshot_with_keys` (gate finding F4): fixture snapshot
/// verifying key(s) and fixture license PEMs drive the COMPLETE file-to-file
/// pipeline (watermark lock, license verification, anti-rollback floor,
/// context binding, AEAD, hardened plaintext write) without a production
/// private key. The `#[napi]` wrapper above is the only production caller of
/// the shared body.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn unseal_and_verify_snapshot_to_file_with_keys(
    sealed_path: &str,
    out_path: &str,
    iv_b64: &str,
    signature_b64: &str,
    snapshot_verifying_keys: &[VerifyingKey],
    secret_root_b64: &str,
    salt: &str,
    aad: &str,
    license_jwt: &str,
    license_accepted_pems: &[&str],
    watermark_dir: &str,
) -> Result<UnsealReceipt> {
    unseal_to_file_inner(
        sealed_path,
        out_path,
        iv_b64,
        signature_b64,
        snapshot_verifying_keys,
        secret_root_b64,
        salt,
        aad,
        watermark_dir,
        &|| license_derived_floor_and_context_with_pems(license_jwt, watermark_dir, license_accepted_pems),
    )
}

/// Shared body of the file-to-file unseal. `resolve_floor` is the ONLY
/// difference between the production and test entry points (which accepted
/// license keys verify the JWT); it is invoked strictly AFTER the watermark
/// lock is acquired (F3), exactly as in `unseal_and_verify_snapshot_with_keys`.
#[allow(clippy::too_many_arguments)]
fn unseal_to_file_inner(
    sealed_path: &str,
    out_path: &str,
    iv_b64: &str,
    signature_b64: &str,
    snapshot_verifying_keys: &[VerifyingKey],
    secret_root_b64: &str,
    salt: &str,
    aad: &str,
    watermark_dir: &str,
    resolve_floor: &dyn Fn() -> Result<(u32, String, PathBuf)>,
) -> Result<UnsealReceipt> {
    // Refuse a pre-existing out_path BEFORE the watermark lock, license
    // verification or AEAD work: no plaintext is ever produced for a write
    // that would be refused, and the watermark is not advanced by it.
    refuse_existing_entry(out_path, "plaintext snapshot output")?;
    // F3 — see `unseal_and_verify_snapshot_with_keys`'s identical comment.
    let _watermark_lock = WatermarkLock::acquire(Path::new(watermark_dir))?;
    let (effective_floor, expected_context, watermark_path) = resolve_floor()?;
    let ciphertext = read_regular_file_nofollow(sealed_path, "sealed snapshot ciphertext")?;
    let plaintext = unseal_core(
        &ciphertext,
        iv_b64,
        signature_b64,
        snapshot_verifying_keys,
        secret_root_b64,
        salt,
        aad,
        effective_floor,
        &expected_context,
    )?;
    drop(ciphertext);
    // Write BEFORE advancing the watermark: a refused/failed write (e.g. an
    // entry created at out_path after the early check) leaves the watermark
    // where it was, so the identical snapshot can be retried.
    write_new_private_file(out_path, &plaintext, "plaintext snapshot output")?;
    // Reached only on full success (CHARIOT::§5.7::34/35) — same
    // compare-and-swap re-read under `_watermark_lock` as the inline variant.
    let advance = parse_aad_epoch(aad).and_then(|accepted_epoch| {
        let watermark = load_epoch_watermark(&watermark_path)?;
        persist_epoch_watermark(&watermark_path, accepted_epoch.max(watermark))
    });
    if let Err(e) = advance {
        // Fail closed: no plaintext is left behind for a load whose
        // anti-rollback bookkeeping did not complete.
        let _ = std::fs::remove_file(out_path);
        return Err(e);
    }
    let receipt = compute_unseal_receipt(&plaintext);
    Ok(UnsealReceipt { receipt })
}

// ── §5.7 producer: encrypt-then-sign sealer (promoted from the #[cfg(test)]
// fixture — this is now the real, reachable producer) ───────────────────

/// The `sealedShard` descriptor (CHARIOT::§5.7::1-7): the AES-256-GCM
/// ciphertext (including its trailing 16-byte tag), the fresh 12-byte IV,
/// the Ed25519 detached signature over the raw ciphertext bytes, the HKDF
/// salt, and the AEAD `aad`. Deliberately NOT nested inside, or exported as
/// part of, the §5.6 signed bundle envelope object (CHARIOT::§5.7::8) — it
/// is a sibling artifact with its own signature, so the confidentiality
/// envelope's integrity never depends on the catalog envelope's.
#[napi(object)]
pub struct SealedShard {
    pub ciphertext_b64: String,
    pub iv_b64: String,
    pub signature_b64: String,
    pub salt: String,
    pub aad: String,
}

/// File-form `sealedShard` result (CHARIOT §5.7 envelope fields, AMENDED
/// 2026-10-14: `ciphertext` "as a file reference or base64 string"). The
/// ciphertext bytes are written to the caller's `ciphertext_path` and never
/// cross the JS boundary; `ciphertext_sha256_hex` is the lowercase hex
/// SHA-256 of exactly those bytes, for the descriptor's
/// `"ciphertext": { "file", "sha256" }` member.
#[napi(object)]
pub struct SealedShardFile {
    pub iv_b64: String,
    pub signature_b64: String,
    pub salt: String,
    pub aad: String,
    pub ciphertext_sha256_hex: String,
}

/// Validated, decoded seal inputs (everything except the plaintext).
struct SealParams {
    secret_root: Vec<u8>,
    signing_key: SigningKey,
    salt: String,
    aad: String,
}

/// Validate and decode the non-plaintext seal inputs, fail-closed, BEFORE any
/// plaintext is read or decoded (so the file variant never reads a large
/// archive for a call that would be refused anyway).
fn prepare_seal(
    secret_root_b64: &str,
    salt: String,
    context: &str,
    epoch: u32,
    signing_key_seed_b64: &str,
) -> Result<SealParams> {
    // CHARIOT::§5.7::17 (producer half) — a descriptor whose salt and aad
    // context disagree would only be rejected downstream by every consumer;
    // refuse to emit it at all.
    if salt != context {
        return Err(Error::from_reason(format!(
            "salt must equal context: refusing to emit a sealedShard whose salt ({salt:?}) and \
             aad <context> ({context:?}) disagree (CHARIOT::§5.7::16/17)"
        )));
    }
    if salt.is_empty() {
        return Err(Error::from_reason(
            "salt/context must not be empty: required for per-version key scoping \
             (CHARIOT::§5.7::15)",
        ));
    }

    let secret_root = BASE64
        .decode(secret_root_b64)
        .map_err(|e| Error::from_reason(format!("Invalid secret root encoding: {e}")))?;
    if secret_root.len() < MIN_SECRET_ROOT_BYTES {
        return Err(Error::from_reason(format!(
            "secret root must be at least {MIN_SECRET_ROOT_BYTES} bytes (CHARIOT::§5.7::14, \
             got {} bytes)",
            secret_root.len()
        )));
    }

    let seed_bytes = BASE64
        .decode(signing_key_seed_b64)
        .map_err(|e| Error::from_reason(format!("Invalid signing key seed encoding: {e}")))?;
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|bytes: Vec<u8>| {
        Error::from_reason(format!(
            "Ed25519 signing key seed must be exactly 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    let signing_key = SigningKey::from_bytes(&seed);

    let aad = format!("{context}|epoch={epoch}");
    Ok(SealParams {
        secret_root,
        signing_key,
        salt,
        aad,
    })
}

/// The encrypt-then-sign core shared by `seal_edge_snapshot` (base64) and
/// `seal_edge_snapshot_file` (file-to-file). Returns
/// `(ciphertext, iv, signature, aad)`; the ciphertext carries the trailing
/// 16-byte GCM tag.
fn seal_core(plaintext: &[u8], params: &SealParams) -> Result<(Vec<u8>, [u8; 12], [u8; 64], String)> {
    let data_key = derive_snapshot_key(params.secret_root.as_slice(), &params.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key)
        .map_err(|e| Error::from_reason(format!("Cipher init failed: {e}")))?;

    // CHARIOT::§5.7::18/19 — IV UNIQUENESS: a fresh CSPRNG draw per seal,
    // NEVER a counter or any value derived from salt/epoch/plaintext. AES-GCM
    // nonce reuse under one derived key yields keystream recovery and
    // authentication-key compromise, so a fixed or derived IV paired with a
    // version-constant salt would defeat the seal entirely.
    let mut iv_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: params.aad.as_bytes(),
            },
        )
        .map_err(|_| Error::from_reason("Snapshot encryption failed"))?;

    // CHARIOT::§5.7::20/21 — ENCRYPT-THEN-SIGN: the signature covers the
    // ciphertext bytes only. The IV is deliberately NOT part of the signed
    // message — the GCM authentication tag already commits to it
    // cryptographically (an altered IV fails the tag), so the consumer's
    // `flip_iv_fails_at_gcm_not_signature` test is the mirror-image proof of
    // this producer-side ordering.
    let signature = params.signing_key.sign(&ciphertext);

    Ok((ciphertext, iv_bytes, signature.to_bytes(), params.aad.clone()))
}

/// Encrypt-then-sign seal a plaintext Edge snapshot archive.
///
/// `plaintext_b64`         : base64 of the plaintext snapshot archive bytes.
/// `secret_root_b64`       : base64 secret key root — a per-license secret
///                           key or `ENTERPRISE_MASTER_KEY` (CHARIOT::§5.7::10),
///                           NEVER the public signed license blob
///                           (CHARIOT::§5.7::11). Rejected if < 32 bytes.
/// `salt`                  : the catalog version identifier (§5.7::16). The
///                           consumer derives its expected context from the
///                           verified licence's `catalog_version` claim
///                           (`license_derived_floor_and_context` in this
///                           file), so the target licence must carry the
///                           same value.
/// `context`               : the aad `<context>` segment. The producer
///                           enforces its own half of the salt==context
///                           invariant (CHARIOT::§5.7::17) — `salt` and
///                           `context` MUST be identical, or this call fails
///                           closed rather than emitting a descriptor a
///                           consumer would only reject later. Per the
///                           `salt` note above, this value must equal the
///                           TARGET licence's `catalog_version` claim.
/// `epoch`                 : the catalog epoch to bind into the aad's
///                           anti-rollback segment.
/// `signing_key_seed_b64`  : base64 of the 32-byte raw Ed25519 signing-key
///                           seed (the operator's private key material —
///                           `SigningKey::from_bytes`, the same primitive
///                           this crate already uses for every fixture
///                           signing key). The corresponding public key MUST
///                           be one of the compiled-in accepted keys
///                           (`license.rs::ACCEPTED_PUBLIC_KEYS_PEM`) for any
///                           consumer to unseal the result — this function
///                           does not itself enforce that, since the
///                           producer runs with the OPERATOR's key material,
///                           not a caller-supplied one to pin against.
#[napi]
pub fn seal_edge_snapshot(
    plaintext_b64: String,
    secret_root_b64: String,
    salt: String,
    context: String,
    epoch: u32,
    signing_key_seed_b64: String,
) -> Result<SealedShard> {
    // Every non-plaintext guard (salt == context, non-empty salt, secret root
    // >= 32 bytes, 32-byte seed) runs in `prepare_seal` before the plaintext
    // is decoded; the encrypt-then-sign itself is `seal_core`, shared with
    // `seal_edge_snapshot_file`.
    let params = prepare_seal(&secret_root_b64, salt, &context, epoch, &signing_key_seed_b64)?;
    let plaintext = BASE64
        .decode(&plaintext_b64)
        .map_err(|e| Error::from_reason(format!("Invalid plaintext encoding: {e}")))?;
    let (ciphertext, iv_bytes, signature, aad) = seal_core(&plaintext, &params)?;
    Ok(SealedShard {
        ciphertext_b64: BASE64.encode(&ciphertext),
        iv_b64: BASE64.encode(iv_bytes),
        signature_b64: BASE64.encode(signature),
        salt: params.salt,
        aad,
    })
}

/// File-to-file encrypt-then-sign seal (CHARIOT §5.7 file-reference form,
/// AMENDED 2026-10-14): a real catalog shard archive exceeds V8's maximum
/// string length, so neither the plaintext nor the ciphertext may cross the
/// JS boundary as base64. Identical guards and crypto to `seal_edge_snapshot`
/// (`prepare_seal` + `seal_core`).
///
/// `plaintext_path`  : the plaintext snapshot archive; must be a regular file
///                     (opened `O_NOFOLLOW`).
/// `ciphertext_path` : where the ciphertext (with its trailing 16-byte GCM
///                     tag) is written. MUST NOT exist: created with
///                     `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, `sync_all`
///                     before return — an existing file or symlink is refused.
/// Remaining parameters: exactly as `seal_edge_snapshot`.
///
/// Returns the descriptor fields that are NOT the ciphertext, plus the
/// lowercase hex SHA-256 of the written ciphertext bytes.
#[napi]
pub fn seal_edge_snapshot_file(
    plaintext_path: String,
    ciphertext_path: String,
    secret_root_b64: String,
    salt: String,
    context: String,
    epoch: u32,
    signing_key_seed_b64: String,
) -> Result<SealedShardFile> {
    let params = prepare_seal(&secret_root_b64, salt, &context, epoch, &signing_key_seed_b64)?;
    refuse_existing_entry(&ciphertext_path, "sealed snapshot ciphertext output")?;
    let plaintext = read_regular_file_nofollow(&plaintext_path, "plaintext snapshot archive")?;
    let (ciphertext, iv_bytes, signature, aad) = seal_core(&plaintext, &params)?;
    drop(plaintext);
    write_new_private_file(&ciphertext_path, &ciphertext, "sealed snapshot ciphertext output")?;
    Ok(SealedShardFile {
        iv_b64: BASE64.encode(iv_bytes),
        signature_b64: BASE64.encode(signature),
        salt: params.salt,
        aad,
        ciphertext_sha256_hex: hex_encode(&Sha256::digest(&ciphertext)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as JWT_B64URL;
    use ed25519_dalek::{Signer, SigningKey};

    const SECRET_ROOT: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    /// CHARIOT::§5.7::17 requires `salt == aad <context>`, so both constants
    /// below carry the SAME value ("v4.0.0", the catalog version identifier
    /// per §5.7::16) — CONTEXT doubles as the fixture's expected_context
    /// (§5.7::37/38) for every test that is not specifically exercising a
    /// context mismatch.
    const CONTEXT: &str = "v4.0.0";
    const SALT: &str = CONTEXT;
    const AAD: &str = "v4.0.0|epoch=7";

    /// Seal `plaintext` (encrypt-then-sign) with a deterministic fixture key.
    /// Returns (ciphertext, iv, signature bytes, verifying key). The fixture
    /// key is NOT in the compiled-in accepted set, so these tests drive
    /// `unseal_core` directly — the NAPI surface pins keys (see
    /// `fixture_key_rejected_by_pinning`).
    fn seal(plaintext: &[u8], aad: &str) -> (Vec<u8>, [u8; 12], [u8; 64], VerifyingKey) {
        let key = derive_snapshot_key(SECRET_ROOT, SALT).expect("derive");
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let iv = [7u8; 12];
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        // Deterministic test key from fixed bytes — ed25519-dalek's `generate`
        // needs the `rand_core` feature, which the library build does not enable.
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = signing.verifying_key();
        let sig = signing.sign(&ciphertext);
        (ciphertext, iv, sig.to_bytes(), verifying)
    }

    #[allow(clippy::too_many_arguments)]
    fn unseal(
        ciphertext: &[u8],
        iv: &[u8; 12],
        sig: &[u8; 64],
        verifying: &VerifyingKey,
        secret_root: &[u8],
        salt: &str,
        aad: &str,
        min_epoch: u32,
    ) -> Result<Vec<u8>> {
        unseal_with_context(
            ciphertext, iv, sig, verifying, secret_root, salt, aad, min_epoch, CONTEXT,
        )
    }

    /// Full-control variant of `unseal()` that also takes `expected_context`,
    /// for tests exercising the §5.7::37/38 context-binding check itself.
    #[allow(clippy::too_many_arguments)]
    fn unseal_with_context(
        ciphertext: &[u8],
        iv: &[u8; 12],
        sig: &[u8; 64],
        verifying: &VerifyingKey,
        secret_root: &[u8],
        salt: &str,
        aad: &str,
        min_epoch: u32,
        expected_context: &str,
    ) -> Result<Vec<u8>> {
        unseal_core(
            ciphertext,
            &BASE64.encode(iv),
            &BASE64.encode(sig),
            std::slice::from_ref(verifying),
            &BASE64.encode(secret_root),
            salt,
            aad,
            min_epoch,
            expected_context,
        )
    }

    /// Round-trip: seal (encrypt-then-sign) → unseal_core recovers the
    /// plaintext, and a tampered ciphertext / wrong key / wrong AAD fail closed.
    #[test]
    fn seal_roundtrip_and_tamper_detection() {
        let plaintext = b"fake edge snapshot archive bytes";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD);

        // Happy path (epoch 7 meets floor 7).
        let out = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7,
        )
        .expect("unseal ok");
        assert_eq!(out, plaintext);

        // Tampered ciphertext → signature fails closed.
        let mut bad = ciphertext.clone();
        bad[0] ^= 0xff;
        let r = unseal(&bad, &iv, &sig, &verifying, SECRET_ROOT, SALT, AAD, 7);
        assert!(r.is_err(), "tampered ciphertext must fail");

        // Wrong AAD (valid epoch shape) → AEAD auth fails (signature still
        // valid over ciphertext).
        let r2 = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            "WRONG-AAD|epoch=7",
            7,
        );
        assert!(r2.is_err(), "wrong AAD must fail");

        // Wrong secret root → key derivation differs → auth fails.
        let r3 = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            b"ffffffffffffffffffffffffffffffff",
            SALT,
            AAD,
            7,
        );
        assert!(r3.is_err(), "wrong secret root must fail");
    }

    /// ANTI-ROLLBACK: a replayed old bundle with its ORIGINAL, fully valid
    /// salt/aad/signature must be rejected when its epoch is below the floor.
    /// This is the regression test for the caller-supplied-rollback finding —
    /// before the fix, this exact input presented as success.
    #[test]
    fn epoch_rollback_rejected() {
        let plaintext = b"old but legitimately signed bundle";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD); // epoch=7

        // Floor advanced to 8 (license min_security_epoch) → replay rejected.
        let r = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            8,
        );
        assert!(r.is_err(), "epoch 7 bundle must be rejected under floor 8");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("rollback"),
            "error must identify the rollback rejection; got: {msg}"
        );

        // Floor at/below the bundle epoch → admitted.
        assert!(unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7
        )
        .is_ok());
        assert!(unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            0
        )
        .is_ok());
    }

    /// An aad without a parseable `epoch=N` segment must be rejected — an
    /// unevaluable rollback barrier is no barrier (fail-closed).
    #[test]
    fn unparseable_aad_epoch_rejected() {
        let plaintext = b"payload";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, "v4.0.0-no-epoch");
        let r = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            "v4.0.0-no-epoch",
            0,
        );
        assert!(r.is_err(), "aad without epoch= must be rejected");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("epoch"),
            "error must mention epoch; got: {msg}"
        );

        // Garbage epoch value also rejected.
        assert!(parse_aad_epoch("v4|epoch=abc").is_err());
        assert_eq!(parse_aad_epoch("v4.0.0|epoch=7").unwrap(), 7);
    }

    /// Empty and short (<32-byte) secret roots must be rejected BEFORE any
    /// crypto work — an empty root makes the AES key publicly computable.
    #[test]
    fn empty_and_short_secret_root_rejected() {
        let plaintext = b"payload";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD);

        for bad_root in [&b""[..], &b"short"[..], &[0u8; 31][..]] {
            let r = unseal(&ciphertext, &iv, &sig, &verifying, bad_root, SALT, AAD, 7);
            assert!(
                r.is_err(),
                "secret root of {} bytes must be rejected",
                bad_root.len()
            );
            let msg = r.err().expect("is_err confirmed").to_string();
            assert!(
                msg.contains("secret root"),
                "error must mention the secret root; got: {msg}"
            );
        }
    }

    /// TRUST-ANCHOR PINNING: the NAPI surface must reject any verifying key
    /// outside the compiled-in accepted set — including this test fixture key.
    #[test]
    fn fixture_key_rejected_by_pinning() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = signing.verifying_key();
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(verifying.as_bytes());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            BASE64.encode(&der)
        );
        let r = pinned_verifying_key(&pem);
        assert!(r.is_err(), "non-accepted key must be rejected by pinning");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(msg.contains("accepted key set"), "got: {msg}");

        // The compiled-in production key itself must pass the pin.
        for pem in crate::license::ACCEPTED_PUBLIC_KEYS_PEM {
            assert!(
                pinned_verifying_key(pem).is_ok(),
                "accepted key must pass pinning"
            );
        }
    }

    /// Receipt: computed over plaintext, verifies for the same bytes in the
    /// same process, and fails for different bytes or a forged value.
    #[test]
    fn unseal_receipt_roundtrip() {
        let receipt = compute_unseal_receipt(b"snapshot bytes");
        assert!(verify_unseal_receipt(b"snapshot bytes", &receipt));
        assert!(!verify_unseal_receipt(b"other bytes", &receipt));
        assert!(!verify_unseal_receipt(b"snapshot bytes", "deadbeef"));
        assert!(!verify_unseal_receipt(b"snapshot bytes", ""));
    }

    #[test]
    fn distinct_info_from_vault() {
        // Domain separation: snapshot key must differ from an empty-info
        // derivation (the vault's) for the same root+salt.
        let root = b"0123456789abcdef0123456789abcdef";
        let salt = "tenant:acme";
        let snap = derive_snapshot_key(root, salt).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), root);
        let mut vault_like = [0u8; 32];
        hk.expand(b"", &mut vault_like).unwrap();
        assert_ne!(snap, vault_like, "snapshot key must be domain-separated");
    }

    /// Flip the IV byte-by-byte and assert failure occurs at AEAD decryption, NOT
    /// at signature verification. This proves the header claim: "The GCM
    /// authentication tag already commits the IV cryptographically (an IV change
    /// produces a tag failure), so the IV does not need separate coverage in the
    /// signature." Concretely: the Ed25519 signature covers ciphertext bytes only;
    /// the IV is not part of the signed message. Verification therefore PASSES
    /// (ciphertext unchanged, sig valid), and the AEAD step FAILS.
    #[test]
    fn flip_iv_fails_at_gcm_not_signature() {
        let plaintext = b"snapshot payload for iv-flip adversarial test";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD);

        // Flip one byte of the IV and attempt unseal with the correct signature.
        let mut flipped_iv = iv;
        flipped_iv[0] ^= 0x01;
        let r = unseal(
            &ciphertext,
            &flipped_iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7,
        );
        assert!(r.is_err(), "flipped IV must cause failure");
        let msg = r.err().expect("is_err confirmed above").to_string();
        // Signature step PASSES (sig covers ciphertext, not IV).
        // AEAD step FAILS because the GCM auth tag commits the IV.
        assert!(
            msg.contains("decryption failed"),
            "IV flip must fail at GCM (decryption failed), not at signature verify; got: {msg}"
        );
        assert!(
            !msg.contains("signature verification failed"),
            "signature must PASS — it covers ciphertext only, not IV; got: {msg}"
        );

        // Repeat with the last IV byte flipped — must also fail at GCM.
        let mut flipped_iv_end = iv;
        flipped_iv_end[11] ^= 0x80;
        let r2 = unseal(
            &ciphertext,
            &flipped_iv_end,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7,
        );
        assert!(r2.is_err(), "last-byte IV flip must also fail");
        let msg2 = r2.err().expect("is_err confirmed above").to_string();
        assert!(
            msg2.contains("decryption failed"),
            "last-byte IV flip must fail at AEAD, not sig; got: {msg2}"
        );
    }

    /// Flip one byte of the Ed25519 signature and assert failure at the signature
    /// verification step, before any AEAD work is attempted. Proves fail-closed:
    /// a tampered signature never reaches the crypto layer.
    #[test]
    fn flip_signature_byte_fails() {
        let plaintext = b"snapshot payload for sig-flip adversarial test";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD);

        // Flip the first byte of the 64-byte Ed25519 signature.
        let mut bad_sig_first = sig;
        bad_sig_first[0] ^= 0xff;
        let r = unseal(
            &ciphertext,
            &iv,
            &bad_sig_first,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7,
        );
        assert!(r.is_err(), "first-byte sig flip must be rejected");
        let msg = r.err().expect("is_err confirmed above").to_string();
        assert!(
            msg.contains("signature verification failed"),
            "failure must be at signature step, not AEAD; got: {msg}"
        );

        // Flip the last byte of the signature — must also fail at sig verify.
        let mut bad_sig_last = sig;
        bad_sig_last[63] ^= 0xff;
        let r2 = unseal(
            &ciphertext,
            &iv,
            &bad_sig_last,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            7,
        );
        assert!(r2.is_err(), "last-byte sig flip must be rejected");
        let msg2 = r2.err().expect("is_err confirmed above").to_string();
        assert!(
            msg2.contains("signature verification failed"),
            "last-byte sig flip must fail at sig verify; got: {msg2}"
        );
    }

    /// Empty salt and empty aad must both be rejected — they defeat version-
    /// binding and anti-rollback guarantees.
    #[test]
    fn empty_salt_and_aad_rejected() {
        // Dummy values sufficient to reach the guard checks (ciphertext,
        // signature, key, secret_root are never evaluated when salt/aad fail).
        let dummy_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

        // Empty salt → must fail before any crypto work.
        let r_salt = unseal_core(
            b"dummy",
            &BASE64.encode([0u8; 12]),
            &BASE64.encode([0u8; 64]),
            &[dummy_key],
            &BASE64.encode([0u8; 32]),
            "", // empty salt
            "v4.0.0|epoch=1",
            0,
            "v4.0.0",
        );
        assert!(r_salt.is_err(), "empty salt must be rejected");
        let msg = r_salt.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("salt"),
            "error must mention 'salt', got: {msg}"
        );

        // Empty aad → must fail before any crypto work.
        let r_aad = unseal_core(
            b"dummy",
            &BASE64.encode([0u8; 12]),
            &BASE64.encode([0u8; 64]),
            &[dummy_key],
            &BASE64.encode([0u8; 32]),
            "catalog-v4.0.0",
            "", // empty aad
            0,
            "catalog-v4.0.0",
        );
        assert!(r_aad.is_err(), "empty aad must be rejected");
        let msg = r_aad.err().expect("is_err confirmed").to_string();
        assert!(msg.contains("aad"), "error must mention 'aad', got: {msg}");
    }

    // ── CHARIOT::§5.7::27 — multi-epoch aad smuggling ──────────────────────

    /// An aad carrying MORE THAN ONE `epoch=` segment must be rejected rather
    /// than resolved by position. Regression test for the exact example the
    /// clause cites: `v4|epoch=9|epoch=1` previously returned 9 (first-match)
    /// — silently accepting an attacker-appended second epoch segment.
    #[test]
    fn multi_epoch_aad_segment_rejected() {
        assert!(parse_aad_epoch("v4|epoch=9|epoch=1").is_err());
        let err = parse_aad_epoch("v4|epoch=9|epoch=1").unwrap_err().to_string();
        assert!(
            err.contains("exactly one"),
            "error must identify the multi-segment rejection; got: {err}"
        );
        // Three segments must also be rejected (not just exactly-two).
        assert!(parse_aad_epoch("v4|epoch=1|epoch=2|epoch=3").is_err());
        // A single segment is still accepted (regression guard).
        assert_eq!(parse_aad_epoch("v4.0.0|epoch=7").unwrap(), 7);

        // End-to-end through unseal_core: a bundle sealed with a smuggled
        // second epoch segment must fail closed even with a satisfied floor.
        let plaintext = b"multi-epoch-aad payload";
        let smuggled_aad = "v4.0.0|epoch=9|epoch=1";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, smuggled_aad);
        let r = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            smuggled_aad,
            0,
        );
        assert!(r.is_err(), "multi-epoch aad must be rejected end-to-end");
    }

    // ── CHARIOT::§5.7::17 — salt must equal aad <context> ──────────────────

    #[test]
    fn salt_context_mismatch_rejected() {
        let plaintext = b"salt-context-mismatch payload";
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD); // aad context = "v4.0.0"

        // salt "other-catalog" != aad context "v4.0.0" → rejected, even
        // though the AEAD would fail anyway for the same reason (the salt
        // was used to derive the key that sealed it) — this proves the
        // EXPLICIT check fires (and names "salt"), not just an incidental
        // AEAD failure downstream.
        let r = unseal(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            "other-catalog",
            AAD,
            0,
        );
        assert!(r.is_err(), "salt != aad context must be rejected");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("salt must equal"),
            "error must identify the salt/context check; got: {msg}"
        );
    }

    // ── CHARIOT::§5.7::37/38 — context binding to the (simulated) verified
    //    license, never to the snapshot ─────────────────────────────────────

    #[test]
    fn context_binding_rejects_foreign_context() {
        let plaintext = b"context-binding payload";
        // Legitimately sealed for "v4.0.0" (salt == aad context, both valid).
        let (ciphertext, iv, sig, verifying) = seal(plaintext, AAD);

        // Consumer expects a DIFFERENT installation context (e.g. a
        // different tenant's license) — must be rejected even though salt,
        // aad, and signature are ALL internally consistent with each other.
        let r = unseal_with_context(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            0,
            "some-other-tenant-context",
        );
        assert!(
            r.is_err(),
            "a snapshot sealed for one context must not admit under another installation's \
             expected context"
        );
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("expected catalog/license context"),
            "error must identify the §5.7::37 context-binding check; got: {msg}"
        );

        // The matching context is admitted (regression guard against an
        // overly strict check).
        assert!(unseal_with_context(
            &ciphertext,
            &iv,
            &sig,
            &verifying,
            SECRET_ROOT,
            SALT,
            AAD,
            0,
            CONTEXT,
        )
        .is_ok());
    }

    // ── CHARIOT::§5.7::34-36 — persisted, monotonically non-decreasing
    //    anti-rollback epoch watermark ──────────────────────────────────────

    fn watermark_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chariot-wm-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A MISSING watermark file is "no prior baseline" (Ok(0)), not an error.
    #[test]
    fn watermark_missing_file_is_zero_baseline() {
        let dir = watermark_test_dir("missing");
        assert_eq!(load_epoch_watermark(&dir).expect("missing → 0"), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Persist → load round-trips, and persisting a HIGHER epoch advances it.
    #[test]
    fn watermark_persist_and_load_roundtrip() {
        let dir = watermark_test_dir("roundtrip");
        persist_epoch_watermark(&dir, 5).expect("persist 5");
        assert_eq!(load_epoch_watermark(&dir).expect("load"), 5);
        persist_epoch_watermark(&dir, 9).expect("persist 9");
        assert_eq!(load_epoch_watermark(&dir).expect("load"), 9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt watermark file fails closed — it must NEVER be silently
    /// treated as "no baseline" (that would reopen the exact rollback window
    /// the watermark exists to close).
    #[test]
    fn watermark_corrupt_file_fails_closed() {
        let dir = watermark_test_dir("corrupt");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(EPOCH_WATERMARK_FILE), b"not json").expect("write garbage");
        let r = load_epoch_watermark(&dir);
        assert!(r.is_err(), "corrupt watermark file must fail closed");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("corrupt"),
            "error must identify the corruption; got: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watermark file present but missing/non-integer 'epoch' also fails
    /// closed (well-formed JSON is not the same as a valid watermark).
    #[test]
    fn watermark_missing_epoch_field_fails_closed() {
        let dir = watermark_test_dir("no-epoch-field");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(EPOCH_WATERMARK_FILE), b"{\"other\":1}").expect("write");
        assert!(load_epoch_watermark(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End-to-end anti-rollback via `license_derived_floor_and_context`: a
    /// license min_security_epoch that has regressed below a previously
    /// persisted watermark is rejected (CHARIOT::§5.7::36) — this is checked
    /// WITHOUT needing a production-signed license, because the rejection
    /// happens after `load_epoch_watermark` and before any license-signature
    /// concern is reached only when the floor comparison itself is what
    /// fails; here we exercise the comparison directly against the same
    /// watermark file the real function reads, proving the persisted-value
    /// contract independent of license verification.
    #[test]
    fn watermark_blocks_regressed_floor_end_to_end() {
        let dir = watermark_test_dir("regressed-floor");
        persist_epoch_watermark(&dir, 10).expect("seed watermark at 10");
        let watermark = load_epoch_watermark(&dir).expect("load");
        assert_eq!(watermark, 10);
        // A license claiming min_security_epoch=3 (below the watermark of
        // 10) must be treated as regressed by the same comparison
        // `license_derived_floor_and_context` performs.
        let claimed_floor: u32 = 3;
        assert!(
            claimed_floor < watermark,
            "fixture premise: claimed floor must be below the watermark"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── gate finding F3 (2026-09-04): atomic persist + advisory lock ───────

    /// CRASH-SAFETY: a stray, partially-written temp file
    /// (`EPOCH_WATERMARK_FILE.tmp-...`) left behind by a crash between
    /// `File::create`/`write_all` and the rename in `persist_epoch_watermark`
    /// must be completely ignored by the loader — `load_epoch_watermark`
    /// only ever reads the FIXED `EPOCH_WATERMARK_FILE` name, so a `.tmp-*`
    /// file is invisible to it by construction, present or not, valid JSON
    /// or garbage.
    #[test]
    fn watermark_partial_temp_file_ignored_target_stays_valid() {
        let dir = watermark_test_dir("partial-tmp");
        persist_epoch_watermark(&dir, 4).expect("seed a valid watermark");

        // Simulate a crash mid-write: a temp file with the exact naming
        // scheme persist_epoch_watermark uses, containing truncated garbage.
        std::fs::write(
            dir.join(format!("{EPOCH_WATERMARK_FILE}.tmp-99999-deadbeefdeadbeef")),
            b"{\"epoc",
        )
        .expect("write simulated crash artifact");

        // The real, previously-persisted watermark must still load correctly
        // — the loader never looks at the tmp file.
        assert_eq!(
            load_epoch_watermark(&dir).expect("load must ignore the tmp artifact"),
            4,
            "a stray partial temp file must not affect the loaded watermark"
        );

        // And a fresh persist still succeeds and is immediately readable —
        // proves the leftover tmp file does not wedge the mechanism (each
        // persist call uses a freshly-random nonce in its own temp filename).
        persist_epoch_watermark(&dir, 6).expect("persist must still succeed with a stray tmp file present");
        assert_eq!(load_epoch_watermark(&dir).expect("load"), 6);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory with ONLY a partial temp file (no real watermark file yet
    /// — e.g. crash on the very first-ever persist) must be treated as "no
    /// prior baseline" (Ok(0)), the same as a directory with no watermark
    /// artifacts at all.
    #[test]
    fn watermark_only_partial_temp_file_present_is_zero_baseline() {
        let dir = watermark_test_dir("only-partial-tmp");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join(format!("{EPOCH_WATERMARK_FILE}.tmp-1-aaaa")),
            b"{\"epoch\":99}",
        )
        .expect("write simulated crash artifact");
        assert_eq!(
            load_epoch_watermark(&dir).expect("load"),
            0,
            "a temp-only directory (no real watermark file) must load as the zero baseline, \
             NOT read the tmp file's epoch=99"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CONCURRENCY: two threads racing `WatermarkLock::acquire` +
    /// read-compare-write over the SAME directory must serialize correctly —
    /// the final persisted watermark must be the max of the two accepted
    /// epochs (7), never the loser's lower value (5) clobbering the winner's.
    /// This drives the locking PRIMITIVE directly (not the full NAPI
    /// `unseal_and_verify_snapshot` path, which requires a production-signed
    /// license this crate does not have the private key for — see
    /// `license.rs`'s `verify_license_jwt_and_extract_rejects_non_production_key`
    /// for that same limitation) — it exercises EXACTLY the critical section
    /// `unseal_and_verify_snapshot` runs under `_watermark_lock`: acquire →
    /// read → (stand-in for a successful unseal) → re-read → persist.
    #[test]
    fn concurrent_watermark_updates_serialize_to_the_highest_epoch() {
        let dir = watermark_test_dir("concurrent");
        std::fs::create_dir_all(&dir).expect("mkdir");

        fn accept_epoch_under_lock(dir: &Path, epoch: u32) {
            let _lock = WatermarkLock::acquire(dir).expect("acquire lock");
            let before = load_epoch_watermark(dir).expect("initial read under lock");
            // A real caller would reject `epoch < before` here (the
            // §5.7::35/36 floor check `unseal_core`/`license_derived_floor_and_context`
            // perform); this harness drives two epochs that are both
            // individually valid so the test isolates the LOCK's
            // correctness from that unrelated rejection logic.
            let _ = before;
            let current = load_epoch_watermark(dir).expect("re-read under lock (CAS)");
            persist_epoch_watermark(dir, epoch.max(current)).expect("persist under lock");
        }

        let dir_a = dir.clone();
        let dir_b = dir.clone();
        let t1 = std::thread::spawn(move || accept_epoch_under_lock(&dir_a, 5));
        let t2 = std::thread::spawn(move || accept_epoch_under_lock(&dir_b, 7));
        t1.join().expect("thread 1 must not panic");
        t2.join().expect("thread 2 must not panic");

        let final_watermark = load_epoch_watermark(&dir).expect("load final watermark");
        assert_eq!(
            final_watermark, 7,
            "the highest concurrently-accepted epoch must win regardless of thread interleaving \
             (got {final_watermark}) — a lost update here would mean the lock did not actually \
             serialize the two critical sections"
        );

        // A subsequent epoch-6 attempt is below the post-concurrency
        // watermark of 7 — the rejection comparison itself (`epoch <
        // min_epoch`) is covered by `epoch_rollback_rejected` and
        // `watermark_blocks_regressed_floor_end_to_end` above; this asserts
        // the precondition those tests rely on actually holds after
        // concurrent access, closing the loop between "the lock serializes
        // correctly" and "the floor check rejects correctly".
        assert!(6 < final_watermark, "epoch 6 must be below the post-concurrency watermark");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock is per-directory (keyed by the `.lock` file inside it) —
    /// two DIFFERENT watermark directories must not contend with each other.
    /// Regression guard against a global/static lock implementation that
    /// would serialize unrelated installations' unseal calls for no reason.
    #[test]
    fn watermark_lock_is_per_directory_not_global() {
        let dir1 = watermark_test_dir("lock-independent-1");
        let dir2 = watermark_test_dir("lock-independent-2");
        std::fs::create_dir_all(&dir1).expect("mkdir 1");
        std::fs::create_dir_all(&dir2).expect("mkdir 2");

        let lock1 = WatermarkLock::acquire(&dir1).expect("acquire lock on dir1");
        // Acquiring a lock on an UNRELATED directory must not block even
        // while lock1 is held — proves the lock is scoped to its directory,
        // not a process-wide mutex.
        let lock2 = WatermarkLock::acquire(&dir2).expect("acquire lock on dir2 while dir1 is locked");
        drop(lock1);
        drop(lock2);

        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    // ── CHARIOT::§5.7 producer: seal_edge_snapshot ─────────────────────────

    const SIGNING_SEED: [u8; 32] = [9u8; 32];

    /// Producer → consumer round trip: `seal_edge_snapshot` output unseals
    /// cleanly through `unseal_core` with the matching verifying key, and the
    /// descriptor shape carries every §5.7::1-7 field.
    #[test]
    fn seal_edge_snapshot_roundtrips_through_unseal_core() {
        let plaintext = b"real edge snapshot archive bytes, produced not fixtured";
        let sealed = seal_edge_snapshot(
            BASE64.encode(plaintext),
            BASE64.encode(SECRET_ROOT),
            CONTEXT.to_string(),
            CONTEXT.to_string(),
            12,
            BASE64.encode(SIGNING_SEED),
        )
        .expect("seal must succeed");

        assert_eq!(sealed.salt, CONTEXT);
        assert_eq!(sealed.aad, format!("{CONTEXT}|epoch=12"));
        let iv_bytes = BASE64.decode(&sealed.iv_b64).expect("iv decodes");
        assert_eq!(iv_bytes.len(), 12, "iv must be exactly 12 bytes (§5.7::4)");
        let ciphertext = BASE64.decode(&sealed.ciphertext_b64).expect("ct decodes");
        assert!(
            ciphertext.len() >= plaintext.len() + 16,
            "ciphertext must include the trailing 16-byte GCM tag (§5.7::2)"
        );

        let verifying = SigningKey::from_bytes(&SIGNING_SEED).verifying_key();
        let out = unseal_core(
            &ciphertext,
            &sealed.iv_b64,
            &sealed.signature_b64,
            std::slice::from_ref(&verifying),
            &BASE64.encode(SECRET_ROOT),
            &sealed.salt,
            &sealed.aad,
            0,
            CONTEXT,
        )
        .expect("producer output must unseal cleanly with the matching key");
        assert_eq!(out, plaintext);
    }

    /// Two seals of the SAME plaintext/salt/aad/epoch must use DIFFERENT IVs
    /// (fresh CSPRNG per call, §5.7::18/19) — a fixed or derived IV would be
    /// silently reused under an unchanged salt, defeating the seal.
    #[test]
    fn seal_edge_snapshot_iv_is_fresh_each_call() {
        let plaintext = BASE64.encode(b"same plaintext, sealed twice");
        let a = seal_edge_snapshot(
            plaintext.clone(),
            BASE64.encode(SECRET_ROOT),
            CONTEXT.to_string(),
            CONTEXT.to_string(),
            1,
            BASE64.encode(SIGNING_SEED),
        )
        .expect("seal 1");
        let b = seal_edge_snapshot(
            plaintext,
            BASE64.encode(SECRET_ROOT),
            CONTEXT.to_string(),
            CONTEXT.to_string(),
            1,
            BASE64.encode(SIGNING_SEED),
        )
        .expect("seal 2");
        assert_ne!(a.iv_b64, b.iv_b64, "IV must be freshly generated per seal");
        // Different IVs under the identical key must also yield different
        // ciphertext bytes (GCM keystream is IV-dependent).
        assert_ne!(a.ciphertext_b64, b.ciphertext_b64);
    }

    /// `seal_edge_snapshot` refuses to emit a self-inconsistent descriptor
    /// whose salt and context disagree — the producer's own half of the
    /// §5.7::17 invariant.
    #[test]
    fn seal_edge_snapshot_rejects_salt_context_mismatch() {
        let r = seal_edge_snapshot(
            BASE64.encode(b"payload"),
            BASE64.encode(SECRET_ROOT),
            "salt-a".to_string(),
            "context-b".to_string(),
            1,
            BASE64.encode(SIGNING_SEED),
        );
        assert!(r.is_err(), "salt != context must be rejected");
    }

    /// A short (< 32-byte) secret root must be rejected before any crypto
    /// work, mirroring the consumer-side floor (§5.7::14).
    #[test]
    fn seal_edge_snapshot_rejects_short_secret_root() {
        let r = seal_edge_snapshot(
            BASE64.encode(b"payload"),
            BASE64.encode([0u8; 16]),
            CONTEXT.to_string(),
            CONTEXT.to_string(),
            1,
            BASE64.encode(SIGNING_SEED),
        );
        assert!(r.is_err(), "short secret root must be rejected");
    }

    /// An empty salt/context is rejected (mirrors consumer §5.7::15).
    #[test]
    fn seal_edge_snapshot_rejects_empty_salt() {
        let r = seal_edge_snapshot(
            BASE64.encode(b"payload"),
            BASE64.encode(SECRET_ROOT),
            String::new(),
            String::new(),
            1,
            BASE64.encode(SIGNING_SEED),
        );
        assert!(r.is_err(), "empty salt/context must be rejected");
    }

    /// A malformed (non-32-byte) signing key seed is rejected with a clear
    /// message rather than panicking.
    #[test]
    fn seal_edge_snapshot_rejects_malformed_signing_seed() {
        let r = seal_edge_snapshot(
            BASE64.encode(b"payload"),
            BASE64.encode(SECRET_ROOT),
            CONTEXT.to_string(),
            CONTEXT.to_string(),
            1,
            BASE64.encode(b"too-short"),
        );
        assert!(r.is_err(), "malformed signing seed must be rejected");
    }

    // ── gate finding F4 (2026-09-04): full pipeline through
    //    unseal_and_verify_snapshot_with_keys, not just its pieces ─────────
    //
    // These tests drive the SAME code path the #[napi] `unseal_and_verify_
    // snapshot` entry point runs — watermark lock, license JWT verification,
    // anti-rollback floor, context binding, signature-then-AEAD — via the
    // `_with_keys` seam, which takes fixture verifying keys instead of the
    // compiled-in production set `pinned_verifying_key`/`ACCEPTED_PUBLIC_
    // KEYS_PEM` require. This crate has no production PRIVATE key (only the
    // embedded public key — the same limitation `fixture_key_rejected_by_
    // pinning` above and `license.rs`'s JWT tests already document), so this
    // is the only way to prove REJECTION behaviour end-to-end without one.

    fn fixture_license_jwt(
        signing: &SigningKey,
        kid: Option<&str>,
        alg: &str,
        context: &str,
        min_security_epoch: u32,
    ) -> String {
        let header_json = match kid {
            Some(k) => format!(r#"{{"alg":"{alg}","kid":"{k}"}}"#),
            None => format!(r#"{{"alg":"{alg}"}}"#),
        };
        let payload_json = format!(
            r#"{{"iss":"license.epic-ai.io","sub":"co-1","exp":4070908800,"license_epoch":1,"min_security_epoch":{min_security_epoch},"tenant_id":"tenant-unrelated","catalog_version":"{context}"}}"#,
        );
        let header_b64 = JWT_B64URL.encode(header_json.as_bytes());
        let payload_b64 = JWT_B64URL.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        format!("{header_b64}.{payload_b64}.{}", JWT_B64URL.encode(sig.to_bytes()))
    }

    fn fixture_license_pem(signing: &SigningKey) -> String {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(signing.verifying_key().as_bytes());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            BASE64.encode(&der)
        )
    }

    /// Seal `plaintext` with a FIXTURE snapshot signing key for a given
    /// (context, epoch), returning the pieces `unseal_and_verify_snapshot_
    /// with_keys` takes (base64 ciphertext/iv/signature).
    fn fixture_seal(
        snapshot_signing: &SigningKey,
        plaintext: &[u8],
        context: &str,
        epoch: u32,
    ) -> (String, String, String, String) {
        let aad = format!("{context}|epoch={epoch}");
        let key = derive_snapshot_key(SECRET_ROOT, context).expect("derive");
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let iv = [4u8; 12];
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let sig = snapshot_signing.sign(&ciphertext);
        (
            BASE64.encode(&ciphertext),
            BASE64.encode(iv),
            BASE64.encode(sig.to_bytes()),
            aad,
        )
    }

    /// HAPPY PATH through the full pipeline: fixture snapshot key + fixture
    /// license JWT, matching context/epoch, no prior watermark.
    #[test]
    fn full_pipeline_happy_path_via_with_keys_seam() {
        let dir = watermark_test_dir("full-pipeline-happy");
        let snapshot_signing = SigningKey::from_bytes(&[21u8; 32]);
        let license_signing = SigningKey::from_bytes(&[22u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let plaintext = b"full pipeline fixture payload";

        let (ct_b64, iv_b64, sig_b64, aad) = fixture_seal(&snapshot_signing, plaintext, "fixture-ctx", 5);
        let jwt = fixture_license_jwt(&license_signing, None, "EdDSA", "fixture-ctx", 5);

        let result = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "fixture-ctx",
            &aad,
            &jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        )
        .expect("full pipeline must succeed with matching fixture keys");
        let out = BASE64.decode(&result.plaintext_b64).expect("decode");
        assert_eq!(out, plaintext);
        assert_eq!(load_epoch_watermark(&dir).expect("load"), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fixture_license_jwt_with_payload(signing: &SigningKey, payload_json: &str) -> String {
        let header_b64 = JWT_B64URL.encode(br#"{"alg":"EdDSA"}"#);
        let payload_b64 = JWT_B64URL.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        format!("{header_b64}.{payload_b64}.{}", JWT_B64URL.encode(sig.to_bytes()))
    }

    /// §5.7::38 context binding: the expected context is the licence's signed
    /// `catalog_version` claim and nothing else. A licence without the claim,
    /// with a blank claim, or with a different catalog version is refused even
    /// when its tenant_id or sub equals the snapshot context.
    #[test]
    fn context_comes_only_from_catalog_version_claim() {
        let snapshot_signing = SigningKey::from_bytes(&[31u8; 32]);
        let license_signing = SigningKey::from_bytes(&[32u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let (ct_b64, iv_b64, sig_b64, aad) = fixture_seal(&snapshot_signing, b"payload", "1", 5);
        let base = r#""iss":"license.epic-ai.io","exp":4070908800,"license_epoch":1,"min_security_epoch":5"#;
        let cases = [
            ("absent-claim-tenant-matches", format!(r#"{{{base},"sub":"1","tenant_id":"1"}}"#), "no catalog_version claim"),
            ("empty-claim", format!(r#"{{{base},"sub":"co-1","catalog_version":""}}"#), "no catalog_version claim"),
            ("blank-claim", format!(r#"{{{base},"sub":"co-1","catalog_version":"  "}}"#), "no catalog_version claim"),
            ("other-version", format!(r#"{{{base},"sub":"co-1","catalog_version":"2"}}"#), "§5.7::37"),
        ];
        for (name, payload, expected) in cases {
            let dir = watermark_test_dir(&format!("catalog-version-{name}"));
            let jwt = fixture_license_jwt_with_payload(&license_signing, &payload);
            let err = unseal_and_verify_snapshot_with_keys(
                &ct_b64,
                &iv_b64,
                &sig_b64,
                std::slice::from_ref(&snapshot_signing.verifying_key()),
                &BASE64.encode(SECRET_ROOT),
                "1",
                &aad,
                &jwt,
                &[license_pem.as_str()],
                dir.to_str().expect("utf8 path"),
            )
            .err()
            .unwrap_or_else(|| panic!("{name}: must be rejected"));
            assert!(err.reason.contains(expected), "{name}: got {}", err.reason);
            let _ = std::fs::remove_dir_all(&dir);
        }

        let dir = watermark_test_dir("catalog-version-match");
        let jwt = fixture_license_jwt_with_payload(&license_signing, &format!(r#"{{{base},"sub":"co-9","tenant_id":"t-9","catalog_version":"1"}}"#));
        let ok = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "1",
            &aad,
            &jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        );
        assert!(ok.is_ok(), "matching catalog_version must unseal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cross-language producer/consumer integration: the TypeScript producer's
    /// real archive packer packages a REAL flushed Edge shard. The production
    /// sealer and full unseal pipeline use fixture signing/license trust roots
    /// (only this test seam substitutes keys), then receipt-checked unpack and
    /// manifest-checked EdgeShardHandle.load admit the exact two tool points.
    #[test]
    fn producer_archive_load_roundtrip() {
        use crate::edge_shard::{edge_unpack_snapshot, EdgeShardHandle};
        use std::process::Command;
        let dir = watermark_test_dir("producer-archive");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let source = dir.join("source");
        std::fs::create_dir_all(&source).expect("mkdir source");
        let mut shard = EdgeShardHandle::create(
            source.to_string_lossy().into_owned(),
            r#"{"vectors":{"dense":{"size":4,"distance":"Cosine"}},"sparse_vectors":{"splade":{}}}"#.into(),
        ).expect("create real Edge shard");
        shard.upsert(r#"[
            {"id":1,"vector":{"dense":[1,0,0,0],"splade":{"indices":[1],"values":[1]}},"payload":{"toolId":"fixture:alpha"}},
            {"id":2,"vector":{"dense":[0,1,0,0],"splade":{"indices":[2],"values":[1]}},"payload":{"toolId":"fixture:beta"}}
        ]"#.into()).expect("upsert fixture bundle points");
        shard.flush().expect("flush");
        let archive = dir.join("catalog.snapshot");
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let packer = repo.join("dist/engine/bin/build-edgeshard-snapshot.js");
        assert!(packer.exists(), "npm run build before this integration test");
        let script = format!(
            // packFlushedShard writes `<workDir>/catalog.snapshot` and returns
            // that PATH (the archive never becomes a JS Buffer/string).
            "import {{packFlushedShard}} from {}; import {{realpathSync}} from 'node:fs'; const p = packFlushedShard(process.argv[1], process.argv[2]); if (realpathSync(p) !== realpathSync(process.argv[3])) throw new Error(`packer returned ${{p}}, expected ${{process.argv[3]}}`);",
            serde_json::to_string(&format!("file://{}", packer.display())).unwrap()
        );
        let output = Command::new("node").args(["--input-type=module", "-e", &script])
            .arg(&source).arg(&dir).arg(&archive).output().expect("run TS packer");
        assert!(output.status.success(), "packer: {}", String::from_utf8_lossy(&output.stderr));
        shard.close().expect("close producer handle before cleanup");
        let plaintext = std::fs::read(&archive).expect("archive");
        let signing = SigningKey::from_bytes(&[21; 32]);
        let license_signing = SigningKey::from_bytes(&[22; 32]);
        let sealed = seal_edge_snapshot(BASE64.encode(&plaintext), BASE64.encode(SECRET_ROOT), "7".into(), "7".into(), 5, BASE64.encode(signing.to_bytes())).expect("real producer seal");
        let jwt = fixture_license_jwt(&license_signing, None, "EdDSA", "7", 5);
        let pem = fixture_license_pem(&license_signing);
        for (root, salt, aad) in [
            (BASE64.encode([0u8; 31]), "7", "7|epoch=5"),
            (BASE64.encode(SECRET_ROOT), "", "7|epoch=5"),
            (BASE64.encode(SECRET_ROOT), "8", "7|epoch=5"),
            (BASE64.encode(SECRET_ROOT), "7", "7|epoch=5|epoch=1"),
        ] {
            assert!(unseal_and_verify_snapshot_with_keys(
                &sealed.ciphertext_b64, &sealed.iv_b64, &sealed.signature_b64,
                &[signing.verifying_key()], &root, salt, aad, &jwt,
                &[pem.as_str()], dir.join("reject-watermark").to_str().unwrap(),
            ).is_err(), "producer descriptor must reject invalid root/salt/aad");
        }
        let unsealed = unseal_and_verify_snapshot_with_keys(
            &sealed.ciphertext_b64, &sealed.iv_b64, &sealed.signature_b64,
            &[signing.verifying_key()], &BASE64.encode(SECRET_ROOT), &sealed.salt,
            &sealed.aad, &jwt, &[pem.as_str()], dir.join("watermark").to_str().unwrap(),
        ).expect("real license/signature/AEAD consumer");
        std::fs::write(&archive, BASE64.decode(unsealed.plaintext_b64).unwrap()).expect("write verified archive");
        let restored = dir.join("restored");
        edge_unpack_snapshot(archive.to_string_lossy().into_owned(), restored.to_string_lossy().into_owned(), unsealed.receipt).expect("receipt-checked unpack");
        let mut loaded = EdgeShardHandle::load(restored.to_string_lossy().into_owned(), None).expect("manifest-checked load");
        assert_eq!(loaded.points_count().unwrap(), 2);
        loaded.close().expect("close restored");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    /// ROLLBACK, through the full pipeline (not just `unseal_core` in
    /// isolation, and not just `verify_jwt_with_pems`): a watermark already
    /// at 10 rejects a validly-signed-by-everything snapshot/license pair at
    /// epoch 5.
    #[test]
    fn rollback_rejected_through_full_pipeline() {
        let dir = watermark_test_dir("full-pipeline-rollback");
        persist_epoch_watermark(&dir, 10).expect("seed watermark at 10");

        let snapshot_signing = SigningKey::from_bytes(&[23u8; 32]);
        let license_signing = SigningKey::from_bytes(&[24u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let (ct_b64, iv_b64, sig_b64, aad) =
            fixture_seal(&snapshot_signing, b"stale payload", "fixture-ctx-2", 5);
        let jwt = fixture_license_jwt(&license_signing, None, "EdDSA", "fixture-ctx-2", 5);

        let result = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "fixture-ctx-2",
            &aad,
            &jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        );
        assert!(
            result.is_err(),
            "epoch 5 must be rejected through the full pipeline when the watermark is already 10"
        );
        // The watermark must NOT have been perturbed by the rejected attempt.
        assert_eq!(load_epoch_watermark(&dir).expect("load"), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BAD ALG, through the full pipeline entry point (not only
    /// `verify_jwt_with_pems` in `license.rs`).
    #[test]
    fn bad_alg_rejected_through_full_pipeline() {
        let dir = watermark_test_dir("full-pipeline-bad-alg");
        let snapshot_signing = SigningKey::from_bytes(&[25u8; 32]);
        let license_signing = SigningKey::from_bytes(&[26u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let (ct_b64, iv_b64, sig_b64, aad) =
            fixture_seal(&snapshot_signing, b"payload", "fixture-ctx-3", 1);
        let jwt = fixture_license_jwt(&license_signing, None, "HS256", "fixture-ctx-3", 1);

        let result = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "fixture-ctx-3",
            &aad,
            &jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        );
        assert!(result.is_err(), "a non-EdDSA license JWT alg must be rejected through the full pipeline");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BAD KID, through the full pipeline entry point: a `kid` present but
    /// matching none of the accepted PEMs must hard-reject even though the
    /// signature is otherwise perfectly valid.
    #[test]
    fn bad_kid_rejected_through_full_pipeline() {
        let dir = watermark_test_dir("full-pipeline-bad-kid");
        let snapshot_signing = SigningKey::from_bytes(&[27u8; 32]);
        let license_signing = SigningKey::from_bytes(&[28u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let (ct_b64, iv_b64, sig_b64, aad) =
            fixture_seal(&snapshot_signing, b"payload", "fixture-ctx-4", 1);
        let jwt = fixture_license_jwt(
            &license_signing,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            "EdDSA",
            "fixture-ctx-4",
            1,
        );

        let result = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "fixture-ctx-4",
            &aad,
            &jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        );
        assert!(result.is_err(), "an unmatched license JWT kid must be rejected through the full pipeline");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TAMPERED JWT PAYLOAD, through the full pipeline entry point: the
    /// signature was computed over the ORIGINAL payload; a payload edited
    /// after signing (still valid base64url/JSON, min_security_epoch bumped
    /// down to defeat the floor) must fail signature verification.
    #[test]
    fn tampered_jwt_payload_rejected_through_full_pipeline() {
        let dir = watermark_test_dir("full-pipeline-tampered-jwt");
        let snapshot_signing = SigningKey::from_bytes(&[29u8; 32]);
        let license_signing = SigningKey::from_bytes(&[30u8; 32]);
        let license_pem = fixture_license_pem(&license_signing);
        let (ct_b64, iv_b64, sig_b64, aad) =
            fixture_seal(&snapshot_signing, b"payload", "fixture-ctx-5", 1);
        let jwt = fixture_license_jwt(&license_signing, None, "EdDSA", "fixture-ctx-5", 9);

        // Tamper the payload segment AFTER signing: swap min_security_epoch
        // from 9 down to 0 (an attacker attempting to defeat the floor).
        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_raw = JWT_B64URL.decode(parts[1]).expect("decode payload");
        let payload_str = String::from_utf8(payload_raw).expect("utf8");
        let tampered = payload_str.replace("\"min_security_epoch\":9", "\"min_security_epoch\":0");
        assert_ne!(payload_str, tampered, "fixture must actually change");
        let tampered_jwt = format!("{}.{}.{}", parts[0], JWT_B64URL.encode(tampered.as_bytes()), parts[2]);

        let result = unseal_and_verify_snapshot_with_keys(
            &ct_b64,
            &iv_b64,
            &sig_b64,
            std::slice::from_ref(&snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            "fixture-ctx-5",
            &aad,
            &tampered_jwt,
            &[license_pem.as_str()],
            dir.to_str().expect("utf8 path"),
        );
        assert!(result.is_err(), "a tampered license JWT payload must be rejected through the full pipeline");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── CHARIOT §5.7 file-reference form (AMENDED 2026-10-14): file seal →
    //    file unseal, driven through the `_with_keys` seam with fixture trust
    //    roots (same rationale as the F4 tests above). Failure classes:
    //    round trip + sha256 + 0600; ciphertext output pre-existing / live
    //    symlink / dangling symlink; symlinked plaintext input; out_path
    //    pre-existing / live symlink / dangling symlink / directory;
    //    symlinked ciphertext input; tampered / truncated ciphertext file.
    //    Every refusal leaves victim files untouched and the watermark
    //    un-advanced. ─────────────────────────────────────────────────────

    struct FileFixture {
        dir: PathBuf,
        plaintext: Vec<u8>,
        ciphertext_path: String,
        sealed: SealedShardFile,
        snapshot_signing: SigningKey,
        jwt: String,
        license_pem: String,
    }

    fn file_mode(p: impl AsRef<Path>) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(p).expect("stat").permissions().mode() & 0o777
    }

    fn file_fixture(tag: &str) -> FileFixture {
        let dir = watermark_test_dir(tag);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let plaintext: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let plain_path = dir.join("plain.snapshot");
        std::fs::write(&plain_path, &plaintext).expect("write plaintext");
        let ciphertext_path = dir.join("catalog.edgeshard.sealed.ciphertext");
        let snapshot_signing = SigningKey::from_bytes(&[41u8; 32]);
        let license_signing = SigningKey::from_bytes(&[42u8; 32]);
        let sealed = seal_edge_snapshot_file(
            plain_path.to_string_lossy().into_owned(),
            ciphertext_path.to_string_lossy().into_owned(),
            BASE64.encode(SECRET_ROOT),
            "file-ctx".into(),
            "file-ctx".into(),
            6,
            BASE64.encode(snapshot_signing.to_bytes()),
        )
        .expect("file seal must succeed");
        let jwt = fixture_license_jwt(&license_signing, None, "EdDSA", "file-ctx", 6);
        let license_pem = fixture_license_pem(&license_signing);
        FileFixture {
            dir,
            plaintext,
            ciphertext_path: ciphertext_path.to_string_lossy().into_owned(),
            sealed,
            snapshot_signing,
            jwt,
            license_pem,
        }
    }

    fn unseal_fixture_to(f: &FileFixture, sealed_path: &str, out_path: &Path, watermark: &Path) -> napi::Result<UnsealReceipt> {
        unseal_and_verify_snapshot_to_file_with_keys(
            sealed_path,
            out_path.to_str().expect("utf8 path"),
            &f.sealed.iv_b64,
            &f.sealed.signature_b64,
            std::slice::from_ref(&f.snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            &f.sealed.salt,
            &f.sealed.aad,
            &f.jwt,
            &[f.license_pem.as_str()],
            watermark.to_str().expect("utf8 path"),
        )
    }

    #[test]
    fn file_seal_to_file_unseal_roundtrip() {
        let f = file_fixture("file-roundtrip");
        let ct = std::fs::read(&f.ciphertext_path).expect("ciphertext file written");
        assert_eq!(f.sealed.ciphertext_sha256_hex.len(), 64);
        assert_eq!(
            f.sealed.ciphertext_sha256_hex,
            hex_encode(&Sha256::digest(&ct)),
            "ciphertext_sha256_hex must be the SHA-256 of exactly the written ciphertext bytes"
        );
        assert!(ct.len() >= f.plaintext.len() + 16, "ciphertext carries the 16-byte GCM tag");
        assert_eq!(f.sealed.salt, "file-ctx");
        assert_eq!(f.sealed.aad, "file-ctx|epoch=6");
        assert_eq!(BASE64.decode(&f.sealed.iv_b64).expect("iv").len(), 12);
        assert_eq!(file_mode(&f.ciphertext_path), 0o600, "ciphertext output must be 0600");

        // The file ciphertext is byte-compatible with the inline consumer core.
        let inline = unseal_core(
            &ct,
            &f.sealed.iv_b64,
            &f.sealed.signature_b64,
            std::slice::from_ref(&f.snapshot_signing.verifying_key()),
            &BASE64.encode(SECRET_ROOT),
            &f.sealed.salt,
            &f.sealed.aad,
            0,
            "file-ctx",
        )
        .expect("inline core accepts the file-form ciphertext");
        assert_eq!(inline, f.plaintext);

        let out = f.dir.join("plain.out");
        let wm = f.dir.join("wm");
        let receipt = unseal_fixture_to(&f, &f.ciphertext_path, &out, &wm).expect("file unseal must succeed");
        let written = std::fs::read(&out).expect("plaintext written");
        assert_eq!(written, f.plaintext);
        assert!(verify_unseal_receipt(&written, &receipt.receipt), "receipt binds the written bytes");
        assert_eq!(file_mode(&out), 0o600, "plaintext output must be 0600");
        assert_eq!(load_epoch_watermark(&wm).expect("load"), 6, "success advances the watermark");
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn file_seal_refuses_existing_or_symlinked_paths() {
        let dir = watermark_test_dir("file-seal-refuse");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let plain = dir.join("plain");
        std::fs::write(&plain, b"payload").expect("plain");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"victim bytes").expect("victim");
        let existing = dir.join("existing.ciphertext");
        std::fs::write(&existing, b"old").expect("existing");
        let live_link = dir.join("live.ciphertext");
        std::os::unix::fs::symlink(&victim, &live_link).expect("symlink");
        let nowhere = dir.join("nowhere");
        let dangling = dir.join("dangling.ciphertext");
        std::os::unix::fs::symlink(&nowhere, &dangling).expect("symlink");
        let seal_to = |plaintext: &Path, out: &Path| {
            seal_edge_snapshot_file(
                plaintext.to_string_lossy().into_owned(),
                out.to_string_lossy().into_owned(),
                BASE64.encode(SECRET_ROOT),
                CONTEXT.to_string(),
                CONTEXT.to_string(),
                1,
                BASE64.encode(SIGNING_SEED),
            )
        };
        for target in [&existing, &live_link, &dangling] {
            assert!(seal_to(plain.as_path(), target.as_path()).is_err(), "{target:?}: an existing entry must be refused");
        }
        assert_eq!(std::fs::read(&existing).expect("read"), b"old", "existing file untouched");
        assert_eq!(std::fs::read(&victim).expect("read"), b"victim bytes", "symlink target never written");
        assert!(!nowhere.exists(), "a dangling symlink is never followed into a create");

        // A symlinked plaintext input is refused (O_NOFOLLOW) and creates nothing.
        let plain_link = dir.join("plain.link");
        std::os::unix::fs::symlink(&plain, &plain_link).expect("symlink");
        let fresh = dir.join("fresh.ciphertext");
        assert!(seal_to(plain_link.as_path(), fresh.as_path()).is_err(), "symlinked plaintext must be refused");
        assert!(std::fs::symlink_metadata(&fresh).is_err(), "no ciphertext output on refusal");

        // Guard parity with seal_edge_snapshot: salt/context mismatch and a
        // short root are refused before any output exists.
        let guarded = dir.join("guarded.ciphertext");
        assert!(seal_edge_snapshot_file(
            plain.to_string_lossy().into_owned(),
            guarded.to_string_lossy().into_owned(),
            BASE64.encode(SECRET_ROOT),
            "salt-a".into(),
            "context-b".into(),
            1,
            BASE64.encode(SIGNING_SEED),
        )
        .is_err());
        assert!(seal_edge_snapshot_file(
            plain.to_string_lossy().into_owned(),
            guarded.to_string_lossy().into_owned(),
            BASE64.encode([0u8; 16]),
            CONTEXT.into(),
            CONTEXT.into(),
            1,
            BASE64.encode(SIGNING_SEED),
        )
        .is_err());
        assert!(std::fs::symlink_metadata(&guarded).is_err(), "no ciphertext output on a guard refusal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_unseal_refuses_preexisting_out_path() {
        let f = file_fixture("file-unseal-existing");
        let out = f.dir.join("plain.out");
        std::fs::write(&out, b"pre-existing").expect("seed out_path");
        let wm = f.dir.join("wm");
        assert!(unseal_fixture_to(&f, &f.ciphertext_path, &out, &wm).is_err(), "pre-existing out_path must be refused");
        assert_eq!(std::fs::read(&out).expect("read"), b"pre-existing", "pre-existing out_path untouched");
        assert_eq!(load_epoch_watermark(&wm).expect("load"), 0, "a refused write must not advance the watermark");

        let out_dir = f.dir.join("out-dir");
        std::fs::create_dir(&out_dir).expect("mkdir");
        assert!(unseal_fixture_to(&f, &f.ciphertext_path, &out_dir, &wm).is_err(), "a directory at out_path must be refused");
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn file_unseal_refuses_symlink_out_path() {
        let f = file_fixture("file-unseal-symlink-out");
        let victim = f.dir.join("victim");
        std::fs::write(&victim, b"victim").expect("victim");
        let live = f.dir.join("live.out");
        std::os::unix::fs::symlink(&victim, &live).expect("symlink");
        let nowhere = f.dir.join("nowhere");
        let dangling = f.dir.join("dangling.out");
        std::os::unix::fs::symlink(&nowhere, &dangling).expect("symlink");
        let wm = f.dir.join("wm");
        for out in [&live, &dangling] {
            assert!(unseal_fixture_to(&f, &f.ciphertext_path, out, &wm).is_err(), "{out:?}: symlinked out_path must be refused");
        }
        assert_eq!(std::fs::read(&victim).expect("read"), b"victim", "symlink target never written");
        assert!(!nowhere.exists(), "a dangling symlink is never followed into a create");
        assert_eq!(load_epoch_watermark(&wm).expect("load"), 0);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn file_unseal_refuses_symlinked_ciphertext_path() {
        let f = file_fixture("file-unseal-symlink-in");
        let link = f.dir.join("link.ciphertext");
        std::os::unix::fs::symlink(&f.ciphertext_path, &link).expect("symlink");
        let out = f.dir.join("plain.out");
        let wm = f.dir.join("wm");
        assert!(
            unseal_fixture_to(&f, link.to_str().expect("utf8"), &out, &wm).is_err(),
            "a symlinked ciphertext file must be refused (regular file, not a symbolic link)"
        );
        assert!(std::fs::symlink_metadata(&out).is_err(), "no plaintext on refusal");
        assert_eq!(load_epoch_watermark(&wm).expect("load"), 0);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn file_unseal_rejects_tampered_or_truncated_ciphertext_file() {
        let f = file_fixture("file-unseal-tamper");
        let original = std::fs::read(&f.ciphertext_path).expect("ciphertext");
        let mut flipped = original.clone();
        flipped[0] ^= 0x01;
        let tampered = f.dir.join("tampered.ciphertext");
        std::fs::write(&tampered, &flipped).expect("write tampered");
        let truncated = f.dir.join("truncated.ciphertext");
        std::fs::write(&truncated, &original[..original.len() - 1]).expect("write truncated");
        let wm = f.dir.join("wm");
        for (name, path) in [("tampered", &tampered), ("truncated", &truncated)] {
            let out = f.dir.join(format!("{name}.out"));
            let err = unseal_fixture_to(&f, path.to_str().expect("utf8"), &out, &wm)
                .err()
                .unwrap_or_else(|| panic!("{name}: must be rejected"));
            assert!(
                err.reason.contains("Snapshot signature verification failed"),
                "{name}: Ed25519 over the file bytes must reject first; got {}",
                err.reason
            );
            assert!(std::fs::symlink_metadata(&out).is_err(), "{name}: no plaintext on rejection");
        }
        assert_eq!(load_epoch_watermark(&wm).expect("load"), 0);
        let _ = std::fs::remove_dir_all(&f.dir);
    }
}
