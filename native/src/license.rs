// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ed25519 public keys accepted for license verification (PEM-encoded,
/// embedded at compile time). Multiple keys are accepted to support
/// rotation: during a transition window, both the old and new keys
/// validate, then the old key is removed in the next major release.
///
/// Mirrors the TypeScript-side rotation model in
/// `src/license/loader.ts ACCEPTED_KEYS_PEM`. The TS path uses
/// JWT `kid` headers for selective lookup; this native path validates
/// detached signatures (no JWT envelope), so we iterate all accepted
/// keys until one verifies.
///
/// Adding a new key: prepend the new entry, ship a release that
/// embeds both, reissue active licenses signed by the new key, then
/// drop the old entry in the next major release.
//
// : synced to the production signing key (kid
// f8b8f6f64a6c43adec00dfff648cf93d6a8e2703122098db46e15c297f2219d0)
// introduced on 2026-04-30 alongside the JWT envelope rewrite. The
// pre-rotation key (MCowBQYDK2VwAyEAaAjNCRAxZlceSqsD3HXRK5HaxYlAtDEIyhebMycQUa8=)
// has been retired from production issuance and is dropped from the
// accepted set. To rotate again: prepend the new entry, ship a release,
// reissue active licenses against the new key, drop the old entry next
// major release.
pub(crate) const ACCEPTED_PUBLIC_KEYS_PEM: &[&str] = &["-----BEGIN PUBLIC KEY-----\n\
     MCowBQYDK2VwAyEACBR74DxcFEvMcBO0YOxA9q5X/75uLAh3Z1CHOg2dHEc=\n\
     -----END PUBLIC KEY-----"];

/// Leeway for nbf (not-before) check in seconds (). Mirrors TS side.
const NBF_LEEWAY_SECONDS: i64 = 60;

/// LicensePayload matches the JWT claim shape signed by the TS billing
/// service in `epic-ai/website/src/lib/billing/sign-license.ts`. Field
/// names use snake_case per RFC 7519 convention; serde does NOT rename.
/// Required claims: iss, sub (companyId), exp (unix seconds),
/// license_epoch, min_security_epoch, renewal_token_hash. Optional:
/// tenant_id, tier, seats, nbf, grace_days, topology, company_name,
/// sla_tier, jti.
#[derive(Debug, Serialize, Deserialize)]
struct LicensePayload {
    iss: String,
    sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seats: Option<u32>,
    /// Unix-seconds expiry timestamp (JWT `exp` claim).
    exp: i64,
    /// Anti-rollback floor — REQUIRED in the chariot 3.x JWT contract.
    license_epoch: u32,
    /// Catalog-side security epoch floor — REQUIRED in the chariot 3.x JWT contract.
    min_security_epoch: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grace_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    topology: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    company_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sla_tier: Option<String>,
    renewal_token_hash: String,
    /// Optional not-before Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

#[napi(object)]
#[derive(Debug)]
pub struct LicenseResult {
    pub valid: bool,
    pub company_id: Option<String>,
    pub company_name: Option<String>,
    pub tenant_id: Option<String>,
    pub tier: Option<String>,
    pub total_seats: Option<u32>,
    pub license_epoch: Option<u32>,
    pub min_security_epoch: Option<u32>,
    pub exp_unix: Option<i64>,
    pub reason: Option<String>,
}

fn extract_public_key_from_pem(pem: &str) -> Result<VerifyingKey> {
    // Extract base64 content from PEM
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .replace(' ', "");

    let der = BASE64
        .decode(&b64)
        .map_err(|e| Error::from_reason(format!("Failed to decode public key: {}", e)))?;

    // Ed25519 SPKI DER: 12-byte header + 32-byte key
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
        .map_err(|e| Error::from_reason(format!("Invalid Ed25519 public key: {}", e)))
}

/// Returns the accepted verifying keys, ordered by preference (newest
/// rotation candidate first). Failures parsing any single key are fatal:
/// a malformed embedded constant indicates a build error and the binary
/// must not silently fall through to a smaller accepted-key set.
/// `pub(crate)`: edge_snapshot.rs pins its snapshot-verification trust
/// anchor to this same compiled-in set.
pub(crate) fn accepted_verifying_keys() -> Result<Vec<VerifyingKey>> {
    let mut out = Vec::with_capacity(ACCEPTED_PUBLIC_KEYS_PEM.len());
    for pem in ACCEPTED_PUBLIC_KEYS_PEM {
        out.push(extract_public_key_from_pem(pem)?);
    }
    Ok(out)
}

/// Build a LicenseResult that mirrors the parsed payload claims.
/// Caller fills `valid` and `reason`; everything else is copied from
/// the payload so the JS-side caller always sees the same claim shape
/// whether validation succeeded or failed (single source of truth).
fn result_from_payload(
    payload: &LicensePayload,
    valid: bool,
    reason: Option<String>,
) -> LicenseResult {
    LicenseResult {
        valid,
        company_id: Some(payload.sub.clone()),
        company_name: payload.company_name.clone(),
        tenant_id: payload.tenant_id.clone(),
        tier: payload.tier.clone(),
        total_seats: payload.seats,
        license_epoch: Some(payload.license_epoch),
        min_security_epoch: Some(payload.min_security_epoch),
        exp_unix: Some(payload.exp),
        reason,
    }
}

fn empty_result(reason: String) -> LicenseResult {
    LicenseResult {
        valid: false,
        company_id: None,
        company_name: None,
        tenant_id: None,
        tier: None,
        total_seats: None,
        license_epoch: None,
        min_security_epoch: None,
        exp_unix: None,
        reason: Some(reason),
    }
}

/// Full validation pipeline against an explicit accepted-key set. This is
/// the entire production logic — `validate_license` only supplies the
/// compiled-in keys — so tests can drive every path (signature, iss, nbf,
/// exp, claim shape) with a deterministic fixture key.
fn validate_license_with_keys(
    license_json: &str,
    signature_b64: &str,
    verifying_keys: &[VerifyingKey],
) -> LicenseResult {
    let payload: LicensePayload = match serde_json::from_str(license_json) {
        Ok(p) => p,
        Err(e) => return empty_result(format!("Invalid license JSON: {}", e)),
    };

    if payload.iss != "license.epic-ai.io" {
        return result_from_payload(
            &payload,
            false,
            Some(format!(
                "Unexpected iss: {} (expected license.epic-ai.io)",
                payload.iss
            )),
        );
    }

    let sig_bytes = match BASE64.decode(signature_b64) {
        Ok(b) => b,
        Err(e) => {
            return result_from_payload(
                &payload,
                false,
                Some(format!("Invalid signature encoding: {}", e)),
            )
        }
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return result_from_payload(
                &payload,
                false,
                Some(format!("Invalid signature format: {}", e)),
            )
        }
    };

    let any_valid = verifying_keys
        .iter()
        .any(|k| k.verify(license_json.as_bytes(), &signature).is_ok());

    if !any_valid {
        return result_from_payload(&payload, false, Some(
            "Signature verification failed — none of the accepted keys validated the signature.".to_string()
        ));
    }

    if let Some(nbf) = payload.nbf {
        let now_unix = chrono::Utc::now().timestamp();
        if now_unix + NBF_LEEWAY_SECONDS < nbf {
            return result_from_payload(
                &payload,
                false,
                Some("License not yet valid (nbf)".to_string()),
            );
        }
    }

    let now_unix = chrono::Utc::now().timestamp();
    if payload.exp < now_unix {
        return result_from_payload(&payload, false, Some("License has expired".to_string()));
    }

    result_from_payload(&payload, true, None)
}

// ── CHARIOT::§5.7::32/33 — real customer license artifact (compact JWT) ────
//
// R2 ruling (2026-09-04, MASTER accept-all): the §5.7 unseal entry point
// verifies the REAL customer license artifact — the compact JWT stored in
// `~/.epic-ai/chariot.license` (`{ "jwt": "<compact JWT>", "renewal_secret":
// … }`, `src/license/loader.ts:4-5`) — not a canonical-JSON + detached-
// signature pair. This mirrors `loader.ts::verifyAndDecode` (loader.ts:527
// split, :560-584 claims) byte-for-byte, including its DELIBERATE omissions:
// it does NOT enforce `nbf` (CHARIOT::§11.1::10: nbf "rides the JWT for
// downstream consumers and audit" and "is not consulted by the loader at
// all") and does NOT reject on `exp` (loader.ts's own doc comment: "Does NOT
// check expiration — caller routes to GRACE/DEGRADED based on `expUnix`").
// The §5.7 entry point is a second consumer of the SAME signed artifact the
// TS loader already validates for licensing/entitlement purposes; it must
// not silently apply a stricter policy than the artifact's own issuer/loader
// contract, or the two verifiers would disagree about which JWTs are valid.

/// JWT header — only `alg` and `kid` are consulted (mirrors `loader.ts`
/// `verifyAndDecode`'s destructure of `{ kid, alg, typ }`).
#[derive(Debug, Deserialize)]
struct JwtHeader {
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// JWT payload claims this crate consults. Deliberately NOT `LicensePayload`
/// above: the real JWT payload carries no `renewal_token_hash` claim (that
/// lives in the envelope's sibling `renewal_secret` field, not the JWT), so
/// `LicensePayload`'s REQUIRED `renewal_token_hash` field would reject every
/// real license. `tenant_id` accepts the legacy `tenantId` alias — mirrors
/// loader.ts:568-575 accepting either spelling for pre-existing licenses.
#[derive(Debug, Deserialize)]
struct JwtPayload {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default, alias = "tenantId")]
    tenant_id: Option<String>,
    #[serde(default)]
    license_epoch: Option<i64>,
    #[serde(default)]
    min_security_epoch: Option<i64>,
    /// The catalog version this licence is entitled to unseal (CHARIOT §5.7:
    /// the seal `salt`/`<context>` is the catalog version identifier and the
    /// consumer's expected context is derived from the verified licence).
    #[serde(default)]
    catalog_version: Option<String>,
}

/// The subset of a verified license JWT's claims the §5.7 unseal entry point
/// needs: the anti-rollback floor and the context-binding identity. Not a
/// `#[napi(object)]` — this stays internal to the native crate (edge_snapshot.rs
/// is the only consumer); the NAPI surface never re-exposes a license's raw
/// claims, only the pass/fail of the seal it gates.
pub(crate) struct VerifiedLicenseFloor {
    pub(crate) company_id: String,
    pub(crate) tenant_id: Option<String>,
    pub(crate) min_security_epoch: u32,
    pub(crate) catalog_version: Option<String>,
}

/// sha256-hex of a PEM's decoded SPKI DER bytes — the `kid` convention
/// `src/license/loader.ts:337`'s `ACCEPTED_KEYS_PEM` map keys are precomputed
/// under (verified against the embedded production key: DER sha256-hex ==
/// the literal kid `ACCEPTED_PUBLIC_KEYS_PEM`'s doc comment records).
fn pem_kid_hex(pem: &str) -> Result<String> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .replace(' ', "");
    let der = BASE64
        .decode(&b64)
        .map_err(|e| Error::from_reason(format!("Failed to decode public key: {e}")))?;
    Ok(crate::edge_snapshot::hex_encode(&Sha256::digest(&der)))
}

/// Verify a compact license JWT's Ed25519 signature against `accepted_pems`
/// and return its verified floor/context claims. Mirrors
/// `loader.ts::verifyAndDecode`:
///   1. split on `.`, require exactly 3 parts;
///   2. header must decode as JSON with `alg == "EdDSA"`;
///   3. key selection by header `kid` (sha256-hex of the DER SPKI,
///      `pem_kid_hex` above) against `accepted_pems` — `kid` ABSENT tries
///      every accepted key (mirrors `accepted_verifying_keys`'s iterate-all
///      pattern elsewhere in this crate); `kid` PRESENT but unmatched is a
///      hard reject (never silently falls through to "try all" — that would
///      let an attacker strip/forge `kid` to dodge a rotated-out key's
///      exclusion);
///   4. Ed25519-verify over the ASCII bytes `{headerB64}.{payloadB64}`
///      (the JWS signing input — NOT the decoded JSON, and NOT the payload
///      alone);
///   5. payload `iss == "license.epic-ai.io"`, `sub` present, `exp` present;
///   6. `min_security_epoch` REQUIRED and non-negative (also `license_epoch`,
///      required by the same billing-service contract loader.ts enforces).
/// Deliberately does NOT check `nbf` or reject on `exp` — see the module
/// doc above this section.
///
/// Takes `accepted_pems` explicitly (same pattern as
/// `validate_license_with_keys` above) so tests can drive the ENTIRE
/// pipeline — including a genuine happy path — against a fixture keypair,
/// while the public wrapper below binds it to the compiled-in accepted set.
/// `pub(crate)` (gate finding F4, 2026-09-04): `edge_snapshot.rs`'s
/// `license_derived_floor_and_context_with_pems` calls this directly so its
/// own tests can drive `unseal_and_verify_snapshot_with_keys` — the FULL
/// §5.7 pipeline, not just this function in isolation — through a fixture
/// JWT, including rollback/bad-alg/bad-kid/tampered-payload rejection.
pub(crate) fn verify_jwt_with_pems(jwt: &str, accepted_pems: &[&str]) -> Result<VerifiedLicenseFloor> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::from_reason(format!(
            "license JWT must have exactly 3 dot-separated parts, got {}",
            parts.len()
        )));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = BASE64URL
        .decode(header_b64)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT header encoding: {e}")))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT header JSON: {e}")))?;
    if header.alg.as_deref() != Some("EdDSA") {
        return Err(Error::from_reason(format!(
            "license JWT alg must be EdDSA, got {:?}",
            header.alg
        )));
    }

    let candidate_keys: Vec<VerifyingKey> = match header.kid.as_deref() {
        Some(kid) => {
            let mut matched: Option<VerifyingKey> = None;
            for pem in accepted_pems {
                if pem_kid_hex(pem)? == kid {
                    matched = Some(extract_public_key_from_pem(pem)?);
                    break;
                }
            }
            match matched {
                Some(k) => vec![k],
                None => {
                    return Err(Error::from_reason(format!(
                        "license JWT kid {kid:?} does not match any compiled-in accepted key"
                    )))
                }
            }
        }
        None => {
            let mut keys = Vec::with_capacity(accepted_pems.len());
            for pem in accepted_pems {
                keys.push(extract_public_key_from_pem(pem)?);
            }
            keys
        }
    };

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = BASE64URL
        .decode(sig_b64)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT signature encoding: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT signature format: {e}")))?;
    if !candidate_keys
        .iter()
        .any(|k| k.verify(signing_input.as_bytes(), &signature).is_ok())
    {
        return Err(Error::from_reason(
            "license JWT signature verification failed",
        ));
    }

    let payload_bytes = BASE64URL
        .decode(payload_b64)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT payload encoding: {e}")))?;
    let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::from_reason(format!("Invalid license JWT payload JSON: {e}")))?;

    if payload.iss.as_deref() != Some("license.epic-ai.io") {
        return Err(Error::from_reason(format!(
            "license JWT iss must be license.epic-ai.io, got {:?}",
            payload.iss
        )));
    }
    let company_id = payload
        .sub
        .clone()
        .ok_or_else(|| Error::from_reason("license JWT missing required sub claim"))?;
    if payload.exp.is_none() {
        return Err(Error::from_reason("license JWT missing required exp claim"));
    }
    let min_security_epoch = match payload.min_security_epoch {
        Some(v) if v >= 0 => v as u32,
        _ => {
            return Err(Error::from_reason(
                "license JWT missing or invalid min_security_epoch claim",
            ))
        }
    };
    if !matches!(payload.license_epoch, Some(v) if v >= 0) {
        return Err(Error::from_reason(
            "license JWT missing or invalid license_epoch claim",
        ));
    }

    Ok(VerifiedLicenseFloor {
        company_id,
        tenant_id: payload.tenant_id,
        min_security_epoch,
        catalog_version: payload.catalog_version,
    })
}

/// Public wrapper: verify a compact license JWT against the compiled-in
/// accepted key set (`ACCEPTED_PUBLIC_KEYS_PEM`) — the entry point
/// `edge_snapshot.rs`'s §5.7 unseal operations call.
pub(crate) fn verify_license_jwt_and_extract(jwt: &str) -> Result<VerifiedLicenseFloor> {
    verify_jwt_with_pems(jwt, ACCEPTED_PUBLIC_KEYS_PEM)
}

/// Validate a Chariot license against the JWT-claim contract enforced
/// by `src/license/loader.ts`. Input is the canonical claim JSON
/// (not the JWS envelope) plus the detached Ed25519 signature over those
/// bytes. Returns the parsed claim shape on every path so JS callers
/// always see the same fields whether validation succeeded or not.
#[napi]
pub fn validate_license(license_json: String, signature_b64: String) -> LicenseResult {
    let verifying_keys = match accepted_verifying_keys() {
        Ok(k) => k,
        Err(e) => {
            // Preserve the claim-shaped result when the payload parses even
            // though the embedded keys are unusable (build error).
            return match serde_json::from_str::<LicensePayload>(&license_json) {
                Ok(p) => result_from_payload(&p, false, Some(format!("Public key error: {}", e))),
                Err(pe) => empty_result(format!("Invalid license JSON: {}", pe)),
            };
        }
    };
    validate_license_with_keys(&license_json, &signature_b64, &verifying_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const FAR_FUTURE_EXP: i64 = 4070908800; // 2099-01-01

    /// Build a minimal license JSON in the JWT-claim shape for testing.
    fn make_license_json(nbf: Option<i64>, exp_unix: i64) -> String {
        make_license_json_iss("license.epic-ai.io", nbf, exp_unix)
    }

    fn make_license_json_iss(iss: &str, nbf: Option<i64>, exp_unix: i64) -> String {
        let nbf_field = match nbf {
            Some(n) => format!(r#","nbf":{}"#, n),
            None => String::new(),
        };
        format!(
            r#"{{"iss":"{}","sub":"test-co","company_name":"Test","seats":10,"license_epoch":1,"min_security_epoch":1,"exp":{},"renewal_token_hash":"sha256:zzz"{}}}"#,
            iss, exp_unix, nbf_field
        )
    }

    /// Deterministic fixture signing key (same pattern as edge_snapshot.rs:
    /// `generate` needs the `rand_core` feature, not enabled here).
    fn fixture_key() -> (SigningKey, Vec<VerifyingKey>) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let keys = vec![signing.verifying_key()];
        (signing, keys)
    }

    /// Sign `json` and run the REAL validation pipeline against the fixture key.
    fn sign_and_validate(json: &str) -> LicenseResult {
        let (signing, keys) = fixture_key();
        let sig = signing.sign(json.as_bytes());
        validate_license_with_keys(json, &BASE64.encode(sig.to_bytes()), &keys)
    }

    // ── validate_license_with_keys — real pipeline coverage ──────────────

    #[test]
    fn happy_path_valid_license() {
        let json = make_license_json(None, FAR_FUTURE_EXP);
        let r = sign_and_validate(&json);
        assert!(
            r.valid,
            "signed unexpired license must validate: {:?}",
            r.reason
        );
        assert_eq!(r.company_id.as_deref(), Some("test-co"));
        assert_eq!(r.license_epoch, Some(1));
        assert_eq!(r.min_security_epoch, Some(1));
        assert!(r.reason.is_none());
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let json = make_license_json(None, FAR_FUTURE_EXP);
        let (signing, keys) = fixture_key();
        let sig = signing.sign(json.as_bytes());
        // Tamper AFTER signing (seat bump) — signature must fail.
        let tampered = json.replace(r#""seats":10"#, r#""seats":9999"#);
        assert_ne!(json, tampered, "fixture must actually change");
        let r = validate_license_with_keys(&tampered, &BASE64.encode(sig.to_bytes()), &keys);
        assert!(!r.valid, "tampered payload must be rejected");
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("Signature verification failed"),
            "reason must be the signature failure; got {:?}",
            r.reason
        );
    }

    #[test]
    fn nbf_beyond_leeway_fails() {
        // nbf = now + 120s — beyond the 60s leeway.
        let json = make_license_json(Some(chrono::Utc::now().timestamp() + 120), FAR_FUTURE_EXP);
        let r = sign_and_validate(&json);
        assert!(!r.valid, "nbf beyond leeway must be rejected");
        assert_eq!(r.reason.as_deref(), Some("License not yet valid (nbf)"));
    }

    #[test]
    fn nbf_within_leeway_passes() {
        // nbf = now + 30s — inside the 60s leeway window.
        let json = make_license_json(Some(chrono::Utc::now().timestamp() + 30), FAR_FUTURE_EXP);
        let r = sign_and_validate(&json);
        assert!(r.valid, "nbf within leeway must pass: {:?}", r.reason);
    }

    #[test]
    fn nbf_in_past_passes() {
        let json = make_license_json(Some(chrono::Utc::now().timestamp() - 3600), FAR_FUTURE_EXP);
        let r = sign_and_validate(&json);
        assert!(r.valid, "past nbf must pass: {:?}", r.reason);
    }

    #[test]
    fn expired_license_fails() {
        let json = make_license_json(None, chrono::Utc::now().timestamp() - 60);
        let r = sign_and_validate(&json);
        assert!(!r.valid, "expired license must be rejected");
        assert_eq!(r.reason.as_deref(), Some("License has expired"));
    }

    #[test]
    fn missing_required_claim_fails_parse() {
        // Drop the REQUIRED license_epoch claim.
        let json = make_license_json(None, FAR_FUTURE_EXP).replace(r#""license_epoch":1,"#, "");
        let r = sign_and_validate(&json);
        assert!(!r.valid, "missing required claim must be rejected");
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("Invalid license JSON"),
            "reason must be the JSON-contract failure; got {:?}",
            r.reason
        );
    }

    #[test]
    fn wrong_iss_rejected() {
        let json = make_license_json_iss("evil.example.com", None, FAR_FUTURE_EXP);
        let r = sign_and_validate(&json);
        assert!(!r.valid, "wrong iss must be rejected");
        assert!(
            r.reason.as_deref().unwrap_or("").contains("Unexpected iss"),
            "reason must be the iss rejection; got {:?}",
            r.reason
        );
    }

    // ── public validate_license — hardcoded-key wiring (key-independent
    //    failure paths, so no fixture private key is needed) ──────────────

    #[test]
    fn public_fn_garbage_base64_signature_rejected() {
        let json = make_license_json(None, FAR_FUTURE_EXP);
        let r = validate_license(json, "!!!not-base64!!!".to_string());
        assert!(!r.valid);
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("Invalid signature encoding"),
            "got {:?}",
            r.reason
        );
    }

    // ── verify_jwt_with_pems / verify_license_jwt_and_extract (CHARIOT::§5.7::32/33, R2) ──

    /// Build a fixture Ed25519 SPKI PEM from a `VerifyingKey` — same DER
    /// header bytes `edge_snapshot.rs::fixture_key_rejected_by_pinning` uses
    /// (12-byte Ed25519 SubjectPublicKeyInfo prefix + 32-byte raw key).
    fn fixture_pem(verifying: &VerifyingKey) -> String {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(verifying.as_bytes());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            BASE64.encode(&der)
        )
    }

    fn b64url(bytes: &[u8]) -> String {
        BASE64URL.encode(bytes)
    }

    /// Build and sign a compact JWT from JSON header/payload strings with the
    /// given fixture signing key. Returns the compact `header.payload.sig`.
    fn make_jwt(signing: &SigningKey, header_json: &str, payload_json: &str) -> String {
        let header_b64 = b64url(header_json.as_bytes());
        let payload_b64 = b64url(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        format!("{header_b64}.{payload_b64}.{}", b64url(&sig.to_bytes()))
    }

    /// Canonical fixture payload JSON: valid iss/sub/exp/license_epoch/
    /// min_security_epoch, with an explicit `kid` in the header matching the
    /// fixture key's own `pem_kid_hex`.
    fn fixture_jwt(kid: Option<&str>, payload_json: &str) -> (String, SigningKey, String) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let pem = fixture_pem(&verifying);
        let header_json = match kid {
            Some(k) => format!(r#"{{"alg":"EdDSA","kid":"{k}","typ":"JWT"}}"#),
            None => r#"{"alg":"EdDSA","typ":"JWT"}"#.to_string(),
        };
        let jwt = make_jwt(&signing, &header_json, payload_json);
        (jwt, signing, pem)
    }

    const FIXTURE_PAYLOAD: &str = r#"{"iss":"license.epic-ai.io","sub":"co-1","exp":4070908800,"license_epoch":2,"min_security_epoch":5,"tenant_id":"tenant-x"}"#;

    /// HAPPY PATH — now possible under R2 (the JWT verifier takes an
    /// explicit accepted-key list, so a fixture keypair drives the ENTIRE
    /// pipeline, unlike the canonical-JSON path this replaces which could
    /// only test rejections against the compiled-in production key).
    #[test]
    fn jwt_happy_path_verifies_via_kid() {
        let kid = pem_kid_hex_for_test();
        let (jwt, _signing, pem) = fixture_jwt(Some(kid.as_str()), FIXTURE_PAYLOAD);
        let floor = verify_jwt_with_pems(&jwt, &[pem.as_str()])
            .expect("a validly-signed JWT with a matching kid must verify");
        assert_eq!(floor.company_id, "co-1");
        assert_eq!(floor.tenant_id.as_deref(), Some("tenant-x"));
        assert_eq!(floor.min_security_epoch, 5);
        assert_eq!(floor.catalog_version, None, "absent claim stays absent");
    }

    /// The signed `catalog_version` claim (CHARIOT §5.7 context binding) is
    /// carried through verification verbatim.
    #[test]
    fn jwt_catalog_version_claim_is_extracted() {
        let payload = r#"{"iss":"license.epic-ai.io","sub":"co-1","exp":4070908800,"license_epoch":2,"min_security_epoch":5,"catalog_version":"1"}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let floor = verify_jwt_with_pems(&jwt, &[pem.as_str()]).expect("must verify");
        assert_eq!(floor.catalog_version.as_deref(), Some("1"));
    }

    /// Compute the `kid` (`pem_kid_hex`) for the SAME fixed fixture key
    /// `fixture_jwt(Some(kid), …)` below signs with, so the happy-path test
    /// can supply a `kid` that actually matches. Small wrapper purely to
    /// keep the two call sites (compute kid, then build the JWT with it)
    /// readable in order.
    fn pem_kid_hex_for_test() -> String {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pem = fixture_pem(&signing.verifying_key());
        pem_kid_hex(&pem).expect("fixture PEM must decode")
    }

    /// HAPPY PATH — kid absent tries every accepted key (mirrors
    /// `accepted_verifying_keys`'s iterate-all pattern).
    #[test]
    fn jwt_happy_path_verifies_without_kid() {
        let (jwt, _signing, pem) = fixture_jwt(None, FIXTURE_PAYLOAD);
        let floor = verify_jwt_with_pems(&jwt, &[pem.as_str()])
            .expect("a validly-signed JWT with no kid must verify against every accepted key");
        assert_eq!(floor.min_security_epoch, 5);
    }

    #[test]
    fn jwt_malformed_shape_rejected() {
        assert!(verify_jwt_with_pems("only-one-part", &[]).is_err());
        assert!(verify_jwt_with_pems("a.b.c.d", &[]).is_err());
    }

    #[test]
    fn jwt_bad_alg_rejected() {
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let pem = fixture_pem(&signing.verifying_key());
        let header_json = r#"{"alg":"HS256"}"#;
        let jwt = make_jwt(&signing, header_json, FIXTURE_PAYLOAD);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(r.is_err(), "non-EdDSA alg must be rejected");
        assert!(r.err().unwrap().to_string().contains("EdDSA"));
    }

    /// A `kid` present but matching NO accepted key must hard-reject — it
    /// must NOT silently fall through to trying every accepted key (that
    /// would let a forged/stripped kid dodge a rotated-out key's exclusion).
    #[test]
    fn jwt_unmatched_kid_hard_rejected() {
        let (jwt, _signing, pem) = fixture_jwt(Some("0000000000000000000000000000000000000000000000000000000000000000"), FIXTURE_PAYLOAD);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(r.is_err(), "an unmatched kid must be rejected");
        assert!(r.err().unwrap().to_string().contains("does not match"));
    }

    /// Signed by a key NOT in the accepted set at all (kid absent, so every
    /// accepted key is tried and none verifies).
    #[test]
    fn jwt_signature_from_non_accepted_key_rejected() {
        let (jwt, _signing, _own_pem) = fixture_jwt(None, FIXTURE_PAYLOAD);
        let other_signing = SigningKey::from_bytes(&[9u8; 32]);
        let other_pem = fixture_pem(&other_signing.verifying_key());
        let r = verify_jwt_with_pems(&jwt, &[other_pem.as_str()]);
        assert!(r.is_err(), "signature from an unaccepted key must be rejected");
    }

    /// Payload tampered AFTER signing (still valid base64url/JSON) must fail
    /// the signature check — proves the signature covers the payload bytes.
    #[test]
    fn jwt_tampered_payload_rejected() {
        let (jwt, _signing, pem) = fixture_jwt(None, FIXTURE_PAYLOAD);
        let parts: Vec<&str> = jwt.split('.').collect();
        let tampered_payload = b64url(
            FIXTURE_PAYLOAD
                .replace(r#""min_security_epoch":5"#, r#""min_security_epoch":0"#)
                .as_bytes(),
        );
        let tampered_jwt = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
        let r = verify_jwt_with_pems(&tampered_jwt, &[pem.as_str()]);
        assert!(r.is_err(), "a tampered payload must fail signature verification");
    }

    #[test]
    fn jwt_missing_min_security_epoch_rejected() {
        let payload = r#"{"iss":"license.epic-ai.io","sub":"co-1","exp":4070908800,"license_epoch":2}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(r.is_err(), "missing min_security_epoch must be rejected");
        assert!(r.err().unwrap().to_string().contains("min_security_epoch"));
    }

    #[test]
    fn jwt_missing_exp_claim_rejected() {
        let payload = r#"{"iss":"license.epic-ai.io","sub":"co-1","license_epoch":2,"min_security_epoch":5}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(r.is_err(), "missing exp claim must be rejected");
    }

    /// R2 / loader.ts parity: `verifyAndDecode`'s own doc comment states
    /// "Does NOT check expiration — caller routes to GRACE/DEGRADED based on
    /// expUnix", and CHARIOT::§11.1::10 states `nbf` "is not consulted by
    /// the loader at all." A PAST `exp` and a FUTURE `nbf` must therefore
    /// still verify here — this is a regression guard against silently
    /// making the §5.7 entry point stricter than the production loader it
    /// mirrors (which would make the two verifiers disagree about which
    /// JWTs are valid).
    #[test]
    fn jwt_past_exp_and_future_nbf_do_not_reject() {
        let payload = r#"{"iss":"license.epic-ai.io","sub":"co-1","exp":1,"nbf":4070908800,"license_epoch":2,"min_security_epoch":5}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(
            r.is_ok(),
            "an expired exp / future nbf must NOT be rejected by this verifier (loader.ts parity); got: {:?}",
            r.err()
        );
    }

    #[test]
    fn jwt_wrong_iss_rejected() {
        let payload = r#"{"iss":"evil.example.com","sub":"co-1","exp":4070908800,"license_epoch":2,"min_security_epoch":5}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let r = verify_jwt_with_pems(&jwt, &[pem.as_str()]);
        assert!(r.is_err(), "wrong iss must be rejected");
    }

    #[test]
    fn jwt_tenant_id_camelcase_alias_accepted() {
        let payload = r#"{"iss":"license.epic-ai.io","sub":"co-1","exp":4070908800,"license_epoch":2,"min_security_epoch":5,"tenantId":"legacy-tenant"}"#;
        let (jwt, _signing, pem) = fixture_jwt(None, payload);
        let floor = verify_jwt_with_pems(&jwt, &[pem.as_str()]).expect("legacy tenantId must be accepted");
        assert_eq!(floor.tenant_id.as_deref(), Some("legacy-tenant"));
    }

    /// The public wrapper must reject a JWT signed by ANY key that is not
    /// the compiled-in production key — proves it is actually bound to
    /// `ACCEPTED_PUBLIC_KEYS_PEM` and not to an arbitrary caller-supplied set.
    #[test]
    fn verify_license_jwt_and_extract_rejects_non_production_key() {
        let (jwt, _signing, _pem) = fixture_jwt(None, FIXTURE_PAYLOAD);
        let r = verify_license_jwt_and_extract(&jwt);
        assert!(
            r.is_err(),
            "a JWT signed by a non-production key must be rejected by the public wrapper"
        );
    }

    #[test]
    fn public_fn_unverifiable_signature_rejected() {
        // Well-formed 64-byte signature that no embedded production key
        // verifies (signed by the fixture key) — exercises the real
        // hardcoded-key iteration in the #[napi] wrapper.
        let json = make_license_json(None, FAR_FUTURE_EXP);
        let (signing, _) = fixture_key();
        let sig = signing.sign(json.as_bytes());
        let r = validate_license(json, BASE64.encode(sig.to_bytes()));
        assert!(
            !r.valid,
            "fixture-key signature must not verify against embedded keys"
        );
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("Signature verification failed"),
            "got {:?}",
            r.reason
        );
    }
}
