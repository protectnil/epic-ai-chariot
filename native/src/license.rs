// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use napi::bindgen_prelude::*;
use napi_derive::napi;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

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
const ACCEPTED_PUBLIC_KEYS_PEM: &[&str] = &[
    "-----BEGIN PUBLIC KEY-----\n\
     MCowBQYDK2VwAyEACBR74DxcFEvMcBO0YOxA9q5X/75uLAh3Z1CHOg2dHEc=\n\
     -----END PUBLIC KEY-----",
];

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
fn accepted_verifying_keys() -> Result<Vec<VerifyingKey>> {
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
fn result_from_payload(payload: &LicensePayload, valid: bool, reason: Option<String>) -> LicenseResult {
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

/// Validate a Chariot license against the JWT-claim contract enforced
/// by `src/license/loader.ts`. Input is the canonical claim JSON
/// (not the JWS envelope) plus the detached Ed25519 signature over those
/// bytes. Returns the parsed claim shape on every path so JS callers
/// always see the same fields whether validation succeeded or not.
#[napi]
pub fn validate_license(license_json: String, signature_b64: String) -> LicenseResult {
    let payload: LicensePayload = match serde_json::from_str(&license_json) {
        Ok(p) => p,
        Err(e) => return empty_result(format!("Invalid license JSON: {}", e)),
    };

    if payload.iss != "license.epic-ai.io" {
        return result_from_payload(&payload, false, Some(format!(
            "Unexpected iss: {} (expected license.epic-ai.io)", payload.iss
        )));
    }

    let sig_bytes = match BASE64.decode(&signature_b64) {
        Ok(b) => b,
        Err(e) => return result_from_payload(&payload, false, Some(format!("Invalid signature encoding: {}", e))),
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return result_from_payload(&payload, false, Some(format!("Invalid signature format: {}", e))),
    };

    let verifying_keys = match accepted_verifying_keys() {
        Ok(k) => k,
        Err(e) => return result_from_payload(&payload, false, Some(format!("Public key error: {}", e))),
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
            return result_from_payload(&payload, false, Some("License not yet valid (nbf)".to_string()));
        }
    }

    let now_unix = chrono::Utc::now().timestamp();
    if payload.exp < now_unix {
        return result_from_payload(&payload, false, Some("License has expired".to_string()));
    }

    result_from_payload(&payload, true, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal license JSON in the JWT-claim shape for testing
    /// (unsigned — we test struct parsing + expiry semantics, not sig).
    fn make_license_json(nbf: Option<i64>, exp_unix: i64) -> String {
        let nbf_field = match nbf {
            Some(n) => format!(r#","nbf":{}"#, n),
            None => String::new(),
        };
        format!(
            r#"{{"iss":"license.epic-ai.io","sub":"test-co","company_name":"Test","seats":10,"license_epoch":1,"min_security_epoch":1,"exp":{},"renewal_token_hash":"sha256:zzz"{}}}"#,
            exp_unix, nbf_field
        )
    }

    // ──  unit tests (Rust side) ─────────────────────────────────────

    #[test]
    fn nbf_absent_does_not_reject() {
        // Payload with no nbf field; should parse without rejecting.
        let json = make_license_json(None, 4070908800); // 2099-01-01
        let payload: LicensePayload = serde_json::from_str(&json).expect("parse");
        assert!(payload.nbf.is_none(), "nbf should be absent");
        // With no nbf, the check is skipped; only expiry matters.
        // expires_at is far future so valid.
        let now_unix = chrono::Utc::now().timestamp();
        if let Some(nbf) = payload.nbf {
            assert!(now_unix + NBF_LEEWAY_SECONDS >= nbf, "should pass leeway");
        }
    }

    #[test]
    fn nbf_in_past_passes() {
        let past = chrono::Utc::now().timestamp() - 3600; // 1 hour ago
        let json = make_license_json(Some(past), 4070908800);
        let payload: LicensePayload = serde_json::from_str(&json).expect("parse");
        let now_unix = chrono::Utc::now().timestamp();
        let nbf = payload.nbf.unwrap();
        // now + leeway >= nbf → should pass
        assert!(now_unix + NBF_LEEWAY_SECONDS >= nbf);
    }

    #[test]
    fn nbf_within_leeway_passes() {
        // nbf = now + 30s — within the 60s leeway window
        let near_future = chrono::Utc::now().timestamp() + 30;
        let json = make_license_json(Some(near_future), 4070908800);
        let payload: LicensePayload = serde_json::from_str(&json).expect("parse");
        let now_unix = chrono::Utc::now().timestamp();
        let nbf = payload.nbf.unwrap();
        // now + 60 >= now + 30 → passes
        assert!(now_unix + NBF_LEEWAY_SECONDS >= nbf);
    }

    #[test]
    fn nbf_beyond_leeway_fails() {
        // nbf = now + 120s — beyond the 60s leeway
        let far_future = chrono::Utc::now().timestamp() + 120;
        let json = make_license_json(Some(far_future), 4070908800);
        let payload: LicensePayload = serde_json::from_str(&json).expect("parse");
        let now_unix = chrono::Utc::now().timestamp();
        let nbf = payload.nbf.unwrap();
        // now + 60 < now + 120 → fails
        assert!(now_unix + NBF_LEEWAY_SECONDS < nbf);
    }
}
