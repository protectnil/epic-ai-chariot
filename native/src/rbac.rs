// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A group→adapter mapping bound to a specific tenant. The native layer
/// rejects any mapping whose `tenant_id` does not match the caller's
/// tenant context, so an accidental cross-tenant mappings_json
/// constructed by the TS caller cannot grant access.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupAdapterMapping {
    tenant_id: String,
    group_id: String,
    adapter_ids: Vec<String>,
    /// Principal-kind scope for this mapping (gap #3 — Wiz 2 finding that
    /// nothing distinguished a human from an agent/service principal).
    /// Values: "human" | "agent" | "service". `None`/absent (every mapping
    /// authored before this field existed) or an empty list means the
    /// mapping applies to ANY principal kind — identical to pre-existing
    /// behavior, so legacy `mappings_json` payloads deserialize and grant
    /// exactly as before. A non-empty list restricts the mapping to those
    /// kinds only; consulted ONLY by the principal-aware surfaces
    /// (`check_access_for_principal` / `resolve_user_adapters_for_principal`),
    /// NOT by the original `check_access` / `resolve_user_adapters`, which
    /// remain principal-kind-agnostic for backward compatibility with
    /// existing callers (src/license/binding.ts) that do not pass a caller
    /// principal kind.
    #[serde(default)]
    principal_scope: Option<Vec<String>>,
}

/// The three recognized principal kinds for the principal-aware RBAC
/// surfaces. Kept as a plain string set (rather than a Rust enum) so it
/// round-trips through `mappings_json`/napi string params without extra
/// serde plumbing; validated centrally in `normalize_principal_type`.
const VALID_PRINCIPAL_TYPES: [&str; 3] = ["human", "agent", "service"];

/// Validate and lowercase a caller-supplied principal type. Returns `Err`
/// for anything outside {human, agent, service} — fail-closed: an
/// unrecognized principal kind must not silently fall back to the most
/// permissive interpretation.
fn normalize_principal_type(raw: &str) -> Result<String, String> {
    let lower = raw.to_lowercase();
    if VALID_PRINCIPAL_TYPES.contains(&lower.as_str()) {
        Ok(lower)
    } else {
        Err(format!(
            "Invalid principal_type '{}': expected one of {:?}",
            raw, VALID_PRINCIPAL_TYPES
        ))
    }
}

#[napi(object)]
#[derive(Debug)]
pub struct AccessResult {
    pub allowed: bool,
    pub granted_adapter_ids: Vec<String>,
    pub denied_adapter_ids: Vec<String>,
    pub reason: Option<String>,
}

/// Filter the supplied mappings to only those scoped to `tenant_id`.
/// Returns `Err` with the offending mapping's groupId if any mapping
/// in the array carries a different tenant — this is treated as a
/// hard error rather than silently filtered, because the caller
/// constructed a mappings array containing data they should not have
/// had access to and the operator must be told.
fn filter_to_tenant(
    mappings: Vec<GroupAdapterMapping>,
    tenant_id: &str,
) -> Result<Vec<GroupAdapterMapping>, String> {
    let mut bad: Vec<String> = Vec::new();
    let mut ours: Vec<GroupAdapterMapping> = Vec::new();
    for m in mappings {
        if m.tenant_id == tenant_id {
            ours.push(m);
        } else {
            bad.push(format!("{}::{}", m.tenant_id, m.group_id));
        }
    }
    if !bad.is_empty() {
        return Err(format!(
            "Cross-tenant mapping(s) supplied to RBAC check for tenant '{}': {}",
            tenant_id,
            bad.join(", ")
        ));
    }
    Ok(ours)
}

/// Compute the effective adapter set granted by `user_groups` over the
/// (already tenant-filtered) `mappings`. SINGLE source of truth for the
/// grant semantics shared by `check_access` and `resolve_user_adapters`
/// so the two authz surfaces can never disagree:
///
/// - Case-fold both sides before comparison. Mixed-case group ids from an
///   IdP (e.g. SAML 'DevOps' vs Okta 'devops') must map to the same RBAC
///   slot. Eval 28 P3 fast-check found that without normalization, a
///   mapping for 'finance' would NOT match a user group 'Finance' even
///   though the deny-precedence test relies on case-insensitive matching.
/// - Deny-precedence: any mapping for a group the user holds with an
///   empty adapter_ids list is an explicit deny that overrides every
///   permissive mapping (standard RBAC semantics — empty-grant means
///   denied for this adapter scope, not no-op). Returns `None` on
///   explicit deny; `Some(set)` otherwise.
fn effective_adapters(
    mappings: &[GroupAdapterMapping],
    user_groups: &[String],
) -> Option<HashSet<String>> {
    let user_group_set: HashSet<String> = user_groups.iter().map(|s| s.to_lowercase()).collect();
    let mut allowed_adapters: HashSet<String> = HashSet::new();

    for mapping in mappings {
        let mapping_group_lc = mapping.group_id.to_lowercase();
        if !user_group_set.contains(&mapping_group_lc) {
            continue;
        }
        if mapping.adapter_ids.is_empty() {
            return None; // explicit deny — overrides every permissive mapping
        }
        for adapter_id in &mapping.adapter_ids {
            allowed_adapters.insert(adapter_id.clone());
        }
    }

    Some(allowed_adapters)
}

/// Principal-aware variant of `effective_adapters` (gap #3). Identical
/// grant semantics (case-fold, deny-precedence) PLUS: a mapping whose
/// `principal_scope` is a non-empty list is skipped entirely unless
/// `principal_type` (already validated/lowercased by the caller) appears
/// in that list. This is what stops an agent/service principal from
/// silently inheriting a mapping an operator scoped to humans only.
///
/// A `principal_scope`-restricted mapping with an EMPTY `adapter_ids` that
/// does not match `principal_type` is simply skipped (not an explicit
/// deny) — the deny only applies to the principal kinds the mapping
/// actually targets; it must not leak into a matching decision for a
/// different principal kind.
fn effective_adapters_for_principal(
    mappings: &[GroupAdapterMapping],
    user_groups: &[String],
    principal_type: &str,
) -> Option<HashSet<String>> {
    let user_group_set: HashSet<String> = user_groups.iter().map(|s| s.to_lowercase()).collect();
    let mut allowed_adapters: HashSet<String> = HashSet::new();

    for mapping in mappings {
        let mapping_group_lc = mapping.group_id.to_lowercase();
        if !user_group_set.contains(&mapping_group_lc) {
            continue;
        }
        if let Some(scope) = &mapping.principal_scope {
            if !scope.is_empty() && !scope.iter().any(|s| s.to_lowercase() == principal_type) {
                // This mapping does not apply to the caller's principal
                // kind — skip it entirely (neither grant nor deny).
                continue;
            }
        }
        if mapping.adapter_ids.is_empty() {
            return None; // explicit deny — overrides every permissive mapping
        }
        for adapter_id in &mapping.adapter_ids {
            allowed_adapters.insert(adapter_id.clone());
        }
    }

    Some(allowed_adapters)
}

/// Check whether a user's groups grant access to the requested adapters.
///
/// `tenant_id`: the caller's tenant context. Mappings whose tenantId does
///   not equal this value cause the entire check to fail with `allowed: false`
///   and a non-empty `reason`. This is the native-layer defense against
///   a TS caller that accidentally constructs a cross-tenant mappings array.
/// `user_groups`: list of group IDs the user belongs to
/// `requested_adapter_ids`: adapter IDs being accessed. An EMPTY list is
///   denied (deny-by-default): there is nothing to authorize, and returning
///   `allowed: true` for a vacuous request would hand a `!result.allowed`
///   caller a silent bypass.
/// `mappings_json`: JSON array of { tenantId, groupId, adapterIds } mappings
#[napi]
pub fn check_access(
    tenant_id: String,
    user_groups: Vec<String>,
    requested_adapter_ids: Vec<String>,
    mappings_json: String,
) -> AccessResult {
    // Deny-by-default guard: an empty request must NOT be vacuous success.
    if requested_adapter_ids.is_empty() {
        return AccessResult {
            allowed: false,
            granted_adapter_ids: vec![],
            denied_adapter_ids: vec![],
            reason: Some(
                "Empty requested_adapter_ids: nothing to authorize; empty request is denied by default"
                    .to_string(),
            ),
        };
    }

    let parsed: Vec<GroupAdapterMapping> = match serde_json::from_str(&mappings_json) {
        Ok(m) => m,
        Err(e) => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(format!("Invalid mappings JSON: {}", e)),
            };
        }
    };

    let mappings = match filter_to_tenant(parsed, &tenant_id) {
        Ok(m) => m,
        Err(reason) => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(reason),
            };
        }
    };

    let allowed_adapters = match effective_adapters(&mappings, &user_groups) {
        None => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(
                    "Explicit deny via empty adapter_ids in one of user's groups".to_string(),
                ),
            };
        }
        Some(set) => set,
    };

    let mut granted: Vec<String> = Vec::new();
    let mut denied: Vec<String> = Vec::new();

    for adapter_id in &requested_adapter_ids {
        if allowed_adapters.contains(adapter_id) {
            granted.push(adapter_id.clone());
        } else {
            denied.push(adapter_id.clone());
        }
    }

    let all_allowed = denied.is_empty();

    AccessResult {
        allowed: all_allowed,
        granted_adapter_ids: granted,
        denied_adapter_ids: denied,
        reason: if all_allowed {
            None
        } else {
            Some("One or more adapters not permitted for user's groups".to_string())
        },
    }
}

/// Resolve all adapter IDs a user can access based on their group memberships,
/// scoped to the caller's tenant. Mappings that carry a different tenant_id
/// are silently filtered out (defense-in-depth: caller already saw the data,
/// but native refuses to honor it).
///
/// Grant semantics are IDENTICAL to `check_access` (shared
/// `effective_adapters` helper): group ids are matched case-insensitively,
/// and any user-held group mapping with an empty adapter_ids list is an
/// explicit deny that overrides every permissive mapping.
///
/// Returns an empty list on JSON parse error, when no in-tenant mappings
/// match, OR on explicit deny — an empty result may therefore mean
/// "explicitly denied", not just "no grants". Use `check_access` if you
/// need to distinguish those cases via a structured reason.
#[napi]
pub fn resolve_user_adapters(
    tenant_id: String,
    user_groups: Vec<String>,
    mappings_json: String,
) -> Vec<String> {
    let parsed: Vec<GroupAdapterMapping> = match serde_json::from_str(&mappings_json) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    // Silently filter foreign tenants here — caller-friendly path, the
    // hard rejection lives in `check_access` where the operator gets a
    // structured error to act on.
    let mappings: Vec<GroupAdapterMapping> = parsed
        .into_iter()
        .filter(|m| m.tenant_id == tenant_id)
        .collect();

    // None = explicit deny → resolve to the empty set, matching the deny
    // check_access would return for any request in this tenant.
    let adapters = match effective_adapters(&mappings, &user_groups) {
        None => return vec![],
        Some(set) => set,
    };

    let mut result: Vec<String> = adapters.into_iter().collect();
    result.sort();
    result
}

/// Principal-aware variant of `check_access` (gap #3 — Wiz 2 human/agent
/// partition). Identical contract to `check_access` PLUS a mandatory
/// `principal_type` argument identifying the CALLER (not the mapping):
/// "human" | "agent" | "service", case-insensitive. Any mapping whose
/// `principalScope` is a non-empty list that does not include the
/// caller's kind is not honored for this call — an agent/service caller
/// cannot inherit a mapping an operator scoped to humans only.
///
/// Fail-closed on an unrecognized `principal_type`: denies with a
/// structured reason rather than guessing a default. This is a NEW,
/// additive export — `check_access` is untouched so existing callers
/// (src/license/binding.ts) keep their exact current behavior.
#[napi]
pub fn check_access_for_principal(
    tenant_id: String,
    principal_type: String,
    user_groups: Vec<String>,
    requested_adapter_ids: Vec<String>,
    mappings_json: String,
) -> AccessResult {
    let normalized_principal = match normalize_principal_type(&principal_type) {
        Ok(p) => p,
        Err(reason) => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(reason),
            };
        }
    };

    if requested_adapter_ids.is_empty() {
        return AccessResult {
            allowed: false,
            granted_adapter_ids: vec![],
            denied_adapter_ids: vec![],
            reason: Some(
                "Empty requested_adapter_ids: nothing to authorize; empty request is denied by default"
                    .to_string(),
            ),
        };
    }

    let parsed: Vec<GroupAdapterMapping> = match serde_json::from_str(&mappings_json) {
        Ok(m) => m,
        Err(e) => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(format!("Invalid mappings JSON: {}", e)),
            };
        }
    };

    let mappings = match filter_to_tenant(parsed, &tenant_id) {
        Ok(m) => m,
        Err(reason) => {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some(reason),
            };
        }
    };

    let allowed_adapters =
        match effective_adapters_for_principal(&mappings, &user_groups, &normalized_principal) {
            None => {
                return AccessResult {
                    allowed: false,
                    granted_adapter_ids: vec![],
                    denied_adapter_ids: requested_adapter_ids,
                    reason: Some(
                        "Explicit deny via empty adapter_ids in one of user's groups".to_string(),
                    ),
                };
            }
            Some(set) => set,
        };

    let mut granted: Vec<String> = Vec::new();
    let mut denied: Vec<String> = Vec::new();

    for adapter_id in &requested_adapter_ids {
        if allowed_adapters.contains(adapter_id) {
            granted.push(adapter_id.clone());
        } else {
            denied.push(adapter_id.clone());
        }
    }

    let all_allowed = denied.is_empty();

    AccessResult {
        allowed: all_allowed,
        granted_adapter_ids: granted,
        denied_adapter_ids: denied,
        reason: if all_allowed {
            None
        } else {
            Some("One or more adapters not permitted for user's groups/principal kind".to_string())
        },
    }
}

/// Principal-aware variant of `resolve_user_adapters` (gap #3). See
/// `check_access_for_principal` for the principal-scope semantics.
/// Returns an empty list on JSON parse error, invalid `principal_type`,
/// when no in-tenant mappings match, OR on explicit deny.
#[napi]
pub fn resolve_user_adapters_for_principal(
    tenant_id: String,
    principal_type: String,
    user_groups: Vec<String>,
    mappings_json: String,
) -> Vec<String> {
    let normalized_principal = match normalize_principal_type(&principal_type) {
        Ok(p) => p,
        Err(_) => return vec![],
    };

    let parsed: Vec<GroupAdapterMapping> = match serde_json::from_str(&mappings_json) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    let mappings: Vec<GroupAdapterMapping> = parsed
        .into_iter()
        .filter(|m| m.tenant_id == tenant_id)
        .collect();

    let adapters =
        match effective_adapters_for_principal(&mappings, &user_groups, &normalized_principal) {
            None => return vec![],
            Some(set) => set,
        };

    let mut result: Vec<String> = adapters.into_iter().collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_FIXTURE: &str = r#"[
        {"tenantId":"t1","groupId":"devops","adapterIds":["a1","a2"]},
        {"tenantId":"t1","groupId":"interns","adapterIds":[]}
    ]"#;

    const CASE_FIXTURE: &str = r#"[
        {"tenantId":"t1","groupId":"finance","adapterIds":["ledger"]}
    ]"#;

    /// Explicit deny (empty adapter_ids on a user-held group) must be
    /// honored by BOTH authz surfaces — check_access denies AND
    /// resolve_user_adapters resolves to the empty set.
    #[test]
    fn deny_precedence_agrees_across_both_surfaces() {
        let groups = vec!["devops".to_string(), "interns".to_string()];

        let check = check_access(
            "t1".to_string(),
            groups.clone(),
            vec!["a1".to_string()],
            DENY_FIXTURE.to_string(),
        );
        assert!(!check.allowed, "check_access must deny on explicit deny");

        let resolved = resolve_user_adapters("t1".to_string(), groups, DENY_FIXTURE.to_string());
        assert!(
            resolved.is_empty(),
            "resolve_user_adapters must honor explicit deny; got {resolved:?}"
        );
    }

    /// Case-fold agreement: a 'Finance' user group must match a 'finance'
    /// mapping in BOTH functions.
    #[test]
    fn case_fold_agrees_across_both_surfaces() {
        let groups = vec!["Finance".to_string()];

        let check = check_access(
            "t1".to_string(),
            groups.clone(),
            vec!["ledger".to_string()],
            CASE_FIXTURE.to_string(),
        );
        assert!(check.allowed, "check_access must case-fold group ids");

        let resolved = resolve_user_adapters("t1".to_string(), groups, CASE_FIXTURE.to_string());
        assert_eq!(
            resolved,
            vec!["ledger".to_string()],
            "resolve_user_adapters must case-fold group ids"
        );
    }

    /// An empty requested_adapter_ids list must be denied (deny-by-default),
    /// never vacuous success.
    #[test]
    fn empty_request_is_denied() {
        let r = check_access(
            "t1".to_string(),
            vec!["devops".to_string()],
            vec![],
            DENY_FIXTURE.to_string(),
        );
        assert!(!r.allowed, "empty requested_adapter_ids must be denied");
        assert!(
            r.reason
                .as_deref()
                .unwrap_or("")
                .contains("Empty requested_adapter_ids"),
            "reason must explain the empty-request deny; got {:?}",
            r.reason
        );
    }

    /// Positive-path sanity: non-denied groups grant exactly the mapped set.
    #[test]
    fn grants_resolve_without_deny() {
        let groups = vec!["devops".to_string()];
        let resolved =
            resolve_user_adapters("t1".to_string(), groups.clone(), DENY_FIXTURE.to_string());
        assert_eq!(resolved, vec!["a1".to_string(), "a2".to_string()]);

        let check = check_access(
            "t1".to_string(),
            groups,
            vec!["a1".to_string(), "a2".to_string()],
            DENY_FIXTURE.to_string(),
        );
        assert!(check.allowed);
        assert_eq!(check.denied_adapter_ids, Vec::<String>::new());
    }

    // -------------------------------------------------------------------
    // gap #3 — principal-kind partition (human vs agent/service)
    // -------------------------------------------------------------------

    const HUMAN_ONLY_FIXTURE: &str = r#"[
        {"tenantId":"t1","groupId":"finance","adapterIds":["ledger"],"principalScope":["human"]}
    ]"#;

    const UNSCOPED_FIXTURE: &str = r#"[
        {"tenantId":"t1","groupId":"devops","adapterIds":["a1","a2"]}
    ]"#;

    /// A mapping scoped to "human" must grant a human caller and DENY an
    /// agent caller holding the exact same group membership — this is the
    /// core Wiz 2 fix: an agent cannot silently inherit a human-only grant.
    #[test]
    fn human_only_mapping_denies_agent_grants_human() {
        let groups = vec!["finance".to_string()];

        let human_check = check_access_for_principal(
            "t1".to_string(),
            "human".to_string(),
            groups.clone(),
            vec!["ledger".to_string()],
            HUMAN_ONLY_FIXTURE.to_string(),
        );
        assert!(
            human_check.allowed,
            "human principal must be granted a human-scoped mapping"
        );

        let agent_check = check_access_for_principal(
            "t1".to_string(),
            "agent".to_string(),
            groups.clone(),
            vec!["ledger".to_string()],
            HUMAN_ONLY_FIXTURE.to_string(),
        );
        assert!(
            !agent_check.allowed,
            "agent principal must NOT inherit a human-only mapping"
        );
        assert_eq!(agent_check.denied_adapter_ids, vec!["ledger".to_string()]);

        let service_check = check_access_for_principal(
            "t1".to_string(),
            "service".to_string(),
            groups,
            vec!["ledger".to_string()],
            HUMAN_ONLY_FIXTURE.to_string(),
        );
        assert!(
            !service_check.allowed,
            "service principal must NOT inherit a human-only mapping"
        );
    }

    /// Legacy mappings with no `principalScope` field at all must keep
    /// granting to every principal kind exactly as before (back-compat).
    #[test]
    fn unscoped_mapping_grants_every_principal_kind() {
        for kind in ["human", "agent", "service"] {
            let resolved = resolve_user_adapters_for_principal(
                "t1".to_string(),
                kind.to_string(),
                vec!["devops".to_string()],
                UNSCOPED_FIXTURE.to_string(),
            );
            assert_eq!(
                resolved,
                vec!["a1".to_string(), "a2".to_string()],
                "unscoped mapping must grant principal kind '{kind}'"
            );
        }
    }

    /// An unrecognized principal_type value must fail closed (deny), never
    /// fall back to the most permissive interpretation.
    #[test]
    fn invalid_principal_type_fails_closed() {
        let check = check_access_for_principal(
            "t1".to_string(),
            "superuser".to_string(),
            vec!["devops".to_string()],
            vec!["a1".to_string()],
            UNSCOPED_FIXTURE.to_string(),
        );
        assert!(!check.allowed, "invalid principal_type must deny");
        assert!(check
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("Invalid principal_type"));

        let resolved = resolve_user_adapters_for_principal(
            "t1".to_string(),
            "superuser".to_string(),
            vec!["devops".to_string()],
            UNSCOPED_FIXTURE.to_string(),
        );
        assert!(
            resolved.is_empty(),
            "invalid principal_type must resolve to no adapters"
        );
    }

    /// principal_type matching is case-insensitive, mirroring the existing
    /// case-fold guarantee for group ids.
    #[test]
    fn principal_type_is_case_insensitive() {
        let check = check_access_for_principal(
            "t1".to_string(),
            "HUMAN".to_string(),
            vec!["finance".to_string()],
            vec!["ledger".to_string()],
            HUMAN_ONLY_FIXTURE.to_string(),
        );
        assert!(
            check.allowed,
            "principal_type must case-fold ('HUMAN' == 'human')"
        );
    }
}
