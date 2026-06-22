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

/// Check whether a user's groups grant access to the requested adapters.
///
/// `tenant_id`: the caller's tenant context. Mappings whose tenantId does
///   not equal this value cause the entire check to fail with `allowed: false`
///   and a non-empty `reason`. This is the native-layer defense against
///   a TS caller that accidentally constructs a cross-tenant mappings array.
/// `user_groups`: list of group IDs the user belongs to
/// `requested_adapter_ids`: adapter IDs being accessed
/// `mappings_json`: JSON array of { tenantId, groupId, adapterIds } mappings
#[napi]
pub fn check_access(
    tenant_id: String,
    user_groups: Vec<String>,
    requested_adapter_ids: Vec<String>,
    mappings_json: String,
) -> AccessResult {
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

    // Case-fold both sides before comparison. Mixed-case group ids
    // from an IdP (e.g. SAML 'DevOps' vs Okta 'devops') must map to
    // the same RBAC slot. Eval 28 P3 fast-check found that without
    // normalization, a mapping for 'finance' would NOT match a user
    // group 'Finance' even though the deny-precedence test relies on
    // case-insensitive matching.
    let user_group_set: HashSet<String> = user_groups.iter().map(|s| s.to_lowercase()).collect();
    let mut allowed_adapters: HashSet<String> = HashSet::new();

    // Single pass: accumulate allowed adapters while watching for explicit
    // deny. Deny-precedence: any mapping for a group the user holds with an
    // empty adapter_ids list is an explicit deny that overrides every
    // permissive mapping. Standard RBAC semantics — empty-grant means denied
    // for this adapter scope, not no-op.
    for mapping in &mappings {
        let mapping_group_lc = mapping.group_id.to_lowercase();
        if !user_group_set.contains(&mapping_group_lc) {
            continue;
        }
        if mapping.adapter_ids.is_empty() {
            return AccessResult {
                allowed: false,
                granted_adapter_ids: vec![],
                denied_adapter_ids: requested_adapter_ids,
                reason: Some("Explicit deny via empty adapter_ids in one of user's groups".to_string()),
            };
        }
        for adapter_id in &mapping.adapter_ids {
            allowed_adapters.insert(adapter_id.clone());
        }
    }

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
/// Returns an empty list on JSON parse error or when no in-tenant mappings
/// match. Use `check_access` if you need to distinguish parse error from
/// "no matching mappings".
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

    let user_group_set: HashSet<&str> = user_groups.iter().map(|s| s.as_str()).collect();
    let mut adapters: HashSet<String> = HashSet::new();

    for mapping in &mappings {
        if user_group_set.contains(mapping.group_id.as_str()) {
            for adapter_id in &mapping.adapter_ids {
                adapters.insert(adapter_id.clone());
            }
        }
    }

    let mut result: Vec<String> = adapters.into_iter().collect();
    result.sort();
    result
}
