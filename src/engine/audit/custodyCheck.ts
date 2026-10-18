/**
 * @epicai/chariot — Audit signing-key custody (MFA/RBAC) check (CHARIOT::§9.8.1::2)
 *
 * CHARIOT-SPEC.md §9.8.1 (docs/spec/CHARIOT-SPEC.md:899-906):
 *   "Key access MUST be gated by the same MFA and RBAC controls used for
 *   production database root credentials. An operator's compromise of the
 *   signing key is operationally equivalent to a compromise of the audit
 *   store's root credentials — treat the risk identically."
 *
 * gate finding F4 (2026-09-04): the first cut of this MUST logged the
 * calling principal on key use (chainSigner.ts `logKeyAccess`), but logging
 * is NOT proof of a gate — a log line records who signed, it does not
 * enforce that only MFA-authenticated, RBAC-scoped principals COULD sign.
 * This module is the application-enforced check the finding requires:
 * `createChainSigner()` calls the backend-appropriate function here in
 * enterprise mode and refuses to construct a signer if it fails. It is
 * also exposed standalone as `chariot audit custody-check` (any mode) so
 * an operator can run it as a diagnostic without touching a live signer.
 *
 * Backend-by-backend, what is and is NOT mechanically verifiable:
 *   - kms: `kms:GetKeyPolicy` is a real, queryable control-plane signal —
 *     every `Allow` statement covering `kms:Sign` on the key MUST carry an
 *     `aws:MultiFactorAuthPresent` boolean condition, or the check fails.
 *   - vault-transit: fully mechanical (2026-09-04 completion — the earlier
 *     revision of this module left the policy-body gap open; it is now
 *     closed). MFA login-enforcement (`identity/mfa/login-enforcement`,
 *     NOT `sys/mfa/...` — that is Enterprise step-up MFA, a different
 *     feature) must cover the signing token's own auth mount (resolved via
 *     `auth/token/lookup-self`'s `path` field -> `sys/auth`), AND the
 *     token's policies (`sys/policies/acl/<name>`, parsed for `path {
 *     capabilities }` blocks) must grant sign-only access to the
 *     configured key — no policy may additionally grant `delete` on the
 *     key or export capability. The one documented simplification: policy
 *     bodies are parsed with a targeted regex for the standard block
 *     shape, not a full HCL parser (`sudo`, Sentinel RGP/EGP composition
 *     are not modeled).
 *   - sealed-store: custody of `ENTERPRISE_MASTER_KEY` is who-holds-the-
 *     secret, not something this process has ANY API to query — bootstrap
 *     already fail-fast-validates the key's presence/shape (CHARIOT
 *     §18.3::1, CH-19) before this code can even run, but has no
 *     visibility into who is authorized to read/rotate it. Where a control
 *     plane cannot express the check at all, this module requires an
 *     explicit operator attestation (`CHARIOT_AUDIT_CUSTODY_ATTESTED=1`)
 *     rather than silently passing — the finding's own instruction: "the
 *     enterprise-mode signer must not construct silently without the check
 *     passing."
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { isEnterpriseModeRequested } from '../../iam/bootstrap.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

export type CustodyBackend = 'kms' | 'vault-transit' | 'sealed-store';

export interface CustodyCheckResult {
  backend: CustodyBackend;
  passed: boolean;
  /** false when the control plane has NO queryable signal this process can
   * check at all (sealed-store) — `passed` in that case reflects only
   * whether an explicit operator attestation was supplied, never an
   * actual verification. */
  checkable: boolean;
  reason: string;
}

export interface CustodyCheckDeps {
  kmsClientFactory?: (region: string | undefined) => {
    send: (cmd: unknown) => Promise<unknown>;
  };
  kmsGetKeyPolicyCommandCtor?: new (input: { KeyId: string; PolicyName: string }) => unknown;
  fetchImpl?: typeof fetch;
}

const KMS_SDK_MODULE_ID: string = '@aws-sdk/client-kms';

interface AwsKmsSdkForPolicy {
  KMSClient: new (cfg: { region?: string }) => { send(command: unknown): Promise<unknown> };
  GetKeyPolicyCommand: new (input: { KeyId: string; PolicyName: string }) => unknown;
}

interface KmsPolicyStatement {
  Sid?: string;
  Effect?: string;
  Action?: string | string[];
  Condition?: { Bool?: Record<string, string | boolean> };
}

/**
 * CHARIOT::§9.8.1::2 — every KMS key-policy statement that Allows `kms:Sign`
 * (or a wildcard covering it) MUST carry `Condition.Bool["aws:MultiFactorAuthPresent"] == "true"`.
 * A single ungated Allow statement means SOME principal can sign without
 * MFA, defeating the "gated the same as production DB root" requirement —
 * so this fails closed on the first ungated Sign-allowing statement found.
 */
export async function checkKmsCustody(keyId: string, region: string | undefined, deps: CustodyCheckDeps = {}): Promise<CustodyCheckResult> {
  let send: (cmd: unknown) => Promise<unknown>;
  let GetKeyPolicyCommandCtor: new (input: { KeyId: string; PolicyName: string }) => unknown;
  if (deps.kmsClientFactory && deps.kmsGetKeyPolicyCommandCtor) {
    send = deps.kmsClientFactory(region).send;
    GetKeyPolicyCommandCtor = deps.kmsGetKeyPolicyCommandCtor;
  } else {
    let mod: AwsKmsSdkForPolicy;
    try {
      mod = (await import(KMS_SDK_MODULE_ID)) as unknown as AwsKmsSdkForPolicy;
    } catch {
      return {
        backend: 'kms',
        passed: false,
        checkable: true,
        reason: "the optional '@aws-sdk/client-kms' package is not installed — cannot fetch the key policy to verify MFA gating.",
      };
    }
    const client = new mod.KMSClient(region ? { region } : {});
    send = (cmd: unknown) => client.send(cmd);
    GetKeyPolicyCommandCtor = mod.GetKeyPolicyCommand;
  }

  let policyJson: string | undefined;
  try {
    const out = (await send(new GetKeyPolicyCommandCtor({ KeyId: keyId, PolicyName: 'default' }))) as { Policy?: string };
    policyJson = out.Policy;
  } catch (err) {
    return { backend: 'kms', passed: false, checkable: true, reason: `kms:GetKeyPolicy failed: ${(err as Error).message}` };
  }
  if (!policyJson) {
    return { backend: 'kms', passed: false, checkable: true, reason: 'kms:GetKeyPolicy returned no Policy document.' };
  }

  let statements: KmsPolicyStatement[];
  try {
    const parsed = JSON.parse(policyJson) as { Statement?: KmsPolicyStatement | KmsPolicyStatement[] };
    statements = Array.isArray(parsed.Statement) ? parsed.Statement : parsed.Statement ? [parsed.Statement] : [];
  } catch (err) {
    return { backend: 'kms', passed: false, checkable: true, reason: `key policy is not valid JSON: ${(err as Error).message}` };
  }

  const signAllowStatements = statements.filter((s) => {
    if (s.Effect !== 'Allow') return false;
    const actions = Array.isArray(s.Action) ? s.Action : s.Action ? [s.Action] : [];
    return actions.some((a) => a === 'kms:Sign' || a === 'kms:*' || a === '*');
  });
  if (signAllowStatements.length === 0) {
    return {
      backend: 'kms',
      passed: false,
      checkable: true,
      reason: `no Allow statement for kms:Sign found in the key policy for ${keyId} — signing is not reachable by any principal, so MFA gating cannot be confirmed.`,
    };
  }
  const ungated = signAllowStatements.filter((s) => {
    const mfa = s.Condition?.Bool?.['aws:MultiFactorAuthPresent'];
    return !(mfa === 'true' || mfa === true);
  });
  if (ungated.length > 0) {
    return {
      backend: 'kms',
      passed: false,
      checkable: true,
      reason:
        `${ungated.length} of ${signAllowStatements.length} Allow-kms:Sign statement(s) on ${keyId} lack an ` +
        `aws:MultiFactorAuthPresent condition (Sid(s): ${ungated.map((s) => s.Sid ?? '(unnamed)').join(', ')}) — ` +
        'MFA is not enforced for every principal that can sign.',
    };
  }
  return {
    backend: 'kms',
    passed: true,
    checkable: true,
    reason: `all ${signAllowStatements.length} Allow-kms:Sign statement(s) on ${keyId} require aws:MultiFactorAuthPresent.`,
  };
}

/**
 * CHARIOT::§9.8.1::2 — Vault-side check, fully mechanical (no undocumented
 * gap): quoting developer.hashicorp.com/vault/api-docs/secret/identity/mfa/login-enforcement
 * — "creates or updates a login enforcement that specifies which MFA
 * methods should be used when logging into Vault" — login MFA enforcement
 * configurations live at `identity/mfa/login-enforcement` (LIST the
 * collection, READ each by name), NOT `sys/mfa/...` (that API is
 * Enterprise step-up MFA for individual paths, a different feature). Each
 * enforcement carries `mfa_method_ids`, `auth_method_accessors`, and
 * `auth_method_types`.
 *
 * `auth/token/lookup-self` does not return the token's auth-mount
 * accessor directly; it DOES return `data.path` (Vault's own doc:
 * "path — Path by which this token was created", e.g.
 * `auth/approle/login`). This check derives the mount (`approle/`) from
 * that path, looks it up in `sys/auth` (which maps mount path -> {type,
 * accessor}), and requires at least one login-enforcement whose
 * `auth_method_accessors` or `auth_method_types` covers that mount.
 * Per-identity enforcement (`identity_group_ids`/`identity_entity_ids`) is
 * out of scope for a service-token custody check and is not consulted.
 *
 * RBAC scope is verified by fetching each of the token's non-default/root
 * policies (`sys/policies/acl/<name>`) and parsing the returned ACL policy
 * text's `path "<pattern>" { capabilities = [...] }` blocks (regex-based —
 * not a full HCL parser; `sudo`/`deny`/Sentinel RGP composition are not
 * modeled, a documented simplification). PASSES only if:
 *   (a) some policy grants `update` or `create` on a path pattern that
 *       covers `transit/sign/<keyName>` (exact match, a trailing `*`
 *       glob, or Vault's `+` single-segment wildcard), AND
 *   (b) no policy grants `delete` on a pattern covering
 *       `transit/keys/<keyName>`, and no policy grants
 *       read/update/create on a pattern covering
 *       `transit/export/*`/`transit/export/.../<keyName>` — either would
 *       let the token destroy or exfiltrate the key material itself,
 *       exceeding "gated the same as production DB root" scoping.
 */
export async function checkVaultCustody(
  addr: string,
  token: string,
  keyName: string,
  deps: CustodyCheckDeps = {},
): Promise<CustodyCheckResult> {
  const doFetch = deps.fetchImpl ?? fetch;
  const base = addr.replace(/\/+$/, '');

  // ── token identity + policies ─────────────────────────────────────────
  let policies: string[] = [];
  let tokenPath: string | undefined;
  try {
    const selfResp = await doFetch(`${base}/v1/auth/token/lookup-self`, { headers: { 'X-Vault-Token': token } });
    if (!selfResp.ok) {
      return {
        backend: 'vault-transit',
        passed: false,
        checkable: true,
        reason: `auth/token/lookup-self failed: HTTP ${selfResp.status} — cannot confirm the signing token's RBAC scope.`,
      };
    }
    const selfJson = (await selfResp.json()) as { data?: { policies?: string[]; path?: string } };
    policies = selfJson.data?.policies ?? [];
    tokenPath = selfJson.data?.path;
  } catch (err) {
    return { backend: 'vault-transit', passed: false, checkable: true, reason: `auth/token/lookup-self failed: ${(err as Error).message}` };
  }

  const scopedPolicies = policies.filter((p) => p !== 'default' && p !== 'root');
  if (scopedPolicies.length === 0) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: `signing token carries only default/root polic(ies) (${policies.join(', ') || '(none)'}) — not scoped RBAC equivalent to production DB root controls.`,
    };
  }

  // ── MFA login-enforcement covers this token's auth mount ────────────────
  const enforcements = await fetchLoginEnforcements(base, token, doFetch);
  if (enforcements.length === 0) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: 'no MFA login-enforcement configuration found under identity/mfa/login-enforcement — MFA is not enforced for this Vault deployment.',
    };
  }
  const mount = await resolveAuthMount(base, token, doFetch, tokenPath);
  if (!mount) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: `could not resolve the signing token's auth mount from lookup-self path '${String(tokenPath)}' via sys/auth — cannot confirm MFA enforcement covers it.`,
    };
  }
  const mfaCovered = enforcements.some(
    (e) =>
      (mount.accessor && e.auth_method_accessors?.includes(mount.accessor)) ||
      (mount.type && e.auth_method_types?.includes(mount.type)),
  );
  if (!mfaCovered) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: `${enforcements.length} MFA login-enforcement configuration(s) exist, but none cover the signing token's auth mount (type=${String(mount.type)}, accessor=${String(mount.accessor)}).`,
    };
  }

  // ── policy body check: grants sign, does not grant broad key control ────
  let grantsSign = false;
  const signGrantedBy: string[] = [];
  const dangerousGrants: string[] = [];
  for (const p of scopedPolicies) {
    const rules = await fetchPolicyPaths(base, token, doFetch, p);
    for (const rule of rules) {
      if (vaultPathMatches(rule.pattern, `transit/sign/${keyName}`) && (rule.capabilities.includes('update') || rule.capabilities.includes('create'))) {
        grantsSign = true;
        signGrantedBy.push(`${p}:${rule.pattern}`);
      }
      if (vaultPathMatches(rule.pattern, `transit/keys/${keyName}`) && rule.capabilities.includes('delete')) {
        dangerousGrants.push(`${p}:${rule.pattern} grants delete on transit/keys/${keyName}`);
      }
      if (
        (rule.pattern === 'transit/export/*' || vaultPathMatches(rule.pattern, `transit/export/encryption-key/${keyName}`)) &&
        (rule.capabilities.includes('read') || rule.capabilities.includes('update') || rule.capabilities.includes('create'))
      ) {
        dangerousGrants.push(`${p}:${rule.pattern} grants export capability over ${keyName}`);
      }
    }
  }
  if (!grantsSign) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: `none of the token's scoped policies (${scopedPolicies.join(', ')}) grant update/create on a path covering transit/sign/${keyName}.`,
    };
  }
  if (dangerousGrants.length > 0) {
    return {
      backend: 'vault-transit',
      passed: false,
      checkable: true,
      reason: `a scoped policy grants broad key control beyond signing: ${dangerousGrants.join('; ')} — this exceeds production-DB-root-equivalent scoping.`,
    };
  }
  return {
    backend: 'vault-transit',
    passed: true,
    checkable: true,
    reason:
      `MFA login-enforcement covers the signing token's auth mount (type=${String(mount.type)}), and ${signGrantedBy.join(', ')} ` +
      `grants sign-only access to ${keyName} with no broader key-control capability.`,
  };
}

interface LoginEnforcement {
  name: string;
  mfa_method_ids?: string[];
  auth_method_accessors?: string[];
  auth_method_types?: string[];
}

async function fetchLoginEnforcements(base: string, token: string, doFetch: typeof fetch): Promise<LoginEnforcement[]> {
  let names: string[] = [];
  try {
    const listResp = await doFetch(`${base}/v1/identity/mfa/login-enforcement`, {
      method: 'LIST',
      headers: { 'X-Vault-Token': token },
    });
    if (listResp.ok) {
      const json = (await listResp.json()) as { data?: { keys?: string[] } };
      names = json.data?.keys ?? [];
    }
  } catch {
    return [];
  }
  const out: LoginEnforcement[] = [];
  for (const name of names) {
    try {
      const readResp = await doFetch(`${base}/v1/identity/mfa/login-enforcement/${encodeURIComponent(name)}`, {
        headers: { 'X-Vault-Token': token },
      });
      if (!readResp.ok) continue;
      const readJson = (await readResp.json()) as { data?: Omit<LoginEnforcement, 'name'> };
      out.push({ name, ...(readJson.data ?? {}) });
    } catch {
      // skip unreadable entries — they cannot vouch for MFA coverage either way
    }
  }
  return out;
}

/**
 * Resolve `auth/<mount>/...` (lookup-self's `path` field) to its
 * `sys/auth` entry ({type, accessor}). `sys/auth` keys mounts WITHOUT the
 * `auth/` prefix (e.g. `approle/`).
 */
async function resolveAuthMount(
  base: string,
  token: string,
  doFetch: typeof fetch,
  tokenPath: string | undefined,
): Promise<{ type?: string; accessor?: string } | undefined> {
  if (!tokenPath) return undefined;
  const parts = tokenPath.split('/').filter(Boolean);
  if (parts[0] !== 'auth' || !parts[1]) return undefined;
  const mountKey = `${parts[1]}/`;
  try {
    const authResp = await doFetch(`${base}/v1/sys/auth`, { headers: { 'X-Vault-Token': token } });
    if (!authResp.ok) return undefined;
    const authJson = (await authResp.json()) as { data?: Record<string, { accessor?: string; type?: string }> };
    return authJson.data?.[mountKey];
  } catch {
    return undefined;
  }
}

interface VaultPolicyPathRule {
  pattern: string;
  capabilities: string[];
}

/**
 * Vault ACL policies are returned as HCL text (`sys/policies/acl/<name>`,
 * `data.policy`). This is a targeted regex extractor for the standard
 * `path "<pattern>" { capabilities = [...] }` block shape — not a general
 * HCL parser; nested/computed values, `sudo`, `denied_parameters`, and
 * Sentinel RGP/EGP policies are not modeled (documented simplification).
 */
function parseAclPolicyPaths(hcl: string): VaultPolicyPathRule[] {
  const rules: VaultPolicyPathRule[] = [];
  const blockRe = /path\s+"([^"]+)"\s*\{([^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(hcl))) {
    const pattern = m[1];
    const body = m[2];
    const capMatch = /capabilities\s*=\s*\[([^\]]*)\]/.exec(body);
    const capabilities = capMatch
      ? capMatch[1]
          .split(',')
          .map((c) => c.trim().replace(/^"|"$/g, ''))
          .filter(Boolean)
      : [];
    rules.push({ pattern, capabilities });
  }
  return rules;
}

async function fetchPolicyPaths(base: string, token: string, doFetch: typeof fetch, name: string): Promise<VaultPolicyPathRule[]> {
  try {
    const resp = await doFetch(`${base}/v1/sys/policies/acl/${encodeURIComponent(name)}`, {
      headers: { 'X-Vault-Token': token },
    });
    if (!resp.ok) return [];
    const json = (await resp.json()) as { data?: { policy?: string } };
    if (!json.data?.policy) return [];
    return parseAclPolicyPaths(json.data.policy);
  } catch {
    return [];
  }
}

/** Vault ACL path-matching: exact, trailing `*` glob, or `+` single-segment wildcard. */
function vaultPathMatches(pattern: string, target: string): boolean {
  if (pattern === target) return true;
  if (pattern.endsWith('*')) {
    return target.startsWith(pattern.slice(0, -1));
  }
  const patParts = pattern.split('/');
  const tgtParts = target.split('/');
  if (patParts.length !== tgtParts.length) return false;
  return patParts.every((p, i) => p === '+' || p === tgtParts[i]);
}

/**
 * CHARIOT::§9.8.1::2 — sealed-store: there is no API this process can
 * query to determine who is authorized to read/rotate ENTERPRISE_MASTER_KEY
 * (bootstrap already fail-fast-validates the key's presence/shape at
 * startup — CHARIOT §18.3::1 / CH-19 — but that says nothing about MFA/RBAC
 * on ITS custody). `checkable: false` always — `passed` reflects only
 * whether the operator has explicitly attested the equivalent gate exists,
 * never an actual verification. Outside enterprise mode this check does
 * not apply (CHARIOT §18.2::1, single-user).
 */
export function checkSealedStoreCustody(): CustodyCheckResult {
  if (!isEnterpriseModeRequested()) {
    return {
      backend: 'sealed-store',
      passed: true,
      checkable: false,
      reason: 'single-user mode (CHARIOT_ENTERPRISE unset) — MFA/RBAC gating is not applicable (CHARIOT §18.2::1).',
    };
  }
  const attested = process.env.CHARIOT_AUDIT_CUSTODY_ATTESTED === '1';
  return {
    backend: 'sealed-store',
    passed: attested,
    checkable: false,
    reason: attested
      ? 'CHARIOT_AUDIT_CUSTODY_ATTESTED=1 — operator attests ENTERPRISE_MASTER_KEY custody is MFA/RBAC-gated ' +
        'equivalently to production DB root credentials. This process cannot verify that attestation; it is not ' +
        'a substitute for an actual audited control. See docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md.'
      : 'sealed-store custody (who can read/rotate ENTERPRISE_MASTER_KEY) has no API this process can query. Set ' +
        'CHARIOT_AUDIT_CUSTODY_ATTESTED=1 only after confirming the same MFA/RBAC gate protecting production DB ' +
        'root credentials also protects this key (CHARIOT §9.8.1::2). See docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md.',
  };
}
