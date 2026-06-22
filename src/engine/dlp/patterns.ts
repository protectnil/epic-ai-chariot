/**
 * Gateway DLP — built-in pattern library
 *
 * Each pattern is conservative by design: prefers false negatives
 * (a real secret slips by) over false positives (legitimate data is
 * blocked). Operators tighten via DlpConfig.customRules with the
 * same id to override.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { DlpRule } from './types.js';

/**
 * Luhn validation for credit-card numbers. Strips non-digits before
 * checking. Returns true only for valid Luhn-passing 13–19 digit strings.
 */
export function luhnValid(input: string): boolean {
  const digits = input.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48; // '0' = 48
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export const BUILTIN_RULES: DlpRule[] = [
  {
    id: 'credit-card',
    label: 'Credit card number',
    // 13–19 digits with optional spaces or hyphens between groups.
    // Match boundaries are non-digit/non-hyphen so we don't hit longer numeric strings.
    pattern: /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g,
    validate: luhnValid,
  },
  {
    id: 'ssn-us',
    label: 'US Social Security Number',
    // XXX-XX-XXXX with SSA hard-invalid exclusions: area 000, area 666, group 00, serial 0000.
    // NOTE: The 9XX exclusion was removed. Since SSA Randomization launched in June 2011 the
    // agency no longer uses geographic area-number assignments, and SSNs with 9XX areas are
    // routinely issued. Excluding them produces false negatives on post-2011 SSNs (e.g.
    // 987-65-4321). The only universally invalid values are 000, 666, XX-00-XXXX, and
    // XXX-XX-0000, which are still excluded here.
    pattern: /\b(?!000|666)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    id: 'aws-access-key-id',
    label: 'AWS Access Key ID',
    // AKIA = long-term, ASIA = STS temp, AROA = role, AIDA = IAM user. All 16 alnum after.
    pattern: /\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b/g,
  },
  {
    id: 'aws-secret-access-key',
    label: 'AWS Secret Access Key',
    // 40-char base64-ish following an aws-style assignment. Anchored to context to
    // limit false-positives — bare 40-char strings are too common.
    pattern: /aws_secret_access_key["'\s:=]+([A-Za-z0-9/+=]{40})\b/gi,
  },
  {
    id: 'private-key-pem',
    label: 'Private key (PEM)',
    // PEM begin marker for any private key flavor:
    //   -----BEGIN PRIVATE KEY-----          (PKCS#8 unencrypted)
    //   -----BEGIN RSA PRIVATE KEY-----      (PKCS#1)
    //   -----BEGIN EC PRIVATE KEY-----       (SEC1 EC)
    //   -----BEGIN DSA PRIVATE KEY-----
    //   -----BEGIN OPENSSH PRIVATE KEY-----
    //   -----BEGIN PGP PRIVATE KEY BLOCK-----  (RFC 4880 — note completely different suffix)
    // Three alternations:
    //   1. RFC 4880 PGP form
    //   2. PKCS#8 encrypted form (ENCRYPTED PRIVATE KEY)
    //   3. Standard PEM `[RSA|EC|DSA|OPENSSH] PRIVATE KEY` form
    pattern: /-----BEGIN (?:PGP PRIVATE KEY BLOCK|ENCRYPTED PRIVATE KEY|(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----/g,
  },
  {
    id: 'jwt',
    label: 'JWT (signed)',
    // Three base64url segments separated by dots. Header begins with `eyJ` (the
    // base64url encoding of `{"`) so we anchor on that to skip random tri-segment hits.
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    id: 'github-pat',
    label: 'GitHub Personal Access Token',
    // ghp_ classic PAT, gho_ OAuth app token, ghu_ user-to-server, ghs_ server-to-server,
    // ghr_ refresh token, github_pat_ fine-grained PAT (launched 2022).
    // Fine-grained tokens use the github_pat_ prefix followed by ~93 base62 chars.
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g,
  },
  {
    id: 'stripe-secret-key',
    label: 'Stripe secret API key',
    // sk_test_… and sk_live_… (and rk_test_/rk_live_ restricted keys).
    // Stripe key bodies are 24+ alphanumerics. The bare-token form is the
    // common leak shape; the generic-api-key rule does NOT catch it.
    pattern: /\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{24,}\b/g,
  },
  {
    id: 'generic-api-key',
    label: 'Generic API key assignment',
    // `api_key`, `api-key`, `apikey`, `secret`, `token` followed by `=` or `:` and a
    // 16+ char value. Conservative: 16 chars to skip booleans/numerics.
    pattern: /\b(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token)["'\s]*[:=]\s*["']?([A-Za-z0-9_-]{16,})["']?/gi,
  },
  {
    id: 'gcp-service-account-key',
    label: 'GCP service account private key JSON marker',
    // GCP service-account JSON credentials always contain "private_key_id" and
    // "private_key" fields. Match the key-id field as a low-FP anchor.
    pattern: /"private_key_id"\s*:\s*"[A-Fa-f0-9]{40}"/g,
  },
  {
    id: 'azure-connection-string',
    label: 'Azure Storage / Service Bus connection string',
    // AccountKey= or SharedAccessKey= followed by base64-encoded 44-char or longer key.
    pattern: /(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{44,}={0,2}/g,
  },
  {
    id: 'slack-token',
    label: 'Slack API token',
    // xoxb- bot token, xoxp- user token, xoxs- service token, xoxa- app token,
    // xoxr- token rotation token. All followed by 10+ chars.
    pattern: /\bxox[bpsar]-[A-Za-z0-9-]{10,255}\b/g,
  },
  {
    id: 'twilio-credentials',
    label: 'Twilio Account SID or Auth Token',
    // Account SID: AC followed by 32 hex chars. Auth Token: 32 hex chars in an auth context.
    pattern: /\bAC[0-9a-fA-F]{32}\b/g,
  },
  {
    id: 'npm-token',
    label: 'npm access token',
    // npm tokens: UUID-style or the newer base64url format prefixed with `npm_`.
    // Classic: npm_[A-Za-z0-9]{36}. Legacy UUID: no prefix but in npm-specific contexts.
    pattern: /\bnpm_[A-Za-z0-9]{36,}\b/g,
  },
];
