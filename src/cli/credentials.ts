/**
 * @epicai/chariot — CLI Credential Helpers
 * Read/write ~/.epic-ai/.env with mode 0600.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { closeSync, existsSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { ENV_FILE, EPIC_AI_DIR, ensureDir } from './paths.js';

const KEY_VALIDATION_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Canonical control-character regex for credential VALUES. Rejects:
 *   - C0 controls + NUL (\x00-\x1f) — TAB, CR, LF, ESC, etc.
 *   - DEL (\x7f)
 *   - C1 controls (\x80-\x9f) — non-printable in Latin-1 / Windows-1252
 *
 * Exported so every credential-writing path (writeCredential below;
 * src/bin/chariot.ts parseInlineCredentialFlags; src/engine/bin/setup.ts
 * cmdAdd + cmdConfigure prompt loops) checks the SAME byte set.
 * Splitting the literal across files reintroduces drift — any
 * relaxation must update this single source.
 *
 * Update 2026-05-27: external review flagged the original `[\r\n\0]`
 * as too narrow. Downstream env-file parsers behave non-deterministically
 * on TAB / ESC / C1 bytes (some truncate, some escape, some pass
 * through), producing silent credential corruption with no
 * runtime diagnostic.
 */
export const CREDENTIAL_VALUE_CONTROL_CHAR_RE = /[\x00-\x1f\x7f-\x9f]/;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Write or replace KEY=value in the user's `~/.epic-ai/.env` file.
 * Atomic: opens a tmp in the same directory with mode 0o600 from
 * O_CREAT, then renameSync — no chmod race. Rejects keys that don't
 * match standard env-var syntax and values containing \r, \n, or NUL
 * (the .env parser is line-based; an unescaped newline would re-parse
 * as a separate key).
 */
export function writeCredential(key: string, value: string): void {
  if (!KEY_VALIDATION_RE.test(key)) {
    throw new Error(`writeCredential: invalid key ${JSON.stringify(key)} (must match /^[A-Za-z_][A-Za-z0-9_]*$/)`);
  }
  // reject the FULL C0 + DEL + C1 control-character
  // range. CREDENTIAL_VALUE_CONTROL_CHAR_RE is exported for use by
  // upstream validators (parseInlineCredentialFlags in src/bin/chariot.ts,
  // setup.ts cmdAdd / cmdConfigure prompt loops) so all callers reject
  // the SAME byte set. writeCredential remains the canonical
  // enforcement point — every direct or transitive writer must clear
  // this check before bytes touch ~/.epic-ai/.env.
  if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(value)) {
    throw new Error(`writeCredential: value for ${key} contains a control character (NUL/CR/LF/TAB/ESC/C1) — env-file format requires printable bytes only`);
  }

  ensureDir(EPIC_AI_DIR);

  let existing = '';
  if (existsSync(ENV_FILE)) {
    existing = readFileSync(ENV_FILE, 'utf-8');
  }

  const lineRe = new RegExp(`^${escapeRegExp(key)}=.*$`, 'm');
  const next = lineRe.test(existing)
    ? existing.replace(lineRe, `${key}=${value}`)
    : (existing.endsWith('\n') || existing === '' ? existing : existing + '\n') + `${key}=${value}\n`;

  // Same-directory tmp so renameSync is a same-fs atomic rename.
  const tmpPath = `${ENV_FILE}.tmp.${process.pid}.${Date.now()}`;
  let fd: number | null = null;
  try {
    fd = openSync(tmpPath, 'wx', 0o600);
    writeSync(fd, next, 0, 'utf-8');
    closeSync(fd);
    fd = null;
    renameSync(tmpPath, ENV_FILE);
  } catch (err) {
    if (fd !== null) {
      try { closeSync(fd); } catch { /* fd already closed by error path */ }
    }
    try { unlinkSync(tmpPath); } catch { /* tmp file may not exist */ }
    throw err;
  }
}

export function parseEnvFile(content: string): Record<string, string> {
  const creds: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) creds[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return creds;
}

/**
 * First-party engine credential keys that must NEVER be forwarded into a
 * dispatched adapter subprocess (mcp.envKeys / mcp.authEnvKey / rest.envKey /
 * cli.envKeys / federation env). A poisoned catalog row could otherwise name
 * one and exfiltrate it. Matched by first-party NAMESPACE PREFIX — so new
 * engine keys are covered automatically and the specific internal backends are
 * not enumerated in public source — plus the two well-known shared LLM keys.
 * The engine reads its own secrets from process.env, never from this map, so
 * stripping them here is safe.
 */
const ENGINE_INTERNAL_EXACT = new Set<string>(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']);
const ENGINE_INTERNAL_PREFIX = /^(?:CHARIOT_|ENTERPRISE_|EPICAI_|DO_MODEL_)/;

/** True when `key` names a first-party engine-internal secret (case-insensitive). */
export function isEngineInternalCredentialKey(key: string): boolean {
  const k = key.trim().toUpperCase();
  return ENGINE_INTERNAL_EXACT.has(k) || ENGINE_INTERNAL_PREFIX.test(k);
}

export function loadCredentialsFrom(path: string): Record<string, string> {
  if (!existsSync(path)) return {};
  const creds = parseEnvFile(readFileSync(path, 'utf-8'));
  // Authoritative gate: strip engine-internal secrets from the credential map
  // so no dispatch path that reads state.credentials (stdio / docker / cli /
  // REST rest.envKey / streamable-http authEnvKey) can forward them.
  for (const key of Object.keys(creds)) {
    if (isEngineInternalCredentialKey(key)) delete creds[key];
  }
  return creds;
}

export function loadCredentials(): Record<string, string> {
  return loadCredentialsFrom(ENV_FILE);
}
