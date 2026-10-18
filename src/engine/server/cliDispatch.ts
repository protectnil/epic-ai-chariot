/**
 * @epicai/chariot — CLI-bridge subprocess primitives (AS §1.5)
 *
 * Shared by BOTH the MCP/REST dispatch path (toolHandlers.ts
 * handleCallInner Case 5) and the `chariot query` CLI path (bin/setup.ts
 * cmdQuery). Hoisted out of toolHandlers.ts so there
 * is exactly ONE spawn-with-timeout implementation and exactly ONE
 * credential-redaction regex set for CLI-bridge subprocess output —
 * before this split, `chariot query` had no cli-bridge branch at all
 *, and the fix must not re-fork the R.9(a) redaction / SIGTERM-
 * then-SIGKILL timeout behavior into a second, driftable copy.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';

/**
 * Phase R.5 §3: minimal allowlist of host env vars passed into a CLI-bridge
 * subprocess. Layered with per-adapter `cli.envKeys` credentials. No spread
 * of `process.env` — nothing else from Chariot's parent env leaks into the
 * subprocess.
 */
export const CLI_BASE_ENV_ALLOWLIST = ['PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'TEMP', 'TMP'] as const;

/**
 * Default stderr capture cap for a CLI-bridge subprocess. Independent of
 * the (much larger) stdout budget — stderr is only ever surfaced as a
 * sliced error excerpt, never as the primary tool result.
 */
export const CLI_STDERR_CAP_BYTES = 16_384;

/**
 * Phase R.5 §6: redact known credentials and common credential-shape patterns
 * from CLI stderr/stdout before returning to the caller. Stderr is the most
 * common leak surface for vendor CLIs that echo bad-credential errors.
 *
 * Redaction ONLY — no size capping. Size budgets are enforced separately by
 * the caller (toolHandlers.ts capCallResult; cmdQuery has no analogous cap
 * today — see spawnWithTimeout's stdout byte cap below for the subprocess-
 * read-side budget).
 */
export function redactStderr(stderr: string, knownCreds: string[]): string {
  let redacted = stderr;
  for (const cred of knownCreds) {
    if (cred.length > 0) {
      redacted = redacted.split(cred).join('<REDACTED>');
    }
  }
  redacted = redacted
    .replace(/\b(ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{20,}/g, '<REDACTED_GH>')
    .replace(/\bglpat-[A-Za-z0-9_-]{20,}/g, '<REDACTED_GITLAB>')
    .replace(/\bsk_(test|live)_[A-Za-z0-9]{20,}/g, '<REDACTED_STRIPE>')
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '<REDACTED_AWS>')
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '<REDACTED_JWT>')
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/g, '<REDACTED_PEM>')
    .replace(/\b[A-Za-z0-9._-]+@[A-Za-z0-9-]+\.iam\.gserviceaccount\.com\b/g, '<REDACTED_GCP_SA>');
  return redacted;
}

/**
 * Phase R.5 §9: spawn a subprocess with a hard wall-clock timeout. SIGTERM
 * first; escalate to SIGKILL after a 2 000 ms grace. Resolves with the
 * captured stdout/stderr/exitCode; rejects with `CLI_TIMEOUT` after the
 * timeout elapses.
 *
 * `maxStdoutBytes` / `maxStderrBytes` are caller-supplied (not a module
 * constant) so each call site names its own budget from ITS OWN canonical
 * source — toolHandlers.ts passes its exported `MAX_RESPONSE_BYTES` +
 * `CLI_STDERR_CAP_BYTES`; cmdQuery does the same — rather than this module
 * silently hardcoding a second copy of that number.
 */
export async function spawnWithTimeout(
  binary: string,
  argv: string[],
  env: Record<string, string>,
  timeoutMs: number,
  maxStdoutBytes: number,
  maxStderrBytes: number = CLI_STDERR_CAP_BYTES,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, argv, {
      env,
      cwd: tmpdir(),
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout?.on('data', (chunk: Buffer) => {
      if (stdoutBytes >= maxStdoutBytes) return;
      stdoutBytes += chunk.length;
      stdout += chunk.toString('utf-8');
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderrBytes >= maxStderrBytes) return;
      stderrBytes += chunk.length;
      stderr += chunk.toString('utf-8');
    });
    let resolved = false;
    const settle = (fn: () => void) => { if (!resolved) { resolved = true; fn(); } };
    const sigtermTimer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* already dead */ }
      const sigkillTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* already dead */ }
        settle(() => reject(new Error('CLI_TIMEOUT')));
      }, 2_000);
      sigkillTimer.unref();
    }, timeoutMs);
    sigtermTimer.unref();
    child.on('error', (err) => {
      clearTimeout(sigtermTimer);
      settle(() => reject(err));
    });
    child.on('close', (exitCode) => {
      clearTimeout(sigtermTimer);
      settle(() => resolve({ stdout, stderr, exitCode: exitCode ?? -1 }));
    });
  });
}
