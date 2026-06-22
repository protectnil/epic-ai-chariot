/**
 * @epicai/chariot — CLI Paths and Filesystem Helpers
 * Canonical Chariot home directory and helpers shared by the outer CLI and engine setup.
 * EPIC_AI_DIR_OVERRIDE env var redirects the home for sandboxed unit tests.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { accessSync, constants as fsConstants, existsSync, mkdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const EPIC_AI_DIR = process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai');
export const ENV_FILE = join(EPIC_AI_DIR, '.env');
export const STATE_FILE = join(EPIC_AI_DIR, 'adapter-state.json');
export const CONFIG_FILE = join(EPIC_AI_DIR, 'config.json');
// AS §1.5 approval-action hash-chained audit log. Append-only JSONL;
// one record per `chariot approve` / `chariot revoke`. Each record's
// hash chains to the previous record so deletion / re-ordering is
// detectable. Lives alongside adapter-state.json under the per-user
// .epic-ai dir.
export const APPROVAL_AUDIT_FILE = join(EPIC_AI_DIR, 'approval-audit.jsonl');

export function ensureDir(dir: string = EPIC_AI_DIR): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function expandHome(p: string): string {
  return p.startsWith('~') ? join(homedir(), p.slice(1)) : p;
}

/**
 * Phase R.5: pure-Node, cross-platform PATH lookup. No subprocess, no shell.
 * Replaces the previous `which`-shelling implementation which (a) didn't work
 * on win32 and (b) had shell-injection surface even on POSIX.
 *
 * Returns the absolute path to the resolved binary, or null when not found.
 * Honors PATHEXT on win32 (.COM/.EXE/.BAT/.CMD by default). Requires an X_OK
 * check on POSIX so non-executable files on PATH don't false-positive.
 */
export function findOnPath(binary: string): string | null {
  const isWin = process.platform === 'win32';
  const sep = isWin ? ';' : ':';
  const pathDirs = (process.env.PATH ?? '').split(sep).filter(d => d.length > 0);
  const exts = isWin
    ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';')
    : [''];  // POSIX: try the bare name only
  for (const dir of pathDirs) {
    for (const ext of exts) {
      const candidate = join(dir, binary + ext);
      try {
        const st = statSync(candidate);
        if (!st.isFile()) continue;
        if (isWin) return candidate;
        try {
          accessSync(candidate, fsConstants.X_OK);
          return candidate;
        } catch { /* not executable; try next */ }
      } catch { /* doesn't exist; try next */ }
    }
  }
  return null;
}

export function commandExists(cmd: string): boolean {
  return findOnPath(cmd) !== null;
}
