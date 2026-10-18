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
// (CHARIOT::§8.5::7 durable restart-surviving store, not InMemoryStore;
// CHARIOT::§23.2::44-45 honest terminal outcome): durable file backing for the chariot_remember /
// chariot_recall / chariot_forget memory subsystem in the OSS single-user build.
// The tool surface advertises PERSISTENT memory, so the default store must
// survive a `serve` restart. Lives under the per-user .epic-ai dir alongside
// adapter-state.json (honors EPIC_AI_DIR_OVERRIDE). Enterprise deployments that
// inject a RedisMongoAdapter-backed PersistentMemory never touch this file.
export const MEMORY_FILE = join(EPIC_AI_DIR, 'memory.json');

// CHARIOT::§3.1::5 — "The system SHALL stage locally the retrieval
// artifacts (ONNX encoder, tokenizer, serializer corpus, manifest) under
// ~/.epic-ai/models/ (customer-owned, optional)." (CHARIOT-SPEC.md:188).
// Individual encoders (dense/splade/reranker) each need their own
// directory of ONNX + tokenizer files (readModelDir() in ChariotState.ts
// reads one model's bytes from one directory), so this is the ROOT the
// per-encoder subdirectories nest under — see ChariotState.ts's
// makeDiskArtifactSource for the dense/splade/reranker defaults.
export const MODELS_DIR = join(EPIC_AI_DIR, 'models');
// CHARIOT::§3.1::6 — "The system SHALL use ~/.epic-ai/qdrant/
// (customer-owned) as the bundled local Qdrant data directory, optional
// but required for persistence." (CHARIOT-SPEC.md:189). CHANGELOG.md's
// 4.0.0 "Changed" section documents `CHARIOT_QDRANT_DATA_DIR` as
// "repurposed as the in-process shard directory", but the actual
// in-process EdgeShard loader (ChariotState.ts makeDiskArtifactSource /
// loadShard) reads `CHARIOT_EDGE_SHARD_DIR`, a different env var name —
// see ChariotState.ts for how both env vars are honored ahead of this
// default.
export const QDRANT_DATA_DIR = join(EPIC_AI_DIR, 'qdrant');
// CHARIOT::§3.1::7 — "The system SHALL use ~/.epic-ai/cache/
// (Chariot-process-owned) for catalog and tool-schema cache, safe to
// delete." (CHARIOT-SPEC.md:190). See src/catalog/cache.ts for the
// read-through cache this directory backs.
export const CACHE_DIR = join(EPIC_AI_DIR, 'cache');
// CHARIOT::§3.1::8 — "The system SHALL write wizard and health-check
// logs to ~/.epic-ai/logs/ (Chariot-process-owned), with Loki-style
// emission also available." (CHARIOT-SPEC.md:191). See
// src/engine/logger.ts's `logFile` createLogger option.
export const LOGS_DIR = join(EPIC_AI_DIR, 'logs');

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
