/**
 * @epicai/chariot — CLI State and Config Persistence
 * adapter-state.json and config.json round-tripping.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { CONFIG_FILE, EPIC_AI_DIR, STATE_FILE, ensureDir } from './paths.js';
import type { AdapterState, ChariotConfig } from './types.js';
// Circular import: approval.ts imports loadState/saveState from this
// file. ESM handles this safely because the bindings are function
// references resolved lazily at call time, not consumed at module-init.
// reconcilePendingApprovals is a pure function on (state) that reads
// only APPROVAL_AUDIT_FILE — never calls back into loadState/saveState
// — so there is no recursion concern.
import { reconcilePendingApprovals } from './approval.js';

function freshState(): AdapterState {
  return { schemaVersion: 1, lastHealthCheck: null, adapters: {} };
}

// ─── Immutable AdapterState helpers ──────────────────────────────────────────
// loadState() returns the cached object by reference. Mutating that
// reference before saveState() would corrupt _stateCache.value if
// saveState() throws — the mutated object stays in the cache while
// disk content is unchanged, so the next loadState() returns a
// phantom. Every state-mutating call site MUST go through these
// helpers so the cached reference is never mutated in place.
// review-flagged.
export function upsertAdapterState(
  state: AdapterState,
  adapterId: string,
  entry: AdapterState['adapters'][string],
): AdapterState {
  return {
    ...state,
    adapters: {
      ...state.adapters,
      [adapterId]: entry,
    },
  };
}

export function removeAdapterState(state: AdapterState, adapterId: string): AdapterState {
  const { [adapterId]: _removed, ...adapters } = state.adapters;
  return { ...state, adapters };
}

export function withLastHealthCheck(state: AdapterState, ts: string): AdapterState {
  return { ...state, lastHealthCheck: ts };
}

// Shared "read+parse JSON, return null on any failure" helper. Used by
// loadConfig and chariot.ts:readLastRenewal so the existsSync /
// readFileSync / JSON.parse / catch-returns-null pattern isn't copy-
// pasted (R6-2 / R9-1). loadState has its own variant because it
// carries the mtime+size+ino cache and can't share this exact shape.
export function readJsonFile<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as T;
  } catch {
    return null;
  }
}

// mtime+size+ino gated in-memory cache. The dispatcher's AS §1.5 CLI
// approval gate calls loadState on every CLI tool call. The cache key
// is (mtimeMs, size, ino):
//   - mtimeMs alone: insufficient on HFS+ (1s) / FAT32 (2s) — two writes
//     within the FS resolution window share an mtime.
//   - + size: catches same-mtime writes that change file length.
//   - + ino: catches the rename-replace pattern that creates a new
//     inode at the same path with coincidentally identical mtime+size
//     (most filesystems assign new inodes monotonically, so this is
//     near-certain to differ when the file is replaced atomically).
let _stateCache: { mtimeMs: number; size: number; ino: number; value: AdapterState } | null = null;

export function loadState(): AdapterState {
  // E-5: single statSync replaces the prior existsSync+statSync pair.
  // Any stat failure (ENOENT, EACCES, EIO) collapses to "no usable
  // state file" → fresh state with cache cleared, matching prior
  // fail-closed semantics.
  let s: import('node:fs').Stats;
  try {
    s = statSync(STATE_FILE);
  } catch {
    _stateCache = null;
    return freshState();
  }
  try {
    if (_stateCache
        && _stateCache.mtimeMs === s.mtimeMs
        && _stateCache.size === s.size
        && _stateCache.ino === s.ino) {
      // review-flagged cache-hit reconcile gap: a cached
      // pending state would otherwise be returned forever if the final
      // saveState() of a 2PC tx failed (the file mtime/size/ino never
      // changed because the in-process saveState that would have moved
      // the chain forward never completed). reconcileAndCache walks
      // the audit chain whenever the cached state has any pending tx
      // and finalises (or rolls back) accordingly. When nothing is
      // pending, this is an O(N) Object.entries scan with no IO — the
      // dispatcher hot path lands here on most calls and pays only
      // that scan.
      return reconcileAndCache(_stateCache.value, s);
    }
    const parsed = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as AdapterState;
    return reconcileAndCache(parsed, s);
  } catch { /* fall through to fresh state on parse/IO failure */ }
  _stateCache = null;
  return freshState();
}

// review-prescribed 2PC reconcile entry point. Called by loadState on
// BOTH cache-hit and cache-miss paths so an in-flight tx that landed
// during a prior save cycle is always rolled forward or back before
// the value reaches the dispatcher.
//
// Returns same-reference state when reconcilePendingApprovals reports
// no change. When reconcile mutates, persist the new state via
// saveState (which also refreshes _stateCache to the reconciled
// value). On reconcile/save failure, cache the input state under the
// current stat key so the next call doesn't re-parse — safe at the
// dispatcher gate because the pending state has approvedAt=null and
// the gate trusts only committed approvedAt/approvedShapeHash.
function reconcileAndCache(state: AdapterState, s: import('node:fs').Stats): AdapterState {
  try {
    const reconciled = reconcilePendingApprovals(state);
    if (reconciled !== state) {
      saveState(reconciled);
      return reconciled;
    }
  } catch { /* reconcile best-effort; cache the un-reconciled state below */ }
  _stateCache = { mtimeMs: s.mtimeMs, size: s.size, ino: s.ino, value: state };
  return state;
}

export function saveState(state: AdapterState): void {
  ensureDir(EPIC_AI_DIR);
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  try {
    const s = statSync(STATE_FILE);
    _stateCache = { mtimeMs: s.mtimeMs, size: s.size, ino: s.ino, value: state };
  } catch {
    _stateCache = null;
  }
}

export function loadConfig(): ChariotConfig | null {
  return readJsonFile<ChariotConfig>(CONFIG_FILE);
}

export function saveConfig(config: ChariotConfig): void {
  ensureDir(EPIC_AI_DIR);
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}
