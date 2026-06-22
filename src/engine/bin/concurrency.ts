/**
 * @epicai/chariot — bin/ concurrency + bundle-row helpers.
 *
 * Extracted so the .mjs one-shot script (stamp-bundle-integrity-2026-05.mjs)
 * and the TypeScript preinstall path can share the same primitives via the
 * compiled dist/ tree (same pattern the supply-chain eval framework already
 * uses for AuditTrail.js).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { freemem, totalmem } from 'node:os';
import type { AdapterEntry } from '../server/ChariotState.js';

export async function runConcurrent<T, R>(items: T[], fn: (item: T) => Promise<R>, concurrency: number): Promise<R[]> {
  const out: R[] = [];
  let next = 0;
  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, worker));
  return out;
}

/**
 * Per-warm-op memory budget. Each `npm pack <pkg>` drove a ~1.6 GB build in
 * the dogfood OOM self-incident (docs/incidents/dogfood-claude-4-OOM-self-incident-2026-05-29.md);
 * budget at 2 GB for headroom.
 */
const WARM_OP_MEMORY_BUDGET_BYTES = 2 * 1024 * 1024 * 1024;

/**
 * Memory-bounded concurrency for the STDIO pre-warm. The prior
 * hard-coded width of 8 fanned out to 8 concurrent `npm pack` ops (~1.6 GB
 * each) → ~13 GB peak, which exhausted swap and triggered a kernel OOM-kill
 * cascade on a 15 GB host. Cap concurrency to what currently-free memory can
 * hold at the per-op budget, clamped to [1, max]. Operators can override with
 * the CHARIOT_WARM_CONCURRENCY env var (a positive integer, still capped at max).
 */
export function warmConcurrency(max = 8): number {
  const override = Number(process.env.CHARIOT_WARM_CONCURRENCY);
  if (Number.isInteger(override) && override >= 1) return Math.min(override, max);
  const avail = freemem() || totalmem();
  const byMemory = Math.floor(avail / WARM_OP_MEMORY_BUDGET_BYTES);
  return Math.max(1, Math.min(max, byMemory));
}

/**
 * Resolve the stdio adapter's package name from `mcp.packageName` (preferred)
 * or by scanning `mcp.args` for the first non-flag positional. Returns null
 * when the adapter is not a stdio row or has no resolvable name.
 */
export function extractStdioPackageName(a: AdapterEntry): string | null {
  if (typeof a.mcp?.packageName === 'string' && a.mcp.packageName.length > 0) {
    return a.mcp.packageName;
  }
  if (Array.isArray(a.mcp?.args)) {
    const pkg = a.mcp.args.find((x): x is string => typeof x === 'string' && x.length > 0 && !x.startsWith('-'));
    if (pkg) return pkg;
  }
  return null;
}
