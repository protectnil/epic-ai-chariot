/**
 * @epicai/chariot — Update-availability notification (bug-tracker-ref)
 *
 * A customer on an outdated (or broken) version is never told a newer
 * release exists; this closes that gap for interactive CLI commands.
 *
 * Constraints honored:
 *   - Air-gap-safe and best-effort: any failure (no network, registry down,
 *     bad JSON, unwritable cache) is silent. A 2s abort caps latency.
 *   - At most one registry probe per 24h, cached in
 *     ~/.epic-ai/update-check.json; every other invocation compares against
 *     the cached `latest` with zero network traffic.
 *   - Opt-out via CHARIOT_NO_UPDATE_CHECK=1 for strict offline deployments.
 *   - Notification goes to stderr so piped stdout output stays clean.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { EPIC_AI_DIR, ensureDir } from '../../cli/paths.js';

const CACHE_PATH = join(EPIC_AI_DIR, 'update-check.json');
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REGISTRY_LATEST_URL = 'https://registry.npmjs.org/@epicai%2fchariot/latest';
const PROBE_TIMEOUT_MS = 2_000;

interface UpdateCheckCache { checkedAt?: number; latest?: string }

function parseSemver(v: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function isNewerVersion(latest: string, current: string): boolean {
  const l = parseSemver(latest);
  const c = parseSemver(current);
  if (!l || !c) return false;
  for (let i = 0; i < 3; i++) {
    if (l[i] !== c[i]) return l[i] > c[i];
  }
  return false;
}

/**
 * Check (cached, rate-limited) whether a newer @epicai/chariot exists and
 * print a one-line stderr notice if so. Never throws; never exits non-zero.
 */
export async function maybeNotifyUpdate(currentVersion: string): Promise<void> {
  try {
    if (process.env.CHARIOT_NO_UPDATE_CHECK) return;
    // Non-TTY stderr (the stream the notice is written to): we are being piped
    // or redirected — skip the notice so it does not pollute captured output
    // (e.g. `chariot list 2>logfile`).
    if (!process.stderr.isTTY) return;
    let cache: UpdateCheckCache = {};
    try {
      cache = JSON.parse(readFileSync(CACHE_PATH, 'utf-8')) as UpdateCheckCache;
    } catch {
      // no cache yet — first run
    }
    let latest = typeof cache.latest === 'string' ? cache.latest : '';
    const checkedAt = typeof cache.checkedAt === 'number' ? cache.checkedAt : 0;
    if (Date.now() - checkedAt > CHECK_INTERVAL_MS) {
      const res = await fetch(REGISTRY_LATEST_URL, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
      if (!res.ok) return;
      const body = (await res.json()) as { version?: unknown };
      if (typeof body.version !== 'string' || !parseSemver(body.version)) return;
      latest = body.version;
      ensureDir(EPIC_AI_DIR);
      writeFileSync(CACHE_PATH, JSON.stringify({ checkedAt: Date.now(), latest }), 'utf-8');
    }
    if (latest && isNewerVersion(latest, currentVersion)) {
      console.error(
        `\n  Update available: @epicai/chariot ${currentVersion} → ${latest}` +
        `\n  Run: npm install -g @epicai/chariot@latest   (set CHARIOT_NO_UPDATE_CHECK=1 to silence)\n`,
      );
    }
  } catch {
    // Best-effort by contract: air-gapped/offline hosts must see no error.
  }
}
