/**
 * @epicai/chariot — interactive adapter picker (data/filter/tier layer)
 * for the setup wizard. CHARIOT-SPEC.md:1408 (§17.2 step 3): "interactive
 * picker, categorized, search, free/starter/scale tier prompts."
 * CHARIOT::§17.2::7 (categorized picker), ::8 (search), ::9 (tier prompts).
 *
 * MASTER ruling (rulings item 92, 2026-09-04): the "free/starter/scale"
 * tier is the CHARIOT LICENSE plan (CHARIOT-SPEC.md §11.1, line 1140:
 * `chariot-trial`, `chariot-starter`, `chariot-10`, `chariot-25`,
 * `chariot-50`, `chariot-100`, `chariot-premium` — `sign-license.ts:22-29`),
 * NOT a per-adapter pricing field (no such field exists on `AdapterEntry`
 * or the bundle schema). The picker reads the loaded license's `tier`
 * claim plus its `totalSeats` allowance (both independent optional claims
 * on `VerifiedClaims`, `src/license/loader.ts:498-513`) and DISPLAYS them
 * — it does not gate which adapters are selectable by tier, because the
 * license carries no per-adapter entitlement list to gate against.
 *
 * Data source: `loadAllAdapters()` (`src/engine/server/ChariotState.ts:999`)
 * — the SAME signed-bundle-backed catalog the running MCP server dispatches
 * against, so the picker can never drift from what's actually installable.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { AdapterEntry } from '../engine/server/ChariotState.js';
import {
  readLicenseEnvelope,
  verifyAndDecode,
  validateLicense,
  type LicenseMode,
} from '../license/loader.js';

// ─── Filter + group (CHARIOT::§17.2::7, ::8) ───────────────────────────────

export interface AdapterFilter {
  search?: string;
  category?: string;
}

function matchesSearch(a: AdapterEntry, needle: string): boolean {
  const hay = [a.id, a.name, a.description ?? '', ...(a.keywords ?? [])].join(' ').toLowerCase();
  return hay.includes(needle);
}

/**
 * CHARIOT::§17.2::8 — text-search filtering. Case-insensitive substring
 * match against id/name/description/keywords. An empty/whitespace-only
 * search is treated as "no filter" (returns all, after any category
 * filter), matching how an unfilled search box in the picker should behave.
 */
export function filterAdapters(all: AdapterEntry[], filter: AdapterFilter = {}): AdapterEntry[] {
  let out = all;
  if (filter.category) {
    out = out.filter((a) => a.category === filter.category);
  }
  const needle = filter.search?.trim().toLowerCase();
  if (needle) {
    out = out.filter((a) => matchesSearch(a, needle));
  }
  return out;
}

/**
 * CHARIOT::§17.2::7 — categorized display. Adapters with no `category`
 * are grouped under `'Uncategorized'` rather than dropped — every adapter
 * in `all` appears in exactly one group's list.
 */
export function groupByCategory(adapters: AdapterEntry[]): Map<string, AdapterEntry[]> {
  const groups = new Map<string, AdapterEntry[]>();
  for (const a of adapters) {
    const key = a.category && a.category.trim().length > 0 ? a.category : 'Uncategorized';
    const bucket = groups.get(key);
    if (bucket) bucket.push(a);
    else groups.set(key, [a]);
  }
  return groups;
}

// ─── License tier display (CHARIOT::§17.2::9) ──────────────────────────────

export interface LicenseTierInfo {
  mode: LicenseMode;
  /** The `tier` claim (e.g. `chariot-starter`) — null when unlicensed or the claim is absent. */
  tier: string | null;
  /** The `totalSeats` claim — the tier's seat allowance, when the producer set it. null when absent (the loader does not derive an allowance FROM the tier name; it only reads what the JWT carries). */
  totalSeats: number | null;
}

export interface LicenseTierInfoDeps {
  validateLicenseFn: () => { valid: boolean; mode: LicenseMode };
  readLicenseEnvelopeFn: () => { jwt: string; renewal_secret: string } | null;
  decodeFn: (jwt: string) => { tier?: string; totalSeats?: number } | null;
}

/**
 * Testable core: every dependency is injected, so a test can exercise
 * "no license file" / "expired signature" / "valid JWT with tier+seats" /
 * "valid JWT missing the optional tier/seats claims" without touching the
 * real filesystem or a real Ed25519 signature. Never throws — an
 * absent/invalid license (or a decodeFn that itself throws) yields
 * `mode:'unlicensed'`.
 */
export function getLicenseTierInfoFrom(deps: LicenseTierInfoDeps): LicenseTierInfo {
  try {
    const info = deps.validateLicenseFn();
    if (!info.valid) {
      return { mode: info.mode, tier: null, totalSeats: null };
    }
    const envelope = deps.readLicenseEnvelopeFn();
    if (!envelope) {
      return { mode: info.mode, tier: null, totalSeats: null };
    }
    const claims = deps.decodeFn(envelope.jwt);
    if (!claims) {
      return { mode: info.mode, tier: null, totalSeats: null };
    }
    return { mode: info.mode, tier: claims.tier ?? null, totalSeats: claims.totalSeats ?? null };
  } catch {
    return { mode: 'unlicensed', tier: null, totalSeats: null };
  }
}

const defaultLicenseTierInfoDeps: LicenseTierInfoDeps = {
  validateLicenseFn: validateLicense,
  readLicenseEnvelopeFn: readLicenseEnvelope,
  decodeFn: verifyAndDecode,
};

/**
 * Reads the currently-loaded license (if any) and returns the plan tier
 * name plus its seat allowance for display in the adapter-picker header —
 * "Licensed: chariot-25 (25 seats)" or "Unlicensed (free tier, 1 seat)".
 * `validateLicense()` alone (`LicenseInfo`) does not carry the `tier`
 * claim, so this reads the JWT claims directly via `verifyAndDecode()`.
 * Thin wrapper over `getLicenseTierInfoFrom()` with the real loader.ts
 * functions — see that function for the testable core.
 */
export function getLicenseTierInfo(): LicenseTierInfo {
  return getLicenseTierInfoFrom(defaultLicenseTierInfoDeps);
}
