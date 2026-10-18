/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: gold-set loader + validation
 *
 * Loads the curated, versioned, per-TOOL labeled gold set (§6.1) from disk,
 * validates its shape with Zod, and — critically — verifies every labeled tool
 * id actually exists in the production catalog. A gold set whose labels have
 * drifted off the catalog would silently deflate recall; this fails closed
 * instead.
 *
 * The gold set is private DATA, not code: it is read at
 * runtime via `readFileSync` (tsc does not copy JSON into dist), resolved from
 * the SOURCE tree relative to the package root, and overridable via
 * `CHARIOT_GOLD_SET_PATH`.
 *
 * Location rationale: the repo's `test/` tree is .gitignored and these evals
 * are served from a private companion repo. The SOURCE-tree path below
 * (`DEFAULT_GOLD_SET_PATH`) is a legacy local default retained ONLY for a
 * private checkout that has manually placed an untracked copy of the file
 * there; the compiled runner lives in `dist/`, but this path is always
 * resolved against `PKG_ROOT`'s `src/` tree, since tsc does not copy JSON.
 * The PUBLIC `protectnil/epic-ai-chariot` repository intentionally does NOT
 * track a copy at this path — TES spec (Chariot Test & Eval Specification,
 * the private TES spec (`protectnil/epic-ai`, `docs/spec/CHARIOT-TEST-EVAL-SPEC.md`)) §2.2 row 2 names the
 * gold set's sole durable home as `protectnil/epic-ai` at
 * `evals/chariot-routing/gold/gold-set.v1.json` (PRIVATE), and R2.2.4 forbids
 * admitting an eval artifact carrying a gold set to a public durable home. If
 * neither `CHARIOT_GOLD_SET_PATH` nor the legacy default path resolves to an
 * existing file, `loadGoldSet` fails closed with a message naming the durable
 * home and the env var to set — it does NOT fall through to a public-repo
 * default that structurally cannot carry this data (TES R3.1.4: recover from
 * the durable home; do not paper over an absent private artifact).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { GoldSet } from './types.js';

// dist/engine/eval/proof/gold.js → 4 levels up to package root.
const HERE = fileURLToPath(new URL('.', import.meta.url));
export const PKG_ROOT = join(HERE, '..', '..', '..', '..');

/**
 * Legacy local gold-set location. It is intentionally absent from the public
 * repository; private callers should set `CHARIOT_GOLD_SET_PATH`.
 */
export const DEFAULT_GOLD_SET_PATH = join(
  PKG_ROOT,
  'src',
  'engine',
  'eval',
  'proof',
  'gold',
  'gold-set.v1.json',
);

const queryStyle = z.enum(['natural-intent', 'paraphrase', 'brand-named', 'cross-domain']);

const goldQuerySchema = z.object({
  id: z.string().min(1),
  query: z.string().min(1),
  relevantToolIds: z.array(z.string().min(1)).min(1),
  domain: z.string().min(1),
  style: queryStyle,
  labelBasis: z.string().min(1),
  bugRef: z.string().optional(),
  pendingP4: z.boolean().optional(),
});

const goldSetMetaSchema = z.object({
  version: z.string().min(1),
  createdUtc: z.string().min(1),
  catalogEpoch: z.union([z.number(), z.string()]),
  catalogVersion: z.union([z.number(), z.string()]),
  methodology: z.string().min(1),
  derivationRules: z.array(z.string().min(1)).min(1),
  targetSize: z.number().int().positive(),
  notes: z.array(z.string()),
});

const goldSetSchema = z.object({
  meta: goldSetMetaSchema,
  queries: z.array(goldQuerySchema).min(1),
});

export interface GoldLoadResult {
  goldSet: GoldSet;
  path: string;
}

/** Parse + schema-validate a gold set from a JSON string. Throws on invalid shape. */
export function parseGoldSet(raw: string): GoldSet {
  const json: unknown = JSON.parse(raw);
  const parsed = goldSetSchema.parse(json);

  // Duplicate-id guard: ids must be unique so per-query results join cleanly.
  const seen = new Set<string>();
  for (const q of parsed.queries) {
    if (seen.has(q.id)) {
      throw new Error(`gold set: duplicate query id "${q.id}"`);
    }
    seen.add(q.id);
  }
  return parsed as GoldSet;
}

/**
 * Load + validate the gold set from disk (explicit arg → `CHARIOT_GOLD_SET_PATH`
 * → legacy local default). Fails closed with an actionable message — naming the
 * durable home and the env var to set — rather than a bare ENOENT, when no
 * candidate path resolves to an existing file. Per TES R2.2.4 / R3.1.4 this
 * function never treats the public repository's source tree as a place the
 * data can durably live; the legacy default is honored only when a file has
 * actually been placed there (untracked) by the caller.
 */
export function loadGoldSet(explicitPath?: string): GoldLoadResult {
  const path = explicitPath ?? process.env.CHARIOT_GOLD_SET_PATH ?? DEFAULT_GOLD_SET_PATH;
  if (!existsSync(path)) {
    throw new Error(
      `Chariot routing gold set not found at "${path}". This is PRIVATE data: ` +
        `TES spec (protectnil/epic-ai: docs/spec/CHARIOT-TEST-EVAL-SPEC.md) §2.2 row 2 ` +
        `names its sole durable home as "protectnil/epic-ai" at ` +
        `"evals/chariot-routing/gold/gold-set.v1.json" (PRIVATE); R2.2.4 forbids ` +
        `admitting an eval artifact carrying a gold set to the public ` +
        `"protectnil/epic-ai-chariot" repository, so no copy is tracked here. ` +
        `Set CHARIOT_GOLD_SET_PATH to that file in your private "epic-ai" ` +
        `checkout, e.g. ` +
        `CHARIOT_GOLD_SET_PATH=<private epic-ai checkout>/evals/chariot-routing/gold/gold-set.v1.json.`,
    );
  }
  const raw = readFileSync(path, 'utf-8');
  return { goldSet: parseGoldSet(raw), path };
}

export interface LabelValidation {
  ok: boolean;
  /** Tool ids referenced by the gold set that are absent from the catalog. */
  unknownLabels: Array<{ queryId: string; toolId: string }>;
  totalLabels: number;
}

/**
 * Verify every labeled tool id exists in the production catalog. This is the
 * defensibility gate for §6.1: a label that points at a non-existent tool is a
 * bug in the gold set, not a retriever miss.
 */
export function validateLabelsAgainstCatalog(
  goldSet: GoldSet,
  catalogToolIds: ReadonlySet<string>,
): LabelValidation {
  const unknownLabels: Array<{ queryId: string; toolId: string }> = [];
  let totalLabels = 0;
  for (const q of goldSet.queries) {
    for (const toolId of q.relevantToolIds) {
      totalLabels += 1;
      if (!catalogToolIds.has(toolId)) {
        unknownLabels.push({ queryId: q.id, toolId });
      }
    }
  }
  return { ok: unknownLabels.length === 0, unknownLabels, totalLabels };
}
