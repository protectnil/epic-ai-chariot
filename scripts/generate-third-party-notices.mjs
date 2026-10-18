#!/usr/bin/env node
/**
 * Generates THIRD-PARTY-NOTICES.md at the repo root from three sources:
 *
 *   1. Production npm dependency licences, read directly from
 *      package-lock.json (lockfileVersion 3 records a `license` field per
 *      package entry). Filtered to `dev !== true` — this is the set that
 *      actually ships in the published npm package and the container image.
 *   2. The Rust `native/` crate graph, read from the point-in-time snapshot
 *      at scripts/rust-license-inventory.generated.json (see
 *      scripts/extract-rust-license-inventory.mjs for how it is produced;
 *      `cargo metadata` needs a warm registry cache or network access that
 *      the CI job generating this file does not have, so the crate graph is
 *      not re-derived live on every run).
 *   3. A hand-verified section for the bundled model and native-runtime
 *      artifacts that are not npm or crates.io packages at all (the SPLADE
 *      sparse encoder, the BIEN dense encoder, the vendored ONNX Runtime
 *      shared library). This section is static prose in this script, not
 *      derived from a manifest, because no machine-readable manifest for
 *      these artifacts exists yet.
 *
 * Usage:
 *   node scripts/generate-third-party-notices.mjs           # write the file
 *   node scripts/generate-third-party-notices.mjs --check   # verify only;
 *     exits 1 if the committed file would differ from a fresh run (stale
 *     notices) or if any dependency's licence is missing, "UNKNOWN", or on
 *     the deny list.
 *
 * Deny list (any match fails the run): AGPL-*, CC-BY-NC*, SSPL, UNLICENSED,
 * and a missing/blank/"UNKNOWN" licence field.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const OUT_PATH = resolve(REPO_ROOT, 'THIRD-PARTY-NOTICES.md');
const LOCKFILE_PATH = resolve(REPO_ROOT, 'package-lock.json');
const RUST_INVENTORY_PATH = resolve(REPO_ROOT, 'scripts', 'rust-license-inventory.generated.json');
const CARGO_LOCK_PATH = resolve(REPO_ROOT, 'native', 'Cargo.lock');

const DENY_PATTERNS = [/AGPL/i, /CC-BY-NC/i, /\bSSPL\b/i, /^UNLICENSED$/i];

function isDenied(license) {
  if (!license || license.trim() === '' || /^UNKNOWN$/i.test(license.trim())) {
    return { denied: true, reason: 'missing/UNKNOWN licence' };
  }
  for (const pattern of DENY_PATTERNS) {
    if (pattern.test(license)) {
      return { denied: true, reason: `matches deny-list pattern ${pattern}` };
    }
  }
  return { denied: false };
}

/** ---- 1. npm production dependencies, from package-lock.json ---- */

function loadNpmDependencies() {
  const lock = JSON.parse(readFileSync(LOCKFILE_PATH, 'utf8'));
  if (lock.lockfileVersion !== 3) {
    throw new Error(`Expected package-lock.json lockfileVersion 3, got ${lock.lockfileVersion}`);
  }
  const rows = [];
  for (const [key, entry] of Object.entries(lock.packages || {})) {
    if (key === '') continue; // the root project entry, not a dependency
    if (entry.dev) continue; // devDependencies never ship
    // The lockfile key is the node_modules path, e.g. "node_modules/@scope/name"
    // or "node_modules/a/node_modules/b" for a nested duplicate. The package
    // name is always the path segment(s) after the LAST "node_modules/".
    const idx = key.lastIndexOf('node_modules/');
    const name = key.slice(idx + 'node_modules/'.length);
    rows.push({
      name,
      version: entry.version || 'unknown',
      license: entry.license || null,
      optional: Boolean(entry.optional),
    });
  }
  rows.sort((a, b) => (a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name)));
  return rows;
}

/** ---- 2. Rust crate graph, from the committed snapshot ---- */

function loadRustCrates() {
  if (!existsSync(RUST_INVENTORY_PATH)) {
    throw new Error(`Missing ${RUST_INVENTORY_PATH} — see scripts/extract-rust-license-inventory.mjs`);
  }
  const snapshot = JSON.parse(readFileSync(RUST_INVENTORY_PATH, 'utf8'));
  return snapshot.crates;
}

/**
 * Best-effort drift check: confirm every crate name+version the snapshot
 * claims is still present in native/Cargo.lock, and vice versa. This does
 * NOT require the cargo toolchain — it parses native/Cargo.lock's own
 * `[[package]]` records — so it can run in --check on any host, including
 * this repo's CI runners that never invoke cargo.
 */
function checkRustSnapshotFreshness(rustCrates) {
  if (!existsSync(CARGO_LOCK_PATH)) {
    return { stale: false, reason: 'native/Cargo.lock not present in this checkout; skipping drift check' };
  }
  const text = readFileSync(CARGO_LOCK_PATH, 'utf8');
  const lockSet = new Set();
  const re = /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    lockSet.add(`${m[1]}@${m[2]}`);
  }
  const snapshotSet = new Set(rustCrates.map((c) => `${c.name}@${c.version}`));
  const missingFromSnapshot = [...lockSet].filter((k) => !snapshotSet.has(k));
  const extraInSnapshot = [...snapshotSet].filter((k) => !lockSet.has(k));
  if (missingFromSnapshot.length > 0 || extraInSnapshot.length > 0) {
    return {
      stale: true,
      reason:
        `native/Cargo.lock and scripts/rust-license-inventory.generated.json disagree. ` +
        `In Cargo.lock but not the snapshot: ${missingFromSnapshot.join(', ') || '(none)'}. ` +
        `In the snapshot but not Cargo.lock: ${extraInSnapshot.join(', ') || '(none)'}. ` +
        `Regenerate: cd native && cargo metadata --offline --format-version 1 -q | ` +
        `node ../scripts/extract-rust-license-inventory.mjs > ../scripts/rust-license-inventory.generated.json`,
    };
  }
  return { stale: false };
}

/** ---- 3. Static, hand-verified model/native-artifact section ---- */

const MODEL_ARTIFACTS_SECTION = `## Model and native artifacts

These artifacts are shipped with the product but are not npm or crates.io
packages, so they are not covered by an automated licence scan. Each entry
below states exactly what was verified and, where a fact could not be
verified from an on-disk, authoritative source, says so rather than
guessing.

### SPLADE sparse encoder

- **Identity (pinned):** \`prithivida/Splade_PP_en_v1\` — Apache-2.0, per its
  Hugging Face model card
  (https://huggingface.co/prithivida/Splade_PP_en_v1), described there as
  "Independent Implementation of SPLADE++ Model (a.k.a splade-cocondenser and
  family) for the Industry setting."
- **Shipped bytes (pinned):** the ONNX export at Hugging Face repo
  \`Qdrant/Splade_PP_en_v1\`, revision \`efcd182bc7eb351e81a9445752d4388c2bab500b\`
  (the export's own \`config.json\` records \`_name_or_path\`:
  \`prithivida/Splade_PP_en_v1\`, confirming it is an export of the pinned
  identity model, not a different model).
- **Licence: Apache-2.0.** Verified directly on the export repository
  (https://huggingface.co/Qdrant/Splade_PP_en_v1, fetched 2026-09-03), which
  carries the apache-2.0 licence tag and whose model card states: "ONNX port
  of prithivida/Splade_PP_en_v1 for text classification and similarity
  searches."

### BIEN dense encoder

- **Base model:** \`nomic-ai/nomic-embed-text-v1.5\` (Nomic AI, US), licensed
  **Apache-2.0** — its Hugging Face model card carries the \`apache-2.0\` licence
  tag (huggingface.co/nomic-ai/nomic-embed-text-v1.5, fetched 2026-09-03), and the
  BIEN specification's candidate table records the same (BIEN SPEC.md §3, verbatim:
  "| **Nomic-embed-text-v1.5** ✅ PRIMARY | Nomic AI (**US**) | **Apache-2.0** |
  137M | 768 / 8192 | LOCKED primary; long context; in fastembed-rs
  (\`NomicEmbedTextV15\`) |").
- **Shipped artifact:** a full fine-tune of that base model on this vendor's
  own tool-retrieval training data. The fine-tuned weights are this vendor's
  proprietary IP — they are not redistributed in source form, are encrypted
  and licence-gated inside the signed retrieval bundle, and are not
  separately open-sourced. The Apache-2.0 licence on the base model permits
  this: Apache-2.0 does not require derivative works (including fine-tunes)
  to be redistributed or relicensed.

### Tier-1 reranker

- **Model:** \`cross-encoder/ms-marco-MiniLM-L6-v2\` (sentence-transformers /
  cross-encoder project), the model identity \`ChariotState.ts\`'s
  \`SHIPPED_RERANKER_MODEL\` locks the shipped reranker artifact to
  (\`assertShippedRerankerModel\` aborts startup on any other value). **Licence:
  Apache-2.0.** Its Hugging Face model card
  (https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2, fetched
  2026-09-04) carries the \`apache-2.0\` licence tag.
- **Shipped artifact:** a bundle-exported ONNX conversion of that model
  (BIEN §16.5/§16.7 M10, \`export_metadata.json\` \`artifact_kind:
  "reranker"\`), not the upstream repository's own files verbatim — the
  Apache-2.0 licence permits this conversion/redistribution; it does not
  require relicensing.

### ONNX Runtime

- **Binding crate:** \`ort\` (native/Cargo.toml pins \`ort = "=2.0.0-rc.12"\`).
  Verified from the crate's own \`Cargo.toml\`: \`license = "MIT OR Apache-2.0"\`.
- **Native shared library (\`libonnxruntime.so\`):** loaded dynamically at
  runtime (\`ort\`'s \`load-dynamic\` feature — no build-time download; the
  container image supplies the shared library via the \`ONNXRUNTIME_DIR\`
  build argument). **Licence: MIT.** The upstream project's \`LICENSE\` file
  (https://github.com/microsoft/onnxruntime, fetched 2026-09-03) begins "MIT
  License / Copyright (c) Microsoft Corporation." No \`LICENSE\` or \`NOTICE\`
  file was found alongside the vendored \`libonnxruntime.so\` build available
  in the environment that generated this file, and this generator has no
  network access to independently query the upstream project at generation
  time, so the *exact upstream version* of the vendored build (and that its
  bytes match a genuine upstream release, not a fork) must still be recorded
  and confirmed at release time from the actual artifact shipped in
  \`\${ONNXRUNTIME_DIR}\`.
- **fastembed-rs** (native/Cargo.toml pins \`fastembed = "=5.17.2"\`, in-process
  dense + SPLADE encoder path): **Licence: Apache-2.0.** Verified from two
  independent sources for the pinned \`5.17.2\`: the vendored crate's own
  \`Cargo.toml\` declares \`license = "Apache-2.0"\`, and the crates.io
  registry metadata for the crate (fetched 2026-09-03; crates.io's newest
  listed version at fetch time was \`6.0.2\`, unrelated to the \`5.17.2\` this
  project pins) also reports \`license: "Apache-2.0"\` — the two sources
  agree. (Historical note: this project's own architecture documentation
  had separately flagged fastembed-rs as labelling itself inconsistently
  across distribution channels; that note is retained there as history, but
  is superseded here by the direct \`5.17.2\` verification above.)

### Qdrant Edge

- **Crate:** \`qdrant-edge\` (native/Cargo.toml pins \`qdrant-edge = "=0.7.2"\`),
  the in-process, embedded vector-search library (no separate server
  process). Verified from the crate's own \`Cargo.toml\`: \`license =
  "Apache-2.0"\`.
`;

/** ---- rendering ---- */

function renderNpmTable(rows) {
  const lines = ['| Package | Version | Licence |', '|---|---|---|'];
  for (const r of rows) {
    const marker = r.optional ? ' (optional)' : '';
    lines.push(`| ${r.name}${marker} | ${r.version} | ${r.license ?? 'UNKNOWN'} |`);
  }
  return lines.join('\n');
}

function renderLicenseCounts(rows) {
  const counts = new Map();
  for (const r of rows) {
    const key = r.license ?? 'UNKNOWN';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const entries = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const lines = ['| Licence | Count |', '|---|---|'];
  for (const [license, count] of entries) {
    lines.push(`| ${license} | ${count} |`);
  }
  return lines.join('\n');
}

function renderRustDirectDepsTable(rustCrates) {
  // Direct dependencies declared in native/Cargo.toml's [dependencies] +
  // [build-dependencies] tables (hand-verified against the file; kept as a
  // literal list here rather than parsed, since Cargo.toml's TOML dependency
  // table has too many shapes — version strings, path deps, feature objects
  // — to parse reliably without a TOML library, and this is a short, stable
  // list that changes only when native/Cargo.toml itself changes).
  const directDepNames = [
    'napi', 'napi-derive', 'serde', 'serde_json', 'ed25519-dalek', 'aes-gcm',
    'hkdf', 'sha2', 'chrono', 'base64', 'rand', 'unicode-normalization',
    'qdrant-edge', 'fastembed', 'ort', 'tokenizers', 'syn', 'regex',
    'walkdir', 'glob', 'libc', 'napi-build',
  ];
  const byName = new Map(rustCrates.map((c) => [c.name, c]));
  const lines = ['| Crate | Version | Licence |', '|---|---|---|'];
  for (const name of directDepNames) {
    const c = byName.get(name);
    if (!c) {
      lines.push(`| ${name} | NOT FOUND in snapshot | — |`);
      continue;
    }
    lines.push(`| ${c.name} | ${c.version} | ${c.license ?? 'UNKNOWN'} |`);
  }
  return lines.join('\n');
}

function renderRustFullTable(rustCrates) {
  const lines = ['| Crate | Version | Licence |', '|---|---|---|'];
  for (const c of rustCrates) {
    lines.push(`| ${c.name} | ${c.version} | ${c.license ?? 'UNKNOWN'} |`);
  }
  return lines.join('\n');
}

function render(npmRows, rustCrates) {
  const npmLicenseCounts = renderLicenseCounts(npmRows);
  const rustLicenseCounts = renderLicenseCounts(rustCrates);
  return `# Third-Party Notices

This file is generated by \`scripts/generate-third-party-notices.mjs\`. Do not
hand-edit it — run the generator instead. It lists every production
dependency shipped in this package and this repository's container image,
with the licence declared by each dependency's own package manifest, plus a
hand-verified section for the bundled model and native-runtime artifacts
that are not npm or crates.io packages.

## npm production dependencies

Source: \`package-lock.json\` (\`dev !== true\` entries only — this is exactly
the set that \`npm ci --omit=dev\` installs and that ships in the published
package and the container image).

**By licence:**

${npmLicenseCounts}

**Full list (${npmRows.length} packages):**

${renderNpmTable(npmRows)}

${MODEL_ARTIFACTS_SECTION}
## Rust crate graph (\`native/\`)

Source: a point-in-time snapshot at
\`scripts/rust-license-inventory.generated.json\`, produced offline via
\`cargo metadata --offline --format-version 1\` against \`native/Cargo.lock\`
(see \`scripts/extract-rust-license-inventory.mjs\`). \`cargo-license\` was not
available in the environment that produced this snapshot; \`cargo metadata\`
was used directly instead, which reports the same manifest \`license\` /
\`license_file\` field per crate.

**Direct dependencies** (from \`native/Cargo.toml\`):

${renderRustDirectDepsTable(rustCrates)}

**By licence (full transitive graph, ${rustCrates.length} crates):**

${rustLicenseCounts}

**Full transitive crate list (${rustCrates.length} crates):**

${renderRustFullTable(rustCrates)}
`;
}

/** ---- main ---- */

function main() {
  const check = process.argv.includes('--check');

  const npmRows = loadNpmDependencies();
  const rustCrates = loadRustCrates();

  const violations = [];
  for (const r of npmRows) {
    const v = isDenied(r.license);
    if (v.denied) violations.push(`npm ${r.name}@${r.version}: ${v.reason} (licence=${JSON.stringify(r.license)})`);
  }
  for (const c of rustCrates) {
    const v = isDenied(c.license);
    if (v.denied) violations.push(`rust ${c.name}@${c.version}: ${v.reason} (licence=${JSON.stringify(c.license)})`);
  }
  if (violations.length > 0) {
    console.error('THIRD-PARTY-NOTICES generation FAILED — deny-listed or missing licence(s):');
    for (const v of violations) console.error(`  - ${v}`);
    process.exit(1);
  }

  const freshness = checkRustSnapshotFreshness(rustCrates);
  if (freshness.stale) {
    console.error('THIRD-PARTY-NOTICES generation FAILED — Rust crate-license snapshot is stale:');
    console.error(`  ${freshness.reason}`);
    process.exit(1);
  }

  const content = render(npmRows, rustCrates);

  if (check) {
    if (!existsSync(OUT_PATH)) {
      console.error(`THIRD-PARTY-NOTICES.md does not exist at ${OUT_PATH}. Run without --check to generate it.`);
      process.exit(1);
    }
    const onDisk = readFileSync(OUT_PATH, 'utf8');
    if (onDisk !== content) {
      console.error('THIRD-PARTY-NOTICES.md is STALE — committed content does not match a fresh generation.');
      console.error('Run: node scripts/generate-third-party-notices.mjs');
      process.exit(1);
    }
    console.log(`THIRD-PARTY-NOTICES.md is up to date (${npmRows.length} npm packages, ${rustCrates.length} Rust crates).`);
    return;
  }

  writeFileSync(OUT_PATH, content);
  console.log(`Wrote ${OUT_PATH} (${npmRows.length} npm packages, ${rustCrates.length} Rust crates).`);
}

main();
