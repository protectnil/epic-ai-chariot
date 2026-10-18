#!/usr/bin/env node
/**
 * Reads `cargo metadata --format-version 1` JSON from stdin and writes the
 * flattened {name, version, license} inventory used by
 * generate-third-party-notices.mjs to build the Rust crate-graph section of
 * THIRD-PARTY-NOTICES.md.
 *
 * This is a point-in-time snapshot, not a live query: `cargo metadata` needs
 * either network access to the crates.io index or a warm local registry
 * cache, neither of which the release CI runner is guaranteed to have for
 * the `native/` crate graph (the Rust build for `native/` runs on separate
 * per-platform runners in release.yml's `build` job, not in `validate`).
 * Regenerate this file offline after any `native/Cargo.lock` change:
 *
 *   cd native && cargo metadata --offline --format-version 1 -q \
 *     | node ../scripts/extract-rust-license-inventory.mjs \
 *     > ../scripts/rust-license-inventory.generated.json
 *
 * `generate-third-party-notices.mjs --check` verifies the snapshot's crate
 * name+version set still matches native/Cargo.lock's; a mismatch means the
 * snapshot is stale and must be regenerated with the command above.
 */

import { readFileSync } from 'node:fs';

function readStdin() {
  return readFileSync(0, 'utf8');
}

function main() {
  const raw = readStdin();
  const metadata = JSON.parse(raw);
  const crates = metadata.packages
    .map((p) => ({
      name: p.name,
      version: p.version,
      license: p.license || (p.license_file ? `see ${p.license_file}` : null),
    }))
    .sort((a, b) => (a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name)));

  const out = {
    generatedFrom: 'cargo metadata --offline --format-version 1 (native/Cargo.lock)',
    generatedNote:
      'Point-in-time snapshot. Regenerate after any native/Cargo.lock change: ' +
      'cd native && cargo metadata --offline --format-version 1 -q | ' +
      'node ../scripts/extract-rust-license-inventory.mjs > ../scripts/rust-license-inventory.generated.json',
    crateCount: crates.length,
    crates,
  };
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

main();
