#!/usr/bin/env node
/**
 * Epic AI® Chariot — Routing Proof-Artifact Eval: catalog introspection
 *
 * Dumps the production-faithful tool catalog (every `${server}:${name}` the
 * live full-catalog router indexes) so gold-set labels can be authored against
 * REAL, retrievable tool ids — never invented ones. Authoring aid only; not
 * part of the measured benchmark.
 *
 *   node dist/engine/eval/proof/dump-catalog.js            # summary
 *   node dist/engine/eval/proof/dump-catalog.js <server>   # one server's tools
 *   node dist/engine/eval/proof/dump-catalog.js --ids      # all ids (sorted)
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { loadProductionCatalog, toolIdOf } from './catalog.js';

async function main(): Promise<void> {
  const arg = process.argv[2];
  const { tools, toolIds, serverCount, adapterCount } = await loadProductionCatalog();

  if (arg === '--ids') {
    for (const id of [...toolIds].sort()) console.log(id);
    return;
  }

  if (arg && !arg.startsWith('--')) {
    const ids = tools
      .filter((t) => t.server === arg)
      .map(toolIdOf)
      .sort();
    console.log(`${arg}: ${ids.length} tools`);
    for (const id of ids) console.log(`  ${id}`);
    return;
  }

  console.log(`adapters kept:   ${adapterCount}`);
  console.log(`servers indexed: ${serverCount}`);
  console.log(`tool ids:        ${toolIds.size}`);
}

main().catch((err) => {
  console.error('dump-catalog failed:', err);
  process.exit(1);
});
