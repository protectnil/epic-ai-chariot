#!/usr/bin/env node
/**
 *  — Lint enforcement for the shortlist-size-policy.
 *
 * Spec: shortlist-size-policy-2026-05.md §3.4. Reviewed and approved.
 *
 * Scans src/**\/*.ts for `maxTools: <int>` literals. For any literal whose
 * value exceeds 12 (Adaline 10-12 ceiling per §1), requires the
 * justification comment `// shortlist-size: > 12 OK because <reason>` on
 * the same line or within the 5 immediately preceding lines.
 *
 * Exits 0 when every >12 literal carries the comment; exits 1 with a list
 * of unjustified violations otherwise. Maintains NO separate allowlist —
 * every >12 literal must be self-justified in the code so future call
 * sites cannot drift unnoticed.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = join(HERE, '..', 'src');
const JUSTIFICATION = 'shortlist-size: > 12 OK because';
const MAX_TOOLS_RE = /maxTools\s*:\s*(\d+)/g;
const PRECEDING_LINES_TO_SCAN = 5;

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...walk(p));
    else if (s.isFile() && p.endsWith('.ts')) out.push(p);
  }
  return out;
}

function checkFile(filepath) {
  const lines = readFileSync(filepath, 'utf-8').split('\n');
  const violations = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    MAX_TOOLS_RE.lastIndex = 0;
    let m;
    while ((m = MAX_TOOLS_RE.exec(line)) !== null) {
      const value = parseInt(m[1], 10);
      if (value <= 12) continue;
      const windowStart = Math.max(0, i - PRECEDING_LINES_TO_SCAN);
      let justified = false;
      for (let j = windowStart; j <= i; j++) {
        if (lines[j].includes(JUSTIFICATION)) { justified = true; break; }
      }
      if (!justified) violations.push({ file: filepath, line: i + 1, value });
    }
  }
  return violations;
}

const files = walk(SRC_ROOT);
const allViolations = files.flatMap(checkFile);

if (allViolations.length === 0) {
  console.log(`[lint-shortlist-size-cap] OK — scanned ${files.length} .ts files; no unjustified maxTools > 12 literals.`);
  process.exit(0);
}

console.error(`[lint-shortlist-size-cap] FAIL — ${allViolations.length} unjustified maxTools > 12 literal(s):`);
for (const v of allViolations) {
  console.error(`  ${v.file}:${v.line}  maxTools: ${v.value}`);
}
console.error('');
console.error('Each >12 literal must carry "// shortlist-size: > 12 OK because <reason>"');
console.error('on the same line or within the 5 immediately preceding lines.');
console.error('Spec: shortlist-size-policy-2026-05.md §3');
process.exit(1);
