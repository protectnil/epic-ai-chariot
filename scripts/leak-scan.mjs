#!/usr/bin/env node
/**
 * Leak denylist scanner.
 *
 * Scans content line-by-line using the mirrored denylist patterns in
 * .leak-denylist/, with the same file-aware allowlist behavior as the
 * GitHub leak-pattern-check workflow and local pre-commit hook.
 */

import { existsSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const ALLOWED_FILES_REGEX = /^(LICENSE|LICENSE-APACHE|LICENSE-ELASTIC|LICENSE-ADAPTERS|NOTICE|TRADEMARK\.md)$/;
const RESTRICTED_BASENAMES = new Set(['LICENSE', 'LICENSE-APACHE', 'LICENSE-ELASTIC', 'LICENSE-ADAPTERS', 'NOTICE', 'TRADEMARK.md']);

function resolveDenylistDir() {
  // Explicit LEAK_DENYLIST_DIR wins when set (CI materializes the canonical
  // denylist there from a secret). A local untracked .leak-denylist/ is only
  // the fallback for developer machines, and must not shadow the override.
  const candidates = [
    process.env.LEAK_DENYLIST_DIR,
    join(REPO_ROOT, '.leak-denylist'),
    join(process.env.HOME || '', '.config', 'epicai-leak-denylist'),
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function loadPatterns(filePath) {
  if (!existsSync(filePath)) {
    return null;
  }
  const lines = readFileSync(filePath, 'utf-8').split(/\r?\n/);
  return lines.filter((line) => line.trim().length > 0 && !line.trimStart().startsWith('#'));
}

function collectFiles(inputPath) {
  const abs = resolve(process.cwd(), inputPath);
  if (!existsSync(abs)) {
    throw new Error(`Path not found: ${inputPath}`);
  }
  const out = [];
  const st = statSync(abs);
  if (st.isFile()) {
    out.push(abs);
    return out;
  }
  if (!st.isDirectory()) {
    return out;
  }
  const SKIP_DIRS = new Set(['.leak-denylist', 'node_modules', '.git']);
  const stack = [abs];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}

function shouldUseRestricted(filePath) {
  const base = basename(filePath);
  return RESTRICTED_BASENAMES.has(base);
}

function scanFile(filePath, fullRegexes, restrictedRegexes) {
  // Pre-compiled regexes are reused across every line. This matters because the
  // published catalog/bundle JSON are multi-hundred-thousand-line files; compiling
  // per line (old behavior) made scanning them prohibitively slow.
  const regexes = shouldUseRestricted(filePath) ? restrictedRegexes : fullRegexes;
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split(/\r?\n/);
  let matched = false;
  for (const [index, line] of lines.entries()) {
    for (const rx of regexes) {
      if (rx.test(line)) {
        console.error(`::error file=${filePath}::Leak pattern matched: ${line}`);
        console.error(`  line ${index + 1}: ${line}`);
        console.error(`  regex: ${rx.source}`);
        matched = true;
      }
    }
  }
  return matched;
}

function compilePatterns(patterns) {
  return patterns.map((pattern) => new RegExp(pattern));
}

function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== '--');
  if (args.length === 0) {
    console.error('Usage: node scripts/leak-scan.mjs <path> [<path> ...]');
    process.exit(2);
  }

  const denylistDir = resolveDenylistDir();
  if (!denylistDir) {
    console.error('::error::Canonical leak denylist not found in .leak-denylist/ or $LEAK_DENYLIST_DIR');
    process.exit(1);
  }

  const fullPatterns = loadPatterns(join(denylistDir, 'patterns.txt'));
  const restrictedPatterns = loadPatterns(join(denylistDir, 'patterns-restricted.txt'));
  if (!fullPatterns || !restrictedPatterns) {
    console.error(`::error::Missing denylist files in ${denylistDir}`);
    process.exit(1);
  }

  const fullRegexes = compilePatterns(fullPatterns);
  const restrictedRegexes = compilePatterns(restrictedPatterns);

  let failed = false;
  for (const inputPath of args) {
    for (const filePath of collectFiles(inputPath)) {
      if (scanFile(filePath, fullRegexes, restrictedRegexes)) {
        failed = true;
      }
    }
  }

  if (failed) {
    process.exit(1);
  }
}

main();
