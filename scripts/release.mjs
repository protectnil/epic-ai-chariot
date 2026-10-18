#!/usr/bin/env node
// EXPORTED API: stripInternalTelemetry is re-exported at the very bottom
// of this file so test/release-pipeline.mjs and
// test/manifest-prepublish-gate.mjs can exercise the strip + verification
// logic against a fixture dist tree without invoking the full pipeline
// (which requires a clean git tree, signing keys, npm credentials, etc).
//
/**
 * Enforced release pipeline for @epicai/chariot.
 *
 * Two modes:
 *
 *   MERGE MODE (CI per-platform job):
 *     node scripts/release.mjs --mode merge \
 *       --key <pem> --platform linux-x64=native/chariot-native.node
 *
 *     Signs one platform hash and merges it into the manifest.
 *     Does NOT run coverage verification (other platforms may not exist yet).
 *     Does NOT publish.
 *
 *   FINAL MODE (CI publish job or local release):
 *     node scripts/release.mjs --mode final \
 *       --key <pem> [--platform ...] [--publish]
 *
 *     Enforced sequence (no step can be skipped):
 *       1. Verify clean git state (no uncommitted or untracked files)
 *       2. Build TypeScript
 *       3. Typecheck
 *       4. Sign integrity manifest (if --platform provided)
 *       5. Verify manifest coverage + freshness (all platforms required)
 *       6. Run full test suite
 *       7. Publish (only if --publish flag is passed)
 *
 * RECURSION GUARD: This script sets CHARIOT_RELEASE_ACTIVE=1 before
 * running npm test (step 6). test/release-pipeline.mjs checks this
 * env var and skips when set, preventing infinite recursion where
 * npm test → release-pipeline.mjs → release.mjs → npm test → ...
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, renameSync, unlinkSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { imageDigestRef, notationSignCommand, notationVerifyCommand } from './image-seal.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

/**
 * Run a subprocess with an argv array (no shell interpolation).
 * Fails the pipeline on non-zero exit.
 */
function runArgv(label, file, args) {
  console.log(`\n  [${label}]`);
  try {
    execFileSync(file, args, { cwd: ROOT, stdio: 'inherit', timeout: 300_000 });
    console.log(`  [${label}] PASSED`);
  } catch {
    console.error(`  [${label}] FAILED`);
    process.exit(1);
  }
}

/**
 * Walk dist/ recursively, strip @chariot-internal-telemetry-begin..end
 * blocks from every .js file, and verify the stripped output is clean.
 *
 * Sentinel pair (both in /* *​/ comment form so the TypeScript compiler
 * preserves them verbatim through dist/):
 *   /​* @chariot-internal-telemetry-begin *​/
 *   ...code to strip...
 *   /​* @chariot-internal-telemetry-end *​/
 *
 * Imports MUST live inside the sentinel pair so the strip also removes
 * them — otherwise the public tarball ships an unused mongodb import
 * and the air-gap promise leaks at runtime through the require graph.
 *
 * Verification rules applied AFTER strip:
 *   - no occurrence of either sentinel string
 *   - no occurrence of any token from the FORBIDDEN_TOKENS list
 *   - any file modified by strip must be smaller than its original
 */
const SENTINEL_BEGIN = '@chariot-internal-telemetry-begin';
const SENTINEL_END = '@chariot-internal-telemetry-end';
const FORBIDDEN_TOKENS = [
  '__chariotWriteDispatchEvent',
  '__chariotInitDispatchEvents',
  '__chariotDispatchEventsCol',
  '__chariotDispatchEventsClient',
  '__chariotDispatchEventsInitFailed',
  '__chariotClassifyTelemetryOutcome',
  'CHARIOT_INTERNAL_TELEMETRY',
  'CHARIOT_INTERNAL_TELEMETRY_MONGODB_URI',
  'CHARIOT_INTERNAL_TELEMETRY_DB',
  // Defense-in-depth: type-only symbols can leak through .d.ts emission
  // even when sentinels are stripped from .js. The scan covers both.
  'DispatchEventDoc',
  '__dispatchStartMs',
  '__dispatchTenantId',
  '__latencyClamped',
  '__retriesClamped',
];

function stripInternalTelemetry(distRoot) {
  // ATOMIC 2-PASS DESIGN: validate the whole tree first; only write if
  // every file validates. Without this, a malformed sentinel in a later
  // file leaves dist/ partially rewritten while the publish gate fails —
  // a failed prepublish run becomes non-idempotent and contaminates
  // subsequent local builds.
  //
  // Pass 1 (validate + plan): walk all files, run the regex + token
  // checks, accumulate planned writes in memory + offenders separately.
  // Pass 2 (commit): only fires when offenders is empty.
  let filesScanned = 0;
  let filesModified = 0;
  let filesDeleted = 0;
  let totalBlocksStripped = 0;
  const offenders = [];
  const plannedWrites = []; // [{ path, stripped, blocksRemoved }]
  const plannedDeletes = []; // map files containing forbidden tokens

  function walk(dir) {
    for (const entry of readdirSync(dir)) {
      const full = resolve(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (entry.endsWith('.js.map') || entry.endsWith('.d.ts.map')) {
        // Source maps embed sourcesContent (the original .ts source) plus
        // mappings that reference the post-build .js. Either can leak the
        // internal-telemetry tokens even when the .js scan passes. Maps
        // are debug-only artifacts; deletion is safe for the public
        // tarball. Scan + plan deletion if any FORBIDDEN_TOKEN or sentinel
        // appears (the sentinel scan catches the verbatim source-block).
        filesScanned++;
        const mapSrc = readFileSync(full, 'utf-8');
        let hasLeak = mapSrc.includes(SENTINEL_BEGIN) || mapSrc.includes(SENTINEL_END);
        if (!hasLeak) {
          for (const tok of FORBIDDEN_TOKENS) {
            if (mapSrc.includes(tok)) { hasLeak = true; break; }
          }
        }
        if (hasLeak) plannedDeletes.push(full);
      }
      else if (entry.endsWith('.js') || entry.endsWith('.d.ts')) {
        filesScanned++;
        const src = readFileSync(full, 'utf-8');
        const beginCount = (src.match(new RegExp(SENTINEL_BEGIN, 'g')) || []).length;
        const endCount = (src.match(new RegExp(SENTINEL_END, 'g')) || []).length;
        if (beginCount !== endCount) {
          offenders.push(`${full}: unmatched sentinel markers (begin=${beginCount} end=${endCount}) — malformed source, strip cannot proceed`);
          continue;
        }
        if (beginCount === 0) {
          // Even files without sentinels must not contain forbidden tokens.
          for (const tok of FORBIDDEN_TOKENS) {
            if (src.includes(tok)) {
              offenders.push(`${full}: contains forbidden token "${tok}" outside any sentinel pair`);
            }
          }
          continue;
        }
        // Strip every sentinel-pair block.
        //
        // Anchored opener: the comment MUST start with `/*` then optional
        // whitespace then the begin token. Without this anchor the regex
        // overshoots and consumes any preceding `/*` (e.g. file-header
        // JSDoc). Two supported forms:
        //   (a) single comment: `/* <begin> ... <end> */`
        //   (b) sentinel-pair:  `/* <begin> */ <code> /* <end> */`
        const re = /\/\*\s*@chariot-internal-telemetry-begin[\s\S]*?@chariot-internal-telemetry-end[\s\S]*?\*\//g;
        const stripped = src.replace(re, '/* internal-telemetry: stripped */');
        const blocksRemoved = (src.match(re) || []).length;
        if (blocksRemoved !== beginCount) {
          offenders.push(`${full}: sentinel-marker count mismatch — ${beginCount} begin/end pairs but only ${blocksRemoved} regex matches (malformed nesting or marker inside string literal)`);
          continue;
        }
        if (stripped === src) continue;
        // Post-strip validation
        if (stripped.includes(SENTINEL_BEGIN) || stripped.includes(SENTINEL_END)) {
          offenders.push(`${full}: still contains a sentinel after strip — pair mismatch or unclosed block`);
          continue;
        }
        for (const tok of FORBIDDEN_TOKENS) {
          if (stripped.includes(tok)) {
            offenders.push(`${full}: still contains "${tok}" after strip — token escaped the sentinel block`);
          }
        }
        if (stripped.length >= src.length) {
          offenders.push(`${full}: strip did not reduce file size (${src.length} → ${stripped.length}) — sentinel block was empty or malformed`);
        }
        plannedWrites.push({ path: full, stripped, blocksRemoved });
      }
    }
  }
  walk(distRoot);

  if (offenders.length > 0) {
    console.error('  STRIP VERIFICATION FAILED (no files written):');
    for (const o of offenders) console.error(`    ${o}`);
    console.log(`  files_scanned=${filesScanned} files_modified=0 blocks_stripped=0 (validation pass aborted before write)`);
    process.exit(1);
  }

  // Pass 2: commit all planned writes atomically (per-file atomic via
  // .tmp + rename; cross-file atomicity guaranteed by the all-pass
  // validation above). Map files identified as leaking are deleted —
  // they are debug-only artifacts and safe to omit from the public
  // tarball.
  for (const { path, stripped, blocksRemoved } of plannedWrites) {
    const tmp = `${path}.strip.tmp`;
    writeFileSync(tmp, stripped, 'utf-8');
    renameSync(tmp, path);
    filesModified++;
    totalBlocksStripped += blocksRemoved;
  }
  for (const path of plannedDeletes) {
    unlinkSync(path);
    filesDeleted++;
  }
  console.log(`  files_scanned=${filesScanned} files_modified=${filesModified} files_deleted=${filesDeleted} blocks_stripped=${totalBlocksStripped}`);
}

// ── Exported for tests ───────────────────────────────────────────────────
// Tests import { stripInternalTelemetry } from this file and exercise the
// strip + verification logic against a fixture dist tree without
// triggering the full pipeline (which requires clean git, signing keys,
// npm creds). The pipeline body below runs only when this script is the
// process entrypoint.
export { stripInternalTelemetry };

/**
 * Compute the immutable container image tag from the package version (CH-26).
 * Format: `chariot-vX.Y.Z`. Refuses a missing / non-semver / `latest` version
 * so a mutable or unversioned tag can never be emitted into a release. The
 * container build pipeline uses this as the single source of truth for the tag:
 *   TAG=$(node scripts/release.mjs --emit-image-tag)
 */
export function imageTag(version) {
  const v = typeof version === 'string' ? version.trim() : '';
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v)) {
    throw new Error(
      `release: refusing to emit image tag for invalid version "${version}" — expected semver X.Y.Z (CH-26).`
    );
  }
  return `chariot-v${v}`;
}

// imageDigestRef is re-exported from image-seal.mjs (single source of truth for
// digest-pinned refs) — imported above, re-exported here, and used internally by
// the --emit-image-ref entrypoint (CH-54). No wrapper indirection.
export { imageDigestRef };

const __thisFilePath = fileURLToPath(import.meta.url);
const __invokedFilePath = process.argv[1] ? resolve(process.argv[1]) : '';
const IS_MAIN = __invokedFilePath === __thisFilePath;
if (!IS_MAIN) {
  // Imported by a test or another module — skip the pipeline.
  // Use process.exit at this point would leak out of the importer's flow,
  // so we just stop module evaluation by guarding the rest of the file
  // behind IS_MAIN below.
}

function usage() {
  console.error('Usage:');
  console.error('  Merge mode (CI per-platform):');
  console.error('    node scripts/release.mjs --mode merge --key <pem> --platform <os-arch>=<path>');
  console.error('');
  console.error('  Final mode (publish):');
  console.error('    node scripts/release.mjs --mode final --key <pem> [--platform ...] [--publish]');
  console.error('');
  console.error('  Verify-only (check existing manifest, no signing):');
  console.error('    node scripts/release.mjs --mode final --verify-only [--publish]');
  console.error('');
  console.error('  Emit immutable container image tag (CH-26), then exit:');
  console.error('    node scripts/release.mjs --emit-image-tag');
  console.error('');
  console.error('  Emit digest-pinned container image reference (CH-54), then exit:');
  console.error('    node scripts/release.mjs --emit-image-ref --repository <repo> --digest <sha256>');
  console.error('');
  console.error('  Emit notation sign argv (CH-54), then exit:');
  console.error('    node scripts/release.mjs --emit-sign-args --image-ref <ref> --id <profile-arn> [--aws-region <r>] [--aws-profile <p>]');
  console.error('');
  console.error('  Emit notation verify argv (CH-54 post-sign confirmation), then exit:');
  console.error('    node scripts/release.mjs --emit-verify-args --image-ref <ref> [--aws-region <r>] [--aws-profile <p>]');
  process.exit(1);
}

// ── Parse args ────────────────────────────────────────────────────────────
// Pipeline body — only runs when this script is the process entrypoint.
// When imported (e.g. by tests for stripInternalTelemetry), the body below
// is skipped via the IS_MAIN guard.

if (!IS_MAIN) {
  // eslint-disable-next-line no-undef
  // The export at the top of this file is all an importer needs; the
  // pipeline body never runs from an import context.
} else {

const args = process.argv.slice(2);
let mode = '';
let keyPath = '';
let doPublish = false;
let verifyOnly = false;
let emitImageTag = false;
let emitImageRef = false;
let emitSignArgs = false;
let emitVerifyArgs = false;
let repositoryArg = '';
let digestArg = '';
let imageRefArg = '';
let signingProfileArnArg = '';
let awsRegionArg = '';
let awsProfileArg = '';
const platformArgs = [];

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--mode' && args[i + 1]) {
    mode = args[++i];
  } else if (a === '--key' && args[i + 1]) {
    keyPath = args[++i];
  } else if (a === '--platform' && args[i + 1]) {
    platformArgs.push(args[++i]);
  } else if (a === '--publish') {
    doPublish = true;
  } else if (a === '--verify-only') {
    verifyOnly = true;
  } else if (a === '--emit-image-tag') {
    emitImageTag = true;
  } else if (a === '--emit-image-ref') {
    emitImageRef = true;
  } else if (a === '--emit-sign-args') {
    emitSignArgs = true;
  } else if (a === '--emit-verify-args') {
    emitVerifyArgs = true;
  } else if (a === '--repository' && args[i + 1]) {
    repositoryArg = args[++i];
  } else if (a === '--digest' && args[i + 1]) {
    digestArg = args[++i];
  } else if (a === '--image-ref' && args[i + 1]) {
    imageRefArg = args[++i];
  } else if (a === '--id' && args[i + 1]) {
    signingProfileArnArg = args[++i];
  } else if (a === '--aws-region' && args[i + 1]) {
    awsRegionArg = args[++i];
  } else if (a === '--aws-profile' && args[i + 1]) {
    awsProfileArg = args[++i];
  } else {
    console.error(`Unknown argument: ${a}`);
    usage();
  }
}

// CH-26: emit the immutable container image tag and exit. Standalone — needs no
// --mode/--key. Used by the container build to derive `chariot-vX.Y.Z`.
if (emitImageTag) {
  const pkgForTag = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf-8'));
  process.stdout.write(`${imageTag(pkgForTag.version)}\n`);
  process.exit(0);
}

if (emitImageRef) {
  if (!repositoryArg || !digestArg) {
    console.error('Error: --emit-image-ref requires --repository and --digest.');
    usage();
  }
  process.stdout.write(`${imageDigestRef(repositoryArg, digestArg)}\n`);
  process.exit(0);
}

// CH-54: emit the notation sign argv (one arg per line) so the release workflow
// and the verify path share a single source of truth (scripts/image-seal.mjs).
if (emitSignArgs) {
  if (!imageRefArg || !signingProfileArnArg) {
    console.error('Error: --emit-sign-args requires --image-ref and --id.');
    usage();
  }
  const signArgv = notationSignCommand({
    imageRef: imageRefArg,
    signingProfileArn: signingProfileArnArg,
    pluginAwsRegion: awsRegionArg,
    pluginAwsProfile: awsProfileArg,
  });
  process.stdout.write(`${signArgv.join('\n')}\n`);
  process.exit(0);
}

// CH-54: emit the notation verify argv (one arg per line) so the release workflow
// post-sign confirmation step shares a single source of truth (scripts/image-seal.mjs).
if (emitVerifyArgs) {
  if (!imageRefArg) {
    console.error('Error: --emit-verify-args requires --image-ref.');
    usage();
  }
  const verifyArgv = notationVerifyCommand({
    imageRef: imageRefArg,
    pluginAwsRegion: awsRegionArg,
    pluginAwsProfile: awsProfileArg,
  });
  process.stdout.write(`${verifyArgv.join('\n')}\n`);
  process.exit(0);
}

if (mode !== 'merge' && mode !== 'final') {
  console.error(`Error: --mode must be "merge" or "final" (got "${mode || '(none)'}").`);
  usage();
}

if (!keyPath && !verifyOnly) {
  console.error('Error: --key is required (or use --verify-only in final mode).');
  usage();
}

if (mode === 'merge' && platformArgs.length === 0) {
  console.error('Error: merge mode requires at least one --platform.');
  usage();
}

if (mode === 'merge' && doPublish) {
  console.error('Error: merge mode cannot publish. Use final mode to publish.');
  usage();
}

const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf-8'));

// ── Helper: build sign-integrity argv ─────────────────────────────────────

function buildSignArgv(extraPlatforms) {
  const argv = [resolve(ROOT, 'scripts', 'sign-integrity.mjs'), '--key', keyPath];
  if (existsSync(resolve(ROOT, 'native', 'integrity.json'))) {
    argv.push('--merge', resolve(ROOT, 'native', 'integrity.json'));
  }
  for (const p of extraPlatforms) {
    argv.push('--platform', p);
  }
  return argv;
}

// ══════════════════════════════════════════════════════════════════════════
// MERGE MODE — CI per-platform job
// ══════════════════════════════════════════════════════════════════════════

if (mode === 'merge') {
  console.log('\n  ═══════════════════════════════════════════════════════');
  console.log(`  @epicai/chariot — Merge Mode (${platformArgs.length} platform(s))`);
  console.log('  ═══════════════════════════════════════════════════════');

  runArgv('Sign/merge platform hash', process.execPath, buildSignArgv(platformArgs));

  console.log('\n  ═══════════════════════════════════════════════════════');
  console.log('  Merge complete. Coverage verification deferred to final mode.');
  console.log('  ═══════════════════════════════════════════════════════\n');
  process.exit(0);
}

// ══════════════════════════════════════════════════════════════════════════
// FINAL MODE — enforced release sequence
// ══════════════════════════════════════════════════════════════════════════

console.log('\n  ═══════════════════════════════════════════════════════');
console.log(`  @epicai/chariot@${pkg.version} — Final Release Pipeline`);
console.log('  ═══════════════════════════════════════════════════════');

// Step 1: Clean git state — uncommitted AND untracked files
console.log('\n  [1. Git cleanliness]');
try {
  const status = execFileSync('git', ['status', '--porcelain'], {
    cwd: ROOT,
    encoding: 'utf-8',
  }).trim();
  if (status) {
    console.error('  FAILED: Working tree is not clean.');
    console.error('  The following files have uncommitted changes or are untracked:\n');
    for (const line of status.split('\n')) {
      console.error(`    ${line}`);
    }
    process.exit(1);
  }
  console.log('  [1. Git cleanliness] PASSED');
} catch {
  console.error('  [1. Git cleanliness] FAILED');
  process.exit(1);
}

// Step 2: Build
runArgv('2. TypeScript build', process.execPath, [resolve(ROOT, 'node_modules/.bin/tsc')]);

// Step 3: Typecheck
runArgv('3. Typecheck', process.execPath, [resolve(ROOT, 'node_modules/.bin/tsc'), '--noEmit']);

// Step 3b: Strip internal-telemetry code from public dist tarball.
//
// Per internal product spec (option c): dispatch_events
// telemetry runs ONLY on protectNIL-internal Chariot installs. The
// shipped npm package is air-gap-by-default per the product tagline
// "Self-hosted. Your data never leaves." Source carries the telemetry
// (with sentinel markers); the public tarball MUST NOT.
//
// This step strips every block delimited by the sentinel pair from
// every .js file under dist/, then verifies the stripped output no
// longer contains any reference to the internal-only writer or env
// vars. If verification fails, the pipeline aborts before publish.
console.log('\n  [3b. Strip internal telemetry from public dist]');
stripInternalTelemetry(resolve(ROOT, 'dist'));
console.log('  [3b. Strip internal telemetry from public dist] PASSED');

// Step 4: Sign integrity manifest (optional — skip if --verify-only)
if (!verifyOnly && platformArgs.length > 0) {
  runArgv('4. Sign integrity manifest', process.execPath, buildSignArgv(platformArgs));
} else if (verifyOnly) {
  console.log('\n  [4. Sign integrity manifest] SKIPPED (--verify-only)');
  if (!existsSync(resolve(ROOT, 'native', 'integrity.json'))) {
    console.error('  Error: --verify-only requires an existing native/integrity.json.');
    process.exit(1);
  }
} else {
  console.log('\n  [4. Sign integrity manifest] SKIPPED (no --platform args)');
}

// Step 5: Verify manifest — coverage + freshness (MANDATORY)
runArgv('5. Verify manifest', process.execPath, [resolve(ROOT, 'scripts', 'verify-manifest-coverage.mjs')]);

// Step 6: Test suite (MANDATORY)
// Set CHARIOT_RELEASE_ACTIVE to prevent test/release-pipeline.mjs from
// re-entering this script, which would cause infinite recursion.
console.log('\n  [6. Test suite]');
try {
  execFileSync('npm', ['test'], {
    cwd: ROOT,
    stdio: 'inherit',
    timeout: 300_000,
    env: { ...process.env, CHARIOT_RELEASE_ACTIVE: '1' },
  });
  console.log('  [6. Test suite] PASSED');
} catch {
  console.error('  [6. Test suite] FAILED');
  process.exit(1);
}

// Step 7: Publish
if (doPublish) {
  runArgv('7. Publish', 'npm', ['publish', '--access', 'public']);
} else {
  console.log('\n  [7. Publish] SKIPPED (pass --publish to execute)');
}

console.log('\n  ═══════════════════════════════════════════════════════');
console.log('  Release pipeline complete.');
console.log('  ═══════════════════════════════════════════════════════\n');

} // end if (IS_MAIN)
