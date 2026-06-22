#!/usr/bin/env bash
#
# scripts/preflight.sh
#
# Local release gate for @epicai/chariot. Runs every check from
# .github/workflows/release.yml that CAN run off-CI, against the
# current working tree, before a release commit is pushed.
#
# This script exists because two consecutive releases (1.1.0 attempts
# 1 and 2) failed in CI on preconditions that would have been caught
# locally in seconds. The release.yml validator and the publish-main
# `npm ci` step are both strict; the only safe way to avoid shipping
# a broken release is to run the same strict checks before git push.
#
# Usage:
#   ./scripts/preflight.sh
#
# Env:
#   CHARIOT_PREFLIGHT_SKIP_TESTS=1   Skip the full npm test suite.
#                                    Useful only for iterating on a
#                                    non-test-touching change. Leave
#                                    unset for any actual release.
#
# Exit codes:
#   0  Every check passed. Safe to commit and push.
#   1  At least one check failed. Do not push.
#
# Matrix of what this script covers versus what only CI can cover:
#
#   Check                                    Local   CI
#   -----                                    -----   --
#   package.json version is semver             Y     Y
#   optionalDependencies pins match version    Y     Y
#   package-lock.json top-level version        Y     Y
#   package-lock.json siblings resolved        Y     Y  (CI catches via npm ci)
#   npm ci strict lockfile coherence           Y     Y  (publish-main)
#   tsc --noEmit                               Y     Y
#   npm run build (tsc emit)                   Y     Y  (publish-main)
#   npm test (full suite)                      Y     Y  (publish-main)
#   npm pack --dry-run                         Y     -
#   npm publish --dry-run                      Y     -
#   native binary build (linux-x64 only)       Y     Y  (build matrix × 4)
#   native binary build (darwin, win32)        -     Y
#   Ed25519 manifest signing                   -     Y  (sign-manifest, secret)
#   Actual npm publish                         -     Y  (publish-sibling, publish-main)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

FAILED=0

pass() { echo -e "  ${GREEN}\xe2\x9c\x93${NC} $1"; }
fail() { echo -e "  ${RED}\xe2\x9c\x97${NC} $1"; FAILED=1; }
skip() { echo -e "  ${YELLOW}\xe2\x80\x94${NC} $1"; }
section() { echo; echo -e "${BOLD}$1${NC}"; }

VERSION="$(node -p "require('./package.json').version")"

echo -e "${BOLD}@epicai/chariot preflight — version ${VERSION}${NC}"
echo "repo: ${REPO_ROOT}"

# ── 1. version well-formedness ──────────────────────────────────────────────
section "1. package.json version is well-formed semver"
if [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  pass "${VERSION}"
else
  fail "version ${VERSION} is not well-formed semver"
fi

# ── 2. optionalDependencies pins match main version ─────────────────────────
section "2. optionalDependencies pins all match main version"
node -e '
  const pkg = require("./package.json");
  const target = pkg.version;
  const deps = pkg.optionalDependencies || {};
  const siblings = [
    "@epicai/chariot-bin-linux-x64-gnu",
    "@epicai/chariot-bin-darwin-arm64",
    "@epicai/chariot-bin-darwin-x64",
    "@epicai/chariot-bin-win32-x64-msvc",
  ];
  let bad = 0;
  for (const name of siblings) {
    const ver = deps[name];
    if (!ver) {
      console.error("    " + name + " missing from optionalDependencies");
      bad = 1;
    } else if (ver !== target) {
      console.error("    " + name + " pinned " + ver + ", must match main " + target);
      bad = 1;
    }
  }
  process.exit(bad);
' 2>&1
if [ "$?" -eq 0 ]; then
  pass "all 4 siblings pinned to ${VERSION}"
else
  fail "optionalDependencies pins mismatch"
fi

# ── 3. package-lock.json top-level version ──────────────────────────────────
section "3. package-lock.json top-level version matches package.json"
LOCK_VERSION="$(node -p "require('./package-lock.json').version")"
if [ "${LOCK_VERSION}" = "${VERSION}" ]; then
  pass "${LOCK_VERSION}"
else
  fail "package-lock.json version (${LOCK_VERSION}) does not match package.json (${VERSION})"
fi

# ── 4. package-lock.json sibling entries fully resolved ────────────────────
# This is the check that would have caught the 1.1.0-attempt-2 failure.
# When `npm install --package-lock-only` runs against a registry that does
# not yet have the target sibling versions, it writes placeholder entries
# like { "optional": true } with no version / resolved / integrity. Those
# slip past the validate job (which only checks top-level lockfile version)
# but `npm ci` in publish-main does a strict per-dependency coherence check
# and fails. We catch it here, before the commit.
section "4. package-lock.json sibling entries are fully resolved"
node -e '
  const lock = require("./package-lock.json");
  const siblings = [
    "@epicai/chariot-bin-linux-x64-gnu",
    "@epicai/chariot-bin-darwin-arm64",
    "@epicai/chariot-bin-darwin-x64",
    "@epicai/chariot-bin-win32-x64-msvc",
  ];
  const expected = require("./package.json").version;
  let bad = 0;
  for (const name of siblings) {
    const entry = (lock.packages || {})["node_modules/" + name];
    if (!entry) {
      console.error("    " + name + " missing from lockfile packages map");
      bad = 1;
      continue;
    }
    if (!entry.version) {
      console.error("    " + name + " has no version field (placeholder entry — regenerate lockfile after siblings publish)");
      bad = 1;
      continue;
    }
    if (entry.version !== expected) {
      console.error("    " + name + " at " + entry.version + ", expected " + expected);
      bad = 1;
      continue;
    }
    if (!entry.resolved) {
      console.error("    " + name + " has no resolved URL");
      bad = 1;
      continue;
    }
    if (!entry.integrity) {
      console.error("    " + name + " has no integrity hash");
      bad = 1;
      continue;
    }
  }
  process.exit(bad);
' 2>&1
if [ "$?" -eq 0 ]; then
  pass "all 4 sibling lockfile entries resolved at ${VERSION}"
else
  fail "sibling lockfile entries incomplete — this will fail publish-main npm ci"
fi

# ── 5. npm ci --dry-run strict check ──────────────────────────────────────
section "5. npm ci --dry-run — strict lockfile / package.json coherence"
if npm ci --dry-run --ignore-scripts > /tmp/preflight-npm-ci.log 2>&1; then
  pass "npm ci coherence check passes"
else
  fail "npm ci would fail in publish-main"
  echo "    last 15 lines of /tmp/preflight-npm-ci.log:"
  tail -15 /tmp/preflight-npm-ci.log | sed 's/^/      /'
fi

# ── 6. typecheck ──────────────────────────────────────────────────────────
section "6. TypeScript typecheck (tsc --noEmit)"
if npx tsc --noEmit > /tmp/preflight-tsc.log 2>&1; then
  pass "tsc --noEmit clean"
else
  fail "tsc --noEmit has errors"
  echo "    last 15 lines of /tmp/preflight-tsc.log:"
  tail -15 /tmp/preflight-tsc.log | sed 's/^/      /'
fi

# ── 7. Build ─────────────────────────────────────────────────────────────
section "7. npm run build (tsc emit to dist/)"
if npm run build > /tmp/preflight-build.log 2>&1; then
  pass "npm run build succeeds"
else
  fail "npm run build failed"
  echo "    last 15 lines of /tmp/preflight-build.log:"
  tail -15 /tmp/preflight-build.log | sed 's/^/      /'
fi

# ── 8. Full test suite ─────────────────────────────────────────────────────
section "8. npm test (full test suite)"
if [ "${CHARIOT_PREFLIGHT_SKIP_TESTS:-0}" = "1" ]; then
  skip "skipped (CHARIOT_PREFLIGHT_SKIP_TESTS=1)"
else
  if npm test > /tmp/preflight-test.log 2>&1; then
    pass "npm test passes"
  else
    fail "npm test failed"
    echo "    last 25 lines of /tmp/preflight-test.log:"
    tail -25 /tmp/preflight-test.log | sed 's/^/      /'
  fi
fi

# ── 9. npm pack --dry-run ─────────────────────────────────────────────────
section "9. npm pack --dry-run (tarball assembly)"
if npm pack --dry-run --ignore-scripts > /tmp/preflight-pack.log 2>&1; then
  pass "npm pack --dry-run succeeds"
else
  fail "npm pack --dry-run failed"
  echo "    last 15 lines of /tmp/preflight-pack.log:"
  tail -15 /tmp/preflight-pack.log | sed 's/^/      /'
fi

# ── 10. npm publish --dry-run ─────────────────────────────────────────────
# Runs with --ignore-scripts so prepublishOnly doesn't re-run the build +
# test + verify-manifest chain we already exercised above.
section "10. npm publish --dry-run (publish manifest validation)"
if npm publish --dry-run --ignore-scripts --access public > /tmp/preflight-publish.log 2>&1; then
  pass "npm publish --dry-run succeeds"
else
  fail "npm publish --dry-run failed"
  echo "    last 15 lines of /tmp/preflight-publish.log:"
  tail -15 /tmp/preflight-publish.log | sed 's/^/      /'
fi

# ── Summary ─────────────────────────────────────────────────────────────
echo
if [ "${FAILED}" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}PREFLIGHT OK${NC} — @epicai/chariot@${VERSION} is safe to commit and push"
  exit 0
else
  echo -e "${RED}${BOLD}PREFLIGHT FAILED${NC} — do not commit or push until the failures above are fixed"
  exit 1
fi
