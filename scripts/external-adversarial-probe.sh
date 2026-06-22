#!/usr/bin/env bash
# External adversarial probe (bug-tracker-ref, 2026-05-22).
#
# Purpose:
#   Run customer-shaped probes against the PUBLISHED @epicai/chariot tarball
#   in a fresh /tmp install — WITHOUT any visibility into the local source
#   tree. This is the gate Alex's item 5 asks for: a bug is not closed until
#   a session that has not seen the fix code can reproduce the customer
#   experience and observe the right answer.
#
# What this script must NOT do:
#   - Reference any path under the repo source tree (other than itself).
#   - Use any compiled artifact under dist/.
#   - Use any helper exported only from the source tree.
#
# What this script MUST do:
#   - npm install @epicai/chariot@latest into a brand-new tempdir.
#   - Invoke `npx @epicai/chariot ...` exactly as the customer would.
#   - Assert customer-visible outcomes, not internal state.
#
# How to use:
#   bash scripts/external-adversarial-probe.sh
#
# Exit codes:
#   0 — all probes passed
#   1 — at least one customer-visible failure
#
# Built on the Epic AI® Intelligence Platform
# Copyright 2026 protectNIL Inc. Elastic-2.0

set -uo pipefail

SANDBOX="$(mktemp -d -t chariot-external-probe-XXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT

passed=0
failed=0
failures=()

probe() {
  local name="$1"; shift
  if "$@"; then
    echo "  ✓ $name"
    passed=$((passed + 1))
  else
    echo "  ✗ $name"
    failures+=("$name")
    failed=$((failed + 1))
  fi
}

# ── Step 1: fresh install ─────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "External adversarial probe — sandbox: $SANDBOX"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "→ Fresh install of @epicai/chariot…"
cd "$SANDBOX"
npm init -y >/dev/null 2>&1
if ! npm install --no-audit --no-fund @epicai/chariot >install.log 2>&1; then
  echo "  ✗ npm install @epicai/chariot failed — see $SANDBOX/install.log"
  exit 1
fi
CHARIOT="$SANDBOX/node_modules/.bin/chariot"
if [ ! -x "$CHARIOT" ]; then
  echo "  ✗ chariot binary not installed at $CHARIOT"
  exit 1
fi
echo "  ✓ installed; binary at $CHARIOT"
echo ""

# ── Customer environment that mimics a clean Workato-dev workstation ──────
export EPIC_AI_DIR_OVERRIDE="$SANDBOX/.epic-ai"
export HOME="$SANDBOX/home"
export CHARIOT_NON_INTERACTIVE=1
export NO_COLOR=1
mkdir -p "$HOME" "$EPIC_AI_DIR_OVERRIDE"

strip_ansi() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g'; }

# ── Probe set: customer-visible failure shapes Alex named ─────────────────

# 1. chariot search slack → slack must be the FIRST result, not a substring sibling.
probe_search_slack_top_hit() {
  local out
  out="$("$CHARIOT" search slack 2>&1 | strip_ansi | tr -d '\r' || true)"
  # Find first id token on a result line.
  local first
  first="$(echo "$out" | awk '/^[[:space:]]+[a-z0-9][a-z0-9-]+[[:space:]]/ { print $1; exit }')"
  if [ "$first" = "slack" ]; then return 0; else
    echo "    first id = '$first' (expected 'slack')"
    echo "    out: $(echo "$out" | head -10)"
    return 1
  fi
}
probe "chariot search slack → top hit is slack" probe_search_slack_top_hit

# 2. chariot search stripe → stripe must be the first result.
probe_search_stripe_top_hit() {
  local out
  out="$("$CHARIOT" search stripe 2>&1 | strip_ansi | tr -d '\r' || true)"
  local first
  first="$(echo "$out" | awk '/^[[:space:]]+[a-z0-9][a-z0-9-]+[[:space:]]/ { print $1; exit }')"
  if [ "$first" = "stripe" ]; then return 0; else
    echo "    first id = '$first' (expected 'stripe')"
    return 1
  fi
}
probe "chariot search stripe → top hit is stripe" probe_search_stripe_top_hit

# 3. chariot add slack with no credentials in non-interactive mode → STDIN_REQUIRED(4).
probe_add_slack_no_creds_fails_closed() {
  local out rc
  out="$("$CHARIOT" add slack 2>&1 | strip_ansi || true)"
  rc=$?
  # bash's $? after pipefail-aware command substitution; verify exit code via $PIPESTATUS would be safer,
  # but spawn separately to capture the actual exit code:
  "$CHARIOT" add slack >/dev/null 2>&1
  rc=$?
  if [ "$rc" = "4" ]; then return 0; else
    echo "    exit code = $rc (expected 4 STDIN_REQUIRED)"
    return 1
  fi
}
probe "chariot add slack (no creds, non-interactive) → exit 4" probe_add_slack_no_creds_fails_closed

# 4. chariot query natural-language wikipedia phrasing → routes to wikipedia, NOT pubmed.
probe_query_wikipedia_natural() {
  "$CHARIOT" add wikipedia >/dev/null 2>&1
  "$CHARIOT" add pubmed >/dev/null 2>&1
  local out
  out="$("$CHARIOT" query "search wikipedia for photosynthesis" 2>&1 | strip_ansi | tr '[:upper:]' '[:lower:]')"
  if echo "$out" | grep -q "routing to wikipedia" && ! echo "$out" | grep -q "routing to pubmed"; then
    return 0
  else
    echo "    out: $(echo "$out" | head -5)"
    return 1
  fi
}
probe "chariot query 'search wikipedia for photosynthesis' → wikipedia" probe_query_wikipedia_natural

# 5. WARN line about dropped undispatchable entries must NOT leak to CLI.
probe_no_warn_leak() {
  local out
  out="$("$CHARIOT" list 2>&1 | strip_ansi)"
  if echo "$out" | grep -qi "dropped undispatchable entries"; then
    echo "    WARN leaked: $(echo "$out" | grep -i 'dropped undispatchable')"
    return 1
  fi
  return 0
}
probe "chariot list → no WARN about dropped entries" probe_no_warn_leak

# 6. The published bundle entry for wayback-machine must reference a real npm pkg.
probe_wayback_pkg_resolvable() {
  local bundle="$SANDBOX/node_modules/@epicai/chariot/chariot-adapter-bundle.json"
  if [ ! -f "$bundle" ]; then
    echo "    bundle missing: $bundle"
    return 1
  fi
  local pkg
  pkg="$(node -e "const b = JSON.parse(require('fs').readFileSync('$bundle','utf-8')); const arr = Array.isArray(b)?b:b.catalog; const wb = arr.find(a => (a.id||a.adapter_id)==='wayback-machine'); console.log(wb && (wb.mcp && (wb.mcp.packageName||wb.mcp.npmPackage)) || '')")"
  if [ -z "$pkg" ]; then
    echo "    wayback-machine has no packageName"
    return 1
  fi
  # Verify the package actually exists on the npm registry.
  local code
  code="$(curl -sfo /dev/null -w '%{http_code}' "https://registry.npmjs.org/$(node -e "console.log(encodeURIComponent('$pkg'))")")"
  if [ "$code" = "200" ]; then
    return 0
  else
    echo "    pkg '$pkg' returns HTTP $code on npm registry"
    return 1
  fi
}
probe "wayback-machine bundle entry → packageName resolves on npm" probe_wayback_pkg_resolvable

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "External adversarial probe: $passed passed, $failed failed"
echo "══════════════════════════════════════════════════════════════"
echo ""
if [ "$failed" -gt 0 ]; then
  echo "Customer-visible failures (a real developer hitting npm install today):"
  for f in "${failures[@]}"; do echo "  ✗ $f"; done
  exit 1
fi
exit 0
