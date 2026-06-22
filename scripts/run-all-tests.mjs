#!/usr/bin/env node
// Aggregator test runner — runs every entry, never bails early, exits 1 if any failed.
// Replaces the &&-chain in package.json `test`.
// One file = one subprocess; per-file timeout 600s; output captured + tail printed on failure.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

// Customer-flow evals (secrets-flow, customer-ux) require
// ENTERPRISE_MASTER_KEY to actually run their assertions. Generate an
// ephemeral 32-byte key for the test run so the eval gate is meaningful
// in every environment (CI, dev, fresh checkout). Children inherit env.
if (!process.env.ENTERPRISE_MASTER_KEY) {
  process.env.ENTERPRISE_MASTER_KEY = randomBytes(32).toString('base64');
}
// Minimal JWT secret if absent — same rationale.
if (!process.env.ENTERPRISE_JWT_SECRET) {
  process.env.ENTERPRISE_JWT_SECRET = randomBytes(48).toString('base64');
}

// Order preserved from prior `npm test` script. `kind: 'node-test'` uses node --test runner.
const ENTRIES = [
  { kind: 'node',      file: 'scripts/lint-shortlist-size-cap.mjs' },
  { kind: 'node',      file: 'test/leak-scan-catalog-gate.mjs' },
  { kind: 'node',      file: 'test/native-integration.mjs' },
  { kind: 'node',      file: 'test/license-states.mjs' },
  { kind: 'node',      file: 'test/license-activate.mjs' },
  { kind: 'node',      file: 'test/license-renew-client.mjs' },
  { kind: 'node-test', file: 'test/license-epoch-persistence.mjs' },
  { kind: 'node-test', file: 'test/rest-startup-guard.mjs' },
  { kind: 'node-test', file: 'test/mcp-rbac-tenant-isolation.mjs' },
  { kind: 'node-test', file: 'test/epoch-store-multireplica-guard.mjs' },
  { kind: 'node',      file: 'test/license-cli-format.mjs' },
  { kind: 'node',      file: 'test/middleware-states.mjs' },
  { kind: 'node',      file: 'test/verified-catalog-enforcement.mjs' },
  { kind: 'node',      file: 'test/tenant-demotion-overrides.mjs' },
  { kind: 'node',      file: 'test/discovery-persistence.mjs' },
  { kind: 'node',      file: 'test/observability.mjs' },
  { kind: 'node',      file: 'test/discovery-config.mjs' },
  { kind: 'node',      file: 'test/discovery-workflow.mjs' },
  { kind: 'node',      file: 'test/enterprise-hardening.mjs' },
  { kind: 'node',      file: 'test/catalog-trust.mjs' },
  { kind: 'node',      file: 'test/chariot-artifacts.mjs' },
  { kind: 'node',      file: 'test/enterprise-hardening-v2.mjs' },
  { kind: 'node',      file: 'test/integrity-manifest.mjs' },
  { kind: 'node',      file: 'test/release-pipeline.mjs' },
  { kind: 'node',      file: 'test/leak-scan.mjs' },
  { kind: 'node',      file: 'test/mfa-totp.mjs' },
  { kind: 'node',      file: 'test/refresh-tokens.mjs' },
  { kind: 'node',      file: 'test/mfa-routes.mjs' },
  { kind: 'node',      file: 'test/idp-mfa.mjs' },
  { kind: 'node',      file: 'test/idp-mfa-routes.mjs' },
  { kind: 'node',      file: 'test/cli-display.mjs' },
  { kind: 'node',      file: 'test/cli-shared.mjs' },
  { kind: 'node',      file: 'test/cli-setup-regression.mjs' },
  { kind: 'node',      file: 'test/cli-enumeration-consistency.mjs' },
  { kind: 'node',      file: 'test/cli-add-query-smoke.mjs' },
  { kind: 'node',      file: 'test/cli-non-interactive-guard.mjs' },
  { kind: 'node',      file: 'test/closure-adversarial.mjs' },
  { kind: 'node',      file: 'test/customer-golden-queries.mjs' },
  { kind: 'node',      file: 'test/canonical-vendor-pin.mjs' },
  { kind: 'node',      file: 'test/multi-turn-classifier.mjs' },
  { kind: 'node',      file: 'test/server-transport-timeouts.mjs' },
  { kind: 'node',      file: 'test/memory-store.mjs' },
  { kind: 'node',      file: 'test/security-bugs-199-214.mjs' },
  { kind: 'node',      file: 'test/external-review-regressions.mjs' },
  { kind: 'node',      file: 'test/license-hardening.mjs' },
  { kind: 'node',      file: 'test/adapter-catalog-hardening.mjs' },
  { kind: 'node',      file: 'test/iam-body-parser-limit.mjs' },
  { kind: 'node',      file: 'test/iam-cli-approval.mjs' },
  { kind: 'node',      file: 'test/autonomy-pending-cap.mjs' },
  { kind: 'node',      file: 'test/hash-chain-anchor.mjs' },
  { kind: 'node',      file: 'test/verify-catalog-signature.mjs' },
  { kind: 'node',      file: 'test/path-confinement.mjs' },
  { kind: 'node',      file: 'test/manifest-injection.mjs' },
  { kind: 'node-test', file: 'test/access-policy-egress.mjs' },
  { kind: 'node-test', file: 'test/mcp-adapter-base-contract.mjs' },
  { kind: 'node',      file: 'test/mcp-adapter-constructor-smoke.mjs' },
  { kind: 'node',      file: 'test/search-tokenized-rank.mjs' },
  { kind: 'node-test', file: 'test/scim-middleware.mjs' },
  { kind: 'node-test', file: 'test/adapter-contract.mjs' },
  { kind: 'node-test', file: 'test/federation-sandbox-dispatch.mjs' },
  { kind: 'node-test', file: 'test/phase-R-runtime-dispatch.mjs' },
  { kind: 'node-test', file: 'test/chariot-health-emitter.mjs' },
  { kind: 'node-test', file: 'test/drift-detector-do-key-gate.mjs' },
  { kind: 'node-test', file: 'test/bug-821-enterprise-oauth-gating.mjs' },
  { kind: 'node',      file: 'test/npm-integrity-guard.mjs' },
  { kind: 'node',      file: 'test/stale-tool-name-dispatch-gate.mjs' },
  { kind: 'node-test', file: 'test/build-tools-for-routing-helper.mjs' },
  { kind: 'node',      file: 'test/ai-evals/_test-ensemble-judge.mjs' },
  { kind: 'node',      file: 'test/secrets-flow-eval-may-2026/validate.mjs' },
  { kind: 'node',      file: 'test/customer-ux-eval-may-2026/validate.mjs' },
  { kind: 'node',      file: 'test/customer-flow-smoke-eval-may-2026/validate.mjs' },
  { kind: 'node',      file: 'test/real-vendor-eval-may-2026/validate.mjs' },
  { kind: 'node',      file: 'test/supply-chain-eval-may-2026/run.mjs' },
  { kind: 'node',      file: 'test/supply-chain-eval-may-2026/validate.mjs' },
  { kind: 'node',      file: 'test/ai-evals/30-agent-safetybench/index.mjs' },
  { kind: 'node',      file: 'test/ai-evals/check-do-nothing-gate.mjs' },
  { kind: 'node',      file: 'test/ai-evals/45-drift-detection.mjs' },
  { kind: 'node',      file: 'test/ai-evals/40-step-attribution.mjs' },
  { kind: 'node',      file: 'test/ai-evals/46-failure-mode-classification.mjs' },
  { kind: 'node',      file: 'test/ai-evals/41-retry-telemetry.mjs' },
  { kind: 'node',      file: 'test/ai-evals/39-four-outcomes.mjs' },
  { kind: 'node',      file: 'test/ai-evals/44-error-classification.mjs' },
  { kind: 'node',      file: 'test/ai-evals/40-failure-policy.mjs' },
  { kind: 'node',      file: 'test/ai-evals/36-per-tool-timeouts.mjs' },
  { kind: 'node',      file: 'test/ai-evals/32-idempotent-retry.mjs' },
  { kind: 'node',      file: 'test/ai-evals/48-parameter-validation.mjs' },
  { kind: 'node',      file: 'test/ai-evals/37-approval-gate.mjs' },
  { kind: 'node',      file: 'test/ai-evals/42-subagent-approval-inheritance.mjs' },
  { kind: 'node',      file: 'test/ai-evals/35-token-budget.mjs' },
  { kind: 'node',      file: 'test/ai-evals/43-context-budget.mjs' },
  { kind: 'node',      file: 'test/ai-evals/31-tool-call-necessity.mjs' },
  { kind: 'node',      file: 'test/ai-evals/33-activation-steering.mjs' },
  { kind: 'node',      file: 'test/ai-evals/38-resume.mjs' },
  { kind: 'node',      file: 'test/ai-evals/49-sqlite-durability.mjs' },
];

const PER_FILE_TIMEOUT_MS = 600_000;

function run(entry) {
  return new Promise((resolve) => {
    const args = entry.kind === 'node-test' ? ['--test', entry.file] : [entry.file];
    if (!existsSync(entry.file)) {
      return resolve({ entry, rc: 127, out: `MISSING FILE: ${entry.file}`, ms: 0 });
    }
    const t0 = Date.now();
    const chunks = [];
    let killed = false;
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const onData = (c) => chunks.push(c);
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    const timer = setTimeout(() => {
      killed = true;
      child.kill('SIGKILL');
    }, PER_FILE_TIMEOUT_MS);
    child.on('close', (code) => {
      clearTimeout(timer);
      const out = Buffer.concat(chunks).toString('utf8');
      resolve({ entry, rc: killed ? 124 : (code ?? 1), out, ms: Date.now() - t0, killed });
    });
  });
}

const results = [];
const startedAt = Date.now();
for (const entry of ENTRIES) {
  process.stdout.write(`▶ ${entry.file.padEnd(60)} `);
  const r = await run(entry);
  results.push(r);
  const tag = r.rc === 0 ? 'OK  ' : `FAIL(rc=${r.rc}${r.killed ? ',TIMEOUT' : ''})`;
  process.stdout.write(`${tag} ${(r.ms / 1000).toFixed(1)}s\n`);
}
const totalMs = Date.now() - startedAt;

const failed = results.filter((r) => r.rc !== 0);
console.log('\n──────── SUMMARY ────────');
console.log(`Total:   ${results.length}`);
console.log(`Passed:  ${results.length - failed.length}`);
console.log(`Failed:  ${failed.length}`);
console.log(`Elapsed: ${(totalMs / 1000).toFixed(1)}s`);

if (failed.length) {
  console.log('\n──────── FAILURES (tail of each) ────────');
  for (const r of failed) {
    console.log(`\n# ${r.entry.file} — rc=${r.rc}${r.killed ? ' TIMEOUT' : ''}`);
    const tail = r.out.split('\n').slice(-20).join('\n');
    console.log(tail);
  }
  process.exit(1);
}
process.exit(0);
