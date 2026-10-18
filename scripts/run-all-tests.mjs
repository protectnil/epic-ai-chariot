#!/usr/bin/env node
// Aggregator test runner — runs every entry, never bails early, exits 1 if any failed.
// Replaces the &&-chain in package.json `test`.
// One file = one subprocess; per-file timeout 600s; output captured + tail printed on failure.

import { spawn } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
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
// CH-54 deploy evals (tracked, not gitignored — require notation/oras/zot/helm binaries).
const ENTRIES = [
  { kind: 'node',      file: 'scripts/lint-shortlist-size-cap.mjs' },
  { kind: 'node-test', file: 'eslint-rules/no-dynamic-crypto-access.test.mjs' }, // CHARIOT::§12.2::11 — binding-aware local ESLint rule (no-restricted-syntax replacement)
  { kind: 'node-test', file: 'eslint-rules/no-dynamic-module-specifier.test.mjs' }, // CHARIOT::§12.2::11 — forbids non-literal import()/require() specifiers
  // Phase 9 — Agent-UX & honest-signal CLI surface (CH-31/32/36/38/42/48/50).
  // test/ is gitignored (companion-repo pattern); registered here as the gate.
  { kind: 'node-test', file: 'test/cli-honest-signal.mjs' },
  { kind: 'node-test', file: 'evals/deploy/ch54-notation-sign-verify.mjs' },
  { kind: 'node-test', file: 'evals/deploy/ch54-helm-fail-closed.mjs' },
  { kind: 'node-test', file: 'evals/deploy/ch54-ecs-taskdef.mjs' },
  { kind: 'node-test', file: 'evals/deploy/s23-image-refs.mjs' }, // §23.2 repo-name consistency + CH-29 no silent Docker Hub
  { kind: 'node-test', file: 'dist/license/boot-gate.test.js' }, // §23.1/CH-24 CheckoutLicense boot gate
  { kind: 'node-test', file: 'dist/bin/gateway-entitlement-boot.test.js' }, // §23.1/CH-24 real entrypoint honors the gate
  { kind: 'node-test', file: 'evals/deploy/bien-dense-encoder-image.mjs' },
  { kind: 'node-test', file: 'evals/deploy/ch54-release-yml.mjs' },
  { kind: 'node',      file: 'test/leak-scan-catalog-gate.mjs' },
  { kind: 'node',      file: 'test/native-integration.mjs' },
  { kind: 'node',      file: 'test/license-states.mjs' },
  { kind: 'node',      file: 'test/license-activate.mjs' },
  { kind: 'node',      file: 'test/license-renew-client.mjs' },
  { kind: 'node-test', file: 'test/license-epoch-persistence.mjs' },
  { kind: 'node-test', file: 'test/rest-startup-guard.mjs' },
  { kind: 'node-test', file: 'test/rate-limiter-token-bucket.mjs' },
  // ── Restored 2026-07-22 ──────────────────────────
  // These three entries had been struck from the roll call because their files
  // were absent from this checkout. `test/` is gitignored (.gitignore:75), so a
  // file can vanish here with no git trace and the only symptom is the roll call
  // quietly getting shorter — which reads as a green suite, not as lost coverage.
  // Recovered and re-run before re-registering:
  //   license-manager-checkout — from .worktrees/consolidation-4.0.0/test/ — 19 pass / 0 fail
  //   deploy-fail-closed       — same worktree — self-skips without notation/oras/zot/helm
  //   admission-gate           — from git blob 05eec0c^ (untracked by 05eec0c), 191 lines,
  //                              7 pass / 1 fail. The failing case
  //                              '§5.6: advancing epoch admitted and persisted' is STALE,
  //                              not a product defect: its fixture builds `catalog: []`
  //                              with a constant recordCount, which CH-22 (2026-07-16) now
  //                              rejects via the recordCount/tool-record parity check at
  //                              VectorIndexVerifier.ts:67, and its persist-on-bm25-only
  //                              expectation was deliberately reversed in loadRetrieval.ts
  //                              (persisting there advances the epoch without the retriever
  //                              being advertised → epoch_replay_rejected on next boot).
  //                              Both behaviours are covered by
  //                              dist/engine/retrieval/loadRetrieval.epoch-persist.test.js.
  //                              Left failing on purpose: rewriting a §5.6 assertion is a
  //                              spec decision, and a red gate is honest where a removed
  //                              entry is not.
  { kind: 'node-test', file: 'test/license-manager-checkout.mjs' },
  { kind: 'node-test', file: 'test/deploy-fail-closed.mjs' },
  { kind: 'node-test', file: 'test/admission-gate.mjs' },
  { kind: 'node-test', file: 'test/mcp-rbac-tenant-isolation.mjs' },
  { kind: 'node-test', file: 'test/request-boundary-mandatory.mjs' }, // CHARIOT::§8.4.1 node 3/4
  { kind: 'node-test', file: 'test/epoch-store-multireplica-guard.mjs' },
  { kind: 'node',      file: 'test/license-cli-format.mjs' },
  { kind: 'node',      file: 'test/middleware-states.mjs' },
  { kind: 'node',      file: 'test/verified-catalog-enforcement.mjs' },
  // Recovered 2026-07-22 from local coding-session archives. These four were
  // never in git — test/ is
  // gitignored (.gitignore:75) and the commits that registered them (33e420c CH-39)
  // could not carry the files.
  { kind: 'node',      file: 'test/engine-entity-subsys.mjs' },
  { kind: 'node',      file: 'test/engine-dispatch-timeout.mjs' },
  { kind: 'node',      file: 'test/engine-claim-validation.mjs' },
  { kind: 'node',      file: 'test/engine-query-serve-envelope.mjs' },
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
  // Recovered 2026-07-22 from session transcripts . Registered by
  // 76e4e1e (CH-46/47) and e7d9706 (CH-43) without their files.
  // NOTE: audit-anchor-ch46-ch47 currently FAILS with a substantive finding —
  // "pinned TSA cert lacks id-kp-timeStamping EKU (1.3.6.1.5.5.7.3.8)" across
  // SHA-256/384/512 — which is exactly the condition this eval exists to catch.
  { kind: 'node',      file: 'test/audit-anchor-ch46-ch47.mjs' },
  { kind: 'node',      file: 'test/audit-chain-liveness-ch45.mjs' },
  { kind: 'node',      file: 'test/curated-resilience-ch43.mjs' },
  { kind: 'node',      file: 'test/verify-catalog-signature.mjs' },
  // W14 (CHARIOT::§5.2::5, CH-52 trust anchor CHARIOT-SPEC.md:525) —
  // positive-signature manifest_mismatch/encoder_load_failed end-to-end
  // fixtures signed with the real production catalog key; requires the
  // CHARIOT_CATALOG_SIGNING_KEY_PATH env var set to that key's path
  // (fails explicitly, never silently skips, if unset or unreadable).
  { kind: 'node',      file: 'test/verified-catalog-e2e-w14.mjs' },
  { kind: 'node',      file: 'test/path-confinement.mjs' },
  { kind: 'node',      file: 'test/manifest-injection.mjs' },
  { kind: 'node-test', file: 'test/access-policy-egress.mjs' },
  { kind: 'node-test', file: 'test/mcp-adapter-base-contract.mjs' },
  { kind: 'node',      file: 'test/mcp-adapter-constructor-smoke.mjs' },
  { kind: 'node',      file: 'test/search-tokenized-rank.mjs' },
  { kind: 'node-test', file: 'test/retrieval-hybrid.mjs' },
  { kind: 'node',      file: 'test/tool-dispatch-route.mjs' },
  { kind: 'node',      file: 'test/vector-index-verifier.mjs' },
  { kind: 'node-test', file: 'test/gc-gate-metrics.mjs' },
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
  // ── Tier-1 retrieval evals (§4.3/§4.4/§8.6) ───────────────────────────────
  // These four existed on disk but were registered NOWHERE, so `npm test` ran
  // green while the entire retrieval subsystem went unexercised. That is how
  // the tracked defect shipped: CrossEncoderReranker was implemented and unit-tested, its
  // scorer accessor returned a hard-coded null, and no suite connected them.
  { kind: 'node-test', file: 'dist/engine/federation/sandbox/sandbox-timeout.test.js' },
  { kind: 'node-test', file: 'dist/engine/gateway/BackendRegistry.probe.test.js' },
  // ── Registered 2026-07-23: tranche-2 spec-compliance fixes (each test proven to
  // fail against the pre-fix code before landing). ──
  { kind: 'node-test', file: 'dist/engine/retrieval/loadRetrieval.startup-failclosed.test.js' },
  { kind: 'node-test', file: 'dist/iam/services/session.revocation-ttl.test.js' },
  { kind: 'node-test', file: 'dist/engine/trust/PolicyLoader.test.js' },
  // ── Registered 2026-07-25: tranche-B security fixes (each proven-on-revert). ──
  { kind: 'node-test', file: 'dist/iam/services/scim.deprovision-match.test.js' },   // §10.4::4
  { kind: 'node-test', file: 'dist/iam/services/session.refresh-store.test.js' },    // §10.6::6
  { kind: 'node-test', file: 'dist/iam/routes/saml.config-hardening.test.js' },      // §10.2::2
  { kind: 'node-test', file: 'dist/iam/routes/adapters.credential-owner.test.js' },  // §10.5::3
  { kind: 'node-test', file: 'dist/iam/routes/admin.tenant-crud.test.js' },          // §10.8::1/2/3
  { kind: 'node-test', file: 'dist/iam/routes/oidc.config-hardening.test.js' },      // §10.3::1
  { kind: 'node-test', file: 'dist/iam/services/tenant.encryption-keyref.test.js' }, // §10.8::4
  { kind: 'node-test', file: 'dist/engine/memory/PersistentMemory.tenant-isolation.test.js' }, // §8.5::1 — cross-tenant memory isolation
  { kind: 'node-test', file: 'dist/engine/memory/adapters/FileStore.legacy-tenant-migration.test.js' }, // §8.5::1 hydrate migration
  { kind: 'node-test', file: 'dist/engine/resilience/RateLimiter.clock-regression.test.js' }, // §8.7 non-monotonic clock
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.tenant-context.test.js' }, // §8.9::11
  { kind: 'node-test', file: 'dist/iam/services/session.session-key.test.js' },      // §3.4::1
  { kind: 'node-test', file: 'dist/iam/services/audit.gap-detection.test.js' },      // §3.5::21
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.reranker-lock.test.js' }, // §4.1::4
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.pre-dispatch-audit.test.js' }, // §3.5::17
  { kind: 'node-test', file: 'dist/engine/federation/AdaptivePool.scale-up-p95.test.js' }, // §7.3::2
  { kind: 'node-test', file: 'dist/engine/orchestrator/Orchestrator.phase-spans.test.js' }, // §8.2::5
  { kind: 'node-test', file: 'dist/engine/resilience/ErrorClassifier.taxonomy.test.js' }, // §8.7::2
  { kind: 'node-test', file: 'dist/engine/federation/sandbox/timeout-termination.test.js' }, // §7.4::7
  { kind: 'node-test', file: 'dist/iam/services/session.alg-pinning.test.js' },      // §10.6::1
  { kind: 'node-test', file: 'dist/engine/retrieval/loadRetrieval.rerank-wiring.test.js' },
  // ── Registered 2026-09-04: rulings item 94 (BIEN-U1) — determines the
  // correct CHARIOT_DENSE_POOLING mode against the real shipped BIEN
  // dense export. Self-skips (does not fail) when
  // BIEN_DENSE_TEST_ONNX_PATH/BIEN_DENSE_TEST_TOKENIZER_DIR are unset —
  // the proprietary model artifact is never checked into this repo.
  { kind: 'node-test', file: 'dist/engine/retrieval/denseEncoder.pooling-mode.test.js' },
  { kind: 'node-test', file: 'dist/engine/retrieval/loadRetrieval.epoch-persist.test.js' },
  { kind: 'node-test', file: 'dist/engine/retrieval/confidence.abstention.test.js' },
  { kind: 'node-test', file: 'dist/engine/retrieval/HybridRetriever.payload-integrity.test.js' },
  { kind: 'node-test', file: 'dist/engine/retrieval/OfficialPartition.test.js' }, // BIEN::§7a official/non-official hard partition + runtime invariant assert
  // ── Registered 2026-09-05: row 1.33 (items 43/44) — BIEN §9::10/13/14
  // on-device overlay-embed pipeline (CHARIOT-SPEC.md §8.6a). Retrieval half.
  { kind: 'node-test', file: 'dist/engine/retrieval/overlay/CompositeEdgeShard.test.js' },
  { kind: 'node-test', file: 'dist/engine/retrieval/overlay/OverlayEmbedder.test.js' },
  { kind: 'node-test', file: 'dist/engine/server/transports/rest.timing-safe-bearer.test.js' }, // constant-time REST bearer compare (crypto.timingSafeEqual)
  { kind: 'node-test', file: 'dist/engine/server/transports/stdio.malformed-frame.test.js' }, // CH-31 §23.2 typed-outcome — malformed JSON-RPC frame rejection
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.resolver-fanout-bucket.test.js' }, // resolver fan-out rate-bucket isolation (per-tenant)
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.list-toolcount-honesty.test.js' }, // §17.3::8,9,10 (CH-50) chariot_list toolCount honesty
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.sse-transport-refused.test.js' }, // §7.2::3 SSE errors on dispatch, not advertised
  { kind: 'node-test', file: 'dist/engine/server/registerChariotTools.tool-surface.test.js' }, // C4AMD::§2::1 (rulings item 25) MCP tool-surface conformance
  { kind: 'node-test', file: 'dist/engine/credentials/credentials.test.js' }, // credentials outside the chat — private loopback portal, ensureCredentials, URL-mode prompter, server instructions (C4AMD::§2::1 stays three tools)
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.credentials-outside-chat.test.js' }, // handleCall: credentials_pending/declined with private URL; inert without a prompter
  { kind: 'node-test', file: 'dist/iam/services/session.insecure-jwt-secret.test.js' }, // §10.1 CH-19 enterprise JWT secret required+strong, no JWT_SECRET fallback
  { kind: 'node-test', file: 'dist/iam/bootstrap.jwt-secret-floor.test.js' },           // §20::4 bootstrap-path 32-char floor
  { kind: 'node-test', file: 'dist/iam/bootstrap.enterprise-gate.test.js' },          // §18.2::1/2, §18.3::1 — CHARIOT_ENTERPRISE mode gate + master-key fail-fast (rulings item 36)
  { kind: 'node-test', file: 'dist/iam/inProcessRedisShim.test.js' },                 // §18.2::2, §18.3::4 — shared in-process Redis fallback shim
  { kind: 'node-test', file: 'dist/iam/resolveEnterpriseRedis.test.js' },             // §18.2::2, §18.3::4 — Wave-3a P1-1: configured-unreachable Redis degrades (both bootstrap paths)
  { kind: 'node-test', file: 'dist/iam/bootstrap.master-key-before-mongo.test.js' },  // §18.3::1 — Wave-3a P1-2: master key validated before any Mongo dial (source-order regression)
  { kind: 'node-test', file: 'dist/iam/services/session.redis-degraded.test.js' }, // §18.3 — Wave-3a gate round 2 P1: missing activity key is JWT-signature-only (not fail-closed) while Redis-degraded
  { kind: 'node-test', file: 'dist/engine/resilience/RateLimiter.penalize.test.js' }, // §8.7::5 RateLimiter.penalize() drain/isolation/recovery
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.rate-limit-backpressure.test.js' }, // §8.7::5 429 back-pressures the same server, not others
  // ── Registered 2026-07-25: 23 src/**/*.test.ts files present on disk but absent
  // from this roll call, so they ran for nobody. Same silent-coverage-loss family
  // as the 2026-07-22 block below, but on the compiled-TypeScript side rather than
  // test/*.mjs. This is the trap named in the Tier-1 retrieval contract investigation: run-all-tests.mjs
  // is an EXPLICIT manifest, not a glob, which is how CrossEncoderReranker could be
  // fully implemented and unit-tested while its scorer accessor returned a
  // hard-coded null with no suite connecting the two. Clause refs are given only
  // where verified; absent comment means the governing clause was not confirmed.
  { kind: 'node-test', file: 'dist/cli/cli-honest-signal.test.js' },
  { kind: 'node-test', file: 'dist/engine/autonomy/TieredAutonomy.classify-default.test.js' }, // CHARIOT::§3.5::15 (CH-11)
  { kind: 'node-test', file: 'dist/engine/bin/setup.test.js' },
  // CHARIOT::§17.2 setup wizard (rulings item 92, W35/W35-b) — hardware/runtime/GPU
  // detection, model recommendation, local-backend flow, adapter picker +
  // license tier display, shared stdio dependency install, config
  // generation, connection verification, and the scripted end-to-end run.
  { kind: 'node-test', file: 'dist/cli/hardware.test.js' }, // §17.2::1/2/3
  { kind: 'node-test', file: 'dist/cli/modelRecommendation.test.js' }, // §17.2::5
  { kind: 'node-test', file: 'dist/cli/localBackendStep.test.js' }, // §17.2::6
  { kind: 'node-test', file: 'dist/cli/adapterPicker.test.js' }, // §17.2::7/8/9
  { kind: 'node-test', file: 'dist/cli/installStdioDependency.test.js' }, // §17.2::10
  { kind: 'node-test', file: 'dist/cli/query-cli-bridge-dispatch.test.js' }, // §17.1 chariot query cli-bridge dispatch (pre-existing tracked test, registered after the gate)
  { kind: 'node-test', file: 'dist/engine/bin/preinstall.npx-warm.test.js' }, // AS §1.1 sub-clauses 2-3 — npx pre-fetch seeds _npx and re-verifies integrity
  { kind: 'node-test', file: 'dist/cli/configGenerator.test.js' }, // §17.2::14
  { kind: 'node-test', file: 'dist/cli/verifyAdapterConnection.test.js' }, // §17.2::13
  { kind: 'node-test', file: 'dist/engine/bin/setup.wizard-integration.test.js' }, // §17.2::1-20 end-to-end
  { kind: 'node-test', file: 'dist/engine/dlp/dlp-sanitizer.test.js' },                 // §13
  { kind: 'node-test', file: 'dist/engine/entity/EntityResolver.test.js' },
  { kind: 'node-test', file: 'dist/engine/logger.chariot-log-level.test.js' },          // §20::8
  { kind: 'node-test', file: 'dist/engine/eval/proof/adversarial.test.js' },
  { kind: 'node-test', file: 'dist/engine/eval/proof/auth-segment.test.js' },           // §4.5 requiresCustomerAuth segment
  { kind: 'node-test', file: 'dist/engine/eval/proof/firstcall.test.js' },              // §4.5::12
  { kind: 'node-test', file: 'dist/engine/eval/proof/metrics.test.js' },
  { kind: 'node-test', file: 'dist/engine/eval/proof/agentcore-retriever.test.js' }, // §4.5/§23 AgentCore Gateway competitor target
  { kind: 'node-test', file: 'dist/engine/eval/proof/run-proof.round.test.js' }, // ndcgAtK rounding in roundPerQuery
  { kind: 'node-test', file: 'dist/engine/eval/routing-eval-gc.test.js' },              // §4.5 G-C-grade exact tool_id assertion
  { kind: 'node-test', file: 'dist/engine/federation/AdapterCatalog.atomic-swap.test.js' }, // §5.5::14/15/17
  { kind: 'node-test', file: 'dist/engine/federation/AdapterCatalog.registry-bundle-fallback.test.js' }, // §5.4::5
  // §5.6 admission — the shared-classifier admission fix. The shared classifier
  // is the SINGLE implementation the clause mandates at CHARIOT-SPEC.md:436, so
  // these two files gate both the adapter-catalog and retrieval admission paths
  // at once.
  { kind: 'node-test', file: 'dist/engine/federation/catalogAdmission.test.js' }, // §5.6::423-424/428-434
  { kind: 'node-test', file: 'dist/engine/federation/AdapterCatalog.restart-readmission.test.js' }, // §5.6::431/457/458
  { kind: 'node-test', file: 'dist/engine/federation/AdapterCatalog.materialized-at.test.js' }, // §3.6::1
  { kind: 'node-test', file: 'dist/catalog/VerifiedCatalog.test.js' }, // §5.2::1-5 catalog-wide trust state machine (CH-02, rulings item 14)
  { kind: 'node-test', file: 'dist/engine/federation/AdapterCatalog.test.js' }, // §5.2::1-5 state wiring — no-throw invalid + empty effective catalog (CH-02, rulings item 14)
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.catalog-state.test.js' }, // §5.2::1-5 production load path (loadAllAdaptersWithState) + §5.2::5 retrieval-triggered invalidation (CH-02, rulings item 14, gate v2)
  { kind: 'node-test', file: 'dist/cli/paths.artifact-dirs.test.js' }, // §3.1::5/6/7/8
  { kind: 'node-test', file: 'dist/catalog/cache.test.js' }, // §3.1::7
  { kind: 'node-test', file: 'dist/engine/logger.file-sink.test.js' }, // §3.1::8
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.artifact-dirs.test.js' }, // §3.1::5/6
  { kind: 'node-test', file: 'dist/engine/retrieval/sealedShardConfig.test.js' }, // §5.7::1-52 operator config resolution
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.sealed-shard.test.js' }, // §5.7 loadShard wiring, fail-closed
  { kind: 'node-test', file: 'dist/license/seal-secret.test.js' }, // §5.7 per-licence seal_secret root: envelope, activate, renewal carry-forward
  { kind: 'node-test', file: 'dist/cli/offline-kit.test.js' }, // offline kit install: sha256 verify-before-copy, traversal, licence via activate
  { kind: 'node-test', file: 'dist/engine/bin/build-edgeshard-snapshot.test.js' }, // §5.7 producer: seal scope, population, drift
  { kind: 'node-test', file: 'dist/engine/bin/build-edgeshard-snapshot.capability-records.test.js' }, // CH-62 capability records
  { kind: 'node-test', file: 'dist/engine/bin/build-edgeshard-snapshot.dense-contract.test.js' }, // §23.2::181 dense max length, BIEN §9 pin
  { kind: 'node-test', file: 'dist/engine/bin/build-edgeshard-snapshot.recipient-license.test.js' }, // §5.7 recipient licence refusals
  { kind: 'node-test', file: 'dist/engine/bin/build-edgeshard-snapshot.sparse-contract.test.js' }, // §5.6 sparse artifact pin + native graph admission at load
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.sealed-shard-staging.test.js' }, // §5.7 gate F1/F2 staging/TOCTOU
  { kind: 'node-test', file: 'dist/engine/federation/AdaptivePool.defaults.test.js' },  // §7.3::3
  { kind: 'node-test', file: 'dist/engine/federation/ConnectionPool.max-connections.test.js' }, // §7.3::1
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.annotation-gate.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.egress-default-allowlist.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.unload-sandbox-teardown.test.js' }, // §7.6::2
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.non-idempotent-no-retry.test.js' }, // AS::§2.5::5
  { kind: 'node-test', file: 'dist/engine/federation/ToolPreFilter.select-async.test.js' },
  { kind: 'node-test', file: 'dist/no-console-in-server-code.test.js' }, // production logging guard (createLogger, never console.*)
  { kind: 'node-test', file: 'dist/engine/federation/ToolPreFilter.warn-coalesce.test.js' }, // CHARIOT::§4.1::14 one WARN per query
  { kind: 'node-test', file: 'dist/engine/federation/QueryExpander.catalog-driven.test.js' }, // CHARIOT::§4.6::1 catalog keywords expansion
  { kind: 'node-test', file: 'dist/engine/server/QueryExpander.call-site-opt-in.test.js' }, // CHARIOT::§4.6::2 expansion opt-in per call site
  { kind: 'node-test', file: 'dist/engine/no-domain-classifier-tier0.test.js' }, // CHARIOT::§4.7::1 DomainClassifier/Tier-0 absence guard
  { kind: 'node-test', file: 'dist/engine/federation/ToolPreFilter.stopwords.test.js' }, // §4.2::3
  { kind: 'node-test', file: 'dist/engine/federation/ToolPreFilter.official-partition.test.js' }, // BIEN::§7a — every selectInternal exit path partitions before its own truncation
  { kind: 'node-test', file: 'dist/engine/federation/ToolPreFilter.overlay-tool-resolution.test.js' }, // §8.6a — overlay: candidate resolution via TenantOverlayToolRegistry
  { kind: 'node-test', file: 'dist/engine/federation/sandbox/ProcessSandbox.rss-cap.test.js' }, // §7.4::6
  { kind: 'node-test', file: 'dist/engine/orchestrator/Orchestrator.out-of-selection-tool.test.js' }, // §8.2::2
  { kind: 'node-test', file: 'dist/engine/orchestrator/OrchestratorProvider.autoProbe.test.js' }, // CHARIOT::§8.3::1-2 provider:'auto' probe order + Ollama deprecation window
  { kind: 'node-test', file: 'dist/engine/orchestrator/Orchestrator.persona-context-wiring.test.js' }, // CHARIOT::§8.4::3 memory/tool context reaches SystemPromptBuilder on the dispatch path
  { kind: 'node-test', file: 'dist/engine/persona/SystemPromptBuilder.test.js' }, // CHARIOT::§8.4::1-3, §8.4.1::1
  { kind: 'node-test', file: 'dist/engine/retrieval/loadRetrieval.epoch-replay-log.test.js' }, // §5.6::17
  { kind: 'node-test', file: 'dist/engine/retrieval/VectorIndexVerifier.ch62.test.js' }, // CH-62 (§23.2::110-134) capability-record gate + widened record-count
  { kind: 'node-test', file: 'dist/engine/retrieval/VectorIndexVerifier.dispatch-identity.test.js' }, // CHARIOT::§3.5a admission-time tool-level dispatch identity gate
  { kind: 'node-test', file: 'dist/engine/server/ClaimValidator.test.js' },
  { kind: 'node-test', file: 'dist/engine/server/transports/tlsServer.test.js' },
  { kind: 'node-test', file: 'dist/license/renew-client.destination.test.js' },         // §1.4::11 / §19::2
  { kind: 'node-test', file: 'dist/observability/emitter.brute-force-lockout.test.js' }, // §10.7::5 / §19::22
  // ── Registered 2026-07-22: 23 evals that existed on disk gated by NOTHING ──
  // Surfaced by the reconciliation gate below as PRESENT-BUT-UNREGISTERED. Each
  // was written, landed in test/, and never added to this roll call — so it ran
  // for nobody. Same silent-coverage-loss family as the four retrieval
  // evals and the ten struck entries, in the opposite direction: file
  // present, name absent. Kind chosen per file by whether it imports node:test.
  { kind: 'node',      file: 'test/anomaly-detection.mjs' },
  { kind: 'node',      file: 'test/arg-extraction-closure.mjs' },
  { kind: 'node',      file: 'test/autonomy-approval-queue.mjs' },
  { kind: 'node',      file: 'test/autonomy-policy-engine.mjs' },
  { kind: 'node',      file: 'test/autonomy-tiered.mjs' },
  { kind: 'node',      file: 'test/canonical-json.mjs' },
  { kind: 'node-test', file: 'test/cli-bridge-dispatch-edge-cases.mjs' },
  { kind: 'node',      file: 'test/dlp-inspector.mjs' },
  { kind: 'node',      file: 'test/dlp-patterns.mjs' },
  { kind: 'node',      file: 'test/hash-chain.mjs' },
  { kind: 'node',      file: 'test/iam-id-jag-dpop.mjs' },
  { kind: 'node',      file: 'test/iam-id-jag-issuer.mjs' },
  { kind: 'node',      file: 'test/iam-id-jag-registries.mjs' },
  { kind: 'node',      file: 'test/iam-id-jag-routes.mjs' },
  { kind: 'node',      file: 'test/iam-id-jag-validator.mjs' },
  // The 47-hard-gate ID-JAG flow eval. Its own header says "This is the gate
  // `npm test` invokes" — that was FALSE: it was never registered here, so the
  // end-to-end ID-JAG gate silently stopped running. Its last recorded result
  // was 2026-06-18 (last-run-report.json). Re-verified 47/47 on 2026-07-28 and
  // registered. This is the harness that actually proves the protocol
  // end-to-end (real HTTP token issuance, bearer use on a tool, replay/JWKS
  // -rotation/cross-tenant rejection) against the local mock IdP.
  { kind: 'node',      file: 'test/id-jag-flow-eval-may-2026/validate.mjs' },
  // XAA structural-compatibility lock against the xaa.dev published metadata.
  // Self-skips with exit 0 unless CHARIOT_TEST_ALLOW_HTTP_LOOPBACK=1, so it is
  // safe to register unconditionally. It was previously UNREGISTERED, which
  // meant the one harness that pins Chariot's ID-JAG wire shape to the
  // interop target never ran in CI at all. NOTE its own disclaimer: it is
  // STRUCTURAL ONLY — it does not perform an end-to-end exchange against
  // xaa.dev, which needs external app registration and public reachability.
  { kind: 'node',      file: 'test/id-jag-flow-eval-may-2026/run-xaa-compatibility.mjs' },
  { kind: 'node',      file: 'test/iam-subject-mutex.mjs' },
  { kind: 'node-test', file: 'test/infobip-send-sms-schema.mjs' },
  { kind: 'node',      file: 'test/license-jwt-verify.mjs' },
  { kind: 'node',      file: 'test/manifest-prepublish-gate.mjs' },
  { kind: 'node-test', file: 'test/seat-reservation.mjs' },
  { kind: 'node',      file: 'test/security-fix-evals.mjs' },
  { kind: 'node',      file: 'test/simplify-coverage.mjs' },
  { kind: 'node',      file: 'test/virtual-catalog.mjs' },
  // ── aa3570e adversarial evals (src/*.test.ts → compiled to dist/) ──────────
  { kind: 'node-test', file: 'dist/engine/audit/hash-chain-tamper.test.js' },
  { kind: 'node-test', file: 'dist/engine/audit/append-failure-no-corruption.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/adapters/mcp-timeout.test.js' },
  // CHARIOT::§8.11::2 — api-profile harness canonical tool list conformance
  // (list/search/read/write-shadow/delete-shadow/error-handling/auth-failure/rate-limit).
  { kind: 'node-test', file: 'dist/engine/harness/shared/toolDefs.test.js' },
  // MCP dispatch fetch suppresses the SDK standalone GET SSE stream.
  { kind: 'node-test', file: 'dist/engine/federation/mcpDispatchFetch.test.js' },
  { kind: 'node-test', file: 'dist/bin/audit-cli-reachable.test.js' },
  { kind: 'node-test', file: 'dist/engine/audit/derive-env-key-verify-anchor.test.js' },
  // Chariot 4.0.0 observability/audit gap closure (Wiz practices 2/5/7).
  { kind: 'node-test', file: 'dist/observability/anomaly/scope-violation.test.js' },
  // Chariot 4.0.0 dispatch/authz reachability closure (feeds #7, #15).
  { kind: 'node-test', file: 'dist/engine/audit/serve-audit-attribution.test.js' },
  // §9.6/§9.8 audit-export streaming + anchor-store-path/filename + cadence
  // startup-warning + tail-truncation-on-export closure.
  { kind: 'node-test', file: 'dist/engine/audit/anchor.store-path-filename.test.js' },     // §9.8.2::5/6
  { kind: 'node-test', file: 'dist/engine/audit/auditCadence.warning-not-throw.test.js' }, // §9.8.4::2/4
  { kind: 'node-test', file: 'dist/engine/audit/length-attestation.reconcile.test.js' },   // §9.8.3::4
  { kind: 'node-test', file: 'dist/engine/audit/length-attestation.verify-shape.test.js' }, // §9.8.3::3
  { kind: 'node-test', file: 'dist/engine/audit/chainSigner.test.js' },                 // CHARIOT::§9.8.1 key custody
  { kind: 'node-test', file: 'dist/engine/audit/keyRotation.test.js' },                  // CHARIOT::§9.8.1::3 rotation
  { kind: 'node-test', file: 'dist/engine/audit/auditCadence.chainSigner.test.js' },     // CHARIOT::§9.8.1::1 live cadence wiring
  { kind: 'node-test', file: 'dist/engine/audit/length-attestation.multikey.test.js' },  // CHARIOT::§9.8.1::3 live multi-key verify
  { kind: 'node-test', file: 'dist/engine/audit/verifyKeyStore.test.js' },            // CHARIOT::§9.8.1::3 verify-key store (F2)
  { kind: 'node-test', file: 'dist/engine/audit/custodyCheck.test.js' },               // CHARIOT::§9.8.1::2 custody check (F4)
  { kind: 'node-test', file: 'dist/bin/audit-rotate-key.test.js' },                     // CHARIOT::§9.8.1::3 rotate-key CLI
  { kind: 'node-test', file: 'dist/bin/audit-verify-length-rotation.test.js' },   // CHARIOT::§9.8.1::3 verify-length reads the store
  { kind: 'node-test', file: 'dist/iam/routes/admin.audit-logs-export.test.js' },          // §9.6::1 / §9.8.3::4
  { kind: 'node-test', file: 'dist/iam/verified-catalog-pending-filter.test.js' },
  // Chariot 4.0.0 human/agent/service principal partition (Wiz gap #3).
  { kind: 'node-test', file: 'dist/iam/principal-partition.test.js' },
  // Durable memory (chariot_remember) survives a serve restart.
  { kind: 'node-test', file: 'dist/engine/memory/adapters/FileStore.test.js' },
  // Oversize-file reporting and config content-disclosure oracle —
  // discovery honest-signal + input-validation regressions
  // (CH-31, CHARIOT::§23.2::45).
  { kind: 'node-test', file: 'dist/discovery/discovery-security.test.js' },
  // The TS seam must represent the full Rust NAPI contract for the
  // sealed-snapshot boundary (anti-rollback minEpoch, verify-before-load receipt).
  // Lives in evals/ (repo-only): it reads native/src/*.rs, which package.json
  // `files:` does not ship and .npmignore:19 excludes — a dist/ copy would throw
  // for every consumer.
  { kind: 'node-test', file: 'evals/napi-seam-conformance.mjs' },
  // AS::§3.1.1::2 — offline-verifier tamper-rejection (throwaway Ed25519
  // fixture key; flips one byte of one shipped record post-signature).
  { kind: 'node-test', file: 'dist/engine/keys/verifyCatalogSignature.tamper-rejection.test.js' },
  // CHARIOT::§5.1::9 / §8.6::37 (CH-52) — the compiled-in rotation set pins the
  // KMS-custodied production key first and the prior production key for the
  // dual-sign cycle; the kill-list watcher walks the same set.
  { kind: 'node-test', file: 'dist/engine/keys/chariot-catalog-public.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/KillListWatcher.rotation-set.test.js' },
  // FPS §7.2.6 consumer lockstep — chariot-adapter-bundle.json's
  // version-selected compact-payload verify path (rulings item 85).
  { kind: 'node-test', file: 'dist/engine/keys/canonicalize.test.js' },
  { kind: 'node-test', file: 'dist/engine/keys/verifyCatalogSignature.compact-payload.test.js' },
  // ── Registered 2026-07-31: CH-10 / §12.2 credential-vault AAD binding ──
  // (tenantId ‖ adapterId) — proves the TS↔Rust plumbing end-to-end against
  // the real native binary and is the relocation-attack prove-on-revert.
  { kind: 'node-test', file: 'dist/iam/crypto.aad-binding.test.js' },
  // ── Registered 2026-09-04: CHARIOT::§12.2/CH-10 rulings item 59 ──
  // upgrade-on-decrypt, hard cutover (env-based refusal triggers), and
  // the v2-prefix-safe splitEncryptedIv fix.
  { kind: 'node-test', file: 'dist/iam/crypto.ch10-cutover.test.js' },
  { kind: 'node-test', file: 'dist/engine/recovery/SqliteCheckpointStore.ch10-legacy-allowed.test.js' },
  { kind: 'node-test', file: 'dist/iam/vaultMigrationSites.coverage.test.js' },
  { kind: 'node-test', file: 'dist/iam/vaultMigrate.seed-all-sites.test.js' },
  // ── Registered 2026-09-04: CHARIOT::§12.2/CH-10 rulings item 59 ──
  // per-site concurrent-upgrade (CAS no-op) + write-failure proofs.
  { kind: 'node-test', file: 'dist/iam/credential-loader.concurrent-upgrade.test.js' },
  { kind: 'node-test', file: 'dist/iam/routes/oidc.concurrent-upgrade.test.js' },
  { kind: 'node-test', file: 'dist/iam/services/id-jag-client.concurrent-upgrade.test.js' },
  { kind: 'node-test', file: 'dist/iam/services/session.casSetWithTtl.concurrent-upgrade.test.js' },
  { kind: 'node-test', file: 'dist/engine/audit/auditFs.atomicOverwriteIfUnchanged.concurrent-upgrade.test.js' },
  { kind: 'node-test', file: 'dist/iam/masterKeyConsumers.test.js' }, // CHARIOT::§12.2::10/11/12 — master-key length floor + domain-separation registry

  // ── Registered 2026-09-03: CHARIOT::§7.5/§7.6/§7.7 revocation wiring ──
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.revocation-audit.test.js' },
  { kind: 'node-test', file: 'dist/engine/autonomy/ApprovalQueue.cancel-by-server.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/KillListWatcher.no-feed.test.js' },
  { kind: 'node-test', file: 'dist/engine/federation/RegistryLoader.wire-and-reload.test.js' },
  // ── Registered 2026-09-04: CHARIOT::§7.5::1/§7.6::1/§7.7::2 gate-fix
  // follow-up (F1-F4) — engine-startup wiring, union revocation set, and
  // the Redis-backed ApprovalQueue.cancelByServer() path.
  { kind: 'node-test', file: 'dist/engine/EpicAI.startup-wiring.test.js' },
  { kind: 'node-test', file: 'dist/engine/autonomy/adapters/RedisQueue.cancel-by-server.test.js' },
  // ── Registered 2026-09-04 (gate round 2): CHARIOT::§7.5::1/§7.6::1
  // F5 (shared ToolPreFilter) + F6 (in-flight dedupe + serialized
  // catalog reconciliation) follow-up fixes.
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.catalog-reconcile-serialization.test.js' },
  { kind: 'node-test', file: 'dist/catalog/VerifiedCatalog.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/EpicAI.sessionid-transport.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/EpicAI.token-usage-registration.test.js' }, // 2026-09-04 W34-4c builder test — CHARIOT::§16.3::1 / gate finding 114(i)
  { kind: 'node-test', file: 'dist/engine/autonomy/TieredAutonomy.emitter.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/autonomy/TieredAutonomy.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/bin/setup.sighup-renewal.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/federation/FederationManager.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/observability/OpenTelemetry.otlp-exporter.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/observability/RunTelemetry.pinned-fields.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/observability/TokenTracker.dimensions.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/orchestrator/Orchestrator.mfa-generator-invalidation.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/orchestrator/Orchestrator.telemetry-instantiation.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/resilience/RateLimiter.emitter.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/engine/federation/CustomerAuthOverlay.test.js' }, // CHARIOT-SPEC §8.6a customer-credential connect; AS §3.2 G10 parity — build-133b, 2026-09-05
  { kind: 'node-test', file: 'dist/engine/federation/TenantOverlayToolRegistry.test.js' }, // CHARIOT-SPEC §8.6a tenant overlay tool registry — build-133b, 2026-09-05
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.customer-auth-overlay.test.js' }, // CHARIOT-SPEC §8.6a dispatch-boundary wiring + tenant overlay tool registry — build-133b, 2026-09-05
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.oauth2-header.test.js' }, // rulings item 196 — oauth2 Authorization header on ordinary MCP dispatch — build-133b, 2026-09-05
  { kind: 'node-test', file: 'dist/iam/routes/adapters.client-auth.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/routes/admin.metrics-route.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/routes/authEvents.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/routes/index.scim-fallback.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/services/credentials.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/services/mfa.assertion-epoch.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/services/mfa.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/services/telemetry-consent.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/license/loader.grace-alert-dedup.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/license/loader.invalidate-cache.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/license/loader.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/license/renew-client.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/alertChannels.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/emitter.taxonomy-adoption.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/metrics.autonomy-tokens.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/tokenUsageRegistry.test.js' }, // 2026-09-04 W34-4c builder test — CHARIOT::§16.3::1 / gate finding 114(i)
  { kind: 'node-test', file: 'dist/observability/operational-telemetry/capture.default-off.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/operational-telemetry/egress-guard.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/observability/operational-telemetry/redact.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  // C4AMD §8 telemetry amendment 2026-10-12 (MASTER: "Approve all three, wire the telemetry commands."): local store, capture on the local store, upload client, agent-operable CLI.
  { kind: 'node-test', file: 'dist/observability/operational-telemetry/local-store.test.js' },
  { kind: 'node-test', file: 'dist/observability/operational-telemetry/capture.local.test.js' },
  { kind: 'node-test', file: 'dist/telemetry-upload/uploader.test.js' },
  { kind: 'node-test', file: 'dist/cli/telemetry.test.js' },
  { kind: 'node-test', file: 'dist/cli/telemetry.export.test.js' },
  { kind: 'node-test', file: 'dist/observability/prometheusRoute.test.js' }, // 2026-09-04 wave-1 builder test (registered by the lead; clause ids in the file header)
  { kind: 'node-test', file: 'dist/iam/services/auditEvents.taxonomy-adoption.test.js' }, // 2026-09-04 W34-1b builder test — CHARIOT::§16.1 Audit
  { kind: 'node-test', file: 'dist/engine/server/ChariotState.catalogEvents.taxonomy-adoption.test.js' }, // 2026-09-04 W34-1b builder test — CHARIOT::§16.1 Catalog
  { kind: 'node-test', file: 'dist/engine/gateway/operationalEvents.taxonomy-adoption.test.js' }, // 2026-09-04 W34-1b builder test — CHARIOT::§16.1 Operational
  { kind: 'node-test', file: 'dist/observability/alertDispatchWiring.test.js' }, // 2026-09-04 W34-2b builder test — CHARIOT::§16.2 live dispatch
  { kind: 'node-test', file: 'dist/engine/server/transports/rest.metrics.taxonomy-adoption.test.js' }, // 2026-09-04 W34-3b builder test — CHARIOT::§16.3 REST /metrics
  { kind: 'node-test', file: 'dist/engine/federation/KillListWatcher.retired.taxonomy-adoption.test.js' }, // 2026-09-04 W34-1c builder test — CHARIOT::§16.1 adapter.retired (renamed per rulings item 121, repo leak-denylist collision on the original spec wording)
  { kind: 'node-test', file: 'dist/bin/chariot.discoverEvents.taxonomy-adoption.test.js' }, // 2026-09-04 W34-1c builder test — CHARIOT::§16.1 Discovery, discover CLI subcommand
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.systemPrincipal.taxonomy-adoption.test.js' }, // 2026-09-04 W34-2c builder test — CHARIOT::§16.2 alert-dispatch system principal
  { kind: 'node-test', file: 'dist/observability/alertDispatchWiring.skip.taxonomy-adoption.test.js' }, // 2026-09-04 W34-2c builder test — CHARIOT::§16.2 gate finding (d) skipped-channel-never-silent
  { kind: 'node-test', file: 'dist/engine/server/toolHandlers.pendingAlerts.taxonomy-adoption.test.js' }, // 2026-09-04 W34-2d builder test — CHARIOT::§16.2 step 4 conversational-queue consumer
  { kind: 'node-test', file: 'dist/iam/redactConnectionString.test.js' }, // 2026-09-04 W-IAM-REDACT builder test — rulings item 126, connection-string redaction
  { kind: 'node-test', file: 'dist/iam/redactConnectionString.leak-guard.test.js' }, // 2026-09-04 W-IAM-REDACT builder test — rulings item 126, repo-wide unredacted-interpolation grep guard
];

// ── Eval-manifest reconciliation gate  ──────────────────────────────
//
// This roll call is version-controlled; the evals it names are NOT — `test/` is
// gitignored (.gitignore:75), and the private eval home
// (the private eval repo) gitignores its tree too, so files there
// must be force-added. That asymmetry produced two silent coverage losses:
//
//   * NAMED-BUT-ABSENT — a feature commit adds an entry here while the eval
//     file itself cannot be committed. The file later vanishes from a checkout,
//     `run()` returns rc=127, and the quickest way back to green is to delete
//     the entry — the one action that erases the only record of the loss.
//     Ten entries were struck this way; eight of them existed in NO repository.
//   * PRESENT-BUT-UNREGISTERED — an eval sits on disk named by nobody. Four
//     retrieval evals did, so the whole Tier-1 subsystem went unexercised while
//     the suite reported green .
//
// This gate runs BEFORE any test and is deliberately NOT an ENTRIES row, so it
// cannot be silenced by deleting a line from the list. It reconciles three
// sets: the roll call, the working tree, and the durable eval repo.
function reconcileEvalManifest() {
  const findings = { namedButAbsent: [], presentButUnregistered: [], notDurable: [] };
  const registered = new Set(ENTRIES.map((e) => e.file));

  for (const f of registered) {
    if (!existsSync(f)) findings.namedButAbsent.push(f);
  }

  // Unregistered evals sitting directly in test/ (not the nested eval suites,
  // which are driven by their own validate.mjs entries).
  try {
    for (const name of readdirSync('test')) {
      if (!name.endsWith('.mjs')) continue;
      const rel = `test/${name}`;
      if (!registered.has(rel)) findings.presentButUnregistered.push(rel);
    }
  } catch { /* no test/ dir in this checkout — the exists check above still fires */ }

  // Durability: every registered eval under test/ should also live in the
  // private eval repo, which is the only version-controlled home it has. Skipped
  // when that repo is not checked out beside us (a consumer clone, CI without it).
  const EVAL_REPO = process.env.CHARIOT_EVAL_REPO;
  if (existsSync(EVAL_REPO)) {
    for (const f of registered) {
      if (!f.startsWith('test/') || !existsSync(f)) continue;
      if (!existsSync(`${EVAL_REPO}/${f}`)) findings.notDurable.push(f);
    }
  }
  return findings;
}

const manifest = reconcileEvalManifest();
if (manifest.namedButAbsent.length || manifest.presentButUnregistered.length || manifest.notDurable.length) {
  console.log('──────── EVAL MANIFEST RECONCILIATION  ────────');
  for (const f of manifest.namedButAbsent) {
    console.log(`  NAMED-BUT-ABSENT      ${f}  — registered here, missing from this checkout. Recover it; do NOT delete the entry.`);
  }
  for (const f of manifest.presentButUnregistered) {
    console.log(`  PRESENT-BUT-UNREGISTERED  ${f}  — on disk, gated by nothing. Register it or delete the file.`);
  }
  for (const f of manifest.notDurable) {
    console.log(`  NOT-DURABLE           ${f}  — absent from the private eval repo. One 'rm' from gone; git add -f it there.`);
  }
  console.log('');
}

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
