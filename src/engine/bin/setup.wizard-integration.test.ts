/**
 * @epicai/chariot — end-to-end scripted-answers integration test for the
 * setup wizard. CHARIOT::§17.2::1-20 combined.
 *
 * `paths.ts` resolves EPIC_AI_DIR (and every path derived from it) ONCE at
 * module load from EPIC_AI_DIR_OVERRIDE, and ESM import hoisting means a
 * same-process `process.env.EPIC_AI_DIR_OVERRIDE = ...` set inside this
 * file runs AFTER setup.js's imports have already resolved — so, exactly
 * like src/cli/paths.artifact-dirs.test.ts, the wizard run is driven in a
 * FRESH subprocess with the env var set on that subprocess from the start.
 *
 * The subprocess script sets two test-only hooks on `globalThis` BEFORE
 * calling the (now-exported) `runSetupWizard()`:
 *   - `__chariotTestClack`   — a scripted-answers `@clack/prompts` double,
 *     resolved by matching a substring of each prompt's `message` (see the
 *     `setup.ts` call site — the hook is read once at the top of
 *     runSetupWizard and is a no-op in every real invocation).
 *   - `__chariotTestAdapters` — a small fixture catalog standing in for
 *     `loadAllAdapters()`, so this test never depends on the real signed
 *     bundle being present/current and never makes a real network call
 *     (no fixture adapter sets `mcp.transport`, so the CHARIOT::§17.2::13
 *     connection-verification dispatcher takes its synchronous
 *     "no MCP transport" branch for all five — no timeout, no I/O).
 *
 * The AI-client multiselect answer is always `[]` — this test NEVER
 * selects a real detected client, so `writeMcpConfig` is never called and
 * nothing is ever written to the operator's real ~/.claude.json /
 * ~/.codex/config.toml / ~/.gemini/settings.json, regardless of what
 * `detectMcpClients()` finds on the host actually running this test. The
 * local-backend "have-one-running" + custom-URL answer is what satisfies
 * the wizard's own `configuredClients.length === 0` early-return gate
 * without touching any real client file.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync, statSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function runWizardScripted(): { status: number | null; stderr: string; epicAiDir: string; projectDir: string } {
  const epicAiDir = mkdtempSync(join(tmpdir(), 'chariot-wizard-epicai-'));
  const projectDir = mkdtempSync(join(tmpdir(), 'chariot-wizard-project-'));

  const setupJsUrl = new URL('./setup.js', import.meta.url).href;

  const script = `
    process.chdir(${JSON.stringify(projectDir)});
    const CANCEL = Symbol('cancel');
    function resolveFor(answers) {
      return (message, fallback) => {
        for (const key of Object.keys(answers)) {
          if (message.includes(key)) return answers[key];
        }
        return fallback;
      };
    }
    const answers = {
      'Select AI clients': [],
      'Continue anyway?': true,
      'Local AI backend:': 'have-one-running',
      'Local backend URL': 'http://localhost:19999',
      'Browse more adapters?': true,
      'Search adapters': '',
      'Select adapters to add': ['fixture-additional'],
      'FIXTURE_TEST_API_KEY': 'fixture-secret-value',
      'epic-ai.config.ts already exists': true,
    };
    const resolve = resolveFor(answers);
    globalThis.__chariotTestClack = {
      note: () => {},
      log: { info: () => {}, success: () => {}, warning: () => {}, error: () => {} },
      intro: () => {},
      outro: () => {},
      cancel: () => {},
      isCancel: (v) => v === CANCEL,
      spinner: () => ({ start: () => {}, stop: () => {}, message: () => {} }),
      select: async (opts) => resolve(opts.message, opts.initialValue),
      confirm: async (opts) => resolve(opts.message, opts.initialValue ?? false),
      multiselect: async (opts) => resolve(opts.message, opts.initialValues ?? []),
      text: async (opts) => resolve(opts.message, opts.placeholder ?? ''),
      password: async (opts) => resolve(opts.message, ''),
    };
    globalThis.__chariotTestAdapters = [
      { id: 'com-claude-mcp-pubmed-pubmed', name: 'PubMed', type: 'mcp' },
      { id: 'govbase-mcp', name: 'Govbase', type: 'mcp' },
      { id: 'searchcode', name: 'Searchcode', type: 'mcp' },
      { id: 'robtex', name: 'Robtex', type: 'mcp' },
      { id: 'fixture-additional', name: 'Fixture Additional', type: 'mcp', category: 'Test', mcp: { envKeys: ['FIXTURE_TEST_API_KEY'] } },
    ];
    const { runSetupWizard } = await import(${JSON.stringify(setupJsUrl)});
    await runSetupWizard();
    process.stdout.write('WIZARD_DONE\\n');
  `;

  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    encoding: 'utf-8',
    timeout: 30_000,
    env: { ...process.env, EPIC_AI_DIR_OVERRIDE: epicAiDir, CHARIOT_NON_INTERACTIVE: '0' },
  });
  return { status: result.status, stderr: result.stderr, epicAiDir, projectDir };
}

describe('setup wizard — scripted end-to-end run (CHARIOT::§17.2::1-20)', () => {
  it('completes and writes every documented artifact with the right shape', () => {
    const { status, stderr, epicAiDir, projectDir } = runWizardScripted();
    try {
      assert.equal(status, 0, `wizard subprocess failed (status=${status}):\n${stderr}`);

      // CHARIOT::§17.2::14 — epic-ai.config.ts at the project root, not ~/.epic-ai.
      const configTsPath = join(projectDir, 'epic-ai.config.ts');
      assert.ok(existsSync(configTsPath), 'epic-ai.config.ts was not written to process.cwd()');
      const configTsSource = readFileSync(configTsPath, 'utf-8');
      assert.ok(configTsSource.includes("Pick<EpicAIConfig, 'federation' | 'autonomy' | 'audit'>"));

      // adapter-state.json — CHARIOT::§17.2::15.
      const statePath = join(epicAiDir, 'adapter-state.json');
      assert.ok(existsSync(statePath), 'adapter-state.json was not written');
      const state = JSON.parse(readFileSync(statePath, 'utf-8')) as {
        adapters: Record<string, { status: string }>;
      };
      for (const id of ['com-claude-mcp-pubmed-pubmed', 'govbase-mcp', 'searchcode', 'robtex']) {
        assert.ok(id in state.adapters, `curated adapter ${id} missing from adapter-state.json`);
      }
      assert.ok('fixture-additional' in state.adapters, 'additionally-picked adapter missing from adapter-state.json');

      // config.json (the HOME-dir CLI config, distinct from the per-project
      // epic-ai.config.ts) — CHARIOT::§17.2 step 7 ("Config generation").
      const configJsonPath = join(epicAiDir, 'config.json');
      assert.ok(existsSync(configJsonPath), 'config.json was not written');

      // CHARIOT::§17.2::11 — credentials land in ~/.epic-ai/.env, chmod 600.
      const envPath = join(epicAiDir, '.env');
      assert.ok(existsSync(envPath), '.env was not written for the additionally-picked adapter\'s credential');
      const envContent = readFileSync(envPath, 'utf-8');
      assert.ok(envContent.includes('FIXTURE_TEST_API_KEY=fixture-secret-value'), '.env does not contain the scripted credential');
      const envMode = statSync(envPath).mode & 0o777;
      assert.equal(envMode, 0o600, `.env mode is ${envMode.toString(8)}, expected 600`);

      // CHARIOT::§17.2::12 — credentials NEVER land under process.cwd() (the
      // project directory). Only epic-ai.config.ts is expected there.
      const projectFiles = readdirSync(projectDir);
      assert.deepEqual(projectFiles, ['epic-ai.config.ts'], `unexpected files written under process.cwd(): ${projectFiles.join(', ')}`);
    } finally {
      rmSync(epicAiDir, { recursive: true, force: true });
      rmSync(projectDir, { recursive: true, force: true });
    }
  });
});
