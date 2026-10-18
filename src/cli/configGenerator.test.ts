/**
 * @epicai/chariot — tests for src/cli/configGenerator.ts
 * CHARIOT::§17.2::14
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderConfigFile, validateGeneratedConfig } from './configGenerator.js';
import type { AdapterEntry } from '../engine/server/ChariotState.js';

const stdioAdapter = {
  id: 'pubmed',
  name: 'PubMed',
  mcp: { transport: 'stdio', packageName: 'com-claude-mcp-pubmed-pubmed' },
} as AdapterEntry;

const restOnlyAdapter = {
  id: 'stripe',
  name: 'Stripe',
  rest: { baseUrl: 'https://api.stripe.com' },
} as AdapterEntry;

describe('renderConfigFile — CHARIOT::§17.2::14', () => {
  it('produces syntactically valid TypeScript for an empty selection', () => {
    const source = renderConfigFile([], { pkgVersion: '4.0.0' });
    assert.deepEqual(validateGeneratedConfig(source), []);
  });

  it('produces syntactically valid TypeScript for a mixed selection', () => {
    const source = renderConfigFile([stdioAdapter, restOnlyAdapter], { pkgVersion: '4.0.0' });
    assert.deepEqual(validateGeneratedConfig(source), []);
  });

  it('emits an npx --no-install server entry for a stdio adapter, pinned to the given version', () => {
    const source = renderConfigFile([stdioAdapter], { pkgVersion: '4.0.0' });
    assert.ok(source.includes('"command": "npx"'));
    assert.ok(source.includes('"--no-install"'));
    assert.ok(source.includes('com-claude-mcp-pubmed-pubmed@4.0.0'));
  });

  it('omits a REST-only adapter from servers[] rather than guessing a command', () => {
    const source = renderConfigFile([restOnlyAdapter], { pkgVersion: '4.0.0' });
    assert.ok(!source.includes('stripe'));
  });

  it('exports Pick<EpicAIConfig, federation|autonomy|audit> only', () => {
    const source = renderConfigFile([], { pkgVersion: '4.0.0' });
    assert.ok(source.includes("Pick<EpicAIConfig, 'federation' | 'autonomy' | 'audit'>"));
    assert.ok(source.includes('federation:'));
    assert.ok(source.includes('autonomy:'));
    assert.ok(source.includes('audit:'));
    assert.ok(!source.includes('orchestrator:'));
    assert.ok(!source.includes('persona:'));
  });

  it('autonomy.tiers defaults to the fail-closed empty policy (nothing auto-approved)', () => {
    const source = renderConfigFile([], { pkgVersion: '4.0.0' });
    assert.ok(source.includes('"auto": []'));
    assert.ok(source.includes('"escalate": []'));
    assert.ok(source.includes('"approve": []'));
  });
});

describe('validateGeneratedConfig', () => {
  it('reports diagnostics for malformed source instead of throwing', () => {
    const diagnostics = validateGeneratedConfig('export const config: = {{{ broken');
    assert.ok(diagnostics.length > 0);
  });
});
