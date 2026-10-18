/**
 * CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
 * 91/105/112(a)/121) — "Federation: `adapter.connected`,
 * `adapter.disconnected`, `adapter.revoked`, [the adapter-retirement
 * event — `adapter.retired` in this codebase, renamed from the spec's
 * original wording per rulings item 121: a repo leak-denylist collision
 * on internal catalog-lifecycle vocabulary; customer-facing semantics
 * unchanged], `tool.dispatched`, `tool.denied`."
 *
 * SOURCE INSPECTION (this repo's established convention — see
 * admin.audit-logs-export.test.ts's header comment): `connect()`/
 * `disconnect()`/`unloadAdapter()` require a real MCP transport (stdio
 * process, streamable-http server, or a sandbox worker) to exercise
 * end-to-end; this proves each event is wired at the right place relative
 * to the existing engine-internal hooks (`observabilityEmitter
 * .emitAdapterRevoked`, `onAdapterRevoked` audit hook) it sits beside.
 *
 * The retirement event is NOT wired inside THIS file (FederationManager.ts
 * has no distinct "retire"/"demote" operation of its own) — it is wired in
 * the sibling federation file `KillListWatcher.ts`, the kill-list's own
 * runtime retirement path. See
 * `KillListWatcher.retired.taxonomy-adoption.test.ts` for that wiring's
 * own real behavioral coverage; the last test below only confirms this
 * file itself does not ALSO independently emit it (no double-count risk).
 *
 * Run (after tsc): node --test dist/engine/federation/FederationManager.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fmSrc = readFileSync(fileURLToPath(new URL('./FederationManager.js', import.meta.url)), 'utf8');

test('§16.1 Federation: connect() emits adapter.connected only AFTER listTools()/registerServer() succeed', () => {
  const connectIdx = fmSrc.indexOf('async connect(');
  const registerIdx = fmSrc.indexOf('this.registry.registerServer(name, tools)', connectIdx);
  const emitIdx = fmSrc.indexOf("chariotEmitter.send('adapter.connected'", connectIdx);
  assert.ok(connectIdx >= 0 && registerIdx > connectIdx && emitIdx > registerIdx, 'adapter.connected must be emitted after tool registration, not before setup could still fail');
});

test('§16.1 Federation: the plain disconnect() emits adapter.disconnected unconditionally (sandboxed and pool-backed branches alike)', () => {
  const disconnectIdx = fmSrc.indexOf('async disconnect(name: string)'.replace(': string', '')); // compiled JS has no type annotation
  // Locate by the distinctive body content instead, since types are erased.
  const start = fmSrc.indexOf('async disconnect(name) {');
  assert.ok(start >= 0, 'disconnect(name) must exist in compiled output');
  const end = fmSrc.indexOf('async disconnectAll()', start);
  const body = fmSrc.slice(start, end);
  assert.match(body, /chariotEmitter\.send\('adapter\.disconnected'/, 'disconnect() must emit adapter.disconnected');
  void disconnectIdx;
});

test('§16.1 Federation: _unloadAdapterImpl emits adapter.disconnected for every successful unload (revoked or not)', () => {
  const start = fmSrc.indexOf('_unloadAdapterImpl(name, reason, options)');
  assert.ok(start >= 0, '_unloadAdapterImpl must exist');
  const cleanDisconnectIdx = fmSrc.indexOf('this.adapterMap.delete(name)', start);
  const emitIdx = fmSrc.indexOf("chariotEmitter.send('adapter.disconnected'", cleanDisconnectIdx);
  const revokedBlockIdx = fmSrc.indexOf('if (options.revoked)', start);
  assert.ok(emitIdx > cleanDisconnectIdx && emitIdx < revokedBlockIdx, 'adapter.disconnected must fire once, after the clean-disconnect point, BEFORE the revoked-only branch — so it fires for both revoked and non-revoked unloads exactly once');
});

test('§16.1 Federation: the revoked branch emits adapter.revoked alongside (not instead of) the existing observabilityEmitter/audit hooks', () => {
  const revokedBlockIdx = fmSrc.indexOf('if (options.revoked)');
  assert.ok(revokedBlockIdx >= 0);
  const revokedBlock = fmSrc.slice(revokedBlockIdx, revokedBlockIdx + 3000);
  const obsIdx = revokedBlock.indexOf('emitAdapterRevoked');
  const chariotIdx = revokedBlock.indexOf("chariotEmitter.send('adapter.revoked'");
  const auditHookIdx = revokedBlock.indexOf('this.onAdapterRevoked');
  assert.ok(obsIdx >= 0 && chariotIdx > obsIdx, 'chariotEmitter.send(adapter.revoked) must come after the existing internal observabilityEmitter call, not replace it');
  assert.ok(auditHookIdx > chariotIdx, 'the audit-chain onAdapterRevoked hook must still run after the customer-facing emit — neither replaces the other');
});

test('§16.1 Federation: tool.dispatched and tool.denied are wired in toolHandlers.ts (the process-wide dispatch path), not here', () => {
  const toolHandlersSrc = readFileSync(fileURLToPath(new URL('../server/toolHandlers.js', import.meta.url)), 'utf8');
  assert.match(toolHandlersSrc, /chariotEmitter\.send\('tool\.dispatched'/);
  assert.match(toolHandlersSrc, /chariotEmitter\.send\('tool\.denied'/);
  // And FederationManager.callTool itself (the per-session orchestrator
  // path, distinct from toolHandlers' process-wide path — see
  // src/engine/EpicAI.ts:308, FederationManager is constructed per
  // EpicAIAgentImpl instance) is NOT where these are wired, by design:
  // wiring both would double-count a call that goes through EpicAI's
  // orchestrator (which calls FederationManager.callTool AFTER its own
  // autonomy/RBAC gate, a distinct decision point from toolHandlers.ts's).
  assert.doesNotMatch(fmSrc, /chariotEmitter\.send\('tool\.dispatched'/);
  assert.doesNotMatch(fmSrc, /chariotEmitter\.send\('tool\.denied'/);
});

test('§16.1 Federation: FederationManager.ts itself never emits the adapter-retirement event (wired exclusively in KillListWatcher.ts — no double-count)', () => {
  assert.doesNotMatch(fmSrc, /chariotEmitter\.send\('adapter\.retired'/, 'the retirement event must be wired in exactly one place (KillListWatcher.ts), not duplicated here');
});
