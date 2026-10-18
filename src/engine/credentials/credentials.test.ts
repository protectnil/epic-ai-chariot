/**
 * Credentials outside the chat — CredentialPortal, ensureCredentials,
 * credentialPrompter, serverInstructions.
 *
 * Failure classes (derived from the design, not the implementation):
 *   portal:   wrong host (rebinding) / wrong path / wrong method / foreign origin /
 *             wrong content type / oversize body / missing key / control char /
 *             unrequested key / store throws / replay after success / TTL / bad-request cap
 *   ensure:   nothing missing / missing + no prompter / pending / declined /
 *             stored but still missing / prompter throws
 *   prompter: no URL-elicitation capability / accept / decline / elicit throws / dedupe
 *   instructions: names exactly the three tools; never invites pasting a secret
 *
 * Run (after tsc): node --test dist/engine/credentials/credentials.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';

import { startCredentialPortal, type PortalSession } from './CredentialPortal.js';
import { ensureCredentials, missingCredentialKeys, type CredentialPrompter } from './ensureCredentials.js';
import { createCredentialPrompter, type ElicitingServer } from './credentialPrompter.js';
import { CHARIOT_SERVER_INSTRUCTIONS } from '../server/serverInstructions.js';

interface Reply { status: number; headers: Record<string, string | string[] | undefined>; body: string }

function http(
  url: string,
  opts: { method?: string; path?: string; host?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Reply> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: u.hostname,
        port: u.port,
        path: opts.path ?? u.pathname,
        method: opts.method ?? 'GET',
        headers: { ...(opts.host !== undefined ? { Host: opts.host } : {}), ...(opts.headers ?? {}) },
      },
      (res) => {
        let b = '';
        res.on('data', (c: Buffer) => { b += c.toString('utf8'); });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
      },
    );
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

async function portal(extra: Partial<Parameters<typeof startCredentialPortal>[0]> = {}) {
  const stored: Array<[string, string]> = [];
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['ACME_API_KEY'],
    store: (k, v) => { stored.push([k, v]); },
    ...extra,
  });
  return { session, stored };
}

test('portal binds loopback only and the token path is 256-bit', async () => {
  const { session } = await portal();
  try {
    const u = new URL(session.url);
    assert.equal(u.hostname, '127.0.0.1');
    assert.match(u.pathname, /^\/c\/[A-Za-z0-9_-]{43}$/);
  } finally { session.close(); }
});

test('portal GET serves the form with strict headers; secrets are never in the page', async () => {
  const { session } = await portal();
  try {
    const r = await http(session.url);
    assert.equal(r.status, 200);
    assert.match(String(r.headers['content-security-policy']), /default-src 'none'/);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(r.headers['referrer-policy'], 'no-referrer');
    assert.match(r.body, /name="ACME_API_KEY"/);
    assert.match(r.body, /type="password"/);
  } finally { session.close(); }
});

test('portal refuses a wrong path, a foreign Host header and a wrong method', async () => {
  const { session } = await portal();
  try {
    assert.equal((await http(session.url, { path: '/c/not-the-token' })).status, 404);
    assert.equal((await http(session.url, { host: 'evil.example' })).status, 403);
    assert.equal((await http(session.url, { method: 'PUT' })).status, 405);
  } finally { session.close(); }
});

test('portal POST: foreign Origin, wrong content type, missing key, control char are refused and store nothing', async () => {
  const { session, stored } = await portal();
  try {
    const port = new URL(session.url).port;
    assert.equal((await http(session.url, { method: 'POST', headers: { ...FORM, Origin: 'http://evil.example' }, body: 'ACME_API_KEY=x' })).status, 403);
    assert.equal((await http(session.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 415);
    assert.equal((await http(session.url, { method: 'POST', headers: FORM, body: 'OTHER=1' })).status, 400);
    assert.equal((await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=a%0Ab' })).status, 400);
    assert.equal(stored.length, 0);
    // a same-origin POST with the right shape still works afterwards
    const ok = await http(session.url, { method: 'POST', headers: { ...FORM, Origin: `http://127.0.0.1:${port}` }, body: 'ACME_API_KEY=sekret' });
    assert.equal(ok.status, 200);
    assert.deepEqual(stored, [['ACME_API_KEY', 'sekret']]);
    assert.ok(!ok.body.includes('sekret'), 'a stored value is never echoed');
  } finally { session.close(); }
});

test('portal stores the requested key, rejects an unrequested key, and is single-use', async () => {
  const { session, stored } = await portal();
  const extra = await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=v1&EXTRA=nope' });
  assert.equal(extra.status, 400);
  assert.equal(stored.length, 0, 'an unrequested key rejects the whole submission');
  const r = await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=v1' });
  assert.equal(r.status, 200);
  assert.equal(await session.completed, 'stored');
  assert.deepEqual(stored, [['ACME_API_KEY', 'v1']]);
  await assert.rejects(http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=v2' }));
  assert.equal(stored.length, 1);
});

test('portal: concurrent POSTs write at most once', async () => {
  const { session, stored } = await portal();
  const replies = await Promise.all(
    Array.from({ length: 6 }, () => http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=same' }).catch(() => null)),
  );
  assert.equal(stored.length, 1);
  assert.equal(replies.filter((r) => r?.status === 200).length, 1);
  assert.equal(await session.completed, 'stored');
});

test('portal: a repeated key with a bad second value writes nothing', async () => {
  const { session, stored } = await portal();
  try {
    const r = await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=good&ACME_API_KEY=bad%00' });
    assert.equal(r.status, 400);
    assert.equal(stored.length, 0);
  } finally { session.close(); }
});

test('portal: a foreign or sibling-host Origin is refused on GET and POST', async () => {
  const { session, stored } = await portal();
  try {
    const port = new URL(session.url).port;
    assert.equal((await http(session.url, { headers: { Origin: 'http://evil.example' } })).status, 403);
    // localhost and 127.0.0.1 are distinct origins: a request to 127.0.0.1 must not accept localhost's origin
    assert.equal((await http(session.url, { headers: { Origin: `http://localhost:${port}` } })).status, 403);
    assert.equal((await http(session.url, { method: 'POST', headers: { ...FORM, Origin: `http://localhost:${port}` }, body: 'ACME_API_KEY=x' })).status, 403);
    assert.equal(stored.length, 0);
  } finally { session.close(); }
});

test('portal: after the TTL passes the page serves nothing even before the socket is closed', async () => {
  const { session, stored } = await portal({ ttlMs: 60 });
  await new Promise((r) => setTimeout(r, 120));
  let status = 0;
  try { status = (await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=late' })).status; } catch { status = 410; }
  assert.equal(status, 410);
  assert.equal(stored.length, 0);
  assert.equal(await session.completed, 'expired');
});

test('portal two-phase: one invalid value among several stores none', async () => {
  const { session, stored } = await portal({ keys: ['A_KEY', 'B_KEY'] });
  try {
    const r = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=good&B_KEY=bad%00' });
    assert.equal(r.status, 400);
    assert.equal(stored.length, 0);
  } finally { session.close(); }
});

test('portal: a store failure reports no value and keeps the portal open', async () => {
  let calls = 0;
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['ACME_API_KEY'],
    store: () => { calls++; throw new Error('disk full: sekret'); },
  });
  try {
    const r = await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=sekret' });
    assert.equal(r.status, 500);
    assert.ok(!r.body.includes('sekret'));
    assert.equal(calls, 1);
  } finally { session.close(); }
});

test('portal: a multi-key write that fails midway is restored and the page stays usable', async () => {
  const state: Record<string, string> = { B_KEY: 'old-b' };
  let failB = true;
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['A_KEY', 'B_KEY'],
    store: (k, v) => { if (k === 'B_KEY' && failB) throw new Error('disk'); state[k] = v; },
    peek: (k) => state[k],
    restore: (k, prev) => { if (prev === undefined) delete state[k]; else state[k] = prev; },
  });
  try {
    const r = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=a&B_KEY=b' });
    assert.equal(r.status, 500);
    assert.deepEqual(state, { B_KEY: 'old-b' }, 'the first key was put back');
    failB = false;
    const ok = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=a&B_KEY=b' });
    assert.equal(ok.status, 200);
    assert.deepEqual(state, { A_KEY: 'a', B_KEY: 'b' });
  } finally { session.close(); }
});

test('portal: a midway failure that cannot be restored closes the page for good', async () => {
  const state: Record<string, string> = {};
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['A_KEY', 'B_KEY'],
    store: (k, v) => { if (k === 'B_KEY') throw new Error('disk'); state[k] = v; },
  });
  const r = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=a&B_KEY=b' });
  assert.equal(r.status, 500);
  assert.equal(await session.completed, 'closed');
  await assert.rejects(http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=z&B_KEY=z' }));
});

test('portal: a key supplied elsewhere meanwhile is not overwritten; the page closes', async () => {
  const state: Record<string, string> = {};
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['A_KEY'],
    store: (k, v) => { state[k] = v; },
    isMissing: (k) => state[k] === undefined,
  });
  state.A_KEY = 'provided-by-another-page';
  const r = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=late' });
  assert.equal(r.status, 409);
  assert.equal(state.A_KEY, 'provided-by-another-page');
  assert.equal(await session.completed, 'closed');
});

test('portal: GET never shows a field for a key supplied meanwhile', async () => {
  const state: Record<string, string> = {};
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['A_KEY'],
    store: (k, v) => { state[k] = v; },
    isMissing: (k) => state[k] === undefined,
  });
  state.A_KEY = 'provided-elsewhere';
  const r = await http(session.url);
  assert.equal(r.status, 409);
  assert.ok(!r.body.includes('name="A_KEY"'));
  assert.equal(await session.completed, 'closed');
});

test('portal: an invalid POST after a key was supplied meanwhile does not re-render its field', async () => {
  const state: Record<string, string> = {};
  const session = await startCredentialPortal({
    adapterName: 'Acme',
    keys: ['A_KEY'],
    store: (k, v) => { state[k] = v; },
    isMissing: (k) => state[k] === undefined,
  });
  state.A_KEY = 'provided-elsewhere';
  const r = await http(session.url, { method: 'POST', headers: FORM, body: 'A_KEY=' });
  assert.equal(r.status, 409);
  assert.ok(!r.body.includes('name="A_KEY"'));
  assert.equal(state.A_KEY, 'provided-elsewhere');
  assert.equal(await session.completed, 'closed');
});

test('portal oversize body is refused', async () => {
  const { session, stored } = await portal();
  try {
    let status = 0;
    try {
      status = (await http(session.url, { method: 'POST', headers: FORM, body: 'ACME_API_KEY=' + 'a'.repeat(40_000) })).status;
    } catch { status = 413; } // connection destroyed by the size cap
    assert.equal(status, 413);
    assert.equal(stored.length, 0);
  } finally { session.close(); }
});

test('portal expires on TTL and closes after too many bad requests', async () => {
  const a = await portal({ ttlMs: 50 });
  assert.equal(await a.session.completed, 'expired');

  const b = await portal({ maxBadRequests: 2 });
  await http(b.session.url, { method: 'POST', headers: FORM, body: 'X=1' });
  await http(b.session.url, { method: 'POST', headers: FORM, body: 'X=1' });
  assert.equal(await b.session.completed, 'closed');
});

test('portal rejects invalid key names and empty key sets', async () => {
  await assert.rejects(startCredentialPortal({ adapterName: 'A', keys: ['bad key'], store: () => {} }));
  await assert.rejects(startCredentialPortal({ adapterName: 'A', keys: [], store: () => {} }));
});

// ── ensureCredentials ────────────────────────────────────────────────────────

const adapter = { id: 'acme', name: 'Acme', rest: { envKey: 'ACME_API_KEY' } } as unknown as Parameters<typeof ensureCredentials>[0]['adapter'];

test('ensure: nothing missing → ok, prompter never called', async () => {
  let called = false;
  const out = await ensureCredentials({
    adapter, env: {},
    prompter: async () => { called = true; return { kind: 'unavailable' }; },
    reload: () => ({ ACME_API_KEY: 'x' }),
  });
  assert.deepEqual(out, { kind: 'ok' });
  assert.equal(called, false);
});

test('ensure: process env counts as present', () => {
  assert.deepEqual(missingCredentialKeys(adapter, {}, { ACME_API_KEY: 'x' }), []);
  assert.deepEqual(missingCredentialKeys(adapter, {}, {}), ['ACME_API_KEY']);
});

test('ensure: missing with no prompter → unavailable', async () => {
  const out = await ensureCredentials({ adapter, env: {}, prompter: undefined, reload: () => ({}) });
  assert.deepEqual(out, { kind: 'unavailable', keys: ['ACME_API_KEY'] });
});

test('ensure: pending / declined / throwing prompter', async () => {
  const mk = (p: CredentialPrompter) => ensureCredentials({ adapter, env: {}, prompter: p, reload: () => ({}) });
  assert.deepEqual(await mk(async () => ({ kind: 'pending', url: 'http://127.0.0.1:1/c/t' })), { kind: 'pending', url: 'http://127.0.0.1:1/c/t', keys: ['ACME_API_KEY'] });
  assert.deepEqual(await mk(async () => ({ kind: 'declined' })), { kind: 'declined', keys: ['ACME_API_KEY'] });
  assert.deepEqual(await mk(async () => { throw new Error('boom'); }), { kind: 'unavailable', keys: ['ACME_API_KEY'] });
});

test('ensure: stored is verified against the store, not trusted', async () => {
  const lying = await ensureCredentials({ adapter, env: {}, prompter: async () => ({ kind: 'stored' }), reload: () => ({}) });
  assert.deepEqual(lying, { kind: 'unavailable', keys: ['ACME_API_KEY'] });
  // first read (before prompting): still missing; second read (after `stored`): present
  let reads = 0;
  const honest = await ensureCredentials({
    adapter, env: {}, prompter: async () => ({ kind: 'stored' }),
    reload: (): Record<string, string> => (++reads === 1 ? {} : { ACME_API_KEY: 'x' }),
  });
  assert.deepEqual(honest, { kind: 'ok' });
  assert.equal(reads, 2);
});

test('ensure: a page finished after an earlier `pending` is seen on the next call (no second prompt)', async () => {
  let prompted = 0;
  const store: Record<string, string> = {};
  const prompter: CredentialPrompter = async () => { prompted++; return { kind: 'pending', url: 'http://127.0.0.1:1/c/t' }; };
  const call = () => ensureCredentials({ adapter, env: {}, prompter, reload: () => ({ ...store }) });
  assert.equal((await call()).kind, 'pending');
  store.ACME_API_KEY = 'entered-in-browser-later';
  assert.deepEqual(await call(), { kind: 'ok' });
  assert.equal(prompted, 1);
});

// ── prompter ─────────────────────────────────────────────────────────────────

function fakeSession(url = 'http://127.0.0.1:9/c/t'): PortalSession & { closed: number; finish(e: 'stored' | 'expired' | 'closed'): void } {
  let finish!: (e: 'stored' | 'expired' | 'closed') => void;
  const completed = new Promise<'stored' | 'expired' | 'closed'>((r) => { finish = r; });
  const s = { url, completed, closed: 0, close() { s.closed++; finish('closed'); }, finish };
  return s;
}

const req = { adapterId: 'acme', adapterName: 'Acme', keys: ['ACME_API_KEY'] };

test('ensure: a credential removed from the store counts as missing again', async () => {
  const store: Record<string, string> = { ACME_API_KEY: 'x' };
  const prompter: CredentialPrompter = async () => ({ kind: 'pending', url: 'http://127.0.0.1:1/c/t' });
  const call = () => ensureCredentials({ adapter, env: {}, prompter, reload: () => ({ ...store }) });
  assert.deepEqual(await call(), { kind: 'ok' });
  delete store.ACME_API_KEY;
  assert.equal((await call()).kind, 'pending');
});

test('prompter: no URL-elicitation capability → pending with the URL, no elicit call', async () => {
  const s = fakeSession();
  let elicited = 0;
  const server: ElicitingServer = {
    getClientCapabilities: () => ({}),
    elicitInput: async () => { elicited++; return { action: 'accept' }; },
  };
  const p = createCredentialPrompter({ server, start: async () => s, store: () => {} });
  assert.deepEqual(await p(req), { kind: 'pending', url: s.url });
  assert.equal(elicited, 0);
  s.close();
});

test('prompter: accept then stored → stored; elicitation carries only the URL', async () => {
  const s = fakeSession();
  let params: Record<string, unknown> = {};
  const server: ElicitingServer = {
    getClientCapabilities: () => ({ elicitation: { url: {} } }),
    elicitInput: async (p) => { params = p as unknown as Record<string, unknown>; setTimeout(() => s.finish('stored'), 5); return { action: 'accept' }; },
  };
  const p = createCredentialPrompter({ server, start: async () => s, store: () => {}, waitMs: 2000 });
  assert.deepEqual(await p(req), { kind: 'stored' });
  assert.equal(params.mode, 'url');
  assert.equal(params.url, s.url);
  assert.ok(!JSON.stringify(params).includes('ACME_API_KEY=')); // no values, ever
});

test('prompter: decline closes the portal and returns declined', async () => {
  const s = fakeSession();
  const server: ElicitingServer = {
    getClientCapabilities: () => ({ elicitation: { url: {} } }),
    elicitInput: async () => ({ action: 'decline' }),
  };
  const p = createCredentialPrompter({ server, start: async () => s, store: () => {} });
  assert.deepEqual(await p(req), { kind: 'declined' });
  assert.equal(s.closed, 1);
});

test('prompter: elicitation throws → pending(url); accepted but not finished within wait → pending(url)', async () => {
  const s1 = fakeSession();
  const throwing: ElicitingServer = {
    getClientCapabilities: () => ({ elicitation: { url: {} } }),
    elicitInput: async () => { throw new Error('unsupported'); },
  };
  assert.deepEqual(await createCredentialPrompter({ server: throwing, start: async () => s1, store: () => {} })(req), { kind: 'pending', url: s1.url });
  s1.close();

  const s2 = fakeSession();
  const slow: ElicitingServer = {
    getClientCapabilities: () => ({ elicitation: { url: {} } }),
    elicitInput: async () => ({ action: 'accept' }),
  };
  assert.deepEqual(await createCredentialPrompter({ server: slow, start: async () => s2, store: () => {}, waitMs: 20 })(req), { kind: 'pending', url: s2.url });
  s2.close();
});

test('prompter: concurrent calls for one adapter start one page', async () => {
  let starts = 0;
  const s = fakeSession();
  const server: ElicitingServer = { getClientCapabilities: () => ({}), elicitInput: async () => ({ action: 'accept' }) };
  const p = createCredentialPrompter({
    server,
    start: async () => { starts++; await new Promise((r) => setTimeout(r, 20)); return s; },
    store: () => {},
  });
  const [a, b, c] = await Promise.all([p(req), p(req), p(req)]);
  assert.equal(starts, 1);
  assert.deepEqual(a, b);
  assert.deepEqual(b, c);
  s.close();
});

test('prompter: one live portal per adapter (second call reuses the same URL)', async () => {
  let starts = 0;
  const s = fakeSession();
  const server: ElicitingServer = { getClientCapabilities: () => ({}), elicitInput: async () => ({ action: 'accept' }) };
  const p = createCredentialPrompter({ server, start: async () => { starts++; return s; }, store: () => {} });
  const a = await p(req);
  const b = await p(req);
  assert.deepEqual(a, b);
  assert.equal(starts, 1);
  s.close();
});

// ── instructions ─────────────────────────────────────────────────────────────

test('instructions name exactly the three tools and never invite pasting a secret', () => {
  const names = CHARIOT_SERVER_INSTRUCTIONS.match(/chariot_[a-z_]+/g) ?? [];
  assert.deepEqual([...new Set(names)].sort(), ['chariot_call', 'chariot_list', 'chariot_query']);
  assert.match(CHARIOT_SERVER_INSTRUCTIONS, /Never ask the user to type or paste a password, token or API key into the chat/);
  assert.ok(CHARIOT_SERVER_INSTRUCTIONS.length < 2000);
});
