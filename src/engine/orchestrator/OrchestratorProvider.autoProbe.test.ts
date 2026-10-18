/**
 * Regression eval: provider:'auto' probe order, mlx-lm coverage, Ollama vs
 * vLLM discrimination, Ollama's Inference Gateway / OllamaShim dispatch
 * path, and the Ollama deprecation warning (CHARIOT::§8.3, §8.10).
 *
 * The defect this exists to catch: createAutoLLM() probed
 * [gateway:8000, llama.cpp:8080, ollama:11434] — reversed order, no mlx-lm
 * probe at all, and treated a reachable Ollama endpoint as an
 * OpenAI-compatible (vLLM) backend by probing /v1/models instead of
 * /api/tags, so it never emitted the required deprecation warning and would
 * call Ollama's server with the wrong request shape. A follow-up defect
 * (caught by gate review): the fix for the above still dispatched
 * auto-detected Ollama through a hand-rolled native `/api/chat` client
 * instead of §8.3::1::2's required "OllamaShim path through the Inference
 * Gateway (§8.10)" — so the X-EpicAI-Deprecation header / shim translation
 * never actually ran for the auto-detected case.
 *
 * CHARIOT::§8.3::1 — "WHEN provider:'auto' the system SHALL run the probe
 * order: (1) GET {baseUrl}/v1/models→ if 200 use OpenAI Chat Completions;
 * (2) Ollama localhost:11434/api/tags→ if reachable log one-time
 * deprecation + use OllamaShim via gateway; (3) llama.cpp localhost:8080;
 * (4) vLLM localhost:8000; (5) mlx-lm localhost:5000 (each as
 * OpenAI-compatible); (6) if none, raise startup error."
 * CHARIOT::§8.3::2 — "Ollama deprecation SHALL be a one-time warning per
 * process per six hours, not per request. The `X-EpicAI-Deprecation:
 * ollama-api; sunset=2026-12-31` header SHALL be set on every shim
 * response."
 * CHARIOT-SPEC.md:811 (§8.10) — "`OllamaShim.ts` — translates `POST
 * /api/chat` and `POST /api/generate` to OpenAI Chat Completions format.
 * Emits the deprecation header."
 *
 * All fixed backend ports (11434/8080/8000/5000) are exercised through a
 * global.fetch stub keyed by URL rather than by binding real sockets on
 * those well-known ports, so the test can't collide with a real backend
 * that happens to be running on the test host. The in-process Inference
 * Gateway path (Ollama only) never opens a real HTTP socket either — the
 * gateway's `handleRequest` is exercised directly against fake
 * IncomingMessage/ServerResponse objects — but it DOES make one real
 * `fetch` call per request to the (stubbed) backend's
 * `/v1/chat/completions`, which the assertions below verify.
 *
 * Run (after tsc):
 *   node --test dist/engine/orchestrator/OrchestratorProvider.autoProbe.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createOrchestratorLLM } from './OrchestratorProvider.js';
import type { OrchestratorConfig } from '../types/index.js';

type FetchLog = { url: string }[];

function installFetchStub(responders: Record<string, () => { status: number; body: string }>): {
  calls: FetchLog;
  restore: () => void;
} {
  const calls: FetchLog = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push({ url });
    for (const [prefix, respond] of Object.entries(responders)) {
      if (url.startsWith(prefix)) {
        const { status, body } = respond();
        return new Response(body, { status });
      }
    }
    // ECONNREFUSED-equivalent for any URL this test did not stub.
    throw new TypeError('fetch failed');
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

function captureStderr(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array) => {
    lines.push(chunk.toString());
    return true;
  }) as typeof process.stderr.write;
  return {
    lines,
    restore: () => {
      process.stderr.write = original;
    },
  };
}

const baseConfig: OrchestratorConfig = {
  provider: 'auto',
  model: 'test-model',
};

// ── CHARIOT::§8.3::1 — probe order ────────────────────────────────────────

test('auto probe: all backends unreachable raises after probing every URL in clause order', async () => {
  const stub = installFetchStub({});
  try {
    const llm = createOrchestratorLLM({ ...baseConfig });
    await assert.rejects(
      () => llm({ messages: [{ role: 'user', content: 'hi' }] }),
      /No inference backend available/,
    );
    // Order: Ollama /api/tags, then llama.cpp, vLLM, mlx-lm — each /v1/models.
    assert.deepEqual(
      stub.calls.map(c => c.url),
      [
        'http://localhost:11434/api/tags',
        'http://localhost:8080/v1/models',
        'http://localhost:8000/v1/models',
        'http://localhost:5000/v1/models',
      ],
    );
  } finally {
    stub.restore();
  }
});

test('auto probe: explicit baseUrl is probed first, then falls through to the fixed sequence on failure', async () => {
  const stub = installFetchStub({
    'http://localhost:5000/v1/models': () => ({ status: 200, body: '{}' }),
    'http://localhost:5000/v1/chat/completions': () => ({
      status: 200,
      body: JSON.stringify({ choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }] }),
    }),
  });
  try {
    const llm = createOrchestratorLLM({ ...baseConfig, baseUrl: 'http://example.internal:9999' });
    const result = await llm({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(result.content, 'ok');
    // Probe calls only (excludes the final dispatch call to /v1/chat/completions).
    const probeCalls = stub.calls.map(c => c.url).filter(u => !u.endsWith('/v1/chat/completions'));
    assert.deepEqual(
      probeCalls,
      [
        'http://example.internal:9999/v1/models',
        'http://localhost:11434/api/tags',
        'http://localhost:8080/v1/models',
        'http://localhost:8000/v1/models',
        'http://localhost:5000/v1/models',
      ],
    );
  } finally {
    stub.restore();
  }
});

// ── CHARIOT::§8.3::1::5 — mlx-lm must be probed ───────────────────────────

test('auto probe: mlx-lm on :5000 is reachable and selected when nothing else is', async () => {
  const stub = installFetchStub({
    'http://localhost:5000/v1/models': () => ({ status: 200, body: '{}' }),
  });
  try {
    const llm = createOrchestratorLLM({ ...baseConfig });
    globalThis.fetch = (async (input: string | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      stub.calls.push({ url });
      if (url.startsWith('http://localhost:5000/v1/models')) return new Response('{}', { status: 200 });
      if (url.startsWith('http://localhost:5000/v1/chat/completions')) {
        return new Response(JSON.stringify({ choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }] }), { status: 200 });
      }
      throw new TypeError('fetch failed');
    }) as typeof fetch;

    const result = await llm({ messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(result.content, 'ok');
    assert.ok(stub.calls.some(c => c.url === 'http://localhost:5000/v1/models'));
  } finally {
    stub.restore();
  }
});

// ── CHARIOT::§8.3::1::2 / §8.10 — Ollama is probed via /api/tags (not
//    /v1/models), dispatched through the in-process Inference Gateway's
//    OllamaShim path (not the vLLM/OpenAI-compat shape directly, and not a
//    real network call to Ollama's native /api/chat), the deprecation
//    header is on the shim response, and the warning is one-time-per-6h.
//    Placed before any other Ollama-triggering test in this file so it
//    observes the module-level warn-state (and gateway singleton) from a
//    guaranteed-fresh starting point — node:test runs tests within one file
//    sequentially, in definition order, in a single shared process. ──────

function installOllamaBackendStub(): { calls: FetchLog; restore: () => void } {
  return installFetchStub({
    'http://localhost:11434/api/tags': () => ({ status: 200, body: '{"models":[]}' }),
    // BackendRegistry's own health probe (§8.10) — uniform /v1/models
    // across backend types, independent of the §8.3 /api/tags detection
    // probe above.
    'http://localhost:11434/v1/models': () => ({ status: 200, body: '{"data":[]}' }),
    // The backend endpoint OllamaShim's proxyToBackend (via
    // InferenceGateway) actually calls — the OpenAI Chat Completions shape.
    'http://localhost:11434/v1/chat/completions': () => ({
      status: 200,
      body: JSON.stringify({
        choices: [{ message: { role: 'assistant', content: 'ollama-ok' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
    }),
  });
}

test('auto probe: a reachable Ollama endpoint is probed on /api/tags and dispatched through the OllamaShim path via the Inference Gateway', async () => {
  const stub = installOllamaBackendStub();
  const stderr = captureStderr();
  try {
    const llm = createOrchestratorLLM({ ...baseConfig, logLevel: 'debug' });
    const result = await llm({ messages: [{ role: 'user', content: 'hi' }] });

    // CHARIOT::§8.3::1::2 — detection probe is /api/tags, and it runs first.
    assert.equal(stub.calls[0]?.url, 'http://localhost:11434/api/tags');

    // The shim translates the backend's OpenAI-shaped response back into
    // the native Ollama response shape, which createOllamaGatewayLLM then
    // parses into LLMResponse — so content survives the round trip.
    assert.equal(result.content, 'ollama-ok');

    // The dispatch reaches the backend via /v1/chat/completions (through
    // OllamaShim -> InferenceGateway.proxyToBackend), never a real network
    // call to Ollama's native /api/chat (that request is synthesized
    // in-process against InferenceGateway.handleRequest, not fetched).
    assert.ok(
      stub.calls.some(c => c.url === 'http://localhost:11434/v1/chat/completions'),
      'expected the gateway to proxy the request to /v1/chat/completions',
    );
    assert.ok(
      !stub.calls.some(c => c.url.includes('/api/chat')),
      'must not make a real network call to /api/chat — that path is handled in-process by the gateway/shim',
    );

    // CHARIOT::§8.3::2 — one-time deprecation warning was logged.
    assert.ok(
      stderr.lines.some(l => l.includes('provider "ollama" is deprecated')),
      'expected a one-time Ollama deprecation warning to be logged',
    );

    // CHARIOT::§8.3::2 / §8.10 — "The X-EpicAI-Deprecation: ollama-api;
    // sunset=2026-12-31 header SHALL be set on every shim response."
    // Surfaced via the gateway-dispatch debug log (logLevel:'debug' above)
    // since LLMResponse itself carries no HTTP headers.
    assert.ok(
      stderr.lines.some(l => l.includes('"deprecationHeader":"ollama-api; sunset=2026-12-31"')),
      'expected the X-EpicAI-Deprecation header to be present on the shim response',
    );
  } finally {
    stub.restore();
    stderr.restore();
  }
});

test('ollama gateway: the in-process gateway/backend registration is reused (not re-probed) and the deprecation warning does not repeat', async () => {
  // Deliberately omit the /v1/models stub: if this regresses to re-running
  // BackendRegistry.discover() on every call instead of reusing the
  // memoized gateway, the unstubbed probe throws and the assertions below
  // fail — proving reuse rather than merely hoping for it.
  const stub = installFetchStub({
    'http://localhost:11434/api/tags': () => ({ status: 200, body: '{"models":[]}' }),
    'http://localhost:11434/v1/chat/completions': () => ({
      status: 200,
      body: JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'ollama-ok-2' }, finish_reason: 'stop' }] }),
    }),
  });
  const stderr = captureStderr();
  try {
    const warnCountBefore = stderr.lines.filter(l => l.includes('provider "ollama" is deprecated')).length;

    const llm = createOrchestratorLLM({ ...baseConfig });
    const result = await llm({ messages: [{ role: 'user', content: 'hi again' }] });

    assert.equal(result.content, 'ollama-ok-2');
    assert.ok(
      !stub.calls.some(c => c.url === 'http://localhost:11434/v1/models'),
      'expected the memoized gateway/backend registration to be reused, not re-probed',
    );

    const warnCountAfter = stderr.lines.filter(l => l.includes('provider "ollama" is deprecated')).length;
    assert.equal(
      warnCountAfter,
      warnCountBefore,
      'the deprecation warning must not repeat within the six-hour window',
    );
  } finally {
    stub.restore();
    stderr.restore();
  }
});

// ── CHARIOT::§8.3::1::6 — no backend reachable raises a startup error ────

test('auto probe: raises a startup error naming every probed URL when nothing responds', async () => {
  const stub = installFetchStub({});
  try {
    const llm = createOrchestratorLLM({ ...baseConfig });
    await assert.rejects(
      () => llm({ messages: [{ role: 'user', content: 'hi' }] }),
      (err: Error) => {
        assert.match(err.message, /No inference backend available/);
        assert.match(err.message, /localhost:11434\/api\/tags/);
        assert.match(err.message, /localhost:8080\/v1\/models/);
        assert.match(err.message, /localhost:8000\/v1\/models/);
        assert.match(err.message, /localhost:5000\/v1\/models/);
        return true;
      },
    );
  } finally {
    stub.restore();
  }
});
