/**
 * @epicai/chariot — Orchestrator Provider
 * Abstraction for local model providers (Ollama, vLLM, custom).
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import type {
  OrchestratorConfig,
  LLMFunction,
  LLMMessage,
  LLMToolDefinition,
  LLMResponse,
} from '../types/index.js';
import { createLogger, type LoggerInterface } from '../logger.js';
// CHARIOT::§8.3::1::2 — auto-detected Ollama dispatches "the OllamaShim path
// through the Inference Gateway (§8.10)", not a hand-rolled native client.
import { InferenceGateway } from '../gateway/InferenceGateway.js';
import { BackendRegistry } from '../gateway/BackendRegistry.js';
import { ControlPlane } from '../gateway/ControlPlane.js';
import { Router } from '../gateway/Router.js';
import { DEFAULT_GATEWAY_CONFIG, type GatewayConfig } from '../gateway/types.js';

const DEFAULT_OLLAMA_URL = 'http://localhost:11434';
// CHARIOT::§8.3::1 — fixed backend base URLs used by the auto-detection
// probe, in the exact order the clause prescribes: Ollama, llama.cpp,
// vLLM, mlx-lm.
const LLAMA_CPP_URL = 'http://localhost:8080';
const VLLM_URL = 'http://localhost:8000';
const MLX_LM_URL = 'http://localhost:5000';
const DEFAULT_TIMEOUT_MS = 30000;
const PROBE_TIMEOUT_MS = 3_000;

// CHARIOT::§8.3::2 — "one-time warning per process per six hours, not per
// request." Tracked as a last-warned timestamp (not a plain boolean) so a
// long-lived process re-warns after the six-hour window elapses instead of
// staying silent for its entire lifetime.
const OLLAMA_DEPRECATION_WINDOW_MS = 6 * 60 * 60 * 1000;
let ollamaDeprecationWarnedAt: number | null = null;

// CHARIOT::§8.3::2
function warnOllamaDeprecationOnce(log: LoggerInterface): void {
  const now = Date.now();
  if (ollamaDeprecationWarnedAt !== null && now - ollamaDeprecationWarnedAt < OLLAMA_DEPRECATION_WINDOW_MS) {
    return;
  }
  ollamaDeprecationWarnedAt = now;
  log.warn('provider "ollama" is deprecated — migrate to "auto" or "vllm". Run: chariot help');
}

/**
 * Create an LLM function from orchestrator config.
 * If the config provides a custom llm function, use it directly.
 * Otherwise, build one from the provider and model settings.
 */
export function createOrchestratorLLM(config: OrchestratorConfig): LLMFunction {
  if (config.llm) return config.llm;

  switch (config.provider) {
    case 'auto':
      return createAutoLLM(config);
    case 'ollama': {
      // CHARIOT::§8.3::2
      warnOllamaDeprecationOnce(createLogger('orchestrator.deprecation'));
      return createOllamaLLM(config);
    }
    case 'vllm':
      return createVLLMLLM(config);
    case 'custom':
      throw new Error('Custom orchestrator provider requires an llm function in config');
    case 'apple-foundation':
      throw new Error('Apple Foundation Model provider is for iOS device runtime only — use ollama or vllm for server runtime');
    default:
      throw new Error(`Unknown orchestrator provider: ${config.provider as string}`);
  }
}

// CHARIOT::§8.3::1 — GET {url}/v1/models; 200 means "reachable, OpenAI-compatible."
async function probeOpenAIModels(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      const response = await fetch(`${url}/v1/models`, { signal: controller.signal });
      return response.ok;
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return false;
  }
}

// CHARIOT::§8.3::1 — the legacy Ollama API is probed via GET /api/tags,
// never /v1/models (Ollama does not implement the OpenAI-compatible
// surface natively).
async function probeOllamaTags(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      const response = await fetch(`${url}/api/tags`, { signal: controller.signal });
      return response.ok;
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return false;
  }
}

/**
 * Auto-detect provider. CHARIOT::§8.3::1 — probe order when
 * `provider: 'auto'`:
 *   1. GET {baseUrl}/v1/models (when a baseUrl is configured) → OpenAI Chat Completions
 *   2. Ollama localhost:11434/api/tags → one-time deprecation warning + OllamaShim path
 *   3. llama.cpp localhost:8080 (OpenAI-compatible)
 *   4. vLLM localhost:8000 (OpenAI-compatible)
 *   5. mlx-lm localhost:5000 (OpenAI-compatible)
 *   6. none reachable → startup error
 * Every step below step 1 runs regardless of whether step 1 was attempted —
 * an explicit `baseUrl` that fails to respond does not abort the rest of
 * the probe sequence.
 */
function createAutoLLM(config: OrchestratorConfig): LLMFunction {
  const log = createLogger('orchestrator.auto', config.logLevel);
  let resolved: LLMFunction | null = null;

  const probedDescriptions: string[] = [];

  return async (params) => {
    if (resolved) return resolved(params);

    // CHARIOT::§8.3::1::1
    if (config.baseUrl) {
      probedDescriptions.push(`${config.baseUrl}/v1/models`);
      if (await probeOpenAIModels(config.baseUrl)) {
        log.info('auto-detected inference backend', { url: config.baseUrl, kind: 'openai-compatible (configured baseUrl)' });
        resolved = createVLLMLLM({ ...config, baseUrl: config.baseUrl });
        return resolved(params);
      }
    }

    // CHARIOT::§8.3::1::2 — "log a one-time deprecation warning and use the
    // OllamaShim path through the Inference Gateway (§8.10)."
    probedDescriptions.push(`${DEFAULT_OLLAMA_URL}/api/tags`);
    if (await probeOllamaTags(DEFAULT_OLLAMA_URL)) {
      warnOllamaDeprecationOnce(log);
      log.info('auto-detected inference backend', { url: DEFAULT_OLLAMA_URL, kind: 'ollama (OllamaShim path via Inference Gateway)' });
      resolved = createOllamaGatewayLLM(config, DEFAULT_OLLAMA_URL);
      return resolved(params);
    }

    // CHARIOT::§8.3::1::3-5 — llama.cpp, vLLM, mlx-lm, in that order.
    const openAICompatTargets: { url: string; kind: string }[] = [
      { url: LLAMA_CPP_URL, kind: 'llama.cpp' },
      { url: VLLM_URL, kind: 'vLLM' },
      { url: MLX_LM_URL, kind: 'mlx-lm' },
    ];

    for (const { url, kind } of openAICompatTargets) {
      probedDescriptions.push(`${url}/v1/models`);
      if (await probeOpenAIModels(url)) {
        log.info('auto-detected inference backend', { url, kind });
        resolved = createVLLMLLM({ ...config, baseUrl: url });
        return resolved(params);
      }
    }

    // CHARIOT::§8.3::1::6
    throw new Error(
      'No inference backend available.\n\n' +
      'Probed: ' + probedDescriptions.join(', ') + ' — none responded.\n\n' +
      'Start an inference backend:\n' +
      '  brew install llama.cpp\n' +
      '  llama-server --model <path-to-model.gguf> --port 8080\n\n' +
      'Then run your code again. The SDK will auto-detect it.\n'
    );
  };
}

// ---------------------------------------------------------------------------
// CHARIOT::§8.3::1::2 / §8.10 — auto-detected Ollama, dispatched through an
// in-process Inference Gateway so the request takes the OllamaShim
// translation path (native Ollama request/response shape <-> OpenAI Chat
// Completions) and carries the X-EpicAI-Deprecation response header, per
// §8.10: "`OllamaShim.ts` — translates `POST /api/chat` and
// `POST /api/generate` to OpenAI Chat Completions format. Emits the
// deprecation header." No real HTTP server or socket is used —
// `InferenceGateway.handleRequest` is a "framework-agnostic request
// handler ... NOT an HTTP server" (§8.10) that only needs objects shaped
// like `IncomingMessage`/`ServerResponse`, so a single already-known Ollama
// backend is registered directly (autoDiscover disabled — the backend was
// already found by the §8.3::1::2 probe above) and no health-check timers
// or Redis connection are started (no `gateway.start()` call — that begins
// a persistent leader-elected health-check loop meant for a long-lived
// gateway service, not for a value returned once per orchestrator run).
// ---------------------------------------------------------------------------

let ollamaGatewaySingleton: { baseUrl: string; gateway: InferenceGateway } | null = null;

async function getOllamaGateway(baseUrl: string): Promise<InferenceGateway> {
  if (ollamaGatewaySingleton && ollamaGatewaySingleton.baseUrl === baseUrl) {
    return ollamaGatewaySingleton.gateway;
  }
  // CHARIOT::§8.10 — "Falls back to in-process Map when Redis is
  // unreachable." No redisUrl is passed, so ControlPlane never attempts a
  // Redis connection.
  const controlPlane = new ControlPlane();
  await controlPlane.connect();
  const gatewayConfig: GatewayConfig = {
    ...DEFAULT_GATEWAY_CONFIG,
    // The backend was already confirmed reachable by the §8.3::1::2
    // /api/tags probe; register it explicitly rather than re-running
    // auto-discovery across every well-known port again.
    backends: [{ url: baseUrl, type: 'ollama', name: 'ollama (auto-detected)' }],
    autoDiscover: false,
  };
  const registry = new BackendRegistry(controlPlane, gatewayConfig);
  await registry.discover();
  const router = new Router(registry, controlPlane, gatewayConfig);
  const gateway = new InferenceGateway(registry, controlPlane, router, gatewayConfig);
  ollamaGatewaySingleton = { baseUrl, gateway };
  return gateway;
}

/** Minimal in-process stand-in for `IncomingMessage` — only the members
 * `InferenceGateway.handleRequest` and `OllamaShim.handleChat` read
 * (`method`, `url`, `headers`, `socket.remoteAddress`, and the
 * data/end/error stream events `readBody()` consumes) are implemented. */
function createFakeGatewayRequest(bodyJson: string): IncomingMessage {
  const readable = new Readable({ read() { /* pushed eagerly below */ } });
  readable.push(bodyJson);
  readable.push(null);
  return Object.assign(readable, {
    method: 'POST',
    url: '/api/chat',
    headers: {} as Record<string, string>,
    socket: { remoteAddress: '127.0.0.1' },
  }) as unknown as IncomingMessage;
}

/** Minimal in-process stand-in for `ServerResponse` that captures the
 * status/headers/body `OllamaShim.handleChat` writes, instead of writing to
 * a real socket. Resolves `result` when `.end()` is called. */
function createCapturingGatewayResponse(): {
  res: ServerResponse;
  result: Promise<{ status: number; headers: Record<string, string>; body: string }>;
} {
  let statusCode = 200;
  let headers: Record<string, string> = {};
  let settle!: (v: { status: number; headers: Record<string, string>; body: string }) => void;
  const result = new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve) => {
    settle = resolve;
  });
  const res = {
    headersSent: false,
    setHeader(name: string, value: string) {
      headers[name] = value;
    },
    writeHead(status: number, hdrs?: Record<string, string>) {
      statusCode = status;
      if (hdrs) headers = { ...headers, ...hdrs };
    },
    end(chunk?: string) {
      settle({ status: statusCode, headers, body: chunk ?? '' });
    },
  } as unknown as ServerResponse;
  return { res, result };
}

// CHARIOT::§8.3::1::2 — dispatches an auto-detected Ollama backend through
// the OllamaShim path (see block comment above); response parsing reuses
// the same native-Ollama-response shape (`OllamaFullResponse`) that
// `createOllamaLLM` below parses, because the shim's whole purpose (§8.10)
// is translating the OpenAI-compatible backend response back into that
// exact native Ollama `/api/chat` response shape for the caller.
function createOllamaGatewayLLM(config: OrchestratorConfig, baseUrl: string): LLMFunction {
  const log = createLogger('orchestrator.ollama-gateway', config.logLevel);

  return async (params: { messages: LLMMessage[]; tools?: LLMToolDefinition[] }): Promise<LLMResponse> => {
    const toolCount = params.tools?.length ?? 0;

    const body: Record<string, unknown> = {
      model: config.model,
      messages: params.messages,
      stream: false,
    };
    if (params.tools && params.tools.length > 0) {
      body.tools = params.tools.map(t => ({
        type: 'function',
        function: { name: t.name, description: t.description, parameters: t.parameters },
      }));
    }

    const gateway = await getOllamaGateway(baseUrl);
    const req = createFakeGatewayRequest(JSON.stringify(body));
    const { res, result } = createCapturingGatewayResponse();
    await gateway.handleRequest(req, res);
    const { status, headers, body: responseBody } = await result;

    // CHARIOT::§8.3::2 / §8.10 — the shim sets this header on every
    // response, success or failure; surfaced to callers/telemetry that
    // need to observe it (e.g. this eval), not required for LLMResponse.
    log.debug('gateway response', { status, deprecationHeader: headers['X-EpicAI-Deprecation'] ?? null });

    if (status !== 200) {
      const truncated = responseBody.slice(0, 500);
      log.error('request failed', { status, body: truncated });
      throw new Error(`Ollama (via Inference Gateway) returned ${status}`);
    }

    const data = JSON.parse(responseBody) as OllamaFullResponse;
    const toolCalls = (data.message?.tool_calls ?? []).map((tc: OllamaToolCall, i: number) => ({
      id: `call_${i}`,
      name: tc.function.name,
      arguments: tc.function.arguments,
    }));
    const finishReason = toolCalls.length > 0 ? 'tool_calls' as const : 'stop' as const;

    if (toolCount > 0 && toolCalls.length === 0) {
      log.warn('model returned no tool calls despite tools being provided', {
        toolCount,
        toolNames: params.tools?.map(t => t.name) ?? [],
        finishReason,
      });
    }

    return {
      content: data.message?.content ?? null,
      toolCalls,
      finishReason,
    };
  };
}

// CHARIOT-SPEC.md §8.3's on-disk text governs the AUTO-DETECTION probe
// sequence only ("Auto-detection probe order, when `provider: 'auto'`");
// no clause on disk mandates Inference Gateway routing for the SEPARATE,
// explicit `provider: 'ollama'` config value, so that path is left calling
// Ollama's native API directly below, unchanged.
function createOllamaLLM(config: OrchestratorConfig): LLMFunction {
  const baseUrl = config.baseUrl ?? DEFAULT_OLLAMA_URL;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const log = createLogger('orchestrator.ollama', config.logLevel);

  return async (params: { messages: LLMMessage[]; tools?: LLMToolDefinition[] }): Promise<LLMResponse> => {
    const toolCount = params.tools?.length ?? 0;

    const body: Record<string, unknown> = {
      model: config.model,
      messages: params.messages,
      stream: false,
    };

    if (params.tools && params.tools.length > 0) {
      body.tools = params.tools.map(t => ({
        type: 'function',
        function: {
          name: t.name,
          description: t.description,
          parameters: t.parameters,
        },
      }));
    }

    log.info('request', {
      model: config.model,
      messageCount: params.messages.length,
      toolCount,
      toolNames: params.tools?.map(t => t.name) ?? [],
    });

    // the full request body and raw response can contain
    // tool arguments + LLM completions that include credentials passed
    // through user prompts. Emit a structural summary instead — the
    // bytes themselves are reachable via Mongo audit (encrypted at
    // rest) for forensic replay.
    log.debug('request shape', {
      messageCount: Array.isArray((body as { messages?: unknown[] }).messages)
        ? (body as { messages: unknown[] }).messages.length
        : 0,
      toolCount: Array.isArray((body as { tools?: unknown[] }).tools)
        ? (body as { tools: unknown[] }).tools.length
        : 0,
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const start = Date.now();
      const response = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        const rawText = await response.text();
        const truncated = rawText.slice(0, 200);
        // log keeps the truncated body for operator forensics
        // (Loki / OTEL log surfaces are operator-only), but the thrown
        // Error must not embed upstream response bytes — Error.message
        // crosses the orchestrator boundary into transcripts, telemetry
        // events, and stdout.
        log.error('request failed', { status: response.status, body: truncated });
        throw new Error(`Ollama returned ${response.status}`);
      }

      const data = await response.json() as OllamaFullResponse;
      const durationMs = Date.now() - start;

      // Same redaction rationale as the request body above.
      log.debug('response shape', {
        hasMessage: Boolean((data as { message?: unknown }).message),
        toolCallCount: Array.isArray((data as { message?: { tool_calls?: unknown[] } }).message?.tool_calls)
          ? ((data as { message: { tool_calls: unknown[] } }).message.tool_calls.length)
          : 0,
      });

      const toolCalls = (data.message?.tool_calls ?? []).map((tc: OllamaToolCall, i: number) => ({
        id: `call_${i}`,
        name: tc.function.name,
        arguments: tc.function.arguments,
      }));

      const finishReason = toolCalls.length > 0 ? 'tool_calls' as const : 'stop' as const;

      log.info('response', {
        model: config.model,
        durationMs,
        finishReason,
        toolCallCount: toolCalls.length,
        toolCallNames: toolCalls.map(tc => tc.name),
        promptTokens: data.prompt_eval_count ?? null,
        completionTokens: data.eval_count ?? null,
        contentLength: data.message?.content?.length ?? 0,
      });

      if (toolCount > 0 && toolCalls.length === 0) {
        log.warn('model returned no tool calls despite tools being provided', {
          toolCount,
          toolNames: params.tools?.map(t => t.name) ?? [],
          finishReason,
          promptTokens: data.prompt_eval_count ?? null,
          contentPreview: data.message?.content?.slice(0, 200) ?? null,
        });
      }

      return {
        content: data.message?.content ?? null,
        toolCalls,
        finishReason,
      };
    } finally {
      clearTimeout(timeout);
    }
  };
}

function createVLLMLLM(config: OrchestratorConfig): LLMFunction {
  const baseUrl = config.baseUrl ?? 'http://localhost:8000';
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const log = createLogger('orchestrator.vllm', config.logLevel);

  return async (params: { messages: LLMMessage[]; tools?: LLMToolDefinition[] }): Promise<LLMResponse> => {
    const toolCount = params.tools?.length ?? 0;

    const body: Record<string, unknown> = {
      model: config.model,
      messages: params.messages,
    };

    if (params.tools && params.tools.length > 0) {
      body.tools = params.tools.map(t => ({
        type: 'function',
        function: {
          name: t.name,
          description: t.description,
          parameters: t.parameters,
        },
      }));
    }

    log.info('request', {
      model: config.model,
      messageCount: params.messages.length,
      toolCount,
      toolNames: params.tools?.map(t => t.name) ?? [],
    });

    // the full request body and raw response can contain
    // tool arguments + LLM completions that include credentials passed
    // through user prompts. Emit a structural summary instead — the
    // bytes themselves are reachable via Mongo audit (encrypted at
    // rest) for forensic replay.
    log.debug('request shape', {
      messageCount: Array.isArray((body as { messages?: unknown[] }).messages)
        ? (body as { messages: unknown[] }).messages.length
        : 0,
      toolCount: Array.isArray((body as { tools?: unknown[] }).tools)
        ? (body as { tools: unknown[] }).tools.length
        : 0,
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const start = Date.now();
      const response = await fetch(`${baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        const rawText = await response.text();

        // CHARIOT::§8.3::3 — llama.cpp returns 500 with a known-bad malformed
        // JSON envelope when it fails to parse multi-tool output. The error
        // body carries the raw tool call data after "Failed to parse input at
        // pos N: ". Example: 'Failed to parse input at pos 158: ;
        // {"name": "check_identity", "parameters": {"userId": "admin@company.com"}}'
        if (response.status === 500 && toolCount > 0 && rawText.includes('Failed to parse input')) {
          // CHARIOT::§8.3::3 — strip the envelope: rawText is JSON of the
          // shape {"error":{"message":"Failed to parse input at pos N: ; {\"name\":...}"}};
          // unwrap it to get the inner message string with unescaped quotes.
          let messageText = rawText;
          try {
            const envelope = JSON.parse(rawText) as { error?: { message?: string } };
            if (envelope.error?.message) {
              messageText = envelope.error.message;
            }
          } catch {
            // Not valid JSON envelope — use rawText as-is
          }
          // CHARIOT::§8.3::3 — try to parse the inner content as the
          // chat-completions tool-call schema; proceed if recoverable.
          const recovered = extractToolCallsFromContent(messageText, params.tools ?? []);
          if (recovered.length > 0) {
            const durationMs = Date.now() - start;
            log.info('recovered tool calls from llama.cpp 500 parse error', {
              recovered: recovered.length,
              names: recovered.map(tc => tc.name),
              durationMs,
            });
            return {
              content: null,
              toolCalls: recovered,
              finishReason: 'tool_calls' as const,
            };
          }
          // CHARIOT::§8.3::3 — recovery parser also failed: fall through and
          // surface the error to the orchestrator below.
        }

        const truncated = rawText.slice(0, 500);
        // see Ollama branch.
        log.error('request failed', { status: response.status, body: truncated });
        throw new Error(`vLLM returned ${response.status}`);
      }

      const data = await response.json() as OpenAICompatResponse;
      const durationMs = Date.now() - start;
      const choice = data.choices?.[0];

      // Same redaction rationale as the request body above.
      log.debug('response shape', {
        hasMessage: Boolean((data as { message?: unknown }).message),
        toolCallCount: Array.isArray((data as { message?: { tool_calls?: unknown[] } }).message?.tool_calls)
          ? ((data as { message: { tool_calls: unknown[] } }).message.tool_calls.length)
          : 0,
      });

      let toolCalls = (choice?.message?.tool_calls ?? []).map((tc: OpenAIToolCall) => {
        let parsedArgs: Record<string, unknown>;
        if (typeof tc.function.arguments === 'string') {
          try {
            parsedArgs = JSON.parse(tc.function.arguments) as Record<string, unknown>;
          } catch {
            log.warn('malformed tool call JSON from model', { toolName: tc.function.name, raw: tc.function.arguments });
            parsedArgs = {};
          }
        } else {
          parsedArgs = tc.function.arguments;
        }
        return { id: tc.id, name: tc.function.name, arguments: parsedArgs };
      });

      // Fallback: if llama.cpp failed to parse multi-tool output, the tool calls
      // may be embedded in the content as text. Try to extract them.
      if (toolCalls.length === 0 && toolCount > 0 && choice?.message?.content) {
        const extracted = extractToolCallsFromContent(choice.message.content, params.tools ?? []);
        if (extracted.length > 0) {
          log.info('recovered tool calls from content (llama.cpp multi-tool parse fallback)', {
            recovered: extracted.length,
            names: extracted.map(tc => tc.name),
          });
          toolCalls = extracted;
        }
      }

      const finishReason = toolCalls.length > 0 ? 'tool_calls' as const :
        (choice?.finish_reason === 'tool_calls' ? 'tool_calls' as const : 'stop' as const);

      log.info('response', {
        model: config.model,
        durationMs,
        finishReason,
        toolCallCount: toolCalls.length,
        toolCallNames: toolCalls.map(tc => tc.name),
        promptTokens: data.usage?.prompt_tokens ?? null,
        completionTokens: data.usage?.completion_tokens ?? null,
        contentLength: choice?.message?.content?.length ?? 0,
      });

      if (toolCount > 0 && toolCalls.length === 0) {
        log.warn('model returned no tool calls despite tools being provided', {
          toolCount,
          toolNames: params.tools?.map(t => t.name) ?? [],
          finishReason,
          promptTokens: data.usage?.prompt_tokens ?? null,
          contentPreview: choice?.message?.content?.slice(0, 200) ?? null,
        });
      }

 // when vLLM is launched with --return-hidden-states (or its
      // OpenAI-compat equivalent), `choice` carries hidden_states / hiddenStates
      // at the last-input-token position. Surface it on LLMResponse.hiddenState
      // so Orchestrator's ToolNecessityProbe can decide whether tool dispatch
      // is even necessary. Absent → probe returns 'unsupported' and no-ops.
      const hs = choice as { hidden_states?: number[]; hiddenStates?: number[] } | undefined;
      const hiddenState = Array.isArray(hs?.hidden_states)
        ? hs.hidden_states
        : (Array.isArray(hs?.hiddenStates) ? hs.hiddenStates : undefined);

      return {
        content: choice?.message?.content ?? null,
        toolCalls,
        finishReason,
        ...(hiddenState ? { hiddenState } : {}),
      };
    } finally {
      clearTimeout(timeout);
    }
  };
}

// Ollama response types
interface OllamaToolCall {
  function: { name: string; arguments: Record<string, unknown> };
}

interface OllamaFullResponse {
  message?: {
    content?: string;
    tool_calls?: OllamaToolCall[];
  };
  prompt_eval_count?: number;
  eval_count?: number;
  eval_duration?: number;
  total_duration?: number;
  load_duration?: number;
}

// OpenAI-compatible response types (vLLM)
interface OpenAIToolCall {
  id: string;
  function: { name: string; arguments: string | Record<string, unknown> };
}

interface OpenAICompatResponse {
  choices?: {
    message?: {
      content?: string;
      tool_calls?: OpenAIToolCall[];
    };
    finish_reason?: string;
  }[];
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

/**
 * Fallback parser for multi-tool calls that llama.cpp fails to parse.
 * When llama.cpp encounters multiple tool calls (e.g. separated by ; or
 * in Llama 3.1's native format), it may fail at the parser level and
 * put the raw tool-call text into the content field instead.
 *
 * This function attempts to extract tool calls from that text content
 * by looking for function call patterns that match known tool names.
 */
function extractToolCallsFromContent(
  content: string,
  tools: LLMToolDefinition[],
): { id: string; name: string; arguments: Record<string, unknown> }[] {
  const toolNames = new Set(tools.map(t => t.name));
  const results: { id: string; name: string; arguments: Record<string, unknown> }[] = [];

  // Pattern 1: JSON objects with "name" and "arguments"/"parameters" fields
  // Matches: {"name":"search_threats","arguments":{"query":"critical"}}
  const jsonPattern = /\{[^{}]*"name"\s*:\s*"([^"]+)"[^{}]*(?:"arguments"|"parameters")\s*:\s*(\{[^}]*\})[^}]*\}/g;
  let match: RegExpExecArray | null;

  while ((match = jsonPattern.exec(content)) !== null) {
    const name = match[1];
    if (!toolNames.has(name)) continue;

    let args: Record<string, unknown>;
    try {
      args = JSON.parse(match[2]) as Record<string, unknown>;
    } catch {
      // Try to be lenient with malformed JSON
      args = {};
    }

    results.push({ id: `fallback_${results.length}`, name, arguments: args });
  }

  if (results.length > 0) return results;

  // Pattern 2: function-call-like syntax in content
  // Matches: search_threats({"query": "critical"}) or search_threats(query="critical")
  for (const toolName of toolNames) {
    const funcPattern = new RegExp(
      toolName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(\\s*(\\{[^)]*\\})\\s*\\)',
      'g',
    );

    while ((match = funcPattern.exec(content)) !== null) {
      let args: Record<string, unknown>;
      try {
        args = JSON.parse(match[1]) as Record<string, unknown>;
      } catch {
        args = {};
      }
      results.push({ id: `fallback_${results.length}`, name: toolName, arguments: args });
    }
  }

  return results;
}
