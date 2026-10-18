/**
 * @epicai/chariot — MCP Client Adapter
 * Wraps @modelcontextprotocol/sdk Client for a single MCP server connection.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Tool, ToolResult, ConnectionStatus } from '../../types/index.js';
import type { MCPAdapter } from './base.js';
import type { ServerConnection } from '../../types/index.js';
import { createLogger } from '../../logger.js';
import { guardNpmStdioAdapter, enforcePinnedArgs, stripDangerousStdioEnv } from './npmIntegrityGuard.js';
import { applyCuratedHostOverride } from '../../../catalog/curated.js';
import { createMcpDispatchFetch } from '../mcpDispatchFetch.js';

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const logger = createLogger('MCPClientAdapter');

/**
 * Stdio launchers that carry a supply-chain integrity gate in connect().
 * Only these may be spawned; any other stdio command fails closed. Adding a
 * launcher here REQUIRES adding an equivalent per-launcher integrity gate
 * (hash-pinned + offline resolution) in connect().
 */
const INTEGRITY_GATED_STDIO_COMMANDS = new Set<string>(['npx']);

/** MCP content block types that are spec-legal but carry no `text` field. */
const NON_TEXT_MCP_BLOCK_TYPES = new Set(['image', 'audio', 'resource', 'resource_link']);

/**
 * Validate and normalize MCP tool result content.
 *
 * Returns `{ content, valid }`. `valid` is FALSE for a malformed/hostile
 * shape so the caller can surface it as an error instead of presenting a
 * broken payload as a successful result (fail-open → fail-closed).
 *
 * Accepts:
 *   - string
 *   - Array of MCP content blocks: text blocks ({type:'text', text:string})
 *     AND spec-legal non-text blocks (image/audio/resource/resource_link),
 *     which are preserved with a descriptive placeholder so they are not
 *     misclassified as malformed.
 */
function validateMCPContent(
  content: unknown,
  serverName: string,
  toolName: string,
): { content: string | Array<{ type: string; text: string }>; valid: boolean } {
  if (typeof content === 'string') {
    return { content, valid: true };
  }

  if (Array.isArray(content)) {
    const normalized: Array<{ type: string; text: string }> = [];
    let allValid = true;
    for (const item of content) {
      const rec = item as Record<string, unknown>;
      if (item !== null && typeof item === 'object' && typeof rec.type === 'string') {
        const t = rec.type;
        if (t === 'text' && typeof rec.text === 'string') {
          normalized.push({ type: t, text: rec.text });
          continue;
        }
        if (NON_TEXT_MCP_BLOCK_TYPES.has(t)) {
          // Spec-legal non-text block — no `text` field. Preserve a
          // descriptive placeholder rather than flagging it malformed.
          normalized.push({ type: t, text: `[${t} content]` });
          continue;
        }
      }
      allValid = false;
      break;
    }
    if (allValid) return { content: normalized, valid: true };
  }

  // Unexpected/malformed shape — warn and mark INVALID so the caller returns
  // an error rather than presenting broken content as success.
  logger.warn(
    `server="${serverName}" tool="${toolName}": ` +
    `unexpected content shape (type=${Array.isArray(content) ? 'array' : typeof content}). ` +
    `Content rejected as malformed.`,
  );
  let repr: string;
  try {
    repr = JSON.stringify(content);
  } catch {
    repr = String(content);
  }
  return { content: `Malformed MCP content from server: ${repr}`, valid: false };
}

/**
 * Recursively remove prototype-pollution keys from an object tree.
 * Handles nested objects and arrays. Uses a seen set for cycle safety.
 */
function sanitizeKeys(obj: Record<string, unknown>, seen?: WeakSet<object>): Record<string, unknown> {
  const visited = seen ?? new WeakSet();
  if (visited.has(obj)) return {};
  visited.add(obj);

  const safe = Object.create(null) as Record<string, unknown>;
  for (const [k, v] of Object.entries(obj)) {
    if (BLOCKED_KEYS.has(k)) continue;
    if (Array.isArray(v)) {
      safe[k] = v.map(item =>
        item && typeof item === 'object' && !(item instanceof Date)
          ? sanitizeKeys(item as Record<string, unknown>, visited)
          : item,
      );
    } else if (v && typeof v === 'object' && !(v instanceof Date)) {
      safe[k] = sanitizeKeys(v as Record<string, unknown>, visited);
    } else {
      safe[k] = v;
    }
  }
  return safe;
}

/** The subset of the MCP SDK Client this adapter actually drives. */
type MCPClientLike = Pick<Client, 'connect' | 'listTools' | 'close' | 'callTool' | 'ping'>;

/**
 * Opt-in construction seams. When omitted (the ONLY production path) the
 * adapter builds a real transport and Client exactly as before — the air-gap
 * launcher allowlist, npm integrity guard, pinned-argument enforcement and
 * offline mode all still run. Supplying a factory performs NO spawn, so these
 * seams cannot be used to launch an ungated stdio launcher; they exist so
 * behavior above the transport (timeout/abort handling) is testable without
 * spawning a child process.
 */
export interface MCPClientAdapterSeams {
  clientFactory?: () => MCPClientLike;
  transportFactory?: () => StdioClientTransport | StreamableHTTPClientTransport;
}

export class MCPClientAdapter implements MCPAdapter {
  readonly name: string;
  private client: MCPClientLike | null = null;
  private transport: StdioClientTransport | StreamableHTTPClientTransport | null = null;
  private readonly config: ServerConnection;
  private readonly seams: MCPClientAdapterSeams;
  private _status: ConnectionStatus = 'disconnected';
  private cachedTools: Tool[] = [];

  constructor(config: ServerConnection, seams: MCPClientAdapterSeams = {}) {
    this.name = config.name;
    this.config = config;
    this.seams = seams;
  }

  get status(): ConnectionStatus {
    return this._status;
  }

  async connect(): Promise<void> {
    if (this._status === 'connected') return;
    this._status = 'connecting';

    try {
      if (this.config.transport === 'stdio' && this.seams.transportFactory) {
        // Test seam ONLY: an injected transport spawns no process, so the
        // launcher allowlist / integrity guard below are not applicable (there
        // is nothing to gate). Production never supplies a transportFactory.
        this.transport = this.seams.transportFactory();
      } else if (this.config.transport === 'stdio') {
        if (!this.config.command) {
          throw new Error(`Server "${this.name}": stdio transport requires a command`);
        }
        // Air-gap FAIL-CLOSED: only stdio launchers that have a supply-chain
        // integrity gate below may be spawned. Previously the entire gate was
        // behind `if (command === 'npx')`, so ANY other stdio command (uvx,
        // docker, sh, node, …) fell through to a verbatim spawn with no hash
        // verification and no offline flag — a registry/PyPI fetch and
        // unpinned code execution. Reject unknown launchers up front rather
        // than failing open. New launchers may be added ONLY together with an
        // equivalent per-launcher integrity gate.
        if (!INTEGRITY_GATED_STDIO_COMMANDS.has(this.config.command)) {
          throw new Error(
            `air-gap: "${this.name}" uses stdio launcher "${this.config.command}" which has no ` +
            `supply-chain integrity gate; only ${[...INTEGRITY_GATED_STDIO_COMMANDS].join(', ')} ` +
            `is supported. Refusing to spawn an unpinned/ungated launcher at runtime.`,
          );
        }
        // Supply-chain integrity gate: when the ServerConnection carries npm
        // integrity fields, verify the tarball is in the local cache with the
        // expected hash BEFORE spawning.  Fail-closed on missing or mismatched
        // hash — no network fetch is permitted at runtime.
        let spawnArgs = this.config.args;
        const spawnEnv: Record<string, string> = {
          ...getDefaultEnvironment(),
          ...(this.config.env ?? {}),
        };
        if (this.config.command === 'npx') {
          // Supply-chain integrity is mandatory for all npx adapters — fail
          // closed when the catalog row lacks version+integrityShasum (which
          // RegistryLoader expresses as integrityPkg being absent).  A missing
          // pin means we cannot verify the tarball before execution, which is
          // the exact air-gap hole this gate exists to prevent.
          if (!this.config.integrityPkg) {
            throw new Error(
              `air-gap: "${this.name}" uses npx but the adapter catalog is missing version ` +
              `and/or integrityShasum. Unpinned npx adapters cannot be launched. ` +
              `Run \`chariot setup --pre-install\` after the catalog is updated with supply-chain metadata.`,
            );
          }
          const guard = guardNpmStdioAdapter(
            this.name,
            this.config.integrityPkg,
            this.config.integrityVersion,
            this.config.integrityShasum,
          );
          if (!guard.ok) {
            throw new Error(`supply-chain integrity check failed for "${this.name}": ${guard.reason}`);
          }
          // Pin enforcement + §1.4 Win-1 launch form: enforcePinnedArgs now
          // returns `--no-install <pkg@version> [server-args]` — npx launches
          // only the pre-fetched, integrity-verified local copy, so no registry
          // fetch and no install step (hence no lifecycle-script code-exec) at
          // runtime, and `latest` cannot be re-resolved.
          const packageFromArgs = Array.isArray(this.config.args)
            && this.config.args.some((arg) =>
              typeof arg === 'string'
              && (
                arg === this.config.integrityPkg
                || arg === `${this.config.integrityPkg}@${this.config.integrityVersion}`
                || arg.startsWith(`${this.config.integrityPkg}@`)
              ));
          spawnArgs = enforcePinnedArgs(
            this.config.args,
            this.config.integrityPkg,
            this.config.integrityVersion as string,
            packageFromArgs,
          );
          // Security hardening: strip any code-exec/preload/npm_config_* channel a
          // catalog row smuggled through this.config.env (NODE_OPTIONS,
          // LD_PRELOAD, npm_config_call, …) BEFORE the engine sets its own npx
          // config, so the engine flags are authoritative and un-overridable.
          stripDangerousStdioEnv(spawnEnv);
          // Air-gap: resolve from the local cache the guard verified, fail
          // closed offline, and never run npm lifecycle scripts at dispatch.
          spawnEnv.npm_config_offline = 'true';
          spawnEnv.npm_config_ignore_scripts = 'true';
        }
        this.transport = new StdioClientTransport({
          command: this.config.command,
          args: spawnArgs,
          env: spawnEnv,
        });
      } else if (this.config.transport === 'streamable-http') {
        // Pool path supports stdio + streamable-http only. SSE adapters
        // are dispatched via the direct-call path in toolHandlers.ts.
        const url = applyCuratedHostOverride(this.config.url);
        if (!url) {
          throw new Error(`Server "${this.name}": streamable-http transport requires a url`);
        }
        const requestInit: RequestInit = {};
        if (this.config.auth) {
          const headers: Record<string, string> = {};
          switch (this.config.auth.type) {
            case 'bearer':
              headers['Authorization'] = `Bearer ${this.config.auth.token ?? ''}`;
              break;
            case 'api-key':
              headers[this.config.auth.headerName ?? 'X-API-Key'] = this.config.auth.token ?? '';
              break;
            case 'basic':
              headers['Authorization'] = `Basic ${Buffer.from(`${this.config.auth.username ?? ''}:${this.config.auth.password ?? ''}`).toString('base64')}`;
              break;
          }
          requestInit.headers = headers;
        }
        // Suppress the SDK's standalone GET SSE listening stream — it
        // otherwise starves the tools/list POST on some remote hosts and hangs
        // the connection until the listTools timeout (see createMcpDispatchFetch).
        this.transport = new StreamableHTTPClientTransport(
          new URL(url),
          { requestInit, fetch: createMcpDispatchFetch() },
        );
      } else {
        throw new Error(`Server "${this.name}": unsupported transport "${this.config.transport as string}"`);
      }

      this.client = this.seams.clientFactory?.() ?? new Client(
        { name: `epic-ai-${this.name}`, version: '0.1.0' },
        { capabilities: {} }
      );

      await this.client.connect(this.transport);

      // Discover tools on connection. A hung MCP server must not block the
      // connection attempt indefinitely — mirror the TSA POST timeout pattern
      // in src/engine/audit/anchor.ts (CH-47). Default 30 s; override via
      // CHARIOT_MCP_CONNECT_TIMEOUT_MS.
      const connectEnvMs = parseInt(process.env.CHARIOT_MCP_CONNECT_TIMEOUT_MS ?? '', 10);
      const connectTimeoutMs = Number.isFinite(connectEnvMs) && connectEnvMs > 0 ? connectEnvMs : 30_000;
      const connectAbort = new AbortController();
      const connectTimer = setTimeout(() => connectAbort.abort(), connectTimeoutMs);
      let toolsResponse: Awaited<ReturnType<typeof this.client.listTools>>;
      try {
        toolsResponse = await this.client.listTools({}, { signal: connectAbort.signal });
      } catch (err) {
        // Detect the timeout via our controller signal OR the MCP SDK's own
        // request-timeout error. Under load the SDK's internal timeout can win
        // the race and surface (as McpError code -32001 / "Request timed out")
        // before `signal.aborted` flips — so a bare signal check misses it. Both
        // paths mean the same thing: emit the descriptive typed message.
        const isTimeout =
          connectAbort.signal.aborted ||
          (err instanceof Error &&
            ((err as { code?: number }).code === -32001 ||
              /request timed out/i.test(err.message)));
        if (isTimeout) {
          throw new Error(
            `MCP server "${this.name}" did not respond to listTools within ${connectTimeoutMs}ms (timed out)`,
          );
        }
        throw err;
      } finally {
        clearTimeout(connectTimer);
      }
      // Cap tool count to guard against hostile servers returning unbounded lists
      // that would exhaust heap. CHARIOT_MCP_TOOL_CAP overrides the default of 500.
      const toolCapEnv = parseInt(process.env.CHARIOT_MCP_TOOL_CAP ?? '', 10);
      const toolCap = Number.isFinite(toolCapEnv) && toolCapEnv > 0 ? toolCapEnv : 500;
      const rawTools = toolsResponse.tools ?? [];
      if (rawTools.length > toolCap) {
        logger.warn(
          `server="${this.name}" returned ${rawTools.length} tools; capping at ${toolCap} to prevent heap exhaustion`,
        );
      }
      this.cachedTools = rawTools.slice(0, toolCap).map(t => ({
        name: t.name,
        description: t.description ?? '',
        parameters: (t.inputSchema as Record<string, unknown>) ?? {},
        server: this.name,
        tier: 'orchestrated' as const,
        // Preserve MCP tool annotations (readOnlyHint etc.) so downstream
        // consumers (e.g. Correlator read-only selection) can gate on them.
        annotations: t.annotations as Tool['annotations'],
      }));

      this._status = 'connected';
    } catch (error) {
      this._status = 'error';
      // Air-gap fail-closed: npx stdio adapters spawn with the integrity-pinned
      // pkg@version and npm_config_offline=true, so resolution is served from
      // the local cache the guard verified and never from the registry. When
      // the package is absent locally the spawn fails here with an opaque
      // npm/ENOENT error; surface a clear, actionable message instead, and
      // never fall back to a network fetch.
      if (this.config.transport === 'stdio') {
        const msg = error instanceof Error ? error.message : String(error);
        const notPresent = /ENOENT|could not determine executable|not found|no such (file|package)|404|npm error/i.test(msg);
        if (notPresent) {
          const pkg = this.config.args?.find((a) => !a.startsWith('-')) ?? this.config.command ?? this.name;
          throw new Error(
            `air-gapped: ${this.name} not present (expected ${pkg}). The adapter package was not pre-fetched or bundled, and Chariot does not fetch from a registry at runtime. Original error: ${msg}`,
          );
        }
      }
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    if (this._status === 'disconnected') return;

    try {
      if (this.client) {
        await this.client.close();
      }
      // If client.close() found _transport already nulled (e.g. onclose
      // fired early), the transport's child process was never killed.
      // Close the transport directly as a fallback.
      if (this.transport) {
        await this.transport.close();
      }
    } finally {
      this.client = null;
      this.transport = null;
      this.cachedTools = [];
      this._status = 'disconnected';
    }
  }

  listTools(): Promise<Tool[]> {
    if (this._status !== 'connected' || !this.client) {
      return Promise.reject(new Error(`Server "${this.name}" is not connected`));
    }
    return Promise.resolve(this.cachedTools);
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    if (this._status !== 'connected' || !this.client) {
      throw new Error(`Server "${this.name}" is not connected`);
    }

    const startTime = Date.now();
    // Bound each MCP tool call so a hung server cannot block dispatch
    // indefinitely. Mirrors the TSA POST timeout in anchor.ts (CH-47).
    // Default 60 s; override via CHARIOT_MCP_CALL_TIMEOUT_MS.
    // callTool's second parameter is a result schema (not options), so we use
    // Promise.race with a timeout rejection rather than an AbortController
    // signal on the SDK call itself.
    const callEnvMs = parseInt(process.env.CHARIOT_MCP_CALL_TIMEOUT_MS ?? '', 10);
    const callTimeoutMs = Number.isFinite(callEnvMs) && callEnvMs > 0 ? callEnvMs : 60_000;
    let callTimer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_res, rej) => {
      callTimer = setTimeout(() => {
        rej(new Error(
          `MCP server "${this.name}" tool "${name}" did not respond within ${callTimeoutMs}ms (timed out)`,
        ));
      }, callTimeoutMs);
    });
    try {
      const safeArgs = sanitizeKeys(args);
      const result = await Promise.race([
        this.client.callTool({ name, arguments: safeArgs }),
        timeoutPromise,
      ]);
      const validated = validateMCPContent(result.content, this.name, name);
      return {
        content: validated.content,
        // Fail-closed: malformed/hostile content is an error, never a silent
        // success — even when the server set isError:false.
        isError: Boolean(result.isError) || !validated.valid,
        server: this.name,
        tool: name,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        content: error instanceof Error ? error.message : String(error),
        isError: true,
        server: this.name,
        tool: name,
        durationMs: Date.now() - startTime,
      };
    } finally {
      clearTimeout(callTimer);
    }
  }

  async ping(): Promise<number> {
    if (this._status !== 'connected' || !this.client) {
      throw new Error(`Server "${this.name}" is not connected`);
    }
    const start = Date.now();
    await this.client.ping();
    return Date.now() - start;
  }
}
