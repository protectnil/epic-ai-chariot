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
import { guardNpmStdioAdapter, enforcePinnedArgs } from './npmIntegrityGuard.js';

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const logger = createLogger('MCPClientAdapter');

/**
 * Validate and normalize MCP tool result content.
 * Accepts:
 *   - string
 *   - Array of {type: string, text: string} objects (MCP content blocks)
 * Anything else is rejected: a warning is emitted and a sanitized string
 * representation is returned so callers always receive a usable value.
 */
function validateMCPContent(
  content: unknown,
  serverName: string,
  toolName: string,
): string | Array<{ type: string; text: string }> {
  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    const normalized: Array<{ type: string; text: string }> = [];
    let allValid = true;
    for (const item of content) {
      if (
        item !== null &&
        typeof item === 'object' &&
        typeof (item as Record<string, unknown>).type === 'string' &&
        typeof (item as Record<string, unknown>).text === 'string'
      ) {
        normalized.push({
          type: (item as { type: string; text: string }).type,
          text: (item as { type: string; text: string }).text,
        });
      } else {
        allValid = false;
        break;
      }
    }
    if (allValid) return normalized;
  }

  // Unexpected shape — warn and return sanitized string representation
  logger.warn(
    `server="${serverName}" tool="${toolName}": ` +
    `unexpected content shape (type=${Array.isArray(content) ? 'array' : typeof content}). ` +
    `Content rejected; returning string representation.`,
  );
  try {
    return JSON.stringify(content);
  } catch {
    return String(content);
  }
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

export class MCPClientAdapter implements MCPAdapter {
  readonly name: string;
  private client: Client | null = null;
  private transport: StdioClientTransport | StreamableHTTPClientTransport | null = null;
  private readonly config: ServerConnection;
  private _status: ConnectionStatus = 'disconnected';
  private cachedTools: Tool[] = [];

  constructor(config: ServerConnection) {
    this.name = config.name;
    this.config = config;
  }

  get status(): ConnectionStatus {
    return this._status;
  }

  async connect(): Promise<void> {
    if (this._status === 'connected') return;
    this._status = 'connecting';

    try {
      if (this.config.transport === 'stdio') {
        if (!this.config.command) {
          throw new Error(`Server "${this.name}": stdio transport requires a command`);
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
          // Pin enforcement (bug-tracker-ref): catalog args are unversioned, so a
          // verbatim spawn would let npx re-resolve `latest` from the
          // registry and run code the guard never verified. Rewrite to
          // pkg@version so what spawns is what was verified.
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
          // Air-gap: npx must resolve from the local cache the guard verified
          // and fail closed when offline resolution is impossible — never
          // fetch from the registry at runtime.
          spawnEnv.npm_config_offline = 'true';
        }
        this.transport = new StdioClientTransport({
          command: this.config.command,
          args: spawnArgs,
          env: spawnEnv,
        });
      } else if (this.config.transport === 'streamable-http') {
        // Pool path supports stdio + streamable-http only. SSE adapters
        // are dispatched via the direct-call path in toolHandlers.ts.
        if (!this.config.url) {
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
        this.transport = new StreamableHTTPClientTransport(
          new URL(this.config.url),
          { requestInit },
        );
      } else {
        throw new Error(`Server "${this.name}": unsupported transport "${this.config.transport as string}"`);
      }

      this.client = new Client(
        { name: `epic-ai-${this.name}`, version: '0.1.0' },
        { capabilities: {} }
      );

      await this.client.connect(this.transport);

      // Discover tools on connection
      const toolsResponse = await this.client.listTools();
      this.cachedTools = (toolsResponse.tools ?? []).map(t => ({
        name: t.name,
        description: t.description ?? '',
        parameters: (t.inputSchema as Record<string, unknown>) ?? {},
        server: this.name,
        tier: 'orchestrated' as const,
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
    try {
      const safeArgs = sanitizeKeys(args);
      const result = await this.client.callTool({ name, arguments: safeArgs });
      return {
        content: validateMCPContent(result.content, this.name, name),
        isError: Boolean(result.isError),
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
