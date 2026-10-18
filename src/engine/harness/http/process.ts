#!/usr/bin/env node
/**
 * @epicai/chariot — Test Harness HTTP Server Process
 * Standalone MCP server over streamable-http for the HTTP harness profile.
 * Spawned as a child process by HttpHarnessBackend.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { HarnessProfile } from '../types.js';
import { createHandlerState, resetHandlerState, handleTool } from '../shared/handlers.js';

const state = createHandlerState(HarnessProfile.Http);

/** Serialize content for MCP text response — strings pass through, objects get JSON.stringify */
function toText(content: unknown): string {
  return typeof content === 'string' ? content : JSON.stringify(content);
}

function createMcpServer(): McpServer {
  const server = new McpServer({ name: 'harness-http', version: '1.0.0' });

  // CHARIOT::§8.11::2 (CHARIOT-SPEC.md:824) — the eight canonical tools, one
  // registration per name in CANONICAL_TOOL_NAMES (shared/toolDefs.ts).
  server.tool('list', { offset: z.number().optional(), limit: z.number().optional() }, async (args) => {
    const r = await handleTool('list', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('search', { query: z.string() }, async (args) => {
    const r = await handleTool('search', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('read', { id: z.string() }, async (args) => {
    const r = await handleTool('read', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('write-shadow', { id: z.string().optional(), fields: z.record(z.string(), z.unknown()) }, async (args) => {
    const r = await handleTool('write-shadow', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('delete-shadow', { id: z.string() }, async (args) => {
    const r = await handleTool('delete-shadow', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('error-handling', { variant: z.number().optional() }, async (args) => {
    const r = await handleTool('error-handling', args, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('auth-failure', {}, async () => {
    const r = await handleTool('auth-failure', {}, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('rate-limit', {}, async () => {
    const r = await handleTool('rate-limit', {}, state);
    return { content: [{ type: 'text' as const, text: toText(r.content) }], isError: r.isError };
  });

  server.tool('_harness_reset', {}, () => {
    resetHandlerState(state);
    return { content: [{ type: 'text' as const, text: JSON.stringify({ reset: true }) }], isError: false };
  });

  return server;
}

// Stateful transport — one persistent session
const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
});

const mcpServer = createMcpServer();
await mcpServer.connect(transport);

const httpServer = createServer((req, res) => {
  void (async () => {
    if (req.url !== '/mcp') {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    try {
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500);
        res.end('Internal error');
      }
    }
  })();
});

httpServer.listen(0, '127.0.0.1', () => {
  const addr = httpServer.address();
  if (addr && typeof addr === 'object') {
    process.stdout.write(`HARNESS_PORT=${addr.port}\n`);
  }
});
