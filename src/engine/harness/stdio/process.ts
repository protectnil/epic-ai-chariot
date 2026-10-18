#!/usr/bin/env node
/**
 * @epicai/chariot — Test Harness STDIO Server Process
 * Standalone MCP server for the STDIO harness profile.
 * Spawned as a child process by StdioHarnessBackend.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { HarnessProfile } from '../types.js';
import { createHandlerState, resetHandlerState, handleTool } from '../shared/handlers.js';

const state = createHandlerState(HarnessProfile.Stdio);
const server = new McpServer({ name: 'harness-stdio', version: '1.0.0' });

/** Serialize content for MCP text response — strings pass through, objects get JSON.stringify */
function toText(content: unknown): string {
  return typeof content === 'string' ? content : JSON.stringify(content);
}

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

// Handle reset via a special tool (since stdio has no out-of-band channel)
server.tool('_harness_reset', {}, () => {
  resetHandlerState(state);
  return { content: [{ type: 'text' as const, text: JSON.stringify({ reset: true }) }], isError: false };
});

const transport = new StdioServerTransport();
await server.connect(transport);
