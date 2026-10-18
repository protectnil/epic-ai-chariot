/**
 * @epicai/chariot — stdio Transport
 * Binds a McpServer to stdio (StdioServerTransport).
 * Default transport — standard stdio MCP server binding.
 *
 * Malformed JSON-RPC frames are answered with a proper JSON-RPC error
 * response (CH-31 — CHARIOT::§23.2::44-45). The SDK's StdioServerTransport routes
 * a parse/validation failure to `onerror` and writes NOTHING back — so an
 * id-bearing request carrying a malformed frame (wrong version, missing
 * method, batch array, oversized/invalid id, truncated JSON) would hang the
 * client forever. We line-buffer stdin ourselves, validate each frame, and
 * emit a -32700 (unparseable) / -32600 (parseable-but-invalid) error —
 * echoing the request id when one is recoverable, else id:null per spec —
 * before forwarding only well-formed frames to the SDK for dispatch.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

type JsonRpcId = string | number | null;

/**
 * Recover the JSON-RPC `id` from a parseable-but-invalid frame so the
 * client's pending call can be resolved. Only string/number ids are valid
 * per JSON-RPC 2.0; anything else (array/object/boolean/absent) → null.
 */
function recoverId(value: unknown): JsonRpcId {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const id = (value as Record<string, unknown>)['id'];
    if (typeof id === 'string' || typeof id === 'number') return id;
  }
  return null;
}

/**
 * Connect the server to stdio.
 * The process remains alive until the parent closes stdin — no handle is returned.
 *
 * @param server  The McpServer to bind.
 * @param stdin   Input stream (defaults to process.stdin; overridable for tests).
 * @param stdout  Output stream (defaults to process.stdout; overridable for tests).
 */
export async function bindStdio(
  server: McpServer,
  stdin: Readable = process.stdin,
  stdout: Writable = process.stdout,
): Promise<void> {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const { JSONRPCMessageSchema } = await import('@modelcontextprotocol/sdk/types.js');
  const { PassThrough } = await import('node:stream');

  // Well-formed frames are forwarded to the SDK transport through this
  // pass-through; malformed frames are answered by us and never reach the SDK.
  const forward = new PassThrough();
  const transport = new StdioServerTransport(forward, stdout);
  await server.connect(transport);

  const writeError = (id: JsonRpcId, code: number, message: string): void => {
    stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } })}\n`);
  };

  const handleLine = (rawLine: string): void => {
    const text = rawLine.replace(/\r$/, '');
    if (text.trim() === '') return;
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      // Unparseable JSON: id is unrecoverable → id:null per JSON-RPC 2.0.
      writeError(null, -32700, 'Parse error');
      return;
    }
    const validated = JSONRPCMessageSchema.safeParse(json);
    if (!validated.success) {
      // Parseable JSON but not a valid JSON-RPC frame (wrong version, missing
      // method, batch array, invalid id, …). Echo the id when recoverable.
      writeError(recoverId(json), -32600, 'Invalid Request');
      return;
    }
    // Well-formed: hand to the SDK transport for normal dispatch.
    forward.write(`${text}\n`);
  };

  // Line-buffer stdin ourselves so we can inspect each frame before the SDK
  // consumes (and discards) it.
  let buffer: Buffer = Buffer.alloc(0);
  stdin.on('data', (chunk: Buffer) => {
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
    let newlineIndex = buffer.indexOf(0x0a);
    while (newlineIndex !== -1) {
      const line = buffer.subarray(0, newlineIndex).toString('utf8');
      buffer = buffer.subarray(newlineIndex + 1);
      handleLine(line);
      newlineIndex = buffer.indexOf(0x0a);
    }
  });
  stdin.on('end', () => {
    if (buffer.length > 0) {
      const line = buffer.toString('utf8');
      buffer = Buffer.alloc(0);
      handleLine(line);
    }
    forward.end();
  });
  stdin.on('error', () => {
    forward.end();
  });
}
