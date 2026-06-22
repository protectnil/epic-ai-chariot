/**
 * HTTP Cat MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://http.cat
// Auth: none (public, no key required)
// Docs: https://http.cat
// Category: entertainment
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://http.cat';

const COMMON_CODES: Array<{ code: number; description: string }> = [
  { code: 100, description: 'Continue' },
  { code: 101, description: 'Switching Protocols' },
  { code: 200, description: 'OK' },
  { code: 201, description: 'Created' },
  { code: 202, description: 'Accepted' },
  { code: 204, description: 'No Content' },
  { code: 206, description: 'Partial Content' },
  { code: 301, description: 'Moved Permanently' },
  { code: 302, description: 'Found' },
  { code: 304, description: 'Not Modified' },
  { code: 307, description: 'Temporary Redirect' },
  { code: 308, description: 'Permanent Redirect' },
  { code: 400, description: 'Bad Request' },
  { code: 401, description: 'Unauthorized' },
  { code: 403, description: 'Forbidden' },
  { code: 404, description: 'Not Found' },
  { code: 405, description: 'Method Not Allowed' },
  { code: 408, description: 'Request Timeout' },
  { code: 409, description: 'Conflict' },
  { code: 410, description: 'Gone' },
  { code: 413, description: 'Payload Too Large' },
  { code: 414, description: 'URI Too Long' },
  { code: 418, description: "I'm a Teapot" },
  { code: 422, description: 'Unprocessable Entity' },
  { code: 425, description: 'Too Early' },
  { code: 429, description: 'Too Many Requests' },
  { code: 500, description: 'Internal Server Error' },
  { code: 501, description: 'Not Implemented' },
  { code: 502, description: 'Bad Gateway' },
  { code: 503, description: 'Service Unavailable' },
  { code: 504, description: 'Gateway Timeout' },
  { code: 508, description: 'Loop Detected' },
];

export class HttpCatMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('HttpCatMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'httpcat',
      displayName: 'HTTP Cat',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'http', 'cat', 'cats', 'status code', 'http status', 'error code',
        'http error', 'meme', 'image', 'fun', '404', '500',
      ],
      toolNames: ['get_status_cat', 'list_codes'],
      description: 'HTTP Cat: get cat-illustrated image URLs for HTTP status codes and list common status codes — free and unauthenticated.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'get_status_cat',
        description: 'Get the http.cat image URL for a given HTTP status code. Returns a direct URL to a cat photo illustrating the status code.',
        inputSchema: {
          type: 'object',
          properties: {
            status_code: {
              type: 'number',
              description: 'HTTP status code (e.g., 200, 404, 500)',
            },
          },
          required: ['status_code'],
        },
      },
      {
        name: 'list_codes',
        description: 'List common HTTP status codes with their descriptions and corresponding http.cat image URLs.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_status_cat': return this.getStatusCat(args.status_code as number);
        case 'list_codes':     return this.listCodes();
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async getStatusCat(statusCode: number): Promise<ToolResult> {
    if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) {
      return {
        content: [{ type: 'text', text: `Invalid HTTP status code: ${statusCode}. Must be an integer between 100 and 599.` }],
        isError: true,
      };
    }
    // Verify the image exists by issuing a HEAD request to the upstream.
    const url = `${this.baseUrl}/${statusCode}`;
    const response = await this.fetchWithRetry(url, {
      method: 'HEAD',
      headers: { Accept: 'image/jpeg,image/*' },
    });
    const known = COMMON_CODES.find((c) => c.code === statusCode);
    if (!response.ok) {
      // Image not found for this code — still return the URL but note it.
      return {
        content: [{
          type: 'text',
          text: this.truncate({
            status_code: statusCode,
            description: known?.description ?? 'Unknown',
            image_url: url,
            note: `http.cat returned ${response.status} for this code — image may not exist.`,
          }),
        }],
        isError: false,
      };
    }
    return {
      content: [{
        type: 'text',
        text: this.truncate({
          status_code: statusCode,
          description: known?.description ?? 'Unknown',
          image_url: url,
        }),
      }],
      isError: false,
    };
  }

  private async listCodes(): Promise<ToolResult> {
    return {
      content: [{
        type: 'text',
        text: this.truncate({
          count: COMMON_CODES.length,
          codes: COMMON_CODES.map((c) => ({
            code: c.code,
            description: c.description,
            image_url: `${this.baseUrl}/${c.code}`,
          })),
        }),
      }],
      isError: false,
    };
  }
}
