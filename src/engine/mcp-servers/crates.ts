/**
 * Crates.io MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://crates.io/api/v1
 * Auth: None (public API — no key required)
 * Docs: https://doc.rust-lang.org/cargo/reference/registry-web-api.html
 * Category: development
 * Rate limits: Polite use; crates.io requires a descriptive User-Agent
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://crates.io/api/v1';
// crates.io policy: User-Agent must identify the application and contact URL
const USER_AGENT = 'epic-ai-chariot/1.0.0 (https://epicai.com)';

export class CratesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CratesMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'crates',
      displayName: 'Crates.io',
      version: '1.0.0',
      category: 'development',
      keywords: [
        'crates', 'crates.io', 'rust', 'cargo', 'packages', 'registry',
        'rust packages', 'rust crates', 'dependencies', 'rust ecosystem',
        'package search', 'versions', 'open source',
      ],
      toolNames: ['search_crates', 'get_crate', 'get_versions'],
      description: 'Search and retrieve metadata from crates.io — the Rust package registry. Find crates by keyword, get detailed metadata, and list published versions.',
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
        name: 'search_crates',
        description:
          'Search crates.io for Rust crates by keyword. Returns name, description, total downloads, newest version, and repository URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default 10, max 100)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_crate',
        description:
          'Get metadata for a specific crate: name, description, total downloads, newest version, repository, homepage, and categories.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Exact crate name (e.g., "serde", "tokio")',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_versions',
        description:
          'List all published versions for a crate, ordered newest first. Returns version number, download count, publish date, yanked status, license, and minimum Rust version.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Crate name',
            },
          },
          required: ['name'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_crates': return this.searchCrates(args);
        case 'get_crate':     return this.getCrate(args);
        case 'get_versions':  return this.getVersions(args);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async cratesGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': USER_AGENT,
      },
    });
    if (!response.ok) {
      if (response.status === 404) {
        return { content: [{ type: 'text', text: `Not found: ${path}` }], isError: true };
      }
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `crates.io API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchCrates(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 10));
    const params = new URLSearchParams({ q: query, per_page: String(limit) });
    return this.cratesGet(`/crates?${params.toString()}`);
  }

  private async getCrate(args: Record<string, unknown>): Promise<ToolResult> {
    const name = encodeURIComponent(args.name as string);
    return this.cratesGet(`/crates/${name}`);
  }

  private async getVersions(args: Record<string, unknown>): Promise<ToolResult> {
    const name = encodeURIComponent(args.name as string);
    return this.cratesGet(`/crates/${name}/versions`);
  }
}
