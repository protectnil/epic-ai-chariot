/**
 * ROR (Research Organization Registry) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://ror.org (public registry, no auth required)
// Base URL: https://api.ror.org/v2/organizations
// Auth: none (public, no-auth-verified)
// Docs: https://ror.readme.io/docs
// Category: research
// Rate limits: None documented; public service

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.ror.org/v2/organizations';

export class RorMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('RorMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ror',
      displayName: 'ROR (Research Organization Registry)',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'ror', 'research organization registry', 'university', 'institution',
        'affiliation', 'academic', 'research', 'organization', 'funder',
        'hospital', 'government', 'nonprofit', 'education', 'open access',
      ],
      toolNames: ['search', 'get', 'affiliation'],
      description: 'ROR: search research organizations by name or filters, retrieve a full ROR record by ID, and resolve fuzzy affiliation strings to ranked organization candidates — free public API, no authentication required.',
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
        name: 'search',
        description: 'Search ROR organizations by name query with optional type and country filters.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Organization name or keyword to search for (e.g. "harvard university")',
            },
            type: {
              type: 'string',
              description: 'Organization type filter: education | healthcare | company | archive | nonprofit | government | facility | other',
            },
            country: {
              type: 'string',
              description: 'ISO-3166 alpha-2 country code to filter by (e.g. "US")',
            },
            page: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get',
        description: 'Retrieve a full ROR organization record by its ROR ID. Accepts the trailing identifier (e.g. "03vek6s52") or the full ROR URL (e.g. "https://ror.org/03vek6s52").',
        inputSchema: {
          type: 'object',
          properties: {
            ror_id: {
              type: 'string',
              description: 'ROR identifier: trailing ID like "03vek6s52" or full URL like "https://ror.org/03vek6s52"',
            },
          },
          required: ['ror_id'],
        },
      },
      {
        name: 'affiliation',
        description: 'Resolve a free-text affiliation string to a ranked list of ROR organization candidates with confidence scores.',
        inputSchema: {
          type: 'object',
          properties: {
            text: {
              type: 'string',
              description: 'Raw affiliation string as it appears in a publication (e.g. "MIT Department of Chemistry, Cambridge MA")',
            },
          },
          required: ['text'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':      return this.search(args);
        case 'get':         return this.getOrg(args);
        case 'affiliation': return this.affiliation(args);
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

  private async rorGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'ROR: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return { content: [{ type: 'text', text: 'query is required and must be a non-empty string' }], isError: true };
    }
    const params = new URLSearchParams({
      query: query.trim(),
      page: String(Math.max(1, typeof args.page === 'number' ? args.page : 1)),
    });
    const filters: string[] = [];
    if (typeof args.type === 'string' && args.type.trim()) {
      filters.push(`types:${args.type.trim()}`);
    }
    if (typeof args.country === 'string' && args.country.trim()) {
      filters.push(`country.country_code:${args.country.trim().toUpperCase()}`);
    }
    if (filters.length > 0) {
      params.set('filter', filters.join(','));
    }
    return this.rorGet(`?${params.toString()}`);
  }

  private async getOrg(args: Record<string, unknown>): Promise<ToolResult> {
    const rorId = args.ror_id;
    if (typeof rorId !== 'string' || !rorId.trim()) {
      return { content: [{ type: 'text', text: 'ror_id is required and must be a non-empty string' }], isError: true };
    }
    const id = rorId.trim().replace(/^https?:\/\/ror\.org\//, '');
    return this.rorGet(`/${encodeURIComponent(id)}`);
  }

  private async affiliation(args: Record<string, unknown>): Promise<ToolResult> {
    const text = args.text;
    if (typeof text !== 'string' || !text.trim()) {
      return { content: [{ type: 'text', text: 'text is required and must be a non-empty string' }], isError: true };
    }
    const params = new URLSearchParams({ affiliation: text.trim() });
    return this.rorGet(`?${params.toString()}`);
  }
}
