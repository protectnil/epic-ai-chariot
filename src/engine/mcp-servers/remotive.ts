/**
 * Remotive Remote Jobs MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://remotive.com/api
// Auth: none (public API)
// Docs: https://remotive.com/api-documentation
// Category: jobs

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://remotive.com/api';

export class RemotiveMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('RemotiveMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'remotive',
      displayName: 'Remotive Remote Jobs',
      version: '1.0.0',
      category: 'jobs',
      keywords: [
        'remotive', 'remote jobs', 'remote work', 'job board', 'jobs',
        'careers', 'hiring', 'remote employment', 'job search',
        'software dev', 'design', 'marketing', 'customer support',
        'remote-only', 'work from home',
      ],
      toolNames: ['search', 'list_categories', 'get_company'],
      description: 'Remotive Remote Jobs: search remote-only job listings, browse job categories, and retrieve company profiles with active openings.',
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
        description: 'Search remote jobs by free-text, category, and/or company name.',
        inputSchema: {
          type: 'object',
          properties: {
            search: {
              type: 'string',
              description: 'Free-text search — matches job title and description.',
            },
            category: {
              type: 'string',
              description: 'Category slug (e.g. "software-dev", "design", "marketing"). Use list_categories to get valid slugs.',
            },
            company_name: {
              type: 'string',
              description: 'Filter results to a specific company name.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of jobs to return (default 25).',
            },
          },
        },
      },
      {
        name: 'list_categories',
        description: 'List all Remotive job categories with their slug and display name.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_company',
        description: 'Retrieve a company profile and its active remote job listings by company slug.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Remotive company slug (e.g. "github", "automattic").',
            },
          },
          required: ['slug'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':         return this.search(args);
        case 'list_categories': return this.listCategories();
        case 'get_company':    return this.getCompany(args);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Remotive: not found (404)' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Remotive API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.search)       params.set('search', String(args.search));
    if (args.category)     params.set('category', String(args.category));
    if (args.company_name) params.set('company_name', String(args.company_name));
    if (args.limit !== undefined) {
      params.set('limit', String(Math.max(1, Number(args.limit))));
    }
    const qs = params.toString();
    return this.get(`/remote-jobs${qs ? `?${qs}` : ''}`);
  }

  private async listCategories(): Promise<ToolResult> {
    return this.get('/remote-jobs/categories');
  }

  private async getCompany(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = args.slug;
    if (typeof slug !== 'string' || !slug.trim()) {
      return {
        content: [{ type: 'text', text: 'get_company: required argument "slug" is missing or empty.' }],
        isError: true,
      };
    }
    return this.get(`/companies/${encodeURIComponent(slug.trim())}`);
  }
}
