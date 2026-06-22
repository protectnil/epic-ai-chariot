/**
 * DOAJ (Directory of Open Access Journals) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://doaj.org/api/v3
 * Auth: none — all read endpoints are public
 * Docs: https://doaj.org/api/v3/docs
 * Category: research
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://doaj.org/api/v3';

export class DOAJMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DOAJMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'doaj',
      displayName: 'DOAJ — Directory of Open Access Journals',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'doaj', 'open access', 'journals', 'articles', 'academic',
        'peer review', 'research', 'scholarly', 'publications',
        'bibliography', 'science', 'open science', 'free journals',
      ],
      toolNames: ['search_articles', 'search_journals', 'get_article', 'get_journal'],
      description: 'Search and retrieve peer-reviewed open-access articles and journals from the Directory of Open Access Journals (DOAJ).',
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
        name: 'search_articles',
        description:
          'Search peer-reviewed open-access articles indexed in DOAJ. Supports Lucene-style field queries (title:climate, abstract:"machine learning", year:2023, author:Doe).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text or Lucene-style query' },
            page: { type: 'number', description: '1-based page number (default 1)' },
            page_size: { type: 'number', description: 'Results per page, 1-100 (default 10)' },
            sort: { type: 'string', description: 'Sort field and direction, e.g. "created_date:desc"' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_journals',
        description: 'Search open-access journals indexed in DOAJ. Supports Lucene-style field queries.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text or Lucene-style query' },
            page: { type: 'number', description: '1-based page number (default 1)' },
            page_size: { type: 'number', description: 'Results per page, 1-100 (default 10)' },
            sort: { type: 'string', description: 'Sort field and direction, e.g. "created_date:desc"' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_article',
        description: 'Fetch a single article record by its DOAJ article id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'DOAJ article id (e.g. "abc123def456...")' },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_journal',
        description: 'Fetch a single journal record by its DOAJ journal id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'DOAJ journal id (e.g. "abc123def456...")' },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_articles':  return this.searchKind('articles', args);
        case 'search_journals':  return this.searchKind('journals', args);
        case 'get_article':      return this.getById('articles', args);
        case 'get_journal':      return this.getById('journals', args);
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

  private async searchKind(
    kind: 'articles' | 'journals',
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    if (typeof args.query !== 'string' || !args.query.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }], isError: true };
    }
    const params = new URLSearchParams({
      page: String(Math.max(1, Number(args.page ?? 1))),
      pageSize: String(Math.min(100, Math.max(1, Number(args.page_size ?? 10)))),
    });
    if (args.sort) params.set('sort', String(args.sort));
    const encodedQuery = encodeURIComponent(args.query.trim());
    return this.doajGet(`/search/${kind}/${encodedQuery}?${params.toString()}`);
  }

  private async getById(
    kind: 'articles' | 'journals',
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    if (typeof args.id !== 'string' || !args.id.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "id" is missing or empty.' }], isError: true };
    }
    return this.doajGet(`/${kind}/${encodeURIComponent(args.id.trim())}`);
  }

  private async doajGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'DOAJ: record not found (404).' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `DOAJ API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
