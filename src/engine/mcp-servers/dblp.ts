/**
 * DBLP Computer Science Bibliography MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://dblp.org — open computer science bibliography
// Base URL: https://dblp.org/search
// Auth: none — fully public API
// Docs: https://dblp.org/faq/13501473.html
// Category: research
// Rate limits: public; DBLP asks for reasonable crawl rates

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class DblpMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DblpMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://dblp.org/search';
  }

  static catalog() {
    return {
      name: 'dblp',
      displayName: 'DBLP Computer Science Bibliography',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'dblp', 'computer science', 'bibliography', 'publications', 'papers',
        'authors', 'venues', 'conferences', 'journals', 'academic', 'research',
        'citations', 'articles', 'theses', 'scholarly', 'cs bibliography',
      ],
      toolNames: ['search_publications', 'search_authors', 'search_venues'],
      description: 'DBLP Computer Science Bibliography: search publications (papers, articles, theses), authors, and venues (conferences and journals) via the public DBLP API.',
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
        name: 'search_publications',
        description:
          'Search DBLP publications (papers, articles, theses). Match by title, author, year, or venue. Default page size 30, max 1000.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term — title, author name, DOI, or venue',
            },
            hits: {
              type: 'number',
              description: 'Results per page, 1–1000 (default 30)',
            },
            first: {
              type: 'number',
              description: '0-based offset for pagination (default 0)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_authors',
        description:
          'Search DBLP authors by name. Returns canonical id, affiliation, and ORCID when available.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Author name — full or partial',
            },
            hits: {
              type: 'number',
              description: 'Results per page, 1–1000 (default 30)',
            },
            first: {
              type: 'number',
              description: '0-based offset for pagination (default 0)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_venues',
        description:
          'Search DBLP venues (conferences and journals) by name or acronym.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Venue name or acronym (e.g. "ICLR", "Nature")',
            },
            hits: {
              type: 'number',
              description: 'Results per page, 1–1000 (default 30)',
            },
            first: {
              type: 'number',
              description: '0-based offset for pagination (default 0)',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_publications': return this.searchEndpoint('publ', args);
        case 'search_authors':      return this.searchEndpoint('author', args);
        case 'search_venues':       return this.searchEndpoint('venue', args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async searchEndpoint(
    endpoint: 'publ' | 'author' | 'venue',
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }],
        isError: true,
      };
    }

    const hits = typeof args.hits === 'number'
      ? Math.min(1000, Math.max(1, args.hits))
      : 30;
    const first = typeof args.first === 'number'
      ? Math.max(0, args.first)
      : 0;

    const params = new URLSearchParams({
      q: query,
      format: 'json',
      h: String(hits),
      f: String(first),
    });

    const url = `${this.baseUrl}/${endpoint}/api?${params.toString()}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0 (+https://epicai.com)',
      },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `DBLP API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return {
      content: [{ type: 'text', text: this.truncate(data) }],
      isError: false,
    };
  }
}
