/**
 * Spaceflight News API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.spaceflightnewsapi.net/v4
// Auth: None (public, free, no key required)
// Docs: https://api.spaceflightnewsapi.net/v4/docs/
// Category: news
// Rate limits: None documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.spaceflightnewsapi.net/v4';

interface SpaceNewsItem {
  id: number;
  title: string;
  url: string;
  image_url: string;
  news_site: string;
  summary: string;
  published_at: string;
  updated_at: string;
}

interface SpaceNewsApiResponse {
  count: number;
  results: SpaceNewsItem[];
}

export class SpaceNewsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('SpaceNewsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'spacenews',
      displayName: 'Spaceflight News API',
      version: '1.0.0',
      category: 'news',
      keywords: [
        'spaceflight', 'space', 'nasa', 'spacex', 'rocket', 'launch',
        'astronomy', 'aerospace', 'satellite', 'iss', 'news', 'articles',
        'blogs', 'space news', 'spaceflightnewsapi',
      ],
      toolNames: ['get_articles', 'search_articles', 'get_blogs'],
      description: 'Spaceflight News API: fetch and search the latest spaceflight news articles and blog posts — free, public, no authentication required.',
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
        name: 'get_articles',
        description:
          'Fetch the latest spaceflight news articles sorted by publication date. Returns title, summary, URL, image, and source.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of articles to return (default 10, max 100)',
            },
          },
        },
      },
      {
        name: 'search_articles',
        description:
          'Search spaceflight news articles by keyword. Returns matching articles with title, summary, URL, and publication date.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (e.g. "SpaceX Starship launch")',
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
        name: 'get_blogs',
        description:
          'Fetch the latest spaceflight blog posts sorted by publication date. Returns title, summary, URL, image, and source.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of blog posts to return (default 10, max 100)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_articles':  return this.getArticles(args);
        case 'search_articles': return this.searchArticles(args);
        case 'get_blogs':    return this.getBlogs(args);
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

  private clampLimit(raw: unknown, def = 10): number {
    const n = typeof raw === 'number' ? raw : def;
    return Math.min(100, Math.max(1, n));
  }

  private formatItem(item: SpaceNewsItem) {
    return {
      id: item.id,
      title: item.title,
      summary: item.summary,
      url: item.url,
      image_url: item.image_url,
      source: item.news_site,
      published_at: item.published_at,
    };
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as SpaceNewsApiResponse;
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getArticles(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = this.clampLimit(args.limit);
    const params = new URLSearchParams({
      limit: String(limit),
      ordering: '-published_at',
    });
    const url = `${this.baseUrl}/articles/?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as SpaceNewsApiResponse;
    const result = {
      total: data.count,
      returned: data.results.length,
      articles: data.results.map(i => this.formatItem(i)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchArticles(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.query !== 'string' || args.query.trim() === '') {
      return {
        content: [{ type: 'text', text: 'search_articles: query is required and must be a non-empty string' }],
        isError: true,
      };
    }
    const limit = this.clampLimit(args.limit);
    const params = new URLSearchParams({
      search: args.query,
      limit: String(limit),
    });
    const url = `${this.baseUrl}/articles/?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as SpaceNewsApiResponse;
    const result = {
      query: args.query,
      total: data.count,
      returned: data.results.length,
      articles: data.results.map(i => this.formatItem(i)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getBlogs(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = this.clampLimit(args.limit);
    const params = new URLSearchParams({
      limit: String(limit),
      ordering: '-published_at',
    });
    const url = `${this.baseUrl}/blogs/?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as SpaceNewsApiResponse;
    const result = {
      total: data.count,
      returned: data.results.length,
      blogs: data.results.map(i => this.formatItem(i)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
