/**
 * PoetryDB MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://poetrydb.org
 * Base URL: https://poetrydb.org
 * Auth: none (public, no-auth-verified)
 * Docs: https://github.com/thundercomb/poetrydb#readme
 * Category: education
 * Rate limits: none documented
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://poetrydb.org';

interface RawPoem {
  title: string;
  author: string;
  lines: string[];
  linecount: string;
}

function formatPoem(raw: RawPoem): Record<string, unknown> {
  return {
    title: raw.title,
    author: raw.author,
    line_count: parseInt(raw.linecount, 10) || raw.lines.length,
    text: raw.lines.join('\n'),
  };
}

export class PoetryMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('PoetryMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'poetry',
      displayName: 'PoetryDB',
      version: '1.0.0',
      category: 'education',
      keywords: [
        'poetry', 'poems', 'poets', 'literature', 'verse', 'author',
        'title', 'lines', 'poetrydb', 'english poetry', 'classic poetry',
        'robert frost', 'emily dickinson', 'shakespeare',
      ],
      toolNames: ['search_poems', 'poems_by_author', 'random_poems'],
      description: 'PoetryDB: search poems by title, retrieve all poems by a specific author, and fetch random poems from the PoetryDB collection — free public API, no authentication required.',
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
        name: 'search_poems',
        description: 'Search for poems by title. Returns matching poems with their full text.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Title or partial title to search for (e.g., "The Road Not Taken")',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'poems_by_author',
        description: 'Get all poems by a specific author. Returns poem titles and full text.',
        inputSchema: {
          type: 'object',
          properties: {
            author: {
              type: 'string',
              description: 'Author name (e.g., "Emily Dickinson", "Robert Frost")',
            },
          },
          required: ['author'],
        },
      },
      {
        name: 'random_poems',
        description: 'Get one or more random poems from the collection.',
        inputSchema: {
          type: 'object',
          properties: {
            count: {
              type: 'number',
              description: 'Number of random poems to return (default 1, max 10)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_poems':   return this.searchPoems(args);
        case 'poems_by_author': return this.poemsByAuthor(args);
        case 'random_poems':   return this.randomPoems(args);
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

  private async searchPoems(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/title/${encodeURIComponent(query)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawPoem[] | { status: number; reason: string };
    // PoetryDB returns a status/reason object when no results are found
    if (!Array.isArray(data)) {
      return {
        content: [{ type: 'text', text: this.truncate({ query, count: 0, poems: [] }) }],
        isError: false,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ query, count: data.length, poems: data.map(formatPoem) }) }],
      isError: false,
    };
  }

  private async poemsByAuthor(args: Record<string, unknown>): Promise<ToolResult> {
    const author = args.author as string;
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/author/${encodeURIComponent(author)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawPoem[] | { status: number; reason: string };
    if (!Array.isArray(data)) {
      return {
        content: [{ type: 'text', text: `Author not found: ${author}` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ author, count: data.length, poems: data.map(formatPoem) }) }],
      isError: false,
    };
  }

  private async randomPoems(args: Record<string, unknown>): Promise<ToolResult> {
    const count = Math.min(10, Math.max(1, ((args.count as number) ?? 1)));
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/random/${count}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawPoem[];
    return {
      content: [{ type: 'text', text: this.truncate({ count: data.length, poems: data.map(formatPoem) }) }],
      isError: false,
    };
  }
}
