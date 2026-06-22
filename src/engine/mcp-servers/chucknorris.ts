/**
 * Chuck Norris Jokes API — Native REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://api.chucknorris.io (free, no auth required)
 * Docs: https://api.chucknorris.io
 * Category: entertainment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.chucknorris.io';

interface RawJoke {
  id: string;
  value: string;
  url: string;
  categories: string[];
  created_at: string;
  updated_at: string;
}

interface RawSearchResponse {
  total: number;
  result: RawJoke[];
}

export class ChuckNorrisMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'chucknorris',
      displayName: 'Chuck Norris Jokes',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'chuck norris', 'jokes', 'humor', 'comedy', 'fun',
        'random joke', 'categories', 'search jokes',
      ],
      toolNames: ['random_joke', 'search_jokes', 'list_categories', 'joke_by_category'],
      description: 'Chuck Norris Jokes API: fetch random jokes, search by keyword, list all categories, and retrieve jokes by category — free and unauthenticated via chucknorris.io.',
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
        name: 'random_joke',
        description: 'Get a random Chuck Norris joke.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_jokes',
        description: 'Search Chuck Norris jokes by keyword.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search for within joke text.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'list_categories',
        description: 'List all available Chuck Norris joke categories.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'joke_by_category',
        description: 'Get a random Chuck Norris joke from a specific category.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Category to fetch a joke from. Use list_categories to see valid values.',
            },
          },
          required: ['category'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_joke':      return this.randomJoke();
        case 'search_jokes':     return this.searchJokes(args.query as string);
        case 'list_categories':  return this.listCategories();
        case 'joke_by_category': return this.jokeByCategory(args.category as string);
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

  private formatJoke(j: RawJoke): object {
    return {
      id: j.id,
      joke: j.value,
      categories: j.categories,
      url: j.url,
    };
  }

  private async randomJoke(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/jokes/random`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawJoke;
    return { content: [{ type: 'text', text: this.truncate(this.formatJoke(data)) }], isError: false };
  }

  private async searchJokes(query: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/jokes/search?query=${encodeURIComponent(query)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawSearchResponse;
    return {
      content: [{
        type: 'text',
        text: this.truncate({ total: data.total, query, jokes: data.result.map(j => this.formatJoke(j)) }),
      }],
      isError: false,
    };
  }

  private async listCategories(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/jokes/categories`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as string[];
    return { content: [{ type: 'text', text: this.truncate({ categories: data }) }], isError: false };
  }

  private async jokeByCategory(category: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/jokes/random?category=${encodeURIComponent(category)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawJoke;
    return { content: [{ type: 'text', text: this.truncate(this.formatJoke(data)) }], isError: false };
  }
}
