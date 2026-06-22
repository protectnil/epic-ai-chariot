/**
 * Dad Jokes MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: icanhazdadjoke.com (free, no auth required)
// Base URL: https://icanhazdadjoke.com
// Docs: https://icanhazdadjoke.com/api
// Category: entertainment
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://icanhazdadjoke.com';

const UPSTREAM_HEADERS = {
  Accept: 'application/json',
  'User-Agent': 'epic-ai-chariot/1.0',
};

export class DadJokesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'dadjokes',
      displayName: 'Dad Jokes',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'dad jokes', 'jokes', 'humor', 'comedy', 'funny', 'puns',
        'random joke', 'trivia', 'fun', 'icanhazdadjoke',
      ],
      toolNames: ['random_joke', 'search_jokes', 'get_joke'],
      description: 'Dad Jokes API: retrieve random dad jokes, search jokes by keyword, or look up a specific joke by ID — free and unauthenticated.',
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
        description: 'Get a random dad joke.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_jokes',
        description: 'Search dad jokes by a keyword or term.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Term to search for within dad jokes.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of jokes to return. Defaults to 10.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_joke',
        description: 'Get a specific dad joke by its ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'The ID of the dad joke to retrieve.',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_joke':  return this.randomJoke();
        case 'search_jokes': return this.searchJokes(args);
        case 'get_joke':     return this.getJoke(args);
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

  private async randomJoke(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/`, {
      method: 'GET',
      headers: UPSTREAM_HEADERS,
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { id: string; joke: string; status: number };
    return {
      content: [{ type: 'text', text: this.truncate({ id: data.id, joke: data.joke }) }],
      isError: false,
    };
  }

  private async searchJokes(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = (args.limit as number | undefined) ?? 10;
    const url = `${BASE_URL}/search?term=${encodeURIComponent(query)}&limit=${limit}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: UPSTREAM_HEADERS,
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      total_jokes: number;
      search_term: string;
      results: Array<{ id: string; joke: string }>;
    };
    const result = {
      total: data.total_jokes,
      query: data.search_term,
      jokes: data.results.map((j) => ({ id: j.id, joke: j.joke })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getJoke(args: Record<string, unknown>): Promise<ToolResult> {
    const id = encodeURIComponent(args.id as string);
    const response = await this.fetchWithRetry(`${BASE_URL}/j/${id}`, {
      method: 'GET',
      headers: UPSTREAM_HEADERS,
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { id: string; joke: string; status: number };
    return {
      content: [{ type: 'text', text: this.truncate({ id: data.id, joke: data.joke }) }],
      isError: false,
    };
  }
}
