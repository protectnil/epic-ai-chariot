/**
 * JokeAPI v2 MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://v2.jokeapi.dev
// Base URL: https://v2.jokeapi.dev
// Auth: None required — JokeAPI v2 is public and free with no auth.
// Docs: https://jokeapi.dev/
// Rate limits: 120 requests/minute on the free tier (no key required).

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface JokesConfig {
  /** Optional base URL override (default: https://v2.jokeapi.dev) */
  baseUrl?: string;
}

export class JokesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: JokesConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('JokeAPI: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://v2.jokeapi.dev';
  }

  static catalog() {
    return {
      name: 'jokes',
      displayName: 'JokeAPI — Jokes & Humor',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'jokes', 'humor', 'comedy', 'funny', 'pun', 'programming jokes',
        'dark humor', 'spooky', 'christmas', 'random joke', 'joke search',
        'jokeapi', 'entertainment', 'safe', 'categories', 'flags',
      ],
      toolNames: ['get_joke', 'search_jokes', 'get_joke_categories', 'get_joke_flags'],
      description: 'JokeAPI v2: fetch random jokes by category and type, search jokes by keyword, list available categories, and list content filter flags — all free and unauthenticated.',
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
        name: 'get_joke',
        description: 'Get a random joke. Optionally filter by category, type (single-line or two-part), and safe mode.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Joke category. One of: Any, Programming, Misc, Dark, Pun, Spooky, Christmas. Defaults to "Any".',
            },
            type: {
              type: 'string',
              description: 'Joke type. One of: single, twopart. Omit to allow either type.',
            },
            safe_mode: {
              type: 'boolean',
              description: 'When true, only return jokes flagged safe by JokeAPI. Defaults to true.',
            },
          },
        },
      },
      {
        name: 'search_jokes',
        description: 'Search for jokes containing a specific keyword or phrase.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search for within joke text.',
            },
            category: {
              type: 'string',
              description: 'Limit search to a category. One of: Any, Programming, Misc, Dark, Pun, Spooky, Christmas. Defaults to "Any".',
            },
            amount: {
              type: 'number',
              description: 'Number of jokes to return. Defaults to 5.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_joke_categories',
        description: 'List all available joke categories supported by JokeAPI.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_joke_flags',
        description: 'List all available joke flags (content filters) supported by JokeAPI.',
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
        case 'get_joke':            return this.getJoke(args);
        case 'search_jokes':        return this.searchJokes(args);
        case 'get_joke_categories': return this.getJokeCategories();
        case 'get_joke_flags':      return this.getJokeFlags();
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
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getJoke(args: Record<string, unknown>): Promise<ToolResult> {
    const category = encodeURIComponent((args.category as string | undefined) ?? 'Any');
    const safeMode = (args.safe_mode as boolean | undefined) ?? true;
    const params = new URLSearchParams();
    if (args.type) params.set('type', args.type as string);
    if (safeMode) params.set('safe-mode', '');
    const query = params.toString();
    const path = `/joke/${category}${query ? `?${query}` : ''}`;
    return this.request(path);
  }

  private async searchJokes(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const category = encodeURIComponent((args.category as string | undefined) ?? 'Any');
    const amount = Math.min(10, Math.max(1, Number(args.amount ?? 5)));
    const params = new URLSearchParams({
      contains: query,
      amount: String(amount),
    });
    return this.request(`/joke/${category}?${params.toString()}`);
  }

  private async getJokeCategories(): Promise<ToolResult> {
    return this.request('/categories');
  }

  private async getJokeFlags(): Promise<ToolResult> {
    return this.request('/flags');
  }
}
