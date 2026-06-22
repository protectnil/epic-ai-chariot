/**
 * AnimeQuotes MCP Adapter — animechan.io (free, no auth)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.animechan.io/v1
 *   (the old animechan.io/api/v1 host 404s — verified 2026-06-09;
 *   api.animechan.io/v1 verified live 2026-06-10 for /quotes/random and
 *   /quotes?anime=. Anonymous tier is rate-limited: HTTP 429, hourly reset.)
 * Auth: None — public API, no key required
 * Upstream: animechan.io
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.animechan.io/v1';

interface RawQuote {
  data?: {
    content: string;
    anime: { name: string };
    character: { name: string };
  };
}

interface RawQuoteList {
  data?: Array<{
    content: string;
    anime: { name: string };
    character: { name: string };
  }>;
}

function formatQuote(entry: {
  content: string;
  anime: { name: string };
  character: { name: string };
}) {
  return {
    quote: entry.content,
    character: entry.character.name,
    anime: entry.anime.name,
  };
}

export class AnimeQuotesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('AnimeQuotesMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || BASE_URL;
  }

  static catalog() {
    return {
      name: 'animequotes',
      displayName: 'AnimeQuotes — animechan.io',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'anime', 'quotes', 'manga', 'characters', 'naruto', 'attack on titan',
        'one piece', 'dragon ball', 'anime quotes', 'japanese animation',
        'animechan', 'anime series', 'anime characters', 'inspirational quotes',
      ],
      toolNames: ['random_quote', 'search_by_anime', 'search_by_character'],
      description: 'animechan.io API v1: retrieve random anime quotes and search quotes by anime series or character name — free, unauthenticated.',
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
        name: 'random_quote',
        description: 'Get a single random quote from an anime series.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_by_anime',
        description: 'Get quotes from a specific anime series by name.',
        inputSchema: {
          type: 'object',
          properties: {
            anime: {
              type: 'string',
              description: 'Name of the anime series (e.g., "Naruto", "Attack on Titan")',
            },
          },
          required: ['anime'],
        },
      },
      {
        name: 'search_by_character',
        description: 'Get quotes from a specific anime character by name.',
        inputSchema: {
          type: 'object',
          properties: {
            character: {
              type: 'string',
              description: 'Name of the anime character (e.g., "Naruto Uzumaki", "Levi Ackerman")',
            },
          },
          required: ['character'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_quote':       return this.randomQuote();
        case 'search_by_anime':    return this.searchByAnime(args);
        case 'search_by_character': return this.searchByCharacter(args);
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

  private async randomQuote(): Promise<ToolResult> {
    const url = `${this.baseUrl}/quotes/random`;
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
    const data = (await response.json()) as RawQuote;
    if (!data.data) {
      return { content: [{ type: 'text', text: 'animechan.io returned an empty response' }], isError: true };
    }
    return { content: [{ type: 'text', text: this.truncate(formatQuote(data.data)) }], isError: false };
  }

  private async searchByAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const anime = args.anime as string;
    if (!anime || typeof anime !== 'string') {
      return { content: [{ type: 'text', text: 'search_by_anime: "anime" parameter is required' }], isError: true };
    }
    const url = `${this.baseUrl}/quotes?anime=${encodeURIComponent(anime)}`;
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
    const data = (await response.json()) as RawQuoteList;
    const quotes = data.data ?? [];
    return {
      content: [{ type: 'text', text: this.truncate({ anime, count: quotes.length, quotes: quotes.map(formatQuote) }) }],
      isError: false,
    };
  }

  private async searchByCharacter(args: Record<string, unknown>): Promise<ToolResult> {
    const character = args.character as string;
    if (!character || typeof character !== 'string') {
      return { content: [{ type: 'text', text: 'search_by_character: "character" parameter is required' }], isError: true };
    }
    const url = `${this.baseUrl}/quotes?character=${encodeURIComponent(character)}`;
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
    const data = (await response.json()) as RawQuoteList;
    const quotes = data.data ?? [];
    return {
      content: [{ type: 'text', text: this.truncate({ character, count: quotes.length, quotes: quotes.map(formatQuote) }) }],
      isError: false,
    };
  }
}
