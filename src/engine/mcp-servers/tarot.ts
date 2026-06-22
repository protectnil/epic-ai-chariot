/**
 * Tarot API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://tarotapi.dev (free, no auth required)
// Base URL: https://tarotapi.dev/api/v1
// Docs: https://tarotapi.dev
// Category: entertainment
// Rate limits: None documented; public free API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://tarotapi.dev/api/v1';

export class TarotMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'tarot',
      displayName: 'Tarot API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'tarot', 'tarot card', 'divination', 'card reading', 'major arcana',
        'minor arcana', 'wands', 'cups', 'swords', 'pentacles', 'oracle',
        'fortune', 'spirituality', 'mysticism',
      ],
      toolNames: ['random_card', 'draw_cards', 'search_cards', 'get_card'],
      description: 'Tarot API: draw random tarot cards, pull multi-card spreads, search cards by keyword, or look up a specific card by its short identifier.',
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
        name: 'random_card',
        description: 'Draw a single random tarot card with its upright and reversed meanings.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'draw_cards',
        description: 'Draw multiple random tarot cards. Count must be between 1 and 78.',
        inputSchema: {
          type: 'object',
          properties: {
            count: {
              type: 'number',
              description: 'Number of cards to draw (1-78).',
            },
          },
          required: ['count'],
        },
      },
      {
        name: 'search_cards',
        description: 'Search tarot cards by keyword — matches against card names and descriptions.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search for (e.g. "moon", "strength", "cups").',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_card',
        description:
          'Get a specific tarot card by its short name identifier (e.g. "ar01" for The Magician, "ar00" for The Fool, "wap01" for Ace of Wands).',
        inputSchema: {
          type: 'object',
          properties: {
            name_short: {
              type: 'string',
              description:
                'The short name identifier of the card (e.g. "ar01", "ar00", "wap01", "cup10").',
            },
          },
          required: ['name_short'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_card':  return this.randomCard();
        case 'draw_cards':   return this.drawCards(args.count as number);
        case 'search_cards': return this.searchCards(args.query as string);
        case 'get_card':     return this.getCard(args.name_short as string);
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
    const url = `${BASE_URL}${path}`;
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

  private async randomCard(): Promise<ToolResult> {
    return this.request('/cards/random?n=1');
  }

  private async drawCards(count: number): Promise<ToolResult> {
    if (typeof count !== 'number' || count < 1 || count > 78) {
      return {
        content: [{ type: 'text', text: 'count must be a number between 1 and 78' }],
        isError: true,
      };
    }
    return this.request(`/cards/random?n=${count}`);
  }

  private async searchCards(query: string): Promise<ToolResult> {
    if (typeof query !== 'string' || query.trim().length === 0) {
      return {
        content: [{ type: 'text', text: 'query must be a non-empty string' }],
        isError: true,
      };
    }
    return this.request(`/cards/search?q=${encodeURIComponent(query)}`);
  }

  private async getCard(nameShort: string): Promise<ToolResult> {
    if (typeof nameShort !== 'string' || nameShort.trim().length === 0) {
      return {
        content: [{ type: 'text', text: 'name_short must be a non-empty string' }],
        isError: true,
      };
    }
    return this.request(`/cards/${encodeURIComponent(nameShort)}`);
  }
}
