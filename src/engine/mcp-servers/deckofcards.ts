/**
 * Deck of Cards MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://deckofcardsapi.com (free, no auth required)
 * Docs:     https://deckofcardsapi.com
 * Category: entertainment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://deckofcardsapi.com/api/deck';

interface DeckResponse {
  success: boolean;
  deck_id: string;
  shuffled: boolean;
  remaining: number;
}

interface CardItem {
  code: string;
  image: string;
  value: string;
  suit: string;
}

interface DrawResponse {
  success: boolean;
  deck_id: string;
  cards: CardItem[];
  remaining: number;
}

export class DeckOfCardsMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'deckofcards',
      displayName: 'Deck of Cards',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'deck', 'cards', 'playing cards', 'shuffle', 'draw', 'poker',
        'blackjack', 'card game', 'random', 'suits', 'deck of cards',
      ],
      toolNames: ['new_deck', 'draw_cards', 'shuffle_deck'],
      description: 'Deck of Cards API: create and shuffle decks of playing cards, draw cards, and re-shuffle existing decks — free and unauthenticated.',
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
        name: 'new_deck',
        description:
          'Create and shuffle a new deck (or multiple decks) of playing cards. Returns a deck_id for subsequent draws.',
        inputSchema: {
          type: 'object',
          properties: {
            count: {
              type: 'number',
              description: 'Number of standard 52-card decks to combine and shuffle. Defaults to 1.',
            },
          },
        },
      },
      {
        name: 'draw_cards',
        description:
          'Draw one or more cards from an existing deck. Requires the deck_id returned by new_deck.',
        inputSchema: {
          type: 'object',
          properties: {
            deck_id: {
              type: 'string',
              description: 'The deck ID returned by new_deck (e.g. "3p40paa87x90").',
            },
            count: {
              type: 'number',
              description: 'Number of cards to draw. Defaults to 1.',
            },
          },
          required: ['deck_id'],
        },
      },
      {
        name: 'shuffle_deck',
        description:
          'Shuffle (or re-shuffle) an existing deck, returning all drawn cards back into it.',
        inputSchema: {
          type: 'object',
          properties: {
            deck_id: {
              type: 'string',
              description: 'The deck ID to shuffle (e.g. "3p40paa87x90").',
            },
          },
          required: ['deck_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'new_deck':    return this.newDeck((args.count as number | undefined) ?? 1);
        case 'draw_cards':  return this.drawCards(args.deck_id as string, (args.count as number | undefined) ?? 1);
        case 'shuffle_deck': return this.shuffleDeck(args.deck_id as string);
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

  private async newDeck(count: number): Promise<ToolResult> {
    const url = `${BASE_URL}/new/shuffle/?deck_count=${encodeURIComponent(String(count))}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as DeckResponse;
    if (!data.success) {
      return { content: [{ type: 'text', text: 'Deck of Cards API returned success: false' }], isError: true };
    }
    return {
      content: [{
        type: 'text',
        text: this.truncate({ deck_id: data.deck_id, shuffled: data.shuffled, remaining: data.remaining }),
      }],
      isError: false,
    };
  }

  private async drawCards(deckId: string, count: number): Promise<ToolResult> {
    const url = `${BASE_URL}/${encodeURIComponent(deckId)}/draw/?count=${encodeURIComponent(String(count))}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as DrawResponse;
    if (!data.success) {
      return { content: [{ type: 'text', text: 'Deck of Cards API returned success: false' }], isError: true };
    }
    const cards = data.cards.map((c) => ({ code: c.code, value: c.value, suit: c.suit, image: c.image }));
    return {
      content: [{
        type: 'text',
        text: this.truncate({ deck_id: data.deck_id, cards, remaining: data.remaining }),
      }],
      isError: false,
    };
  }

  private async shuffleDeck(deckId: string): Promise<ToolResult> {
    const url = `${BASE_URL}/${encodeURIComponent(deckId)}/shuffle/`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as DeckResponse;
    if (!data.success) {
      return { content: [{ type: 'text', text: 'Deck of Cards API returned success: false' }], isError: true };
    }
    return {
      content: [{
        type: 'text',
        text: this.truncate({ deck_id: data.deck_id, shuffled: data.shuffled, remaining: data.remaining }),
      }],
      isError: false,
    };
  }
}
