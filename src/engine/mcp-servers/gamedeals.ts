/**
 * Game Deals MCP Adapter — CheapShark API (game deal aggregator, no auth required)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://www.cheapshark.com/api/1.0
// Auth: None (public API)
// Docs: https://apidocs.cheapshark.com/
// Category: gaming
// Rate limits: No documented rate limit; reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.cheapshark.com/api/1.0';

// --- Raw API types ---

type RawDeal = {
  gameID: string;
  title: string;
  dealID: string;
  storeID: string;
  salePrice: string;
  normalPrice: string;
  savings: string;
  metacriticScore: string;
  steamRatingPercent: string;
  steamRatingCount: string;
  dealRating: string;
  thumb: string;
};

type RawGame = {
  gameID: string;
  external: string;
  cheapest: string;
  cheapestDealID: string;
  thumb: string;
};

type RawGameDeal = {
  storeID: string;
  dealID: string;
  price: string;
  retailPrice: string;
  savings: string;
};

type RawGameInfo = {
  name: string;
  steamAppID: string | null;
  thumb: string;
};

type RawGameDetails = {
  info: RawGameInfo;
  cheapestPriceEver: { price: string; date: number };
  deals: RawGameDeal[];
};

type RawStore = {
  storeID: string;
  storeName: string;
  isActive: number;
  images: {
    banner: string;
    logo: string;
    icon: string;
  };
};

export class GameDealsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('GameDealsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || BASE_URL;
  }

  static catalog() {
    return {
      name: 'gamedeals',
      displayName: 'Game Deals — CheapShark',
      version: '1.0.0',
      category: 'gaming',
      keywords: [
        'gamedeals', 'cheapshark', 'game deals', 'pc games', 'steam',
        'game prices', 'deals', 'discounts', 'sale', 'gaming',
        'cheapest games', 'price comparison', 'game store',
      ],
      toolNames: ['search_deals', 'search_games', 'get_game_details', 'list_stores'],
      description: 'CheapShark API: search PC game deals across dozens of stores, compare prices, look up price history, and list all tracked storefronts — no authentication required.',
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
        name: 'search_deals',
        description:
          'Search for game deals with optional filters. Returns deal title, store, sale price, normal price, savings percentage, Metacritic score, and deal rating.',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Filter deals by game title (partial match supported)',
            },
            upper_price: {
              type: 'number',
              description: 'Maximum price filter (e.g., 5 for deals under $5)',
            },
            lower_price: {
              type: 'number',
              description: 'Minimum price filter',
            },
            store_id: {
              type: 'string',
              description: 'Filter by store ID (use list_stores to get IDs)',
            },
            sort_by: {
              type: 'string',
              description:
                'Sort order: "Deal Rating" (default), "Price", "Metacritic", or "Reviews"',
            },
            page_size: {
              type: 'number',
              description: 'Number of results to return (default: 10, max: 60)',
            },
          },
        },
      },
      {
        name: 'search_games',
        description:
          'Search for games by title. Returns each game with its cheapest current price and a deal ID to get more details.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Game title to search for',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default: 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_game_details',
        description:
          'Get full price details for a game including price history, cheapest price ever recorded, and current deals across all stores.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'CheapShark game ID (obtained from search_games)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'list_stores',
        description:
          'List all game stores tracked by CheapShark. Returns store names and IDs for use with search_deals.',
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
        case 'search_deals':  return this.searchDeals(args);
        case 'search_games':  return this.searchGames(args);
        case 'get_game_details': return this.getGameDetails(args);
        case 'list_stores':   return this.listStores();
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CheapShark API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDeals(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.title)        params.set('title', args.title as string);
    if (args.upper_price != null) params.set('upperPrice', String(args.upper_price));
    if (args.lower_price != null) params.set('lowerPrice', String(args.lower_price));
    if (args.store_id)     params.set('storeID', args.store_id as string);
    if (args.sort_by)      params.set('sortBy', args.sort_by as string);
    params.set('pageSize', String((args.page_size as number | undefined) ?? 10));

    const url = `${this.baseUrl}/deals?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CheapShark API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawDeal[];
    const result = {
      total: data.length,
      deals: data.map((d) => ({
        game_id: d.gameID,
        deal_id: d.dealID,
        title: d.title,
        store_id: d.storeID,
        sale_price: parseFloat(d.salePrice),
        normal_price: parseFloat(d.normalPrice),
        savings_percent: Math.round(parseFloat(d.savings)),
        metacritic_score: d.metacriticScore !== '0' ? parseInt(d.metacriticScore, 10) : null,
        steam_rating_percent: d.steamRatingPercent !== '0' ? parseInt(d.steamRatingPercent, 10) : null,
        deal_rating: parseFloat(d.dealRating),
        thumb: d.thumb,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchGames(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = (args.limit as number | undefined) ?? 10;
    const params = new URLSearchParams({ title: query, limit: String(limit) });
    const url = `${this.baseUrl}/games?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CheapShark API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawGame[];
    const result = {
      total: data.length,
      games: data.map((g) => ({
        game_id: g.gameID,
        title: g.external,
        cheapest_price: parseFloat(g.cheapest),
        cheapest_deal_id: g.cheapestDealID,
        thumb: g.thumb,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getGameDetails(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as string;
    const url = `${this.baseUrl}/games?id=${encodeURIComponent(id)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CheapShark API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawGameDetails;
    const result = {
      game_id: id,
      name: data.info.name,
      steam_app_id: data.info.steamAppID ?? null,
      thumb: data.info.thumb,
      cheapest_price_ever: {
        price: parseFloat(data.cheapestPriceEver.price),
        date: new Date(data.cheapestPriceEver.date * 1000).toISOString().split('T')[0],
      },
      deals: data.deals.map((d) => ({
        store_id: d.storeID,
        deal_id: d.dealID,
        price: parseFloat(d.price),
        retail_price: parseFloat(d.retailPrice),
        savings_percent: Math.round(parseFloat(d.savings)),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listStores(): Promise<ToolResult> {
    const url = `${this.baseUrl}/stores`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CheapShark API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawStore[];
    const result = {
      total: data.filter((s) => s.isActive === 1).length,
      stores: data
        .filter((s) => s.isActive === 1)
        .map((s) => ({
          store_id: s.storeID,
          name: s.storeName,
          icon: `https://www.cheapshark.com${s.images.icon}`,
        })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
