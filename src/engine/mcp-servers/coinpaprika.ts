/**
 * Coinpaprika Crypto Data MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.coinpaprika.com/v1
// Auth: None required — free public API, 25k req/month
// Docs: https://api.coinpaprika.com/
// Category: finance
// Rate limits: 25,000 requests/month on free tier; no signup needed

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class CoinpaprikaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CoinpaprikaMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.coinpaprika.com/v1';
  }

  static catalog() {
    return {
      name: 'coinpaprika',
      displayName: 'Coinpaprika Crypto Data',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'crypto', 'cryptocurrency', 'bitcoin', 'ethereum', 'altcoin',
        'market cap', 'ticker', 'price', 'ohlc', 'historical', 'coin',
        'exchange', 'dominance', 'volume', 'search', 'coinpaprika',
        'defi', 'blockchain', 'token', 'digital asset',
      ],
      toolNames: [
        'list_coins',
        'get_coin',
        'tickers_latest',
        'historical_ohlc',
        'global_market',
        'search',
      ],
      description: 'Coinpaprika Crypto Data: fetch live and historical prices, OHLC, market cap, global market overview, and fuzzy coin/exchange search — free and unauthenticated.',
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
        name: 'list_coins',
        description: 'All ~25k tracked coins — id, name, symbol, rank, is_active.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_coin',
        description: 'Full coin profile — description, team, links, tags.',
        inputSchema: {
          type: 'object',
          properties: {
            coin_id: {
              type: 'string',
              description: 'Coinpaprika coin id (e.g. "btc-bitcoin")',
            },
          },
          required: ['coin_id'],
        },
      },
      {
        name: 'tickers_latest',
        description: 'Latest price + market cap + volume. Without coin_id returns all tickers; with coin_id returns one.',
        inputSchema: {
          type: 'object',
          properties: {
            coin_id: {
              type: 'string',
              description: 'Coinpaprika coin id (e.g. "btc-bitcoin"). Omit to retrieve all tickers.',
            },
            quotes: {
              type: 'string',
              description: 'Comma-separated quote currencies — USD,BTC,ETH,EUR,GBP,JPY (default USD)',
            },
          },
        },
      },
      {
        name: 'historical_ohlc',
        description: 'Daily OHLC + volume + market cap. Free tier: up to 1 year back.',
        inputSchema: {
          type: 'object',
          properties: {
            coin_id: {
              type: 'string',
              description: 'Coinpaprika coin id (e.g. "btc-bitcoin")',
            },
            start: {
              type: 'string',
              description: 'Start date — YYYY-MM-DD or unix timestamp',
            },
            end: {
              type: 'string',
              description: 'End date — YYYY-MM-DD or unix timestamp (optional)',
            },
            limit: {
              type: 'number',
              description: 'Number of days to return: 1–365 (default 1)',
            },
            quote: {
              type: 'string',
              description: 'Quote currency: usd | btc (default usd)',
            },
          },
          required: ['coin_id', 'start'],
        },
      },
      {
        name: 'global_market',
        description: 'Total market cap, 24h volume, BTC dominance, active currencies.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search',
        description: 'Fuzzy search across coins, exchanges, ICOs, people, tags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term',
            },
            modifier: {
              type: 'string',
              description: 'Pass "symbol_search" to search by ticker symbol instead of name',
            },
            limit: {
              type: 'number',
              description: 'Max results per category: 1–250 (default 6)',
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
        case 'list_coins':     return this.listCoins();
        case 'get_coin':       return this.getCoin(args);
        case 'tickers_latest': return this.tickersLatest(args);
        case 'historical_ohlc': return this.historicalOhlc(args);
        case 'global_market':  return this.globalMarket();
        case 'search':         return this.search(args);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `Coinpaprika: not found (${path})` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Coinpaprika API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v.trim();
  }

  private async listCoins(): Promise<ToolResult> {
    return this.get('/coins');
  }

  private async getCoin(args: Record<string, unknown>): Promise<ToolResult> {
    const coinId = this.requireString(args, 'coin_id', '"btc-bitcoin"');
    return this.get(`/coins/${encodeURIComponent(coinId)}`);
  }

  private async tickersLatest(args: Record<string, unknown>): Promise<ToolResult> {
    const quotes = String(args.quotes ?? 'USD').toUpperCase();
    const params = new URLSearchParams({ quotes });
    const id = (args.coin_id as string | undefined)?.trim();
    if (id) {
      return this.get(`/tickers/${encodeURIComponent(id)}?${params}`);
    }
    return this.get(`/tickers?${params}`);
  }

  private async historicalOhlc(args: Record<string, unknown>): Promise<ToolResult> {
    const coinId = this.requireString(args, 'coin_id', '"btc-bitcoin"');
    const start = this.requireString(args, 'start', '"2024-01-01"');
    const rawLimit = args.limit as number | undefined;
    const limit = rawLimit !== undefined ? Math.min(365, Math.max(1, rawLimit)) : 1;
    const quote = String((args.quote as string | undefined) ?? 'usd').toLowerCase();
    const params = new URLSearchParams({
      start,
      limit: String(limit),
      quote,
    });
    if (args.end) params.set('end', String(args.end));
    return this.get(`/coins/${encodeURIComponent(coinId)}/ohlcv/historical?${params}`);
  }

  private async globalMarket(): Promise<ToolResult> {
    return this.get('/global');
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"bitcoin"');
    const rawLimit = args.limit as number | undefined;
    const limit = rawLimit !== undefined ? Math.min(250, Math.max(1, rawLimit)) : 6;
    const params = new URLSearchParams({
      q: query,
      c: 'currencies',
      limit: String(limit),
    });
    if (args.modifier) params.set('modifier', String(args.modifier));
    return this.get(`/search?${params}`);
  }
}
