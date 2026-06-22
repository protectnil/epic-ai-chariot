/**
 * The Odds API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.the-odds-api.com/v4
 * Auth: apiKey query parameter
 * Docs: https://the-odds-api.com/liveapi/guides/v4/
 * Category: sports
 * Rate limits: Free tier: 500 requests/month; each market type per region = 1 credit
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface OddsApiConfig {
  apiKey: string;
  baseUrl?: string;
}

export class OddsApiMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: OddsApiConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('The Odds API: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('The Odds API: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.the-odds-api.com/v4';
  }

  static catalog() {
    return {
      name: 'odds-api',
      displayName: 'The Odds API — Sportsbook Odds & Scores',
      version: '1.0.0',
      category: 'sports',
      keywords: [
        'odds', 'sportsbook', 'betting', 'sports betting', 'nfl', 'nba', 'mlb', 'nhl',
        'soccer', 'football', 'basketball', 'baseball', 'hockey', 'h2h', 'spreads',
        'totals', 'moneyline', 'live scores', 'sports odds', 'bookmaker', 'draftkings',
        'fanduel', 'bovada', 'player props', 'alt lines', 'outrights',
      ],
      toolNames: ['list_sports', 'get_odds', 'get_event_odds', 'get_scores', 'get_events'],
      description: 'The Odds API: real-time sportsbook odds across 70+ bookmakers and 30+ leagues, live and upcoming event scores, and event discovery — directly via the Odds API REST service.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'list_sports',
        description: 'List available sports and leagues. By default returns only in-season; pass all=true to include out-of-season.',
        inputSchema: {
          type: 'object',
          properties: {
            all: {
              type: 'boolean',
              description: 'Include out-of-season sports (default false)',
            },
          },
        },
      },
      {
        name: 'get_odds',
        description: 'Current odds for upcoming and live events in a league. Each market type costs 1 quota credit per region per call — pick markets carefully.',
        inputSchema: {
          type: 'object',
          properties: {
            sport_key: {
              type: 'string',
              description: 'Sport key from list_sports, e.g. "americanfootball_nfl"',
            },
            regions: {
              type: 'string',
              description: 'us | uk | eu | au — comma-separated (default us)',
            },
            markets: {
              type: 'string',
              description: 'h2h | spreads | totals | outrights — comma-separated (default h2h)',
            },
            odds_format: {
              type: 'string',
              description: 'american (default) | decimal',
            },
            date_format: {
              type: 'string',
              description: 'iso (default) | unix',
            },
            bookmakers: {
              type: 'string',
              description: 'Comma-separated bookmaker keys (e.g. "draftkings,fanduel") to restrict results',
            },
            event_ids: {
              type: 'string',
              description: 'Restrict to specific event IDs (comma-separated)',
            },
          },
          required: ['sport_key'],
        },
      },
      {
        name: 'get_event_odds',
        description: 'Odds for a single event — allows richer markets including player props and alternate lines. Higher quota cost per call.',
        inputSchema: {
          type: 'object',
          properties: {
            sport_key: {
              type: 'string',
              description: 'Sport key from list_sports, e.g. "americanfootball_nfl"',
            },
            event_id: {
              type: 'string',
              description: 'Event ID from get_events',
            },
            regions: {
              type: 'string',
              description: 'us | uk | eu | au — comma-separated (default us)',
            },
            markets: {
              type: 'string',
              description: 'Includes player_props_* markets for some leagues (default h2h)',
            },
            odds_format: {
              type: 'string',
              description: 'american (default) | decimal',
            },
          },
          required: ['sport_key', 'event_id'],
        },
      },
      {
        name: 'get_scores',
        description: 'Live and recent final scores for a sport. Costs 2 quota credits per call.',
        inputSchema: {
          type: 'object',
          properties: {
            sport_key: {
              type: 'string',
              description: 'Sport key from list_sports, e.g. "americanfootball_nfl"',
            },
            days_from: {
              type: 'number',
              description: '1-3 days from now to include completed games (default 1)',
            },
          },
          required: ['sport_key'],
        },
      },
      {
        name: 'get_events',
        description: 'Upcoming and live events for a league without odds — useful for discovering event IDs to pass to get_event_odds.',
        inputSchema: {
          type: 'object',
          properties: {
            sport_key: {
              type: 'string',
              description: 'Sport key from list_sports, e.g. "americanfootball_nfl"',
            },
            date_format: {
              type: 'string',
              description: 'iso (default) | unix',
            },
            event_ids: {
              type: 'string',
              description: 'Restrict to specific event IDs (comma-separated)',
            },
          },
          required: ['sport_key'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_sports':    return this.listSports(args);
        case 'get_odds':       return this.getOdds(args);
        case 'get_event_odds': return this.getEventOdds(args);
        case 'get_scores':     return this.getScores(args);
        case 'get_events':     return this.getEvents(args);
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
    if (response.status === 401) {
      return { content: [{ type: 'text', text: 'Odds API: unauthorized — check API key' }], isError: true };
    }
    if (response.status === 403) {
      return { content: [{ type: 'text', text: 'Odds API: quota exhausted or forbidden' }], isError: true };
    }
    if (response.status === 422) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Odds API bad request: ${errText.slice(0, 200)}` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Odds API error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private buildParams(base: Record<string, string>, args: Record<string, unknown>, optionals: Array<{ src: string; dest: string }>): URLSearchParams {
    const params = new URLSearchParams({ ...base, apiKey: this.apiKey });
    for (const { src, dest } of optionals) {
      if (args[src] !== undefined && args[src] !== null) {
        params.set(dest, String(args[src]));
      }
    }
    return params;
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async listSports(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ apiKey: this.apiKey, all: String(args.all === true) });
    return this.request(`/sports?${params}`);
  }

  private async getOdds(args: Record<string, unknown>): Promise<ToolResult> {
    const sportKey = this.reqStr(args, 'sport_key', '"americanfootball_nfl"');
    const params = this.buildParams(
      {
        regions: String(args.regions ?? 'us'),
        markets: String(args.markets ?? 'h2h'),
        oddsFormat: String(args.odds_format ?? 'american'),
        dateFormat: String(args.date_format ?? 'iso'),
      },
      args,
      [
        { src: 'bookmakers', dest: 'bookmakers' },
        { src: 'event_ids',  dest: 'eventIds'   },
      ],
    );
    return this.request(`/sports/${encodeURIComponent(sportKey)}/odds?${params}`);
  }

  private async getEventOdds(args: Record<string, unknown>): Promise<ToolResult> {
    const sportKey = this.reqStr(args, 'sport_key', '"americanfootball_nfl"');
    const eventId  = this.reqStr(args, 'event_id',  '"e1234abcd"');
    const params = this.buildParams(
      {
        regions:    String(args.regions    ?? 'us'),
        markets:    String(args.markets    ?? 'h2h'),
        oddsFormat: String(args.odds_format ?? 'american'),
      },
      args,
      [],
    );
    return this.request(
      `/sports/${encodeURIComponent(sportKey)}/events/${encodeURIComponent(eventId)}/odds?${params}`,
    );
  }

  private async getScores(args: Record<string, unknown>): Promise<ToolResult> {
    const sportKey = this.reqStr(args, 'sport_key', '"americanfootball_nfl"');
    const daysFrom = Math.min(3, Math.max(1, Number(args.days_from ?? 1)));
    const params = new URLSearchParams({ apiKey: this.apiKey, daysFrom: String(daysFrom) });
    return this.request(`/sports/${encodeURIComponent(sportKey)}/scores?${params}`);
  }

  private async getEvents(args: Record<string, unknown>): Promise<ToolResult> {
    const sportKey = this.reqStr(args, 'sport_key', '"americanfootball_nfl"');
    const params = this.buildParams(
      { dateFormat: String(args.date_format ?? 'iso') },
      args,
      [{ src: 'event_ids', dest: 'eventIds' }],
    );
    return this.request(`/sports/${encodeURIComponent(sportKey)}/events?${params}`);
  }
}
