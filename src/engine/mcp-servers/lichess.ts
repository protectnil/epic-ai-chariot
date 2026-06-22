/**
 * Lichess MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://lichess.org/api
// Auth: none required for public read-only endpoints
// Docs: https://lichess.org/api
// Category: gaming
// Rate limits: varies by endpoint; 429 returned when exceeded

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://lichess.org/api';
const EXPLORER_URL = 'https://explorer.lichess.ovh';
const TABLEBASE_URL = 'https://tablebase.lichess.ovh';
const UA = 'epic-ai-chariot/1.0 (+https://epicai.io)';

const COMMON_HEADERS = {
  Accept: 'application/json',
  'User-Agent': UA,
};

export class LichessMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;
  private readonly explorerUrl: string;
  private readonly tablebaseUrl: string;

  constructor(config?: { baseUrl?: string; explorerUrl?: string; tablebaseUrl?: string }) {
    super();
    if (config === null) { throw new Error('LichessMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
    this.explorerUrl = config?.explorerUrl ?? EXPLORER_URL;
    this.tablebaseUrl = config?.tablebaseUrl ?? TABLEBASE_URL;
  }

  static catalog() {
    return {
      name: 'lichess',
      displayName: 'Lichess',
      version: '1.0.0',
      category: 'gaming',
      keywords: [
        'lichess', 'chess', 'game', 'opening', 'explorer', 'tablebase',
        'stockfish', 'cloud eval', 'player', 'ratings', 'leaderboard',
        'tv', 'chess960', 'blitz', 'bullet', 'rapid', 'classical',
      ],
      toolNames: [
        'user',
        'users',
        'user_status',
        'user_performance',
        'top_players',
        'leaderboards',
        'tv_channels',
        'cloud_eval',
        'tablebase',
        'opening_explorer',
      ],
      description: 'Lichess: public read-only API for player profiles, ratings, game TV, Stockfish cloud evaluation, Syzygy tablebase lookups, and the opening explorer.',
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
        name: 'user',
        description: 'Player profile with ratings across all variants.',
        inputSchema: {
          type: 'object',
          properties: {
            username: { type: 'string', description: 'Lichess username.' },
          },
          required: ['username'],
        },
      },
      {
        name: 'users',
        description: 'Bulk lookup of up to 300 users by username.',
        inputSchema: {
          type: 'object',
          properties: {
            usernames: {
              type: 'array',
              items: { type: 'string' },
              description: '1–300 usernames.',
            },
          },
          required: ['usernames'],
        },
      },
      {
        name: 'user_status',
        description: 'Online / playing status for the given usernames (up to 100).',
        inputSchema: {
          type: 'object',
          properties: {
            usernames: {
              type: 'array',
              items: { type: 'string' },
              description: '1–100 usernames.',
            },
          },
          required: ['usernames'],
        },
      },
      {
        name: 'user_performance',
        description: 'Single-variant performance and best rated game for a user.',
        inputSchema: {
          type: 'object',
          properties: {
            username: { type: 'string', description: 'Lichess username.' },
            perf: {
              type: 'string',
              description: 'Variant: bullet | blitz | rapid | classical | correspondence | chess960 | crazyhouse | antichess | atomic | horde | kingOfTheHill | racingKings | threeCheck | ultraBullet',
            },
          },
          required: ['username', 'perf'],
        },
      },
      {
        name: 'top_players',
        description: 'Top-rated players for one variant.',
        inputSchema: {
          type: 'object',
          properties: {
            perf: { type: 'string', description: 'Variant name (e.g. blitz, bullet, rapid).' },
            limit: { type: 'number', description: '1–200, default 50.' },
          },
          required: ['perf'],
        },
      },
      {
        name: 'leaderboards',
        description: 'Top-10 leaderboard across all variants in one call.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'tv_channels',
        description: 'Currently-featured TV games per variant.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'cloud_eval',
        description: 'Stockfish cloud evaluation for a FEN position.',
        inputSchema: {
          type: 'object',
          properties: {
            fen: { type: 'string', description: 'FEN of the position to evaluate.' },
            multi_pv: { type: 'number', description: 'Number of principal variations to return: 1–5. Default 1.' },
          },
          required: ['fen'],
        },
      },
      {
        name: 'tablebase',
        description: 'Syzygy tablebase lookup for positions with 7 or fewer pieces.',
        inputSchema: {
          type: 'object',
          properties: {
            fen: { type: 'string', description: 'FEN of the position to look up.' },
            variant: {
              type: 'string',
              description: 'standard (default) | atomic | antichess',
            },
          },
          required: ['fen'],
        },
      },
      {
        name: 'opening_explorer',
        description: 'Opening explorer. scope: "lichess" (community games), "masters" (top 2200+ OTB), "player" (single user).',
        inputSchema: {
          type: 'object',
          properties: {
            scope: {
              type: 'string',
              description: 'lichess | masters | player',
            },
            fen: {
              type: 'string',
              description: 'FEN of the position. Mutually exclusive with play.',
            },
            play: {
              type: 'string',
              description: 'Comma-separated UCI move list from starting position. Mutually exclusive with fen.',
            },
            player: {
              type: 'string',
              description: 'Username (required when scope is "player").',
            },
            speeds: {
              type: 'string',
              description: 'Comma-separated speed filters: ultraBullet,bullet,blitz,rapid,classical,correspondence',
            },
            ratings: {
              type: 'string',
              description: 'Comma-separated rating buckets (lichess scope only): 0,1000,1200,1400,1600,1800,2000,2200,2500',
            },
            moves: {
              type: 'number',
              description: 'Number of top moves to return. Default 12, max 64.',
            },
          },
          required: ['scope'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'user':             return this.getUser(args);
        case 'users':            return this.getUsers(args);
        case 'user_status':      return this.getUserStatus(args);
        case 'user_performance': return this.getUserPerformance(args);
        case 'top_players':      return this.getTopPlayers(args);
        case 'leaderboards':     return this.getLeaderboards();
        case 'tv_channels':      return this.getTvChannels();
        case 'cloud_eval':       return this.getCloudEval(args);
        case 'tablebase':        return this.getTablebase(args);
        case 'opening_explorer': return this.getOpeningExplorer(args);
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

  private async lichessGet(path: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: COMMON_HEADERS,
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Not found' }], isError: true };
    }
    if (response.status === 429) {
      return { content: [{ type: 'text', text: 'Rate limit exceeded (HTTP 429). Try again later.' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" must be a non-empty string.`);
    }
    return v;
  }

  private requireStringArray(args: Record<string, unknown>, key: string): string[] {
    const v = args[key];
    if (!Array.isArray(v) || v.length === 0) {
      throw new Error(`Required argument "${key}" must be a non-empty array of strings.`);
    }
    return v.filter((s): s is string => typeof s === 'string');
  }

  private async getUser(args: Record<string, unknown>): Promise<ToolResult> {
    const username = this.requireString(args, 'username');
    return this.lichessGet(`/user/${encodeURIComponent(username)}`);
  }

  private async getUsers(args: Record<string, unknown>): Promise<ToolResult> {
    const usernames = this.requireStringArray(args, 'usernames').slice(0, 300);
    const response = await this.fetchWithRetry(`${this.baseUrl}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', Accept: 'application/json', 'User-Agent': UA },
      body: usernames.join(','),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getUserStatus(args: Record<string, unknown>): Promise<ToolResult> {
    const usernames = this.requireStringArray(args, 'usernames').slice(0, 100);
    return this.lichessGet(`/users/status?ids=${encodeURIComponent(usernames.join(','))}`);
  }

  private async getUserPerformance(args: Record<string, unknown>): Promise<ToolResult> {
    const username = this.requireString(args, 'username');
    const perf = this.requireString(args, 'perf');
    return this.lichessGet(`/user/${encodeURIComponent(username)}/perf/${encodeURIComponent(perf)}`);
  }

  private async getTopPlayers(args: Record<string, unknown>): Promise<ToolResult> {
    const perf = this.requireString(args, 'perf');
    const limit = Math.min(200, Math.max(1, (args.limit as number | undefined) ?? 50));
    return this.lichessGet(`/player/top/${limit}/${encodeURIComponent(perf)}`);
  }

  private async getLeaderboards(): Promise<ToolResult> {
    return this.lichessGet('/player');
  }

  private async getTvChannels(): Promise<ToolResult> {
    return this.lichessGet('/tv/channels');
  }

  private async getCloudEval(args: Record<string, unknown>): Promise<ToolResult> {
    const fen = this.requireString(args, 'fen');
    const params = new URLSearchParams({ fen });
    if (args.multi_pv !== undefined) {
      params.set('multiPv', String(Math.min(5, Math.max(1, args.multi_pv as number))));
    }
    return this.lichessGet(`/cloud-eval?${params}`);
  }

  private async getTablebase(args: Record<string, unknown>): Promise<ToolResult> {
    const fen = this.requireString(args, 'fen');
    const variant = ((args.variant as string | undefined) ?? 'standard').toLowerCase();
    if (!['standard', 'atomic', 'antichess'].includes(variant)) {
      return {
        content: [{ type: 'text', text: 'variant must be one of: standard, atomic, antichess.' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({ fen });
    const response = await this.fetchWithRetry(`${this.tablebaseUrl}/${variant}?${params}`, {
      method: 'GET',
      headers: COMMON_HEADERS,
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Tablebase error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getOpeningExplorer(args: Record<string, unknown>): Promise<ToolResult> {
    const scope = this.requireString(args, 'scope').toLowerCase();
    if (!['lichess', 'masters', 'player'].includes(scope)) {
      return {
        content: [{ type: 'text', text: 'scope must be one of: lichess, masters, player.' }],
        isError: true,
      };
    }
    const params = new URLSearchParams();
    if (args.fen)    params.set('fen', String(args.fen));
    if (args.play)   params.set('play', String(args.play));
    if (args.speeds) params.set('speeds', String(args.speeds));
    if (args.moves)  params.set('moves', String(Math.min(64, Math.max(1, args.moves as number))));
    if (scope === 'lichess' && args.ratings) params.set('ratings', String(args.ratings));
    if (scope === 'player') {
      const player = this.requireString(args, 'player');
      params.set('player', player);
      params.set('color', 'white');
    }
    const endpoint = scope === 'lichess' ? 'lichess' : scope;
    const response = await this.fetchWithRetry(`${this.explorerUrl}/${endpoint}?${params}`, {
      method: 'GET',
      headers: COMMON_HEADERS,
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Explorer error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
