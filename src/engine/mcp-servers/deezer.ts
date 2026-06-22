/**
 * Deezer MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://api.deezer.com
// Auth: None (public API, no key required)
// Docs: https://developers.deezer.com/api
// Category: entertainment
// Rate limits: Deezer public API — unauthenticated, no published rate limit

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.deezer.com';

export class DeezerMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DeezerMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'deezer',
      displayName: 'Deezer',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'deezer', 'music', 'tracks', 'albums', 'artists', 'playlists',
        'search', 'chart', 'top tracks', 'streaming', 'audio',
        'song', 'discography', 'music catalog', 'free',
      ],
      toolNames: ['search', 'track', 'album', 'artist', 'artist_top', 'chart'],
      description: 'Deezer public catalog: search tracks, albums, artists and playlists; retrieve metadata by ID; fetch artist top tracks and genre charts — all unauthenticated.',
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
        name: 'search',
        description: 'Search Deezer for tracks, albums, artists, or playlists.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query, e.g. "Daft Punk Get Lucky".',
            },
            type: {
              type: 'string',
              description: 'Resource type to search: track | album | artist | playlist (default: track).',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return, 1–100 (default: 25).',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'track',
        description: 'Get track metadata by Deezer track ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Deezer numeric track ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'album',
        description: 'Get album metadata and tracklist by Deezer album ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Deezer numeric album ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'artist',
        description: 'Get artist metadata by Deezer artist ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Deezer numeric artist ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'artist_top',
        description: "Get top tracks for an artist by Deezer artist ID.",
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Deezer numeric artist ID.',
            },
            limit: {
              type: 'number',
              description: 'Number of top tracks to return, 1–100 (default: 25).',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'chart',
        description: 'Get the current chart (top tracks, albums, artists) for a genre. Pass genre_id 0 for worldwide.',
        inputSchema: {
          type: 'object',
          properties: {
            genre_id: {
              type: 'number',
              description: 'Deezer genre ID. Use 0 for worldwide/all genres (default: 0).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':    return this.search(args);
        case 'track':     return this.getById('track', args);
        case 'album':     return this.getById('album', args);
        case 'artist':    return this.getById('artist', args);
        case 'artist_top': return this.artistTop(args);
        case 'chart':     return this.chart(args);
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

  private async deezerGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Deezer API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as { error?: { type?: string; message?: string; code?: number } };
    if (data.error) {
      return {
        content: [{ type: 'text', text: `Deezer error: ${data.error.message ?? data.error.type ?? 'unknown'}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireId(args: Record<string, unknown>): number {
    const id = (args.id as number) | 0;
    if (!id) throw new Error('Required argument "id" must be a non-zero Deezer numeric ID.');
    return id;
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    if (!query || !query.trim()) {
      throw new Error('Required argument "query" is missing.');
    }
    const type = ((args.type as string) ?? 'track').toLowerCase();
    if (!['track', 'album', 'artist', 'playlist'].includes(type)) {
      throw new Error('Argument "type" must be one of: track, album, artist, playlist.');
    }
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 25));
    const params = new URLSearchParams({ q: query, limit: String(limit) });
    return this.deezerGet(`/search/${type}?${params}`);
  }

  private async getById(resource: 'track' | 'album' | 'artist', args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireId(args);
    return this.deezerGet(`/${resource}/${id}`);
  }

  private async artistTop(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireId(args);
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 25));
    return this.deezerGet(`/artist/${id}/top?limit=${limit}`);
  }

  private async chart(args: Record<string, unknown>): Promise<ToolResult> {
    const genreId = (args.genre_id as number) ?? 0;
    return this.deezerGet(`/chart/${genreId}`);
  }
}
