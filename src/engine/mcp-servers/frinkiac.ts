/**
 * Frinkiac / Morbotron / Master of All Science MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URLs (public, no auth required):
//   Simpsons:     https://frinkiac.com/api
//   Futurama:     https://morbotron.com/api
//   Rick & Morty: https://masterofallscience.com/api
//
// Category: entertainment
// Auth: none (all three sites are public)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASES: Record<string, string> = {
  simpsons:    'https://frinkiac.com/api',
  futurama:    'https://morbotron.com/api',
  rickandmorty: 'https://masterofallscience.com/api',
};

const FRAME_HOSTS: Record<string, string> = {
  simpsons:    'https://frinkiac.com',
  futurama:    'https://morbotron.com',
  rickandmorty: 'https://masterofallscience.com',
};

export class FrinkiacMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'frinkiac',
      displayName: 'Frinkiac / Morbotron / Master of All Science',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'frinkiac', 'morbotron', 'masterofallscience',
        'simpsons', 'futurama', 'rick and morty',
        'screencap', 'screenshot', 'quote', 'caption',
        'gif', 'meme', 'frame', 'episode', 'subtitle',
        'tv', 'animation', 'comedy',
      ],
      toolNames: ['search', 'random', 'caption'],
      description:
        'Search and retrieve screencaps, captions, and GIFs from The Simpsons (Frinkiac), ' +
        'Futurama (Morbotron), and Rick and Morty (Master of All Science).',
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
        description: 'Find screencaps matching a quote across Simpsons, Futurama, or Rick and Morty.',
        inputSchema: {
          type: 'object',
          properties: {
            show: {
              type: 'string',
              description: 'Which show to search: simpsons | futurama | rickandmorty (default: simpsons)',
            },
            query: {
              type: 'string',
              description: 'Quote or keywords to search for.',
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return, 1–100 (default: 20).',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'random',
        description: 'Fetch a random screencap and its caption from the chosen show.',
        inputSchema: {
          type: 'object',
          properties: {
            show: {
              type: 'string',
              description: 'Which show: simpsons | futurama | rickandmorty (default: simpsons)',
            },
          },
        },
      },
      {
        name: 'caption',
        description: 'Retrieve the full caption for a specific episode and frame timestamp.',
        inputSchema: {
          type: 'object',
          properties: {
            show: {
              type: 'string',
              description: 'Which show: simpsons | futurama | rickandmorty (default: simpsons)',
            },
            episode: {
              type: 'string',
              description: 'Episode key, e.g. "S05E15" for Simpsons.',
            },
            timestamp: {
              type: 'number',
              description: 'Frame timestamp in milliseconds from search results.',
            },
          },
          required: ['episode', 'timestamp'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':  return this.search(args);
        case 'random':  return this.randomFrame(args);
        case 'caption': return this.caption(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private pickShow(args: Record<string, unknown>): 'simpsons' | 'futurama' | 'rickandmorty' {
    const raw = ((args.show as string | undefined) ?? 'simpsons').toLowerCase().trim();
    if (raw !== 'simpsons' && raw !== 'futurama' && raw !== 'rickandmorty') {
      throw new Error('show must be simpsons | futurama | rickandmorty');
    }
    return raw;
  }

  private async apiGet(url: string): Promise<unknown> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`API error ${response.status}: ${errText.slice(0, 200)}`);
    }
    return response.json();
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      throw new Error('Required argument "query" is missing or empty.');
    }
    const show = this.pickShow(args);
    const limit = Math.min(100, Math.max(1, typeof args.limit === 'number' ? args.limit : 20));
    const base = BASES[show];
    const frameHost = FRAME_HOSTS[show];

    const data = (await this.apiGet(
      `${base}/search?q=${encodeURIComponent(query.trim())}`,
    )) as Array<{ Id: number; Episode: string; Timestamp: number }>;

    const results = (Array.isArray(data) ? data : []).slice(0, limit).map((r) => ({
      id: r.Id,
      episode: r.Episode,
      timestamp: r.Timestamp,
      frame_url: `${frameHost}/img/${r.Episode}/${r.Timestamp}.jpg`,
      gif_url: `${frameHost}/gif/${r.Episode}/${r.Timestamp}/${r.Timestamp + 5000}.gif`,
    }));

    return {
      content: [{ type: 'text', text: this.truncate({ show, count: results.length, results }) }],
      isError: false,
    };
  }

  private async randomFrame(args: Record<string, unknown>): Promise<ToolResult> {
    const show = this.pickShow(args);
    const base = BASES[show];
    const frameHost = FRAME_HOSTS[show];

    const data = (await this.apiGet(`${base}/random`)) as {
      Frame?: { Episode?: string; Timestamp?: number };
      Subtitles?: { Content?: string }[];
    };

    const ep = data.Frame?.Episode;
    const ts = data.Frame?.Timestamp;
    const caption = (data.Subtitles ?? [])
      .map((s) => s.Content)
      .filter(Boolean)
      .join('\n');

    const result = {
      show,
      episode: ep ?? null,
      timestamp: ts ?? null,
      caption,
      frame_url: ep && ts != null ? `${frameHost}/img/${ep}/${ts}.jpg` : null,
      gif_url: ep && ts != null ? `${frameHost}/gif/${ep}/${ts}/${ts + 5000}.gif` : null,
    };

    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  private async caption(args: Record<string, unknown>): Promise<ToolResult> {
    const episode = args.episode;
    if (typeof episode !== 'string' || !episode.trim()) {
      throw new Error('Required argument "episode" is missing or empty.');
    }
    const ts = args.timestamp;
    if (typeof ts !== 'number' || ts <= 0 || !Number.isFinite(ts)) {
      throw new Error('Required argument "timestamp" must be a positive finite number (frame ms).');
    }
    const show = this.pickShow(args);
    const base = BASES[show];

    const data = await this.apiGet(
      `${base}/caption?e=${encodeURIComponent(episode.trim())}&t=${Math.floor(ts)}`,
    );

    return {
      content: [{ type: 'text', text: this.truncate(data) }],
      isError: false,
    };
  }
}
