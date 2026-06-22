/**
 * Giphy MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://api.giphy.com/v1/gifs
// Auth: API key query parameter (api_key)
// Docs: https://developers.giphy.com/docs/api/
// Category: entertainment
// Rate limits: Depends on plan — public beta key: limited rate

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface GiphyConfig {
  apiKey: string;
  baseUrl?: string;
}

// ── API types ─────────────────────────────────────────────────────────────────

interface GiphyImage {
  url: string;
  width: string;
  height: string;
}

interface GiphyImages {
  original: GiphyImage;
  fixed_height: GiphyImage;
  downsized: GiphyImage & { size?: string };
}

interface GiphyGif {
  id: string;
  title: string;
  slug: string;
  url: string;
  rating: string;
  import_datetime: string;
  images: GiphyImages;
}

interface GiphyListResponse {
  data: GiphyGif[];
  pagination: { total_count: number; count: number; offset: number };
  meta: { status: number; msg: string };
}

interface GiphyRandomResponse {
  data: GiphyGif;
  meta: { status: number; msg: string };
}

export class GiphyMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: GiphyConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Giphy: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Giphy: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.giphy.com/v1/gifs';
  }

  static catalog() {
    return {
      name: 'giphy',
      displayName: 'Giphy',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'giphy', 'gif', 'gifs', 'animated', 'animation', 'trending',
        'search', 'random', 'meme', 'reaction', 'media', 'image',
      ],
      toolNames: ['search_gifs', 'trending_gifs', 'random_gif'],
      description: 'Giphy: search for GIFs by keyword, retrieve trending GIFs, or get a single random GIF — optionally filtered by tag.',
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
        name: 'search_gifs',
        description:
          'Search Giphy for GIFs matching a keyword or phrase. Returns GIF title, URL, rating, and image URLs in original and fixed-height sizes.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query, e.g. "funny cats" or "celebration"',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–25, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'trending_gifs',
        description:
          'Get the currently trending GIFs on Giphy. Returns title, URL, rating, and image URLs.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of results to return (1–25, default 10)',
            },
          },
        },
      },
      {
        name: 'random_gif',
        description:
          'Get a single random GIF from Giphy, optionally filtered by a tag. Returns title, URL, rating, and image URLs.',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description: 'Optional tag to filter by, e.g. "dogs" or "anime"',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_gifs':
          return this.searchGifs(args.query as string, args.limit as number | undefined);
        case 'trending_gifs':
          return this.trendingGifs(args.limit as number | undefined);
        case 'random_gif':
          return this.randomGif(args.tag as string | undefined);
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

  private buildUrl(path: string, params: Record<string, string>): string {
    const qs = new URLSearchParams({ api_key: this.apiKey, ...params });
    return `${this.baseUrl}${path}?${qs.toString()}`;
  }

  private formatGif(gif: GiphyGif): Record<string, unknown> {
    return {
      id: gif.id,
      title: gif.title,
      url: gif.url,
      rating: gif.rating,
      gif_url: gif.images.original.url,
      fixed_height_url: gif.images.fixed_height.url,
      downsized_url: gif.images.downsized.url,
      width: parseInt(gif.images.original.width, 10),
      height: parseInt(gif.images.original.height, 10),
    };
  }

  private async searchGifs(query: string, limit = 10): Promise<ToolResult> {
    if (!query || typeof query !== 'string') {
      return { content: [{ type: 'text', text: 'search_gifs: query is required' }], isError: true };
    }
    const clampedLimit = Math.min(Math.max(Math.trunc(limit), 1), 25);
    const url = this.buildUrl('/search', {
      q: query,
      limit: String(clampedLimit),
    });
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
    const data = (await response.json()) as GiphyListResponse;
    if (data.meta.status !== 200) {
      return {
        content: [{ type: 'text', text: `Giphy API error: ${data.meta.msg}` }],
        isError: true,
      };
    }
    const result = {
      total: data.pagination.total_count,
      count: data.pagination.count,
      gifs: data.data.map((g) => this.formatGif(g)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async trendingGifs(limit = 10): Promise<ToolResult> {
    const clampedLimit = Math.min(Math.max(Math.trunc(limit ?? 10), 1), 25);
    const url = this.buildUrl('/trending', { limit: String(clampedLimit) });
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
    const data = (await response.json()) as GiphyListResponse;
    if (data.meta.status !== 200) {
      return {
        content: [{ type: 'text', text: `Giphy API error: ${data.meta.msg}` }],
        isError: true,
      };
    }
    const result = {
      count: data.pagination.count,
      gifs: data.data.map((g) => this.formatGif(g)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async randomGif(tag?: string): Promise<ToolResult> {
    const params: Record<string, string> = {};
    if (tag) params.tag = tag;
    const url = this.buildUrl('/random', params);
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
    const data = (await response.json()) as GiphyRandomResponse;
    if (data.meta.status !== 200) {
      return {
        content: [{ type: 'text', text: `Giphy API error: ${data.meta.msg}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(this.formatGif(data.data)) }], isError: false };
  }
}
