/**
 * XKCD MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://xkcd.com
// Auth: None — free public JSON API, no key required
// Docs: https://xkcd.com/json.html
// Category: entertainment
// Rate limits: None documented; be a good citizen

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://xkcd.com';

interface XkcdConfig {
  baseUrl?: string;
}

interface RawComic {
  num: number;
  title: string;
  safe_title: string;
  alt: string;
  img: string;
  year: string;
  month: string;
  day: string;
  transcript: string;
  link: string;
  news: string;
}

export class XkcdMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: XkcdConfig) {
    super();
    if (config === null) { throw new Error('XkcdMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'xkcd',
      displayName: 'XKCD Comics',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'xkcd', 'comic', 'comics', 'webcomic', 'humor', 'geek', 'tech humor',
        'randall munroe', 'stick figure', 'science', 'math', 'random comic',
      ],
      toolNames: ['get_latest', 'get_comic', 'random_comic'],
      description: 'XKCD Comics: retrieve the latest comic, fetch a specific comic by number, or get a random comic from the full archive.',
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
        name: 'get_latest',
        description: 'Get the latest published XKCD comic with its title, image, and alt text.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_comic',
        description: 'Get a specific XKCD comic by its number.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'number',
              description: 'The XKCD comic number (e.g. 1, 353, 2867).',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'random_comic',
        description: 'Get a random XKCD comic from the full archive.',
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
        case 'get_latest':  return this.getLatest();
        case 'get_comic':   return this.getComic(args.number as number);
        case 'random_comic': return this.randomComic();
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

  private formatComic(comic: RawComic): Record<string, unknown> {
    return {
      number: comic.num,
      title: comic.title,
      safe_title: comic.safe_title,
      alt: comic.alt,
      img: comic.img,
      date: `${comic.year}-${comic.month.padStart(2, '0')}-${comic.day.padStart(2, '0')}`,
      transcript: comic.transcript || null,
      link: comic.link || null,
      url: `https://xkcd.com/${comic.num}/`,
    };
  }

  private async getLatest(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/info.0.json`, {
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
    const data = await response.json() as RawComic;
    return { content: [{ type: 'text', text: this.truncate(this.formatComic(data)) }], isError: false };
  }

  private async getComic(number: number): Promise<ToolResult> {
    if (typeof number !== 'number' || !Number.isInteger(number) || number < 1) {
      return {
        content: [{ type: 'text', text: 'get_comic: number must be a positive integer' }],
        isError: true,
      };
    }
    const response = await this.fetchWithRetry(`${this.baseUrl}/${number}/info.0.json`, {
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
    const data = await response.json() as RawComic;
    return { content: [{ type: 'text', text: this.truncate(this.formatComic(data)) }], isError: false };
  }

  private async randomComic(): Promise<ToolResult> {
    // Fetch latest to determine the max comic number
    const latestResponse = await this.fetchWithRetry(`${this.baseUrl}/info.0.json`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!latestResponse.ok) {
      const errText = await latestResponse.text().catch(() => latestResponse.statusText);
      return {
        content: [{ type: 'text', text: `API error fetching latest: ${latestResponse.status} ${errText}` }],
        isError: true,
      };
    }
    const latest = await latestResponse.json() as RawComic;
    const maxNum = latest.num;

    // Comic 404 doesn't exist (intentional joke), so skip it
    let randomNum: number;
    do {
      randomNum = Math.floor(Math.random() * maxNum) + 1;
    } while (randomNum === 404);

    const response = await this.fetchWithRetry(`${this.baseUrl}/${randomNum}/info.0.json`, {
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
    const data = await response.json() as RawComic;
    return { content: [{ type: 'text', text: this.truncate(this.formatComic(data)) }], isError: false };
  }
}
