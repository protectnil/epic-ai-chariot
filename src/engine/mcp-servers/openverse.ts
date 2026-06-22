/**
 * Openverse MCP Adapter — Creative-Commons-licensed image + audio search.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: Openverse API (https://api.openverse.engineering/v1/)
 * Auth: none required (anonymous, rate-limited; optional OAuth tokens not implemented)
 * Docs: https://api.openverse.engineering/v1/
 * Category: media
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.openverse.engineering/v1';

export class OpenverseMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('OpenverseMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'openverse',
      displayName: 'Openverse',
      version: '1.0.0',
      category: 'media',
      keywords: [
        'openverse', 'creative commons', 'cc0', 'open license', 'images',
        'audio', 'media search', 'stock photos', 'free images', 'music',
        'sound effects', 'flickr', 'wikimedia', 'met museum', 'attribution',
        'public domain', 'open culture',
      ],
      toolNames: [
        'search_images',
        'search_audio',
        'get_image',
        'get_audio',
        'image_related',
        'audio_related',
      ],
      description: 'Openverse API: search and retrieve Creative-Commons-licensed images and audio — filter by license, size, source, and more. No API key required for anonymous access.',
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
        name: 'search_images',
        description: 'Search Creative-Commons-licensed images on Openverse.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string (e.g. "sunset", "cat")',
            },
            license: {
              type: 'string',
              description: 'Comma-separated license identifiers, e.g. "cc0,by"',
            },
            license_type: {
              type: 'string',
              description: '"commercial" | "modification" | "all"',
            },
            size: {
              type: 'string',
              description: '"small" | "medium" | "large"',
            },
            source: {
              type: 'string',
              description: 'Provider id, e.g. "flickr", "met", "wikimedia"',
            },
            page: {
              type: 'number',
              description: 'Result page number (default 1)',
            },
            page_size: {
              type: 'number',
              description: 'Results per page, 1–500 (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_audio',
        description: 'Search Creative-Commons-licensed audio on Openverse.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string (e.g. "piano", "birds")',
            },
            license: {
              type: 'string',
              description: 'Comma-separated license identifiers, e.g. "cc0,by"',
            },
            license_type: {
              type: 'string',
              description: '"commercial" | "modification" | "all"',
            },
            source: {
              type: 'string',
              description: 'Provider id, e.g. "freesound", "jamendo"',
            },
            page: {
              type: 'number',
              description: 'Result page number (default 1)',
            },
            page_size: {
              type: 'number',
              description: 'Results per page, 1–500 (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_image',
        description: 'Retrieve a single image record by its Openverse UUID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Openverse image UUID',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_audio',
        description: 'Retrieve a single audio record by its Openverse UUID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Openverse audio UUID',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'image_related',
        description: 'Retrieve images related to a given Openverse image UUID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Openverse image UUID to find related images for',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'audio_related',
        description: 'Retrieve audio tracks related to a given Openverse audio UUID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Openverse audio UUID to find related tracks for',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_images':  return this.searchMedia('images', args);
        case 'search_audio':   return this.searchMedia('audio', args);
        case 'get_image':      return this.getRecord('images', args);
        case 'get_audio':      return this.getRecord('audio', args);
        case 'image_related':  return this.getRelated('images', args);
        case 'audio_related':  return this.getRelated('audio', args);
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

  // ── Private helpers ──────────────────────────────────────────────────────

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Openverse API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private buildSearchParams(args: Record<string, unknown>): string {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      throw new Error('Required argument "query" is missing or empty.');
    }
    const params = new URLSearchParams({ q: query.trim() });
    for (const key of ['license', 'license_type', 'size', 'source'] as const) {
      if (args[key] && typeof args[key] === 'string') {
        params.set(key, args[key] as string);
      }
    }
    const page = typeof args.page === 'number' ? Math.max(1, args.page) : 1;
    const pageSize = typeof args.page_size === 'number'
      ? Math.min(500, Math.max(1, args.page_size))
      : 20;
    params.set('page', String(page));
    params.set('page_size', String(pageSize));
    return params.toString();
  }

  private reqId(args: Record<string, unknown>): string {
    const id = args.id;
    if (typeof id !== 'string' || !id.trim()) {
      throw new Error('Required argument "id" is missing or empty.');
    }
    return id.trim();
  }

  private async searchMedia(type: 'images' | 'audio', args: Record<string, unknown>): Promise<ToolResult> {
    const qs = this.buildSearchParams(args);
    return this.request(`/${type}?${qs}`);
  }

  private async getRecord(type: 'images' | 'audio', args: Record<string, unknown>): Promise<ToolResult> {
    return this.request(`/${type}/${encodeURIComponent(this.reqId(args))}`);
  }

  private async getRelated(type: 'images' | 'audio', args: Record<string, unknown>): Promise<ToolResult> {
    return this.request(`/${type}/${encodeURIComponent(this.reqId(args))}/related`);
  }
}
