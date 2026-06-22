/**
 * Iconify MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.iconify.design
// Auth: None (public API, no auth required)
// Docs: https://iconify.design/docs/api/
// Category: design
// Rate limits: Public, no documented rate limit

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class IconifyMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('IconifyMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || 'https://api.iconify.design';
  }

  static catalog() {
    return {
      name: 'iconify',
      displayName: 'Iconify',
      version: '1.0.0',
      category: 'design',
      keywords: [
        'iconify', 'icons', 'svg', 'icon search', 'icon library',
        'material design', 'font awesome', 'heroicons', 'lucide',
        'mdi', 'icon collections', 'vector icons', 'ui icons',
      ],
      toolNames: ['search_icons', 'get_icons', 'list_collections'],
      description: 'Iconify: search icons by keyword, retrieve SVG data for specific icons, and list all available icon collections across thousands of open-source icon sets.',
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
        name: 'search_icons',
        description:
          'Search for icons by keyword across all Iconify collections. Returns icon names in "prefix:name" format (e.g., "mdi:home").',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search keyword (e.g., "home", "arrow", "user")',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results (1-999, default 32)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_icons',
        description:
          'Retrieve SVG body data for one or more icons in a specific collection. Returns SVG body, width, and height for each icon.',
        inputSchema: {
          type: 'object',
          properties: {
            prefix: {
              type: 'string',
              description: 'Collection prefix (e.g., "mdi", "fa", "heroicons", "lucide")',
            },
            icons: {
              type: 'string',
              description: 'Comma-separated icon names within the collection (e.g., "home,arrow-left,user")',
            },
          },
          required: ['prefix', 'icons'],
        },
      },
      {
        name: 'list_collections',
        description:
          'List all available icon collections in Iconify. Returns collection prefix, name, total icon count, author, license, and category.',
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
        case 'search_icons':   return this.searchIcons(args);
        case 'get_icons':      return this.getIcons(args);
        case 'list_collections': return this.listCollections();
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

  private async searchIcons(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = Math.min(999, Math.max(1, (args.limit as number) ?? 32));
    const params = new URLSearchParams({
      query,
      limit: String(limit),
    });
    const url = `${this.baseUrl}/search?${params}`;
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
    const data = await response.json() as { icons: string[]; total: number; limit: number; start: number };
    return {
      content: [{ type: 'text', text: this.truncate({ total: data.total, icons: data.icons }) }],
      isError: false,
    };
  }

  private async getIcons(args: Record<string, unknown>): Promise<ToolResult> {
    const prefix = encodeURIComponent(args.prefix as string);
    const icons = args.icons as string;
    const params = new URLSearchParams({ icons });
    const url = `${this.baseUrl}/${prefix}.json?${params}`;
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
    const data = await response.json() as {
      prefix: string;
      icons: Record<string, { body: string; width?: number; height?: number }>;
      width?: number;
      height?: number;
    };
    const defaultWidth = data.width ?? 24;
    const defaultHeight = data.height ?? 24;
    const result = {
      prefix: data.prefix,
      icons: Object.entries(data.icons).map(([name, icon]) => ({
        name,
        full_name: `${data.prefix}:${name}`,
        svg_body: icon.body,
        width: icon.width ?? defaultWidth,
        height: icon.height ?? defaultHeight,
      })),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  private async listCollections(): Promise<ToolResult> {
    const url = `${this.baseUrl}/collections`;
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
    const data = await response.json() as Record<string, {
      name: string;
      total: number;
      author?: { name: string; url?: string };
      license?: { title: string; spdx?: string; url?: string };
      category?: string;
      tags?: string[];
    }>;
    const result = {
      total: Object.keys(data).length,
      collections: Object.entries(data).map(([prefix, meta]) => ({
        prefix,
        name: meta.name,
        total_icons: meta.total,
        category: meta.category ?? null,
        author: meta.author?.name ?? null,
        license: meta.license?.title ?? null,
      })),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }
}
