/**
 * CATAAS — Cat as a Service MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://cataas.com
 * Auth: None — public, unauthenticated API
 * Docs: https://cataas.com/#/
 * Category: entertainment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://cataas.com';

type RawCatJson = {
  id: string;
  tags: string[];
  url?: string;
  createdAt?: string;
  updatedAt?: string;
  mimetype?: string;
  size?: number;
};

type RawTagsResponse = string[];

export class CataasMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CataasMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'cataas',
      displayName: 'CATAAS — Cat as a Service',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'cat', 'cats', 'cataas', 'image', 'photo', 'random', 'animal',
        'tag', 'cute', 'fun', 'pet',
      ],
      toolNames: ['random_cat', 'cat_by_tag', 'list_tags'],
      description: 'CATAAS (Cat as a Service): retrieve random cat images or filter by tag, and list all available tags — free, public, unauthenticated.',
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
        name: 'random_cat',
        description: 'Get a random cat image from CATAAS (Cat as a Service). Returns the image URL, cat ID, and associated tags.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'cat_by_tag',
        description: 'Get a random cat image matching a specific tag from CATAAS. Use list_tags first to discover available tags. Returns the image URL, cat ID, and tags.',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description: 'Tag to filter cats by (e.g. "cute", "orange", "grumpy"). Use list_tags to see available tags.',
            },
          },
          required: ['tag'],
        },
      },
      {
        name: 'list_tags',
        description: 'List all available cat tags on CATAAS. Use these tags with cat_by_tag to find cats of a specific type or appearance.',
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
        case 'random_cat':  return this.randomCat();
        case 'cat_by_tag':  return this.catByTag(args.tag as string);
        case 'list_tags':   return this.listTags();
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

  private buildCatUrl(id: string): string {
    return `${this.baseUrl}/cat/${id}`;
  }

  private async randomCat(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/cat?json=true`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawCatJson;
    const result = {
      id: data.id,
      url: this.buildCatUrl(data.id),
      tags: data.tags ?? [],
      mimetype: data.mimetype ?? null,
      created_at: data.createdAt ?? null,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async catByTag(tag: string): Promise<ToolResult> {
    if (!tag || typeof tag !== 'string') {
      return { content: [{ type: 'text', text: 'cat_by_tag: tag parameter is required' }], isError: true };
    }
    const encodedTag = encodeURIComponent(tag);
    const response = await this.fetchWithRetry(`${this.baseUrl}/cat/${encodedTag}?json=true`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawCatJson;
    const result = {
      id: data.id,
      url: this.buildCatUrl(data.id),
      tags: data.tags ?? [],
      mimetype: data.mimetype ?? null,
      created_at: data.createdAt ?? null,
      searched_tag: tag,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listTags(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/api/tags`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawTagsResponse;
    const result = {
      count: data.length,
      tags: data,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
