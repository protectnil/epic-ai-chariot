/**
 * EmojiHub MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://emojihub.yurace.pro/api (free, no auth)
// Docs: https://github.com/cheatsnake/emojihub
// Category: entertainment
// Tools: random_emoji, get_by_category, get_by_group

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://emojihub.yurace.pro/api';

export class EmojiHubMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'emojihub',
      displayName: 'EmojiHub',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'emoji', 'emojis', 'unicode', 'symbols', 'emoticons',
        'smileys', 'people', 'animals', 'food', 'flags',
        'random emoji', 'emoji category', 'emoji group',
      ],
      toolNames: ['random_emoji', 'get_by_category', 'get_by_group'],
      description: 'EmojiHub API: retrieve a random emoji or browse emojis by category or group — free and unauthenticated.',
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
        name: 'random_emoji',
        description: 'Get a random emoji from the EmojiHub API.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_by_category',
        description:
          'Get all emojis in a given category. Example categories: smileys-and-people, animals-and-nature, food-and-drink, travel-and-places, activities, objects, symbols, flags.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description:
                'The emoji category slug, e.g. "smileys-and-people", "animals-and-nature", "food-and-drink".',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'get_by_group',
        description:
          'Get all emojis in a given group. Example groups: face-positive, face-negative, face-neutral, hand-fingers-open, animals-mammal.',
        inputSchema: {
          type: 'object',
          properties: {
            group: {
              type: 'string',
              description:
                'The emoji group slug, e.g. "face-positive", "face-negative", "animals-mammal".',
            },
          },
          required: ['group'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_emoji':    return this.randomEmoji();
        case 'get_by_category': return this.getByCategory(args.category as string);
        case 'get_by_group':    return this.getByGroup(args.group as string);
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

  private async randomEmoji(): Promise<ToolResult> {
    return this.request('/random');
  }

  private async getByCategory(category: string): Promise<ToolResult> {
    if (!category) {
      return { content: [{ type: 'text', text: 'get_by_category: category is required' }], isError: true };
    }
    return this.request(`/all/category/${encodeURIComponent(category)}`);
  }

  private async getByGroup(group: string): Promise<ToolResult> {
    if (!group) {
      return { content: [{ type: 'text', text: 'get_by_group: group is required' }], isError: true };
    }
    return this.request(`/all/group/${encodeURIComponent(group)}`);
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
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
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
