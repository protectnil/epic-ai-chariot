/**
 * Lobsters MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://lobste.rs (public JSON API, no auth required)
// Base URL: https://lobste.rs
// Auth: none (public, no-auth-verified)
// Category: news
// Rate limits: None documented; be respectful of the public server

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://lobste.rs';

export class LobstersMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('LobstersMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'lobsters',
      displayName: 'Lobsters',
      version: '1.0.0',
      category: 'news',
      keywords: [
        'lobsters', 'lobste.rs', 'tech news', 'programming', 'hacker news',
        'stories', 'discussions', 'link aggregator', 'community', 'tags',
        'rust', 'security', 'open source', 'software',
      ],
      toolNames: ['get_hottest', 'get_newest', 'get_story', 'get_tag'],
      description: 'Lobsters: fetch front-page and newest stories, look up a single story with its comments, and browse stories by tag — free public API, no authentication required.',
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
        name: 'get_hottest',
        description: 'Get the hottest (front page) stories on Lobsters.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_newest',
        description: 'Get the newest stories on Lobsters.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_story',
        description: 'Get a single Lobsters story and its comments by short ID.',
        inputSchema: {
          type: 'object',
          properties: {
            short_id: {
              type: 'string',
              description: 'The short alphanumeric story ID from the Lobsters URL (e.g. "abcdef")',
            },
          },
          required: ['short_id'],
        },
      },
      {
        name: 'get_tag',
        description: 'Get stories for a specific Lobsters tag (e.g. "rust", "programming", "security").',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description: 'Tag name (e.g. "rust", "programming", "security")',
            },
          },
          required: ['tag'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_hottest': return this.getHottest();
        case 'get_newest':  return this.getNewest();
        case 'get_story':   return this.getStory(args);
        case 'get_tag':     return this.getTag(args);
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

  private mapStory(s: LobstersStory): MappedStory {
    return {
      short_id: s.short_id,
      url: s.url,
      comments_url: s.comments_url,
      title: s.title,
      score: s.score,
      upvotes: s.upvotes,
      downvotes: s.downvotes,
      comment_count: s.comment_count,
      created_at: s.created_at,
      submitter: s.submitter_user.username,
      tags: s.tags,
      description: s.description_plain ?? s.description ?? null,
    };
  }

  private async getHottest(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/hottest.json`, {
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
    const data = (await response.json()) as LobstersStory[];
    return {
      content: [{ type: 'text', text: this.truncate({ count: data.length, stories: data.map(s => this.mapStory(s)) }) }],
      isError: false,
    };
  }

  private async getNewest(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/newest.json`, {
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
    const data = (await response.json()) as LobstersStory[];
    return {
      content: [{ type: 'text', text: this.truncate({ count: data.length, stories: data.map(s => this.mapStory(s)) }) }],
      isError: false,
    };
  }

  private async getStory(args: Record<string, unknown>): Promise<ToolResult> {
    const shortId = args.short_id as string;
    if (!shortId || typeof shortId !== 'string') {
      return { content: [{ type: 'text', text: 'short_id is required and must be a string' }], isError: true };
    }
    const response = await this.fetchWithRetry(`${this.baseUrl}/s/${encodeURIComponent(shortId)}.json`, {
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
    const data = (await response.json()) as LobstersStoryWithComments;
    const result = {
      story: this.mapStory(data),
      comments: (data.comments ?? []).map((c) => ({
        short_id: c.short_id,
        url: c.url,
        created_at: c.created_at,
        score: c.score,
        indent_level: c.indent_level,
        author: c.commenting_user.username,
        body: c.comment_plain ?? c.comment,
        is_deleted: c.is_deleted,
        is_moderated: c.is_moderated,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTag(args: Record<string, unknown>): Promise<ToolResult> {
    const tag = args.tag as string;
    if (!tag || typeof tag !== 'string') {
      return { content: [{ type: 'text', text: 'tag is required and must be a string' }], isError: true };
    }
    const response = await this.fetchWithRetry(`${this.baseUrl}/t/${encodeURIComponent(tag)}.json`, {
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
    const data = (await response.json()) as LobstersStory[];
    return {
      content: [{ type: 'text', text: this.truncate({ tag, count: data.length, stories: data.map(s => this.mapStory(s)) }) }],
      isError: false,
    };
  }
}

// ── Upstream type shapes ────────────────────────────────────────────────────

interface LobstersStory {
  short_id: string;
  short_id_url: string;
  created_at: string;
  title: string;
  url: string;
  score: number;
  upvotes: number;
  downvotes: number;
  comment_count: number;
  description?: string;
  description_plain?: string;
  comments_url: string;
  submitter_user: { username: string };
  tags: string[];
}

interface LobstersComment {
  short_id: string;
  created_at: string;
  updated_at: string;
  is_deleted: boolean;
  is_moderated: boolean;
  score: number;
  upvotes: number;
  downvotes: number;
  comment: string;
  comment_plain: string;
  url: string;
  indent_level: number;
  commenting_user: { username: string };
}

interface LobstersStoryWithComments extends LobstersStory {
  comments: LobstersComment[];
}

interface MappedStory {
  short_id: string;
  url: string;
  comments_url: string;
  title: string;
  score: number;
  upvotes: number;
  downvotes: number;
  comment_count: number;
  created_at: string;
  submitter: string;
  tags: string[];
  description: string | null;
}
