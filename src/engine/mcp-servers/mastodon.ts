/**
 * Mastodon MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://mastodon.social/api
// Auth: None required — public Mastodon REST API (no key needed)
// Docs: https://docs.joinmastodon.org/api/
// Category: social
// Rate limits: Standard Mastodon public rate limits (300 req / 5 min per IP)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class MastodonMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('MastodonMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://mastodon.social/api';
  }

  static catalog() {
    return {
      name: 'mastodon',
      displayName: 'Mastodon',
      version: '1.0.0',
      category: 'social',
      keywords: [
        'mastodon', 'fediverse', 'social', 'microblogging', 'activitypub',
        'timeline', 'trending', 'statuses', 'toots', 'accounts', 'hashtags',
        'search', 'public timeline', 'decentralized social',
      ],
      toolNames: ['search', 'get_trending', 'get_account', 'get_timeline'],
      description: 'Mastodon public API: search accounts, statuses, and hashtags; fetch trending statuses; retrieve public account profiles; and browse the public timeline — no authentication required.',
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
        description: 'Search Mastodon for accounts, statuses, or hashtags on mastodon.social.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string',
            },
            type: {
              type: 'string',
              description: 'Type of results: accounts, statuses, or hashtags (default: statuses)',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default: 10, max: 40)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_trending',
        description: 'Get currently trending statuses on mastodon.social.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of trending statuses to return (default: 10, max: 40)',
            },
          },
        },
      },
      {
        name: 'get_account',
        description: 'Get a public Mastodon account profile by numeric account ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Numeric Mastodon account ID (e.g. "109302436954721982")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_timeline',
        description: 'Get recent trending public statuses from mastodon.social (uses the trending-statuses endpoint; the global public timeline requires authentication).',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of statuses to return (default: 20, max: 40)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':       return this.search(args);
        case 'get_trending': return this.getTrending(args);
        case 'get_account':  return this.getAccount(args);
        case 'get_timeline': return this.getTimeline(args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query  = args.query as string;
    const type   = (args.type as string) ?? 'statuses';
    const limit  = Math.max(1, Math.min(40, (args.limit as number) ?? 10));

    const params = new URLSearchParams({ q: query, type, limit: String(limit) });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/v2/search?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Mastodon search error: ${response.status} ${errText}` }], isError: true };
    }

    const data = await response.json() as {
      accounts: MastodonAccount[];
      statuses: MastodonStatus[];
      hashtags: MastodonHashtag[];
    };

    const result = {
      query,
      type,
      accounts: data.accounts.map(mapAccount),
      statuses: data.statuses.map(mapStatus),
      hashtags: data.hashtags.map((h) => ({ name: h.name, url: h.url })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTrending(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = Math.max(1, Math.min(40, (args.limit as number) ?? 10));

    const params = new URLSearchParams({ limit: String(limit) });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/v1/trends/statuses?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Mastodon trending error: ${response.status} ${errText}` }], isError: true };
    }

    const data = await response.json() as MastodonStatus[];

    const result = {
      count: data.length,
      statuses: data.map(mapStatus),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAccount(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as string;

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/v1/accounts/${encodeURIComponent(id)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Mastodon account error: ${response.status} ${errText}` }], isError: true };
    }

    const data = await response.json() as MastodonAccount;

    return { content: [{ type: 'text', text: this.truncate(mapAccount(data)) }], isError: false };
  }

  private async getTimeline(args: Record<string, unknown>): Promise<ToolResult> {
    // mastodon.social locked /v1/timelines/public behind authentication (returns 422).
    // /v1/trends/statuses is the public, no-auth equivalent returning the same MastodonStatus[] shape.
    const limit = Math.max(1, Math.min(40, (args.limit as number) ?? 20));

    const params = new URLSearchParams({ limit: String(limit) });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/v1/trends/statuses?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Mastodon timeline error: ${response.status} ${errText}` }], isError: true };
    }

    const data = await response.json() as MastodonStatus[];

    const result = {
      count: data.length,
      statuses: data.map(mapStatus),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Type definitions ───────────────────────────────────────────────────────

interface MastodonAccount {
  id: string;
  username: string;
  acct: string;
  display_name: string;
  note: string;
  url: string;
  followers_count: number;
  following_count: number;
  statuses_count: number;
  created_at: string;
  bot: boolean;
  avatar: string;
}

interface MastodonStatus {
  id: string;
  created_at: string;
  url: string;
  content: string;
  visibility: string;
  favourites_count: number;
  reblogs_count: number;
  replies_count: number;
  account: {
    id: string;
    username: string;
    acct: string;
    display_name: string;
  };
  tags: Array<{ name: string; url: string }>;
  language?: string | null;
  sensitive: boolean;
  spoiler_text?: string;
}

interface MastodonHashtag {
  name: string;
  url: string;
  history?: Array<{ day: string; uses: string; accounts: string }>;
}

// ── Mappers ────────────────────────────────────────────────────────────────

function mapAccount(a: MastodonAccount) {
  return {
    id: a.id,
    username: a.username,
    acct: a.acct,
    display_name: a.display_name,
    url: a.url,
    followers_count: a.followers_count,
    following_count: a.following_count,
    statuses_count: a.statuses_count,
    created_at: a.created_at,
    bot: a.bot,
    avatar: a.avatar,
    note: a.note,
  };
}

function mapStatus(s: MastodonStatus) {
  return {
    id: s.id,
    created_at: s.created_at,
    url: s.url,
    content: s.content,
    visibility: s.visibility,
    favourites_count: s.favourites_count,
    reblogs_count: s.reblogs_count,
    replies_count: s.replies_count,
    language: s.language ?? null,
    sensitive: s.sensitive,
    spoiler_text: s.spoiler_text || null,
    tags: s.tags.map((t) => t.name),
    account: {
      id: s.account.id,
      username: s.account.username,
      acct: s.account.acct,
      display_name: s.account.display_name,
    },
  };
}
