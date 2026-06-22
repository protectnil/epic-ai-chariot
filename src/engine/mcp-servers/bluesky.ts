/**
 * Bluesky AT Protocol MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL (public): https://public.api.bsky.app/xrpc
// Base URL (auth):   https://bsky.social/xrpc
// Auth: None required for 7 of 8 tools (public AT Protocol XRPC).
//       search_posts requires a Bluesky handle + app-password supplied
//       as tool args; the adapter exchanges them for a session JWT at
//       call time — no credential storage at the adapter level.
// Docs: https://docs.bsky.app/docs/api/
// Category: social
// Rate limits: Not published; fair-use. Public endpoints are generous.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface BlueskyConfig {
  /** Optional base URL override for public XRPC calls */
  baseUrl?: string;
  /** Optional auth base URL override */
  authBaseUrl?: string;
}

// ── Internal response shape helpers ──────────────────────────────────

interface BskyProfile {
  did: string;
  handle: string;
  displayName?: string;
  description?: string;
  followersCount?: number;
  followsCount?: number;
  postsCount?: number;
}

interface BskyPostView {
  uri: string;
  cid: string;
  author: { handle: string; displayName?: string };
  record: { text?: string; createdAt?: string };
  likeCount?: number;
  repostCount?: number;
  replyCount?: number;
}

function formatProfile(p: BskyProfile) {
  return {
    did: p.did,
    handle: p.handle,
    displayName: p.displayName ?? '',
    description: p.description ?? '',
    followers: p.followersCount ?? 0,
    following: p.followsCount ?? 0,
    posts: p.postsCount ?? 0,
  };
}

function formatPost(p: BskyPostView) {
  return {
    uri: p.uri,
    author: p.author.displayName || p.author.handle,
    handle: p.author.handle,
    text: p.record?.text ?? '',
    createdAt: p.record?.createdAt ?? '',
    likes: p.likeCount ?? 0,
    reposts: p.repostCount ?? 0,
    replies: p.replyCount ?? 0,
  };
}

// ── Adapter ───────────────────────────────────────────────────────────

export class BlueskyMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;
  private readonly authBaseUrl: string;

  constructor(config: BlueskyConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Bluesky: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://public.api.bsky.app/xrpc';
    this.authBaseUrl = config.authBaseUrl ?? 'https://bsky.social/xrpc';
  }

  static catalog() {
    return {
      name: 'bluesky',
      displayName: 'Bluesky',
      version: '1.0.0',
      category: 'social',
      keywords: [
        'bluesky', 'bsky', 'at protocol', 'atproto', 'social media',
        'decentralized', 'feed', 'posts', 'profile', 'followers',
        'follows', 'thread', 'handle', 'did', 'search',
      ],
      toolNames: [
        'get_profile',
        'get_posts',
        'search_posts',
        'get_feed',
        'get_followers',
        'get_follows',
        'get_thread',
        'resolve_handle',
      ],
      description:
        'Bluesky AT Protocol API: read user profiles, posts, feeds, followers, threads, and resolve handles. ' +
        'Seven tools are fully public (no auth). search_posts requires a Bluesky handle and app-password supplied as tool args.',
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
        name: 'get_profile',
        description:
          '[Public] Get a Bluesky user profile by handle (e.g., "alice.bsky.social"). ' +
          'Returns DID, display name, bio, follower/following/post counts.',
        inputSchema: {
          type: 'object',
          properties: {
            handle: {
              type: 'string',
              description: 'Bluesky handle (e.g., alice.bsky.social)',
            },
          },
          required: ['handle'],
        },
      },
      {
        name: 'get_posts',
        description:
          "[Public] Get recent posts from a Bluesky user's author feed.",
        inputSchema: {
          type: 'object',
          properties: {
            handle: {
              type: 'string',
              description: 'Bluesky handle',
            },
            limit: {
              type: 'number',
              description: 'Number of posts to return (1–100, default 20)',
            },
          },
          required: ['handle'],
        },
      },
      {
        name: 'search_posts',
        description:
          '[Auth required] Search Bluesky posts by keyword. ' +
          'Requires bsky_handle and bsky_app_password (generate at https://bsky.app/settings/app-passwords). ' +
          'Returns matching posts with author, text, engagement counts, and timestamps.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1–100, default 25)',
            },
            bsky_handle: {
              type: 'string',
              description: 'Your Bluesky handle (required for auth, e.g., you.bsky.social)',
            },
            bsky_app_password: {
              type: 'string',
              description: 'Your Bluesky app-password (generate at https://bsky.app/settings/app-passwords)',
            },
          },
          required: ['query', 'bsky_handle', 'bsky_app_password'],
        },
      },
      {
        name: 'get_feed',
        description:
          '[Public] Get posts from a Bluesky feed generator. ' +
          'Defaults to the "What\'s Hot" discovery feed when feed_uri is omitted.',
        inputSchema: {
          type: 'object',
          properties: {
            feed_uri: {
              type: 'string',
              description:
                'AT URI of the feed generator (default: at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.generator/whats-hot)',
            },
            limit: {
              type: 'number',
              description: 'Number of posts to return (1–100, default 20)',
            },
          },
        },
      },
      {
        name: 'get_followers',
        description: "[Public] Get a user's followers on Bluesky.",
        inputSchema: {
          type: 'object',
          properties: {
            handle: {
              type: 'string',
              description: 'Bluesky handle',
            },
            limit: {
              type: 'number',
              description: 'Number of followers to return (1–100, default 50)',
            },
          },
          required: ['handle'],
        },
      },
      {
        name: 'get_follows',
        description: '[Public] Get the accounts that a Bluesky user follows.',
        inputSchema: {
          type: 'object',
          properties: {
            handle: {
              type: 'string',
              description: 'Bluesky handle',
            },
            limit: {
              type: 'number',
              description: 'Number of follows to return (1–100, default 50)',
            },
          },
          required: ['handle'],
        },
      },
      {
        name: 'get_thread',
        description:
          '[Public] Get a post and its reply thread by AT URI ' +
          '(format: at://did:plc:xxx/app.bsky.feed.post/rkey).',
        inputSchema: {
          type: 'object',
          properties: {
            post_uri: {
              type: 'string',
              description:
                'AT URI of the post (e.g., at://did:plc:abc123/app.bsky.feed.post/3xyz)',
            },
          },
          required: ['post_uri'],
        },
      },
      {
        name: 'resolve_handle',
        description: '[Public] Resolve a Bluesky handle to its DID (Decentralized Identifier).',
        inputSchema: {
          type: 'object',
          properties: {
            handle: {
              type: 'string',
              description: 'Bluesky handle to resolve (e.g., alice.bsky.social)',
            },
          },
          required: ['handle'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_profile':     return this.getProfile(args);
        case 'get_posts':       return this.getPosts(args);
        case 'search_posts':    return this.searchPosts(args);
        case 'get_feed':        return this.getFeed(args);
        case 'get_followers':   return this.getFollowers(args);
        case 'get_follows':     return this.getFollows(args);
        case 'get_thread':      return this.getThread(args);
        case 'resolve_handle':  return this.resolveHandle(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
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

  // ── Private helpers ───────────────────────────────────────────────────

  /** GET from the public XRPC endpoint with query parameters. */
  private async publicGet(method: string, params: Record<string, string>): Promise<ToolResult> {
    const qs = new URLSearchParams(params);
    const url = `${this.baseUrl}/${method}?${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Bluesky API error ${response.status}: ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  /** POST to the auth XRPC endpoint and return session JWT. */
  private async createSession(handle: string, appPassword: string): Promise<{ accessJwt: string; did: string }> {
    const url = `${this.authBaseUrl}/com.atproto.server.createSession`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ identifier: handle, password: appPassword }),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Bluesky auth failed (${response.status}): ${errText}`);
    }
    return response.json() as Promise<{ accessJwt: string; did: string }>;
  }

  /** GET from the auth XRPC endpoint with a Bearer token. */
  private async authGet(
    method: string,
    params: Record<string, string>,
    accessJwt: string,
  ): Promise<ToolResult> {
    const qs = new URLSearchParams(params);
    const url = `${this.authBaseUrl}/${method}?${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessJwt}`,
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Bluesky API error ${response.status}: ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  // ── Tool implementations ──────────────────────────────────────────────

  private async getProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('app.bsky.actor.getProfile', {
      actor: args.handle as string,
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as BskyProfile;
    return {
      content: [{ type: 'text', text: this.truncate(formatProfile(raw)) }],
      isError: false,
    };
  }

  private async getPosts(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('app.bsky.feed.getAuthorFeed', {
      actor: args.handle as string,
      limit: String((args.limit as number) ?? 20),
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      feed: { post: BskyPostView }[];
    };
    return {
      content: [{ type: 'text', text: this.truncate({ posts: raw.feed.map((item) => formatPost(item.post)) }) }],
      isError: false,
    };
  }

  private async searchPosts(args: Record<string, unknown>): Promise<ToolResult> {
    const handle = args.bsky_handle as string;
    const appPassword = args.bsky_app_password as string;

    let session: { accessJwt: string; did: string };
    try {
      session = await this.createSession(handle, appPassword);
    } catch (err) {
      return {
        content: [{
          type: 'text',
          text: `Authentication failed: ${err instanceof Error ? err.message : String(err)}`,
        }],
        isError: true,
      };
    }

    const data = await this.authGet(
      'app.bsky.feed.searchPosts',
      {
        q: args.query as string,
        limit: String((args.limit as number) ?? 25),
      },
      session.accessJwt,
    );
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      posts: BskyPostView[];
    };
    return {
      content: [{ type: 'text', text: this.truncate({ posts: raw.posts.map(formatPost) }) }],
      isError: false,
    };
  }

  private async getFeed(args: Record<string, unknown>): Promise<ToolResult> {
    const feedUri =
      (args.feed_uri as string) ??
      'at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.generator/whats-hot';
    const data = await this.publicGet('app.bsky.feed.getFeed', {
      feed: feedUri,
      limit: String((args.limit as number) ?? 20),
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      feed: { post: BskyPostView }[];
    };
    return {
      content: [{ type: 'text', text: this.truncate({ posts: raw.feed.map((item) => formatPost(item.post)) }) }],
      isError: false,
    };
  }

  private async getFollowers(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('app.bsky.graph.getFollowers', {
      actor: args.handle as string,
      limit: String((args.limit as number) ?? 50),
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      followers: BskyProfile[];
    };
    return {
      content: [{ type: 'text', text: this.truncate({ followers: raw.followers.map(formatProfile) }) }],
      isError: false,
    };
  }

  private async getFollows(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('app.bsky.graph.getFollows', {
      actor: args.handle as string,
      limit: String((args.limit as number) ?? 50),
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      follows: BskyProfile[];
    };
    return {
      content: [{ type: 'text', text: this.truncate({ follows: raw.follows.map(formatProfile) }) }],
      isError: false,
    };
  }

  private async getThread(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('app.bsky.feed.getPostThread', {
      uri: args.post_uri as string,
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as {
      thread: { post: BskyPostView; replies?: { post: BskyPostView }[] };
    };
    return {
      content: [{
        type: 'text',
        text: this.truncate({
          post: formatPost(raw.thread.post),
          replies: (raw.thread.replies ?? []).map((r) => formatPost(r.post)),
        }),
      }],
      isError: false,
    };
  }

  private async resolveHandle(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.publicGet('com.atproto.identity.resolveHandle', {
      handle: args.handle as string,
    });
    if (data.isError) return data;
    const raw = JSON.parse((data.content[0] as { text: string }).text) as { did: string };
    return {
      content: [{ type: 'text', text: this.truncate({ handle: args.handle, did: raw.did }) }],
      isError: false,
    };
  }
}
